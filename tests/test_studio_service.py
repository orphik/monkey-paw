from __future__ import annotations

import csv
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.extract_repo_surface import scan_repository  # noqa: E402
from studio.backlog_compiler import (  # noqa: E402
    export_backlog_markdown,
    export_jira_csv,
    normalize_backlog_tree,
)
from studio.github_ingest import ingest_repository_surface, parse_github_target  # noqa: E402
from studio.server import build_server  # noqa: E402
from studio.store import StudioSessionStore  # noqa: E402


class TestStudioService(unittest.TestCase):
    def test_csharp_and_ruby_surface_extractors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "PayoutsController.cs").write_text(
                """
public enum PayoutState { Pending, Settled }
public record RetryBatchRequest(string BatchId, int Count);

[ApiController]
[Route("api/v1/payouts")]
public class PayoutsController {
    [Authorize("TreasuryAdmin")]
    [HttpPost("retry")]
    public object Retry(RetryBatchRequest req) => null;
}
""",
                encoding="utf-8",
            )
            (root / "invoice.rb").write_text(
                """
class Invoice < ApplicationRecord
end

class ReconcileJob < ApplicationJob
end
""",
                encoding="utf-8",
            )
            (root / "routes.rb").write_text(
                "post '/webhooks/stripe', to: 'webhooks#stripe'\n",
                encoding="utf-8",
            )

            payload, _ = scan_repository(root)
            surface = payload["surface"]
            models = {m["name"] for m in surface["models"]}
            enums = {e["name"] for e in surface["enums"]}
            routes = {r["name"] for r in surface["routes"]}
            auth = {a["name"] for a in surface["auth"]}
            workers = {w["name"] for w in surface["workers"]}

            self.assertTrue({"RetryBatchRequest", "Invoice"}.issubset(models))
            self.assertIn("PayoutState", enums)
            self.assertIn("POST /api/v1/payouts/retry", routes)
            self.assertIn("POST /webhooks/stripe", routes)
            self.assertTrue(any("Authorize" in a for a in auth))
            self.assertIn("ReconcileJob", workers)

    def test_github_url_validation_and_cloud_local_path_guard(self) -> None:
        clone_url, label, branch = parse_github_target("orphik/monkey-paw", "main")
        self.assertEqual(clone_url, "https://github.com/orphik/monkey-paw.git")
        self.assertEqual(label, "github:orphik/monkey-paw@main")
        self.assertEqual(branch, "main")

        clone2, label2, branch2 = parse_github_target("https://github.com/orphik/monkey-paw/tree/feat/studio")
        self.assertEqual(clone2, "https://github.com/orphik/monkey-paw.git")
        self.assertEqual(branch2, "feat/studio")
        self.assertIn("feat/studio", label2)

        for unsafe in (
            "http://github.com/orphik/monkey-paw",
            "https://gitlab.com/orphik/monkey-paw",
            "https://token:secret@github.com/orphik/monkey-paw",
            "file:///etc/passwd",
            "-upload-pack/evil",
        ):
            with self.assertRaises(ValueError, msg=f"Should reject {unsafe!r}"):
                parse_github_target(unsafe)

        with self.assertRaises(PermissionError):
            ingest_repository_surface(
                source_type="local_path",
                repo_target=str(REPO_ROOT),
                allow_local_paths=False,
            )

    def test_sqlite_store_strips_transient_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StudioSessionStore(Path(tmp) / "studio.sqlite3")
            created = store.create_session(
                {
                    "title": "Billing PRD",
                    "mode": "greenfield",
                    "api_key": "sk-should-never-persist",
                    "github_token": "ghp_should_never_persist",
                    "nested": {"passcode": "topsecret"},
                }
            )
            loaded = store.get_session(created["id"])
            assert loaded is not None
            raw = json.dumps(loaded)
            self.assertNotIn("sk-should-never-persist", raw)
            self.assertNotIn("ghp_should_never_persist", raw)
            self.assertNotIn("topsecret", raw)
            self.assertEqual(len(store.list_sessions()), 1)
            self.assertTrue(store.delete_session(created["id"]))
            self.assertIsNone(store.get_session(created["id"]))

    def test_backlog_hierarchy_presets_and_jira_csv_export(self) -> None:
        raw_tree = [
            {
                "title": "Subscription Pause Initiative",
                "description": "Reduce churn via self-serve pause.",
                "children": [
                    {
                        "title": "Billing Lifecycle Control",
                        "children": [
                            {
                                "title": "Atomic Pause & Resume",
                                "children": [
                                    {
                                        "title": "Pause Active Subscription",
                                        "description": "As a billing owner, I want to pause for 90 days, so that I avoid canceling.",
                                        "estimate": "5",
                                        "acceptance_criteria": [
                                            "WHEN pause is requested, THE SYSTEM SHALL lock Subscription FOR UPDATE."
                                        ],
                                        "guardrail_ids": ["MP-001"],
                                        "repo_touchpoints": ["app/billing.py:42"],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]

        norm_4 = normalize_backlog_tree(raw_tree, preset="enterprise_4tier")
        self.assertEqual(norm_4[0]["id"], "EPIC-1")
        self.assertEqual(norm_4[0]["children"][0]["id"], "CAP-1.1")
        self.assertEqual(norm_4[0]["children"][0]["children"][0]["id"], "FEAT-1.1.1")
        self.assertEqual(norm_4[0]["children"][0]["children"][0]["children"][0]["id"], "US-1.1.1.1")

        norm_cap = normalize_backlog_tree(raw_tree, preset="capability_first")
        self.assertEqual(norm_cap[0]["id"], "CAP-1")
        self.assertEqual(norm_cap[0]["children"][0]["id"], "EPIC-1.1")

        csv_text = export_jira_csv(norm_4, parked_items=[{"id": "PL-001", "item": "Usage meters", "category": "phase-2"}], include_parked=True)
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["Issue Type"], "Epic")
        self.assertEqual(rows[1]["Parent ID"], "EPIC-1")
        self.assertEqual(rows[3]["Issue Type"], "Story")
        self.assertIn("MP-001", rows[3]["Guardrail IDs"])

        md = export_backlog_markdown("Subscription Pause", "enterprise_4tier", "brownfield", norm_4)
        self.assertIn("EPIC-1 [EPIC]", md)
        self.assertIn("US-1.1.1.1 [STORY]", md)

    def test_studio_http_server_end_to_end_flow_and_passcode_gate(self) -> None:
        os.environ["STUDIO_QUIET_LOGS"] = "1"
        with tempfile.TemporaryDirectory() as tmp:
            db_file = Path(tmp) / "uat.sqlite3"
            dotenv_file = Path(tmp) / ".env"
            server = build_server(
                host="127.0.0.1",
                port=0,
                db_path=db_file,
                passcode="uat-secret-2026",
                allow_local_paths=True,
                dotenv_path=dotenv_file,
            )
            port = server.server_address[1]
            base_url = f"http://127.0.0.1:{port}"
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def _req(method: str, path: str, body: dict[str, Any] | None = None, passcode: str = "uat-secret-2026") -> tuple[int, Any]:
                headers: dict[str, str] = {"Content-Type": "application/json"}
                if passcode:
                    headers["X-Studio-Passcode"] = passcode
                data = json.dumps(body).encode("utf-8") if body is not None else None
                request = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
                try:
                    with urllib.request.urlopen(request, timeout=10) as resp:
                        raw = resp.read().decode("utf-8")
                        ctype = resp.headers.get("Content-Type", "")
                        return resp.status, (json.loads(raw) if "application/json" in ctype else raw)
                except urllib.error.HTTPError as exc:
                    try:
                        raw = exc.read().decode("utf-8")
                        return exc.code, json.loads(raw)
                    finally:
                        exc.close()

            try:
                # 1. Healthcheck works without passcode (Railway probe)
                st_h, health = _req("GET", "/api/health", passcode="")
                self.assertEqual(st_h, 200)
                self.assertTrue(health["ok"])

                # 2. Protected route rejects missing passcode with 401
                st_unauth, _ = _req("GET", "/api/sessions", passcode="")
                self.assertEqual(st_unauth, 401)

                # 3. Analyze PRD against local brownfield repo using Deterministic Sandbox
                st_a, res_a = _req(
                    "POST",
                    "/api/analyze",
                    {
                        "title": "Merchant Refund Portal",
                        "prd_text": (
                            "Allow merchants to issue full or partial refunds from the Charge Details screen via Stripe, "
                            "update ledger status, and notify customers via email without double-refunding."
                        ),
                        "source_type": "local_path",
                        "repo_target": str(REPO_ROOT),
                        "hierarchy_preset": "enterprise_4tier",
                        "provider_config": {"provider": "demo"},
                    },
                )
                self.assertEqual(st_a, 200, msg=res_a)
                session = res_a["session"]
                sid = session["id"]
                self.assertEqual(session["mode"], "brownfield")
                self.assertGreaterEqual(len(session["findings_doc"]["findings"]), 3)

                # 4. Park an off-scope tangent
                st_p, res_p = _req(
                    "POST",
                    f"/api/sessions/{sid}/park",
                    {"item": "Build chargeback dispute analytics page", "category": "phase-2"},
                )
                self.assertEqual(st_p, 200)
                self.assertEqual(res_p["parked"]["id"], "PL-001")

                # 5. Generate editable Epic/Capability/Feature/User Story backlog tree
                st_b, res_b = _req(
                    "POST",
                    f"/api/sessions/{sid}/backlog",
                    {"provider_config": {"provider": "demo"}},
                )
                self.assertEqual(st_b, 200, msg=res_b)
                session = res_b["session"]
                self.assertTrue(len(session["backlog_tree"]) >= 1)

                # 6. Simulate inline PM edit on Epic title and save via PUT
                session["backlog_tree"][0]["title"] = "Edited Epic: Merchant Self-Serve Refunds v1"
                st_put, res_put = _req("PUT", f"/api/sessions/{sid}", session)
                self.assertEqual(st_put, 200)
                self.assertEqual(res_put["session"]["backlog_tree"][0]["title"], "Edited Epic: Merchant Self-Serve Refunds v1")

                # 7. Export Jira CSV, BACKLOG.md, EARS SPEC.md, and PARKING-LOT.md
                for fmt, expected_substr in (
                    ("jira-csv", "Edited Epic: Merchant Self-Serve Refunds v1"),
                    ("backlog-md", "Edited Epic: Merchant Self-Serve Refunds v1"),
                    ("ears", "THE SYSTEM SHALL"),
                    ("parking-md", "PL-001"),
                ):
                    st_ex, res_ex = _req("POST", "/api/export", {"format": fmt, "session_id": sid, "include_parked": True})
                    self.assertEqual(st_ex, 200, msg=res_ex)
                    self.assertIn(expected_substr, res_ex["content"])

                # 8. Shareable SPA route `/s/<sid>` returns HTML UI
                st_html, html = _req("GET", f"/s/{sid}", passcode="")
                self.assertEqual(st_html, 200)
                self.assertIn("Monkey's Paw Studio", html)
                self.assertIn("Setup Env Vars", html)

                # 9. Localhost Setup Env Vars saves masked `.env` and rejects unwhitelisted keys
                fake_gem_key = "AIzaSyTestDummyKey1234567890XYZ"
                st_env, res_env = _req(
                    "POST",
                    "/api/env",
                    {"variables": {"GEMINI_API_KEY": fake_gem_key, "STUDIO_DEFAULT_MODEL": "gemini-3.8-flash"}},
                )
                self.assertEqual(st_env, 200, msg=res_env)
                raw_env_resp = json.dumps(res_env)
                self.assertNotIn(fake_gem_key, raw_env_resp)
                self.assertIn("AIza****XYZ", raw_env_resp)

                st_bad_env, _ = _req("POST", "/api/env", {"variables": {"PATH": "/evil"}})
                self.assertEqual(st_bad_env, 400)

                # Clear temporary test key so host environment stays clean
                _req("POST", "/api/env", {"variables": {"GEMINI_API_KEY": "__CLEAR__", "STUDIO_DEFAULT_MODEL": "__CLEAR__"}})
            finally:
                server.shutdown()
                server.server_close()

        # 10. Hosted / Railway mode (`allow_local_paths=False`) blocks POST /api/env with 403
        with tempfile.TemporaryDirectory() as tmp2:
            cloud_srv = build_server(
                host="127.0.0.1",
                port=0,
                db_path=Path(tmp2) / "cloud.sqlite3",
                passcode="",
                allow_local_paths=False,
                dotenv_path=Path(tmp2) / ".env",
            )
            cport = cloud_srv.server_address[1]
            cthread = threading.Thread(target=cloud_srv.serve_forever, daemon=True)
            cthread.start()
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{cport}/api/env",
                    data=json.dumps({"variables": {"GEMINI_API_KEY": "AIzaBlocked"}}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx_err:
                    urllib.request.urlopen(req, timeout=5)
                try:
                    self.assertEqual(ctx_err.exception.code, 403)
                finally:
                    ctx_err.exception.close()
            finally:
                cloud_srv.shutdown()
                cloud_srv.server_close()


if __name__ == "__main__":
    unittest.main()
