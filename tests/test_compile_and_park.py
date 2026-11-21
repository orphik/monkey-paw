from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.compile_locked_spec import SUPPORTED_FORMATS, compile_specification  # noqa: E402
from scripts.mcp_stdio_server import serve_stdio  # noqa: E402
from scripts.park_tangent import park_tangent_entry  # noqa: E402


class TestCompileParkAndMcp(unittest.TestCase):
    def setUp(self) -> None:
        fixture_dir = REPO_ROOT / "assets" / "examples" / "sample-fintech-refund"
        self.draft_text = (fixture_dir / "raw-ticket.md").read_text(encoding="utf-8")
        self.findings_doc = json.loads((fixture_dir / "findings.json").read_text(encoding="utf-8"))
        self.committed_spec = (fixture_dir / "SPEC.md").read_text(encoding="utf-8")

    def test_sample_spec_matches_deterministic_ears_compiler(self) -> None:
        compiled = compile_specification(self.draft_text, self.findings_doc, output_format="ears")
        self.assertEqual(compiled, self.committed_spec)
        self.assertIn("WHEN `POST /v1/charges/{charge_id}/refund` is invoked, THE SYSTEM SHALL", compiled)

    def test_all_four_export_formats_compile_cleanly(self) -> None:
        expected_markers = {
            "ears": "# Locked Specification (EARS):",
            "spec-kit": "## User Journeys & Failure-Boundary Scenarios",
            "openspec": "## ADDED Requirements",
            "jira": "## Acceptance Criteria Checklist",
        }
        for fmt in SUPPORTED_FORMATS:
            rendered = compile_specification(self.draft_text, self.findings_doc, output_format=fmt)
            self.assertIn(expected_markers[fmt], rendered, msg=f"Missing marker for {fmt}")
            self.assertIn("MP-001", rendered)
            self.assertIn("SHALL", rendered)

    def test_unresolved_findings_rejected_by_compiler(self) -> None:
        unresolved_doc = {
            "mode": "greenfield",
            "draft_title": "Draft Feature",
            "findings": [
                {
                    "id": "MP-001",
                    "exploit_class": "silent_fallback",
                    "spec_quote": "Sync profile avatars nightly from external URL.",
                    "monkeys_paw_grant": "Agent overwrites existing avatar with empty byte buffer when upstream returns 503.",
                    "repo_citations": [],
                    "eng_options": {
                        "option_a": "Abort avatar overwrite on non-200 HTTP status or zero-byte body.",
                        "option_b": "Stage downloads in content-addressed bucket and swap pointer after MIME verification.",
                    },
                    "pm_tradeoff": "Option A keeps previous avatar intact on outage; Option B adds storage staging step.",
                }
            ],
        }
        with self.assertRaises(ValueError):
            compile_specification("Sync avatars nightly.", unresolved_doc, output_format="ears")

        # Now resolve with custom decision and verify automatic EARS synthesis
        unresolved_doc["findings"][0]["resolution"] = {
            "selected": "custom",
            "custom_design": "Verify HTTP 200 and image Content-Type header before replacing existing avatar reference.",
        }
        compiled = compile_specification("Sync avatars nightly.", unresolved_doc, output_format="ears")
        self.assertIn("THE SYSTEM SHALL", compiled)
        self.assertIn("Custom Decision", compiled)

    def test_park_tangent_sequential_ids_dedup_and_spec_linking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pl_path = Path(tmp) / "PARKING-LOT.md"
            r1 = park_tangent_entry(
                pl_path,
                item="Migrate legacy Stripe Charges API to PaymentIntents | v2",
                category="tech-debt",
                reason="Out of scope for v1 refund button",
                spec_name="Merchant Refunds",
                related_finding="MP-002",
                date_str="2026-11-21",
            )
            self.assertEqual(r1["id"], "PL-001")
            self.assertTrue(r1["created"])
            self.assertFalse(r1["duplicate"])

            # Duplicate submission returns PL-001 without adding a second row
            r_dup = park_tangent_entry(
                pl_path,
                item="Migrate legacy Stripe Charges API to PaymentIntents | v2",
                category="tech-debt",
            )
            self.assertEqual(r_dup["id"], "PL-001")
            self.assertTrue(r_dup["duplicate"])

            r2 = park_tangent_entry(
                pl_path,
                item="Add Slack webhook alert for >$1,000 refunds",
                category="phase-2",
                date_str="2026-11-21",
            )
            self.assertEqual(r2["id"], "PL-002")

            pl_text = pl_path.read_text(encoding="utf-8")
            self.assertIn("\\| v2", pl_text)

            compiled = compile_specification(
                self.draft_text,
                self.findings_doc,
                output_format="ears",
                parking_lot_text=pl_text,
            )
            self.assertIn("PL-001", compiled)
            self.assertIn("PL-002", compiled)

    def test_mcp_stdio_server_newline_and_content_length_framing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            pl_out = tmp_dir / "PARKING-LOT.md"
            surf_out = tmp_dir / ".monkey-paw" / "surface.json"

            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "extract_repo_surface",
                        "arguments": {"repo": str(tmp_dir), "out": str(surf_out)},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "validate_findings",
                        "arguments": {"findings": self.findings_doc, "require_resolved": True},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "compile_locked_spec",
                        "arguments": {
                            "draft_text": self.draft_text,
                            "findings": self.findings_doc,
                            "format": "openspec",
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "park_tangent",
                        "arguments": {
                            "item": "Support CSV bulk refund uploads",
                            "category": "phase-2",
                            "out": str(pl_out),
                        },
                    },
                },
                {"jsonrpc": "2.0", "id": 7, "method": "unknown/method"},
            ]

            # 1. Test newline-delimited JSON-RPC stdio stream
            in_buf = io.BytesIO(
                "".join(json.dumps(r) + "\n" for r in requests).encode("utf-8")
            )
            out_buf = io.BytesIO()
            rc = serve_stdio(in_buf, out_buf)
            self.assertEqual(rc, 0)

            responses = [
                json.loads(line)
                for line in out_buf.getvalue().decode("utf-8").splitlines()
                if line.strip()
            ]
            # 8 messages minus 1 notification = 7 responses
            self.assertEqual(len(responses), 7)
            self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "monkey-paw")

            tool_names = {t["name"] for t in responses[1]["result"]["tools"]}
            self.assertEqual(
                tool_names,
                {"extract_repo_surface", "validate_findings", "compile_locked_spec", "park_tangent"},
            )
            self.assertFalse(responses[2]["result"]["isError"])
            self.assertFalse(responses[3]["result"]["isError"])
            self.assertIn("ADDED Requirements", responses[4]["result"]["content"][0]["text"])
            self.assertFalse(responses[5]["result"]["isError"])
            self.assertEqual(responses[6]["error"]["code"], -32601)

            # 2. Test Content-Length framed JSON-RPC message
            ping_bytes = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode("utf-8")
            framed_in = io.BytesIO(f"Content-Length: {len(ping_bytes)}\r\n\r\n".encode("ascii") + ping_bytes)
            framed_out = io.BytesIO()
            serve_stdio(framed_in, framed_out)
            raw_reply = framed_out.getvalue()
            self.assertTrue(raw_reply.startswith(b"Content-Length:"))
            _, body = raw_reply.split(b"\r\n\r\n", 1)
            self.assertEqual(json.loads(body.decode("utf-8"))["id"], 99)


if __name__ == "__main__":
    unittest.main()
