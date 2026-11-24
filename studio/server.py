#!/usr/bin/env python3
"""Zero-dependency HTTP & REST server for Monkey's Paw Studio.

Runs locally (`python3 -m studio`) or on Railway (`0.0.0.0:$PORT`), exposing:
- `GET  /` & `GET /s/<id>`              : Single-page Studio Workbench UI
- `GET  /api/health`                    : Railway / container readiness probe
- `GET  /api/config`                    : Runtime capabilities, presets, and passcode status
- `POST /api/auth/verify`               : Constant-time `STUDIO_PASSCODE` check
- `GET  /api/sessions`                  : Recent SQLite sessions list
- `POST /api/sessions`                  : Create/import session
- `GET  /api/sessions/<id>`             : Load session by shareable ID
- `PUT  /api/sessions/<id>`             : Save inline edits (cards, backlog tree, parked items)
- `DELETE /api/sessions/<id>`           : Delete session
- `POST /api/analyze`                   : Scan repo (GitHub / local / greenfield) + run Monkey's Paw audit
- `POST /api/sessions/<id>/park`        : Append off-scope tangent (`PL-NNN`)
- `POST /api/sessions/<id>/backlog`     : Generate editable Epic/Capability/Feature/Story hierarchy
- `POST /api/export`                    : Export Jira CSV, BACKLOG.md, EARS/Spec-Kit/OpenSpec, PARKING-LOT.md, or JSON
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.compile_locked_spec import infer_title  # noqa: E402
from scripts.validate_findings import validate_findings_data  # noqa: E402
from studio import __version__  # noqa: E402
from studio.backlog_compiler import (  # noqa: E402
    HIERARCHY_PRESETS,
    export_backlog_markdown,
    export_jira_csv,
    export_session_spec,
    format_parking_lot_markdown,
    normalize_backlog_tree,
)
from studio.env_manager import (  # noqa: E402
    get_env_status,
    load_dotenv_into_environ,
    update_local_dotenv,
)
from studio.github_ingest import ingest_repository_surface  # noqa: E402
from studio.llm_engine import (  # noqa: E402
    detect_server_providers,
    generate_editable_backlog,
    generate_validated_findings,
    resolve_provider_config,
)
from studio.store import StudioSessionStore  # noqa: E402

MAX_REQUEST_BYTES = 2 * 1024 * 1024  # 2 MB JSON body cap
STATIC_INDEX_PATH = Path(__file__).resolve().parent / "static" / "index.html"
_SESSION_ROUTE_RE = re.compile(r"^/api/sessions/(s_[A-Za-z0-9_-]+)(?:/(park|backlog))?$")


class StudioAppContext:
    """Shared server configuration and thread-safe SQLite session store."""

    def __init__(
        self,
        *,
        db_path: Path,
        passcode: str = "",
        allow_local_paths: bool = False,
        dotenv_path: Path | None = None,
    ) -> None:
        self.store = StudioSessionStore(db_path)
        self.passcode = passcode.strip()
        self.allow_local_paths = allow_local_paths
        self.dotenv_path = dotenv_path or (_REPO_ROOT / ".env")

    @property
    def passcode_required(self) -> bool:
        return bool(self.passcode)

    def check_passcode(self, provided: str) -> bool:
        if not self.passcode:
            return True
        return hmac.compare_digest(self.passcode.encode("utf-8"), (provided or "").strip().encode("utf-8"))


def create_handler_class(ctx: StudioAppContext) -> type[BaseHTTPRequestHandler]:
    """Bind `StudioAppContext` into a request handler class for `ThreadingHTTPServer`."""

    class StudioRequestHandler(BaseHTTPRequestHandler):
        server_version = f"MonkeyPawStudio/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:
            if os.environ.get("STUDIO_QUIET_LOGS") == "1":
                return
            super().log_message(fmt, *args)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html_bytes: bytes) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(html_bytes)

        def _read_json_body(self) -> dict[str, Any]:
            length_hdr = self.headers.get("Content-Length")
            if not length_hdr:
                return {}
            length = int(length_hdr)
            if length > MAX_REQUEST_BYTES:
                raise ValueError(f"Request payload exceeds {MAX_REQUEST_BYTES} bytes.")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("JSON request body must be an object.")
            return parsed

        def _require_auth(self) -> bool:
            if not ctx.passcode_required:
                return True
            supplied = self.headers.get("X-Studio-Passcode", "")
            if ctx.check_passcode(supplied):
                return True
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Studio passcode required.", "passcode_required": True},
            )
            return False

        # ------------------------------------------------------------------
        # HTTP Verb Routers
        # ------------------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/api/health":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "service": "monkey-paw-studio",
                        "version": __version__,
                    },
                )
                return

            if path == "/api/config":
                providers = detect_server_providers()
                any_cloud_key = any(providers[k] for k in ("gemini", "anthropic", "openai"))
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "version": __version__,
                        "passcode_required": ctx.passcode_required,
                        "allow_local_paths": ctx.allow_local_paths,
                        "server_providers": providers,
                        "github_token_configured": bool(os.environ.get("GITHUB_TOKEN", "").strip()),
                        "hierarchy_presets": {
                            k: {"label": v["label"], "levels": v["levels"]}
                            for k, v in HIERARCHY_PRESETS.items()
                        },
                        "unprotected_key_warning": bool(any_cloud_key and not ctx.passcode_required),
                    },
                )
                return

            if path == "/" or path.startswith("/s/"):
                if not STATIC_INDEX_PATH.is_file():
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Studio UI asset missing."})
                    return
                self._send_html(STATIC_INDEX_PATH.read_bytes())
                return

            if path == "/api/sessions":
                if not self._require_auth():
                    return
                self._send_json(HTTPStatus.OK, {"sessions": ctx.store.list_sessions(limit=30)})
                return

            if path == "/api/env":
                if not self._require_auth():
                    return
                self._send_json(
                    HTTPStatus.OK,
                    get_env_status(ctx.dotenv_path, editable_on_server=ctx.allow_local_paths),
                )
                return

            m = _SESSION_ROUTE_RE.match(path)
            if m and m.group(2) is None:
                if not self._require_auth():
                    return
                session = ctx.store.get_session(m.group(1))
                if session is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Session not found."})
                    return
                self._send_json(HTTPStatus.OK, {"session": session})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route not found: {path}"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path

            try:
                body = self._read_json_body()
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            if path == "/api/auth/verify":
                ok = ctx.check_passcode(str(body.get("passcode") or self.headers.get("X-Studio-Passcode") or ""))
                status = HTTPStatus.OK if ok else HTTPStatus.UNAUTHORIZED
                self._send_json(status, {"authenticated": ok})
                return

            if not self._require_auth():
                return

            if path == "/api/sessions":
                created = ctx.store.create_session(body)
                self._send_json(HTTPStatus.CREATED, {"session": created})
                return

            if path == "/api/env":
                if not ctx.allow_local_paths:
                    self._send_json(
                        HTTPStatus.FORBIDDEN,
                        {
                            "error": "Direct .env editing is enabled on localhost only. On Railway, configure environment variables in the Railway Dashboard -> Variables tab."
                        },
                    )
                    return
                try:
                    applied = update_local_dotenv(ctx.dotenv_path, body.get("variables") or {})
                    ctx.passcode = os.environ.get("STUDIO_PASSCODE", "").strip()
                    status_payload = get_env_status(ctx.dotenv_path, editable_on_server=True)
                    status_payload["applied"] = applied
                    self._send_json(HTTPStatus.OK, status_payload)
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            if path == "/api/analyze":
                self._handle_analyze(body)
                return

            if path == "/api/export":
                self._handle_export(body)
                return

            m = _SESSION_ROUTE_RE.match(path)
            if m and m.group(2) == "park":
                self._handle_park_tangent(m.group(1), body)
                return
            if m and m.group(2) == "backlog":
                self._handle_generate_backlog(m.group(1), body)
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route not found: {path}"})

        def do_PUT(self) -> None:  # noqa: N802
            if not self._require_auth():
                return
            path = urlparse(self.path).path
            m = _SESSION_ROUTE_RE.match(path)
            if not m or m.group(2) is not None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route not found: {path}"})
                return

            try:
                body = self._read_json_body()
                preset = str(body.get("hierarchy_preset") or "enterprise_4tier")
                if "backlog_tree" in body:
                    body["backlog_tree"] = normalize_backlog_tree(body["backlog_tree"], preset=preset)
                saved = ctx.store.save_session(m.group(1), body)
                self._send_json(HTTPStatus.OK, {"session": saved})
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        def do_DELETE(self) -> None:  # noqa: N802
            if not self._require_auth():
                return
            path = urlparse(self.path).path
            m = _SESSION_ROUTE_RE.match(path)
            if not m or m.group(2) is not None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route not found: {path}"})
                return
            deleted = ctx.store.delete_session(m.group(1))
            self._send_json(HTTPStatus.OK, {"deleted": deleted})

        # ------------------------------------------------------------------
        # Domain Action Handlers
        # ------------------------------------------------------------------

        def _handle_analyze(self, body: dict[str, Any]) -> None:
            prd_text = str(body.get("prd_text") or "").strip()
            if len(prd_text) < 15:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Provide a PRD, ticket, or acceptance criteria draft (at least 15 characters)."},
                )
                return

            source_type = str(body.get("source_type") or "greenfield")
            repo_target = str(body.get("repo_target") or "")
            branch = str(body.get("branch") or "")
            github_token = str(body.get("github_token") or "")
            preset = str(body.get("hierarchy_preset") or "enterprise_4tier")
            if preset not in HIERARCHY_PRESETS:
                preset = "enterprise_4tier"

            try:
                provider_cfg = resolve_provider_config(body.get("provider_config"))
                surface_payload, repo_label = ingest_repository_surface(
                    source_type=source_type,
                    repo_target=repo_target,
                    branch=branch,
                    github_token=github_token,
                    allow_local_paths=ctx.allow_local_paths,
                )
                findings_doc, engine_used = generate_validated_findings(
                    prd_text, surface_payload, provider_cfg
                )
            except PermissionError as exc:
                self._send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
                return
            except (ValueError, FileNotFoundError, RuntimeError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            title = str(body.get("title") or "").strip() or infer_title(prd_text, findings_doc)
            session_state: dict[str, Any] = {
                "title": title,
                "prd_text": prd_text,
                "mode": surface_payload["mode"],
                "source_type": source_type,
                "repo_target": repo_target,
                "branch": branch,
                "repo_label": repo_label,
                "hierarchy_preset": preset,
                "engine_used": engine_used,
                "surface_summary": {
                    "mode": surface_payload["mode"],
                    "stats": surface_payload["stats"],
                    "sample_files": surface_payload.get("code_files", [])[:20],
                    "surface": {
                        k: v[:12] for k, v in surface_payload.get("surface", {}).items()
                    },
                },
                "findings_doc": findings_doc,
                "parked_items": body.get("parked_items") if isinstance(body.get("parked_items"), list) else [],
                "backlog_tree": [],
            }

            existing_id = str(body.get("session_id") or "").strip()
            if existing_id.startswith("s_"):
                saved = ctx.store.save_session(existing_id, session_state)
            else:
                saved = ctx.store.create_session(session_state)

            self._send_json(HTTPStatus.OK, {"session": saved})

        def _handle_park_tangent(self, session_id: str, body: dict[str, Any]) -> None:
            session = ctx.store.get_session(session_id)
            if session is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Session not found."})
                return

            item_text = str(body.get("item") or "").strip()
            if len(item_text) < 5:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Tangent description must be >= 5 characters."})
                return

            parked: list[dict[str, Any]] = list(session.get("parked_items") or [])
            for existing in parked:
                if str(existing.get("item", "")).lower() == item_text.lower():
                    self._send_json(HTTPStatus.OK, {"session": session, "parked": existing, "duplicate": True})
                    return

            next_id = f"PL-{len(parked) + 1:03d}"
            entry = {
                "id": next_id,
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "category": str(body.get("category") or "phase-2"),
                "item": item_text,
                "reason": str(body.get("reason") or "Deferred during Studio refinement to keep v1 scope bounded."),
                "related_finding": str(body.get("related_finding") or ""),
                "origin": session.get("title") or "Studio Session",
            }
            parked.append(entry)
            session["parked_items"] = parked
            saved = ctx.store.save_session(session_id, session)
            self._send_json(HTTPStatus.OK, {"session": saved, "parked": entry, "duplicate": False})

        def _handle_generate_backlog(self, session_id: str, body: dict[str, Any]) -> None:
            session = ctx.store.get_session(session_id)
            if session is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Session not found."})
                return

            if isinstance(body.get("findings_doc"), dict):
                session["findings_doc"] = body["findings_doc"]
            if body.get("hierarchy_preset") in HIERARCHY_PRESETS:
                session["hierarchy_preset"] = body["hierarchy_preset"]

            preset = session.get("hierarchy_preset") or "enterprise_4tier"
            findings_doc = session.get("findings_doc") or {}
            prd_text = session.get("prd_text") or ""

            ok, errors, _ = validate_findings_data(findings_doc, require_resolved=True)
            if not ok:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Resolve all Monkey's Paw cards first: " + "; ".join(errors)},
                )
                return

            try:
                provider_cfg = resolve_provider_config(body.get("provider_config"))
                tree, engine_label = generate_editable_backlog(prd_text, findings_doc, preset, provider_cfg)
            except (ValueError, RuntimeError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            session["backlog_tree"] = tree
            session["backlog_engine_used"] = engine_label
            saved = ctx.store.save_session(session_id, session)
            self._send_json(HTTPStatus.OK, {"session": saved})

        def _handle_export(self, body: dict[str, Any]) -> None:
            fmt = str(body.get("format") or "backlog-md").strip().lower()
            session = body.get("session")
            if not isinstance(session, dict):
                sid = str(body.get("session_id") or "").strip()
                session = ctx.store.get_session(sid) if sid else None
            if not isinstance(session, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Provide 'session' or valid 'session_id'."})
                return

            title = str(session.get("title") or "Specification").strip()
            preset = str(session.get("hierarchy_preset") or "enterprise_4tier")
            mode = str(session.get("mode") or "greenfield")
            prd_text = str(session.get("prd_text") or "")
            findings_doc = session.get("findings_doc") or {}
            parked = session.get("parked_items") or []
            tree = normalize_backlog_tree(session.get("backlog_tree") or [], preset=preset)

            try:
                if fmt == "jira-csv":
                    content = export_jira_csv(tree, parked_items=parked, include_parked=bool(body.get("include_parked", False)))
                    filename = "BACKLOG-JIRA.csv"
                    mime = "text/csv"
                elif fmt == "backlog-md":
                    content = export_backlog_markdown(title, preset, mode, tree, parked_items=parked)
                    filename = "BACKLOG.md"
                    mime = "text/markdown"
                elif fmt in {"ears", "spec-kit", "openspec", "jira"}:
                    content = export_session_spec(prd_text, findings_doc, fmt, title, parked_items=parked)
                    filename = "SPEC.md" if fmt != "spec-kit" else "spec.md"
                    mime = "text/markdown"
                elif fmt == "parking-md":
                    content = format_parking_lot_markdown(parked)
                    filename = "PARKING-LOT.md"
                    mime = "text/markdown"
                elif fmt == "bundle-json":
                    content = json.dumps(session, indent=2, ensure_ascii=False)
                    filename = f"monkey-paw-{session.get('id', 'session')}.json"
                    mime = "application/json"
                else:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Unsupported export format: {fmt}"})
                    return
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "format": fmt,
                    "filename": filename,
                    "mime": mime,
                    "content": content,
                },
            )

    return StudioRequestHandler


def compute_default_db_path() -> Path:
    explicit = os.environ.get("STUDIO_DB_PATH", "").strip()
    if explicit:
        return Path(explicit)
    # Use mounted `/data` volume automatically on Railway when writable
    railway_data = Path("/data")
    if os.environ.get("RAILWAY_ENVIRONMENT") and railway_data.is_dir() and os.access(railway_data, os.W_OK):
        return railway_data / "monkey_paw_studio.sqlite3"
    return _REPO_ROOT / ".monkey-paw" / "studio.sqlite3"


def build_server(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    db_path: Path | None = None,
    passcode: str | None = None,
    allow_local_paths: bool | None = None,
    dotenv_path: Path | None = None,
) -> ThreadingHTTPServer:
    effective_dotenv = dotenv_path or (_REPO_ROOT / ".env")
    if allow_local_paths is None:
        env_flag = os.environ.get("STUDIO_ALLOW_LOCAL_PATHS", "").strip().lower()
        if env_flag in {"1", "true", "yes"}:
            effective_local = True
        elif env_flag in {"0", "false", "no"} or os.environ.get("RAILWAY_ENVIRONMENT"):
            effective_local = False
        else:
            effective_local = host in {"127.0.0.1", "localhost", "::1"}
    else:
        effective_local = allow_local_paths

    if effective_local:
        load_dotenv_into_environ(effective_dotenv, override=False)

    effective_db = db_path or compute_default_db_path()
    effective_passcode = passcode if passcode is not None else os.environ.get("STUDIO_PASSCODE", "")

    ctx = StudioAppContext(
        db_path=effective_db,
        passcode=effective_passcode,
        allow_local_paths=effective_local,
        dotenv_path=effective_dotenv,
    )
    handler_cls = create_handler_class(ctx)
    return ThreadingHTTPServer((host, port), handler_cls)


def build_arg_parser() -> argparse.ArgumentParser:
    default_host = "0.0.0.0" if os.environ.get("PORT") or os.environ.get("RAILWAY_ENVIRONMENT") else "127.0.0.1"
    default_port = int(os.environ.get("PORT", "8787"))
    parser = argparse.ArgumentParser(
        prog="python3 -m studio",
        description="Start Monkey's Paw Studio web service locally or in a container.",
    )
    parser.add_argument("--host", default=default_host, help=f"Bind address (default: {default_host}).")
    parser.add_argument("--port", type=int, default=default_port, help=f"Listen port (default: {default_port}).")
    parser.add_argument("--db", default=None, help="Optional SQLite database file path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    db_path = Path(args.db) if args.db else None
    httpd = build_server(host=args.host, port=args.port, db_path=db_path)
    actual_host, actual_port = httpd.server_address[:2]
    display_host = "localhost" if actual_host in {"127.0.0.1", "0.0.0.0"} else actual_host
    print(f"Monkey's Paw Studio v{__version__} listening on http://{display_host}:{actual_port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Monkey's Paw Studio.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
