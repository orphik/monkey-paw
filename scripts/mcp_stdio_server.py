#!/usr/bin/env python3
"""Zero-dependency JSON-RPC 2.0 `stdio` MCP server for monkey-paw.

Exposes the four deterministic monkey-paw referee tools over Model Context Protocol:
- `extract_repo_surface`
- `validate_findings`
- `compile_locked_spec`
- `park_tangent`

Supports both newline-delimited JSON-RPC 2.0 messages (MCP 2024-11-05 / 2025-03-26 stdio
standard) and `Content-Length` HTTP-header framing for universal MCP host compatibility.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, BinaryIO

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from compile_locked_spec import SUPPORTED_FORMATS, compile_specification  # noqa: E402
from extract_repo_surface import (  # noqa: E402
    DEFAULT_MAX_OUTPUT_BYTES,
    is_sensitive_path,
    scan_repository,
)
from park_tangent import VALID_CATEGORIES, park_tangent_entry  # noqa: E402
from validate_findings import VALID_MODES, load_json_file, validate_findings_data  # noqa: E402

SERVER_NAME = "monkey-paw"
SERVER_VERSION = "1.0.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "extract_repo_surface",
        "description": (
            "Deterministically scan a repository read-only for models, SQL tables, enums, API routes, "
            "auth boundaries, and background workers into .monkey-paw/surface.json. "
            "Degrades cleanly to greenfield mode on empty directories."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {
                    "type": "string",
                    "description": "Target repository directory path (default: '.').",
                    "default": ".",
                },
                "out": {
                    "type": "string",
                    "description": "Optional JSON output file path (default: '.monkey-paw/surface.json').",
                    "default": ".monkey-paw/surface.json",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Maximum UTF-8 byte cap for surface JSON output.",
                    "default": DEFAULT_MAX_OUTPUT_BYTES,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "validate_findings",
        "description": (
            "Validate 1..5 Monkey's Paw findings against exploit_class enum, brownfield repo_citations, "
            "distinct A/B engineering options, plain-English PM trade-offs, and generic-filler rejection."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "findings_path": {
                    "type": "string",
                    "description": "Path to findings JSON file (provide either findings_path or inline findings).",
                },
                "findings": {
                    "type": "object",
                    "description": "Inline findings JSON object containing 'mode' and 'findings'.",
                },
                "surface_path": {
                    "type": "string",
                    "description": "Optional path to .monkey-paw/surface.json for mode consistency.",
                },
                "mode": {
                    "type": "string",
                    "enum": sorted(VALID_MODES),
                    "description": "Optional explicit mode override ('brownfield' or 'greenfield').",
                },
                "require_resolved": {
                    "type": "boolean",
                    "description": "Require every finding to include a locked resolution choice.",
                    "default": False,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "compile_locked_spec",
        "description": (
            "Compile resolved findings and draft text into a locked specification in EARS, "
            "Spec-Kit, OpenSpec, or Jira checklist markdown."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "draft_path": {
                    "type": "string",
                    "description": "Path to raw draft ticket/PRD markdown file.",
                },
                "draft_text": {
                    "type": "string",
                    "description": "Inline raw draft text (used if draft_path is omitted).",
                },
                "findings_path": {
                    "type": "string",
                    "description": "Path to resolved findings JSON file.",
                },
                "findings": {
                    "type": "object",
                    "description": "Inline resolved findings JSON object (used if findings_path is omitted).",
                },
                "format": {
                    "type": "string",
                    "enum": list(SUPPORTED_FORMATS),
                    "default": "ears",
                    "description": "Output specification standard.",
                },
                "title": {
                    "type": "string",
                    "description": "Optional explicit specification title.",
                },
                "out": {
                    "type": "string",
                    "description": "Optional file path to write compiled markdown (e.g., 'SPEC.md').",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "park_tangent",
        "description": (
            "Append an off-scope tech-debt item or Phase-2 idea to PARKING-LOT.md with sequential PL-NNN IDs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "item": {
                    "type": "string",
                    "description": "Concise summary of the deferred tangent.",
                },
                "category": {
                    "type": "string",
                    "enum": list(VALID_CATEGORIES),
                    "default": "phase-2",
                },
                "reason": {
                    "type": "string",
                    "description": "Why the item was parked or trigger to revisit.",
                },
                "spec": {
                    "type": "string",
                    "description": "Optional source draft/feature name.",
                },
                "related_finding": {
                    "type": "string",
                    "description": "Optional finding ID (e.g., MP-002).",
                },
                "out": {
                    "type": "string",
                    "default": "PARKING-LOT.md",
                    "description": "Target parking-lot markdown file path.",
                },
            },
            "required": ["item"],
            "additionalProperties": False,
        },
    },
]


def _tool_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


def dispatch_tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute one of the 4 monkey-paw tools and return an MCP CallToolResult dict."""
    try:
        if name == "extract_repo_surface":
            repo = str(arguments.get("repo", "."))
            max_bytes = int(arguments.get("max_bytes", DEFAULT_MAX_OUTPUT_BYTES))
            out = arguments.get("out", ".monkey-paw/surface.json")
            payload, encoded = scan_repository(Path(repo), max_bytes=max_bytes)
            if out and out != "-":
                out_path = Path(str(out))
                if is_sensitive_path(out_path.as_posix(), out_path.name):
                    return _tool_result(f"Refusing to write to sensitive path: {out_path}", is_error=True)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(encoded)
            return _tool_result(json.dumps(payload, indent=2), is_error=False)

        if name == "validate_findings":
            if "findings" in arguments and arguments["findings"] is not None:
                findings_doc = arguments["findings"]
            elif arguments.get("findings_path"):
                findings_doc = load_json_file(Path(str(arguments["findings_path"])), "findings")
            else:
                return _tool_result("Provide either 'findings_path' or inline 'findings'.", is_error=True)

            surface_doc = None
            if arguments.get("surface_path"):
                surface_doc = load_json_file(Path(str(arguments["surface_path"])), "surface")

            is_valid, errors, meta = validate_findings_data(
                findings_doc,
                mode_override=arguments.get("mode"),
                surface_data=surface_doc,
                require_resolved=bool(arguments.get("require_resolved", False)),
            )
            report = {**meta, "errors": errors}
            return _tool_result(json.dumps(report, indent=2), is_error=not is_valid)

        if name == "compile_locked_spec":
            if arguments.get("draft_text") is not None:
                draft_text = str(arguments["draft_text"])
            elif arguments.get("draft_path"):
                draft_text = Path(str(arguments["draft_path"])).read_text(encoding="utf-8")
            else:
                return _tool_result("Provide either 'draft_path' or 'draft_text'.", is_error=True)

            if "findings" in arguments and arguments["findings"] is not None:
                findings_doc = arguments["findings"]
            elif arguments.get("findings_path"):
                findings_doc = load_json_file(Path(str(arguments["findings_path"])), "findings")
            else:
                return _tool_result("Provide either 'findings_path' or inline 'findings'.", is_error=True)

            fmt = str(arguments.get("format", "ears"))
            compiled = compile_specification(
                draft_text,
                findings_doc,
                output_format=fmt,
                title_override=arguments.get("title"),
            )
            out = arguments.get("out")
            if out and out != "-":
                out_path = Path(str(out))
                if is_sensitive_path(out_path.as_posix(), out_path.name):
                    return _tool_result(f"Refusing to write to sensitive path: {out_path}", is_error=True)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(compiled, encoding="utf-8")
            return _tool_result(compiled, is_error=False)

        if name == "park_tangent":
            item = str(arguments.get("item", ""))
            category = str(arguments.get("category", "phase-2"))
            reason = str(
                arguments.get("reason")
                or "Deferred during pre-code referee session to keep v1 scope bounded."
            )
            spec_name = str(arguments.get("spec", ""))
            related = str(arguments.get("related_finding", ""))
            out_path = Path(str(arguments.get("out", "PARKING-LOT.md")))
            res = park_tangent_entry(
                out_path,
                item=item,
                category=category,
                reason=reason,
                spec_name=spec_name,
                related_finding=related,
            )
            return _tool_result(json.dumps(res, indent=2), is_error=False)

        return _tool_result(f"Unknown tool: {name}", is_error=True)
    except (OSError, ValueError, TypeError) as exc:
        return _tool_result(f"ERROR: {exc}", is_error=True)


def handle_jsonrpc_message(msg: Any) -> dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 request or notification and return response dict (or None)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return {
            "jsonrpc": "2.0",
            "id": msg.get("id") if isinstance(msg, dict) else None,
            "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 Request"},
        }

    method = msg.get("method")
    has_id = "id" in msg
    req_id = msg.get("id")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    # JSON-RPC notifications (no `id` field) do not receive responses
    if not has_id:
        return None

    if method == "initialize":
        client_version = str(params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": client_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}

    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments")
        if not isinstance(tool_name, str) or not tool_name:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Missing 'name' in tools/call params"},
            }
        if tool_args is None:
            tool_args = {}
        if not isinstance(tool_args, dict):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "'arguments' must be an object"},
            }
        result = dispatch_tool_call(tool_name, tool_args)
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _read_next_message(stream: BinaryIO) -> tuple[bytes | None, bool]:
    """Read next JSON-RPC message from `stream`.

    Returns `(raw_json_bytes, used_content_length_framing)`.
    Returns `(None, False)` on EOF.
    """
    while True:
        first_line = stream.readline()
        if not first_line:
            return None, False
        stripped = first_line.strip()
        if not stripped:
            continue

        if stripped.lower().startswith(b"content-length:"):
            length_str = stripped.split(b":", 1)[1].strip()
            content_length = int(length_str)
            # Consume remaining header lines up to blank line
            while True:
                hdr = stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            body = stream.read(content_length)
            return body, True

        return stripped, False


def _write_message(stream: BinaryIO, payload: dict[str, Any], use_content_length: bool) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if use_content_length:
        header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
        stream.write(header + encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


def serve_stdio(in_stream: BinaryIO | None = None, out_stream: BinaryIO | None = None) -> int:
    """Run the synchronous JSON-RPC 2.0 MCP server loop until EOF."""
    reader = in_stream if in_stream is not None else sys.stdin.buffer
    writer = out_stream if out_stream is not None else sys.stdout.buffer

    while True:
        try:
            raw_bytes, framed = _read_next_message(reader)
        except ValueError as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Framing error: {exc}"},
            }
            _write_message(writer, err_resp, False)
            continue

        if raw_bytes is None:
            return 0

        try:
            msg = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            _write_message(writer, err_resp, framed)
            continue

        response = handle_jsonrpc_message(msg)
        if response is not None:
            _write_message(writer, response, framed)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if "--help" in argv or "-h" in argv:
        print("Usage: python3 scripts/mcp_stdio_server.py")
        print("Starts the zero-dependency JSON-RPC 2.0 stdio MCP server for monkey-paw.")
        return 0
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
