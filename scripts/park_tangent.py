#!/usr/bin/env python3
"""Tangent Trap CLI: append off-scope tech debt and Phase-2 ideas to PARKING-LOT.md.

Keeps pre-code specification refinement under 10 minutes by acknowledging valuable
but out-of-scope concerns, persisting them with sequential IDs (`PL-001`, `PL-002`, ...),
and returning focus immediately to the active Bilingual Decision Card.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from extract_repo_surface import is_sensitive_path, scrub_secrets  # noqa: E402

VALID_CATEGORIES: tuple[str, ...] = (
    "phase-2",
    "tech-debt",
    "ux-polish",
    "infra",
    "open-question",
)

PARKING_LOT_HEADER = """# Parking Lot (`PARKING-LOT.md`)

> Captured by **Monkey's Paw Tangent Trap** during pre-code specification refinement so scope locks in under 10 minutes without losing valid engineering or product follow-ups.

| ID | Date | Category | Parked Item | Why Deferred / Revisit Trigger | Origin |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""

_UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")
_PL_ID_RE = re.compile(r"^PL-(\d+)$")


def _sanitize_cell(value: str) -> str:
    """Sanitize text for safe inclusion inside a single GFM table cell."""
    cleaned = scrub_secrets(value)
    cleaned = " ".join(cleaned.replace("\r", " ").replace("\n", " ").split())
    return cleaned.replace("|", "\\|")


def park_tangent_entry(
    out_path: Path,
    *,
    item: str,
    category: str = "phase-2",
    reason: str = "Deferred during pre-code referee session to keep v1 scope bounded.",
    spec_name: str = "",
    related_finding: str = "",
    date_str: str | None = None,
) -> dict[str, Any]:
    """Append a tangent row to `out_path` idempotently and return entry metadata."""
    clean_item = _sanitize_cell(item)
    if len(clean_item) < 5:
        raise ValueError("Parked tangent 'item' must be at least 5 characters long.")

    if category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category {category!r}; expected one of {VALID_CATEGORIES}.")

    if is_sensitive_path(out_path.as_posix(), out_path.name):
        raise ValueError(f"Refusing to write parking lot to sensitive path: {out_path}")

    existing_text = ""
    if out_path.exists():
        existing_text = out_path.read_text(encoding="utf-8")

    max_num = 0
    for raw_ln in existing_text.splitlines():
        ln = raw_ln.strip()
        if not ln.startswith("|"):
            continue
        cells = [c.strip() for c in _UNESCAPED_PIPE_RE.split(ln.strip("|"))]
        if len(cells) < 4:
            continue
        id_match = _PL_ID_RE.match(cells[0])
        if not id_match:
            continue
        num = int(id_match.group(1))
        existing_item = cells[3]
        max_num = max(max_num, num)
        if existing_item.lower() == clean_item.lower():
            existing_id = f"PL-{num:03d}"
            return {
                "id": existing_id,
                "created": False,
                "duplicate": True,
                "item": clean_item,
                "category": category,
                "path": str(out_path),
            }

    next_id = f"PL-{max_num + 1:03d}"
    effective_date = _sanitize_cell(date_str) if date_str else datetime.now(timezone.utc).strftime("%Y-%m-%d")
    clean_reason = _sanitize_cell(reason or "Deferred during pre-code referee session to keep v1 scope bounded.")

    origin_parts: list[str] = []
    if spec_name.strip():
        origin_parts.append(_sanitize_cell(spec_name.strip()))
    if related_finding.strip():
        origin_parts.append(f"`{_sanitize_cell(related_finding.strip())}`")
    origin_cell = " / ".join(origin_parts) if origin_parts else "Referee Session"

    new_row = f"| {next_id} | {effective_date} | `{category}` | {clean_item} | {clean_reason} | {origin_cell} |"

    if not existing_text.strip():
        updated = PARKING_LOT_HEADER.rstrip("\n") + "\n" + new_row + "\n"
    else:
        base = existing_text.rstrip("\n")
        if "| ID |" not in base:
            updated = base + "\n\n" + PARKING_LOT_HEADER.rstrip("\n") + "\n" + new_row + "\n"
        else:
            updated = base + "\n" + new_row + "\n"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(updated, encoding="utf-8")
    return {
        "id": next_id,
        "created": True,
        "duplicate": False,
        "item": clean_item,
        "category": category,
        "path": str(out_path),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="park_tangent.py",
        description="Append an off-scope tangent or Phase-2 item to PARKING-LOT.md.",
    )
    parser.add_argument(
        "--item",
        "--title",
        dest="item",
        required=True,
        help="Concise description of the off-scope idea, refactor, or Phase-2 feature.",
    )
    parser.add_argument(
        "--category",
        choices=VALID_CATEGORIES,
        default="phase-2",
        help="Classification tag for the parked item (default: phase-2).",
    )
    parser.add_argument(
        "--reason",
        "--why-parked",
        "--context",
        dest="reason",
        default="Deferred during pre-code referee session to keep v1 scope bounded.",
        help="Why this item was deferred or what condition triggers revisiting it.",
    )
    parser.add_argument(
        "--spec",
        default="",
        help="Optional draft/feature name where this tangent surfaced.",
    )
    parser.add_argument(
        "--related-finding",
        default="",
        help="Optional finding ID (e.g., MP-002) associated with this tangent.",
    )
    parser.add_argument(
        "--date",
        default=None,
        help="Optional ISO date YYYY-MM-DD override (defaults to current UTC date).",
    )
    parser.add_argument(
        "--out",
        default="PARKING-LOT.md",
        help="Output markdown file path (default: PARKING-LOT.md).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        result = park_tangent_entry(
            Path(args.out),
            item=args.item,
            category=args.category,
            reason=args.reason,
            spec_name=args.spec,
            related_finding=args.related_finding,
            date_str=args.date,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if result["duplicate"]:
        print(f"OK: Tangent already parked as {result['id']} in {result['path']}")
    else:
        print(f"OK: Parked tangent as {result['id']} ({result['category']}) in {result['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
