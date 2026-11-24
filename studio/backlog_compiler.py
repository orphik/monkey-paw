"""Editable Agile/Enterprise work-breakdown compiler and exporters for Monkey's Paw Studio.

Supports three configurable hierarchy presets:
- `enterprise_4tier` : Epic -> Capability -> Feature -> User Story
- `capability_first` : Capability -> Epic -> Feature -> User Story
- `agile_3tier`      : Epic -> Feature -> User Story

Exports to Jira CSV (External System Import ready), Backlog Markdown (`BACKLOG.md`),
Locked Specifications (`ears`, `spec-kit`, `openspec`, `jira`), and `PARKING-LOT.md`.
"""

from __future__ import annotations

import csv
import io
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.compile_locked_spec import compile_specification  # noqa: E402
from scripts.park_tangent import PARKING_LOT_HEADER  # noqa: E402

HIERARCHY_PRESETS: dict[str, dict[str, Any]] = {
    "enterprise_4tier": {
        "label": "Enterprise 4-Tier (Epic -> Capability -> Feature -> User Story)",
        "levels": ["epic", "capability", "feature", "story"],
    },
    "capability_first": {
        "label": "Capability-First (Capability -> Epic -> Feature -> User Story)",
        "levels": ["capability", "epic", "feature", "story"],
    },
    "agile_3tier": {
        "label": "Agile 3-Tier (Epic -> Feature -> User Story)",
        "levels": ["epic", "feature", "story"],
    },
}

LEVEL_PREFIXES: dict[str, str] = {
    "epic": "EPIC",
    "capability": "CAP",
    "feature": "FEAT",
    "story": "US",
}

LEVEL_JIRA_TYPES: dict[str, str] = {
    "epic": "Epic",
    "capability": "Capability",
    "feature": "Feature",
    "story": "Story",
}


def get_preset_levels(preset: str) -> list[str]:
    if preset not in HIERARCHY_PRESETS:
        return list(HIERARCHY_PRESETS["enterprise_4tier"]["levels"])
    return list(HIERARCHY_PRESETS[preset]["levels"])


def normalize_backlog_tree(raw_items: Any, preset: str = "enterprise_4tier") -> list[dict[str, Any]]:
    """Normalize and assign deterministic hierarchical IDs to an editable work-breakdown tree."""
    levels = get_preset_levels(preset)
    if not isinstance(raw_items, list):
        return []

    def _norm_node(node: Any, depth: int, path_nums: tuple[int, ...]) -> dict[str, Any]:
        lvl = levels[min(depth, len(levels) - 1)]
        prefix = LEVEL_PREFIXES[lvl]
        num_str = ".".join(str(n) for n in path_nums)
        default_id = f"{prefix}-{num_str}"

        if not isinstance(node, dict):
            node = {"title": str(node)}

        title = str(node.get("title") or f"Untitled {lvl.capitalize()}").strip()
        description = str(node.get("description") or "").strip()
        estimate = str(node.get("estimate") or ("" if lvl != "story" else "3")).strip()

        raw_acs = node.get("acceptance_criteria")
        acs: list[str] = []
        if isinstance(raw_acs, list):
            acs = [str(a).strip() for a in raw_acs if str(a).strip()]
        elif isinstance(raw_acs, str) and raw_acs.strip():
            acs = [ln.strip("- *").strip() for ln in raw_acs.splitlines() if ln.strip()]

        raw_guards = node.get("guardrail_ids")
        guards = [str(g).strip() for g in raw_guards if str(g).strip()] if isinstance(raw_guards, list) else []

        raw_touch = node.get("repo_touchpoints")
        touchpoints = [str(t).strip() for t in raw_touch if str(t).strip()] if isinstance(raw_touch, list) else []

        children_out: list[dict[str, Any]] = []
        raw_children = node.get("children")
        if depth < len(levels) - 1 and isinstance(raw_children, list):
            for idx, child in enumerate(raw_children, start=1):
                children_out.append(_norm_node(child, depth + 1, (*path_nums, idx)))

        return {
            "id": str(node.get("id") or default_id).strip() or default_id,
            "level": lvl,
            "title": title,
            "description": description,
            "estimate": estimate,
            "acceptance_criteria": acs,
            "guardrail_ids": guards,
            "repo_touchpoints": touchpoints,
            "children": children_out,
        }

    return [_norm_node(item, 0, (idx,)) for idx, item in enumerate(raw_items, start=1)]


def flatten_backlog_tree(tree: list[dict[str, Any]]) -> list[tuple[dict[str, Any], str]]:
    """Flatten nested backlog tree into `(node, parent_id)` pairs in pre-order traversal."""
    rows: list[tuple[dict[str, Any], str]] = []

    def _walk(nodes: list[dict[str, Any]], parent_id: str) -> None:
        for n in nodes:
            rows.append((n, parent_id))
            children = n.get("children")
            if isinstance(children, list) and children:
                _walk(children, n["id"])

    _walk(tree, "")
    return rows


def export_jira_csv(
    tree: list[dict[str, Any]],
    parked_items: list[dict[str, Any]] | None = None,
    include_parked: bool = False,
) -> str:
    """Export normalized backlog tree to Jira External System Import CSV format."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        [
            "Issue ID",
            "Parent ID",
            "Issue Type",
            "Summary",
            "Description",
            "Acceptance Criteria",
            "Story Points",
            "Guardrail IDs",
            "Repo Touchpoints",
            "Labels",
        ]
    )

    for node, parent_id in flatten_backlog_tree(tree):
        lvl = str(node.get("level") or "story").lower()
        issue_type = LEVEL_JIRA_TYPES.get(lvl, "Story")
        acs_joined = "\n".join(f"- {ac}" for ac in node.get("acceptance_criteria", []))
        guards = node.get("guardrail_ids", [])
        touchpoints = node.get("repo_touchpoints", [])
        labels = ["monkey-paw-locked"] + [g.lower() for g in guards]
        est_raw = str(node.get("estimate") or "").replace("pts", "").replace("pt", "").strip()

        writer.writerow(
            [
                node.get("id", ""),
                parent_id,
                issue_type,
                node.get("title", ""),
                node.get("description", ""),
                acs_joined,
                est_raw,
                ", ".join(guards),
                ", ".join(touchpoints),
                " ".join(labels),
            ]
        )

    if include_parked and parked_items:
        for p in parked_items:
            writer.writerow(
                [
                    p.get("id", ""),
                    "",
                    "Task",
                    f"[PARKED] {p.get('item', '')}",
                    p.get("reason", ""),
                    "",
                    "",
                    p.get("related_finding", ""),
                    "",
                    f"parking-lot {p.get('category', 'phase-2')}",
                ]
            )

    return buf.getvalue()


def export_backlog_markdown(
    title: str,
    preset: str,
    mode: str,
    tree: list[dict[str, Any]],
    parked_items: list[dict[str, Any]] | None = None,
) -> str:
    """Render an executive & engineering ready `BACKLOG.md` work breakdown document."""
    preset_label = HIERARCHY_PRESETS.get(preset, HIERARCHY_PRESETS["enterprise_4tier"])["label"]
    flat = flatten_backlog_tree(tree)
    counts: dict[str, int] = {}
    for n, _ in flat:
        lvl = n.get("level", "story")
        counts[lvl] = counts.get(lvl, 0) + 1
    summary_counts = " · ".join(f"{v} {k.capitalize()}(s)" for k, v in counts.items()) or "0 items"

    lines: list[str] = [
        f"# Locked Work Breakdown: {title}",
        "",
        f"> **Hierarchy:** {preset_label} · **Repo Mode:** `{mode}` · **Totals:** {summary_counts}",
        "",
    ]

    def _render_nodes(nodes: list[dict[str, Any]], depth: int) -> None:
        heading_hashes = "#" * min(2 + depth, 5)
        for node in nodes:
            lvl_badge = str(node.get("level", "item")).upper()
            est = f" · `{node['estimate']}`" if node.get("estimate") else ""
            guards = " ".join(f"`[{g}]`" for g in node.get("guardrail_ids", []))
            guard_suffix = f" {guards}" if guards else ""

            lines.append(f"{heading_hashes} {node['id']} [{lvl_badge}]: {node['title']}{est}{guard_suffix}")
            lines.append("")
            if node.get("description"):
                lines.append(node["description"])
                lines.append("")
            if node.get("repo_touchpoints"):
                refs = ", ".join(f"`{t}`" for t in node["repo_touchpoints"])
                lines.append(f"- **Codebase Touchpoints:** {refs}")
            if node.get("acceptance_criteria"):
                lines.append("- **Acceptance Criteria:**")
                for ac in node["acceptance_criteria"]:
                    lines.append(f"  - [ ] {ac}")
            if node.get("repo_touchpoints") or node.get("acceptance_criteria"):
                lines.append("")

            children = node.get("children")
            if isinstance(children, list) and children:
                _render_nodes(children, depth + 1)

    _render_nodes(tree, 0)

    if parked_items:
        lines.extend(
            [
                "---",
                "",
                "## Out-of-Scope Parking Lot (`PARKING-LOT.md`)",
                "",
                "| ID | Category | Parked Item | Why Deferred / Revisit Trigger |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for p in parked_items:
            lines.append(
                f"| {p.get('id', 'PL-001')} | `{p.get('category', 'phase-2')}` | "
                f"{p.get('item', '')} | {p.get('reason', '')} |"
            )
        lines.append("")

    return "\n".join(lines)


def format_parking_lot_markdown(parked_items: list[dict[str, Any]]) -> str:
    """Format in-memory session parked items into canonical `PARKING-LOT.md` markdown."""
    base = PARKING_LOT_HEADER.rstrip("\n")
    if not parked_items:
        return base + "\n"
    rows: list[str] = [base]
    for idx, p in enumerate(parked_items, start=1):
        pid = p.get("id") or f"PL-{idx:03d}"
        date = p.get("date") or "2026-11-24"
        cat = p.get("category") or "phase-2"
        item = str(p.get("item") or "").replace("|", "\\|")
        reason = str(p.get("reason") or "Deferred during Studio refinement").replace("|", "\\|")
        origin = str(p.get("origin") or p.get("related_finding") or "Studio Session").replace("|", "\\|")
        rows.append(f"| {pid} | {date} | `{cat}` | {item} | {reason} | {origin} |")
    return "\n".join(rows) + "\n"


def export_session_spec(
    prd_text: str,
    findings_doc: dict[str, Any],
    output_format: str,
    title: str,
    parked_items: list[dict[str, Any]] | None = None,
) -> str:
    """Delegate locked specification rendering to `scripts/compile_locked_spec.py`."""
    pl_md = format_parking_lot_markdown(parked_items or []) if parked_items else None
    return compile_specification(
        prd_text,
        findings_doc,
        output_format=output_format,
        title_override=title,
        parking_lot_text=pl_md,
    )
