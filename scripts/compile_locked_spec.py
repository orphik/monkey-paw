#!/usr/bin/env python3
"""Compile resolved monkey-paw findings + draft ticket into a locked specification.

Supported output formats (`--format`):
- `ears`     : Easy Approach to Requirements Syntax (`WHEN ... THE SYSTEM SHALL ...`)
- `spec-kit` : GitHub Spec-Kit `spec.md` structure (Purpose, Scenarios, Requirements, Acceptance Criteria)
- `openspec` : OpenSpec Delta Specification (`ADDED Requirements` + `GIVEN / WHEN / THEN` scenarios)
- `jira`     : Engineering-ready Jira / Linear markdown checklist
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from extract_repo_surface import is_sensitive_path  # noqa: E402
from validate_findings import (  # noqa: E402
    extract_option_text,
    extract_pm_tradeoff_text,
    load_json_file,
    validate_findings_data,
)

SUPPORTED_FORMATS: tuple[str, ...] = ("ears", "spec-kit", "openspec", "jira")

EXPLOIT_LABELS: dict[str, str] = {
    "orphaned_state": "Orphaned State",
    "partial_mutation": "Partial Mutation / Split-Brain",
    "auth_boundary_leak": "Authorization Boundary Leak",
    "concurrency_race": "Concurrency / TOCTOU Race",
    "blast_radius_scale": "Unbounded Blast Radius",
    "silent_fallback": "Silent Failure Fallback",
}


def infer_title(draft_text: str, findings_doc: Any, fallback_name: str = "Feature Specification") -> str:
    """Derive a clean specification title from findings metadata or the draft's first heading."""
    if isinstance(findings_doc, dict):
        doc_title = str(findings_doc.get("draft_title") or findings_doc.get("title") or "").strip()
        if doc_title:
            return doc_title

    for raw_line in draft_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            cleaned = line.lstrip("#").strip()
            if cleaned:
                return cleaned
        return line[:90] + ("..." if len(line) > 90 else "")
    return fallback_name


def resolve_finding_choice(finding: dict[str, Any]) -> dict[str, Any]:
    """Extract normalized decision fields from a validated, resolved finding."""
    res = finding.get("resolution") if isinstance(finding.get("resolution"), dict) else {}
    selected = str(res.get("selected") or res.get("selected_option") or finding.get("selected_option") or "").strip()
    eng = finding["eng_options"]

    if selected in {"option_a", "option_b"}:
        opt_label, opt_body = extract_option_text(eng[selected])
        rejected_key = "option_b" if selected == "option_a" else "option_a"
        rej_label, rej_body = extract_option_text(eng[rejected_key])
        chosen_tag = "Option A" if selected == "option_a" else "Option B"
        if opt_label:
            chosen_tag = f"{chosen_tag} ({opt_label})"
        chosen_design = opt_body
        rejected_summary = f"{rej_label}: {rej_body}".strip(": ")
    else:
        chosen_tag = "Custom Decision"
        chosen_design = str(
            res.get("custom_design")
            or res.get("decision_summary")
            or res.get("summary")
            or finding.get("custom_design")
            or finding.get("decision_summary")
            or ""
        ).strip()
        _, body_a = extract_option_text(eng["option_a"])
        _, body_b = extract_option_text(eng["option_b"])
        rejected_summary = f"Option A ({body_a}); Option B ({body_b})"

    rationale = str(res.get("rationale") or res.get("decision_summary") or "").strip()
    raw_clauses = res.get("ears_clauses")
    if isinstance(raw_clauses, list) and raw_clauses:
        ears_clauses = [str(c).strip() for c in raw_clauses if str(c).strip()]
    else:
        ears_clauses = [_synthesize_ears_clause(finding, chosen_design)]

    title = str(finding.get("title") or "").strip()
    if not title:
        title = EXPLOIT_LABELS.get(finding["exploit_class"], finding["exploit_class"])

    citations = [c.strip() for c in finding.get("repo_citations", []) if str(c).strip()]
    return {
        "id": finding["id"].strip(),
        "title": title,
        "exploit_class": finding["exploit_class"],
        "exploit_label": EXPLOIT_LABELS.get(finding["exploit_class"], finding["exploit_class"]),
        "spec_quote": finding["spec_quote"].strip(),
        "monkeys_paw_grant": finding["monkeys_paw_grant"].strip(),
        "chosen_key": selected,
        "chosen_tag": chosen_tag,
        "chosen_design": chosen_design,
        "rejected_summary": rejected_summary,
        "rationale": rationale,
        "pm_tradeoff": extract_pm_tradeoff_text(finding["pm_tradeoff"]),
        "citations": citations,
        "ears_clauses": ears_clauses,
    }


def _synthesize_ears_clause(finding: dict[str, Any], chosen_design: str) -> str:
    """Synthesize a deterministic EARS requirement when explicit `ears_clauses` are omitted."""
    upper = chosen_design.upper()
    if upper.startswith(("WHEN ", "WHILE ", "IF ", "WHERE ", "THE SYSTEM SHALL ")):
        if "SHALL" in upper:
            return chosen_design if chosen_design.endswith(".") else f"{chosen_design}."

    design_sentence = chosen_design.rstrip(".")
    ec = finding["exploit_class"]
    fid = finding["id"].strip()

    if ec == "concurrency_race":
        return (
            f"WHEN concurrent or duplicate requests target the same resource ({fid}), "
            f"THE SYSTEM SHALL { _lower_lead(design_sentence) }."
        )
    if ec == "partial_mutation":
        return (
            f"IF an upstream dependency or persistence step fails mid-operation ({fid}), "
            f"THEN THE SYSTEM SHALL { _lower_lead(design_sentence) }."
        )
    if ec == "auth_boundary_leak":
        return (
            f"WHEN a caller invokes the protected operation ({fid}), "
            f"THE SYSTEM SHALL { _lower_lead(design_sentence) }."
        )
    if ec == "orphaned_state":
        return (
            f"WHEN lifecycle state transitions mutate or deactivate a record ({fid}), "
            f"THE SYSTEM SHALL { _lower_lead(design_sentence) }."
        )
    if ec == "blast_radius_scale":
        return (
            f"WHILE processing batch or multi-entity workloads ({fid}), "
            f"THE SYSTEM SHALL { _lower_lead(design_sentence) }."
        )
    # silent_fallback
    return (
        f"IF a downstream lookup, webhook, or external call fails or returns unexpected state ({fid}), "
        f"THEN THE SYSTEM SHALL { _lower_lead(design_sentence) }."
    )


def _lower_lead(text: str) -> str:
    if not text:
        return text
    first_word = text.split()[0]
    # Keep all-caps acronyms (e.g., SQL, HTTP, RBAC, DB) uppercase
    if first_word.isupper() and len(first_word) > 1:
        return f"enforce: {text}"
    return text[0].lower() + text[1:]


def _format_citations(citations: list[str], mode: str) -> str:
    if not citations:
        return "_None (greenfield mode)_" if mode == "greenfield" else "_None_"
    return ", ".join(f"`{c}`" for c in citations)


def _extract_parked_summary(parking_lot_text: str | None) -> list[str]:
    if not parking_lot_text:
        return []
    rows: list[str] = []
    for raw_ln in parking_lot_text.splitlines():
        ln = raw_ln.strip()
        if ln.startswith("| PL-"):
            cells = [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", ln.strip("|"))]
            if len(cells) >= 4:
                rows.append(f"- **{cells[0]}** ({cells[2]}): {cells[3]}")
    return rows


def render_ears(
    title: str,
    draft_text: str,
    mode: str,
    resolved: list[dict[str, Any]],
    parked_rows: list[str],
) -> str:
    lines: list[str] = [
        f"# Locked Specification (EARS): {title}",
        "",
        f"> **Status:** LOCKED · **Mode:** `{mode}` · **Resolved Guardrails:** {len(resolved)}",
        "",
        "## 1. Original Draft Baseline",
        "",
        "```text",
        draft_text.strip(),
        "```",
        "",
        "## 2. Locked EARS Requirements",
        "",
    ]

    for item in resolved:
        lines.append(f"### [{item['id']}] {item['title']} (`{item['exploit_class']}`)")
        lines.append("")
        lines.append(f"- **Ambiguous Draft Trigger:** \"{item['spec_quote']}\"")
        lines.append(f"- **Blocked Monkey's Paw Exploit:** {item['monkeys_paw_grant']}")
        lines.append(f"- **Locked Engineering Choice — {item['chosen_tag']}:** {item['chosen_design']}")
        lines.append(f"- **Product / PM Trade-off Accepted:** {item['pm_tradeoff']}")
        lines.append(f"- **Repo Surface Citations:** {_format_citations(item['citations'], mode)}")
        lines.append("")
        for clause in item["ears_clauses"]:
            lines.append(f"- **Requirement:** {clause}")
        lines.append("")

    lines.extend(
        [
            "## 3. Decision Traceability Matrix",
            "",
            "| ID | Exploit Class | Locked Option | Cited Touchpoints |",
            "| :--- | :--- | :--- | :--- |",
        ]
    )
    for item in resolved:
        cits = ", ".join(f"`{c}`" for c in item["citations"]) if item["citations"] else "greenfield"
        lines.append(f"| `{item['id']}` | `{item['exploit_class']}` | {item['chosen_tag']} | {cits} |")

    if parked_rows:
        lines.extend(["", "## 4. Out-of-Scope (Parked in `PARKING-LOT.md`)", ""])
        lines.extend(parked_rows)

    lines.append("")
    return "\n".join(lines)


def render_spec_kit(
    title: str,
    draft_text: str,
    mode: str,
    resolved: list[dict[str, Any]],
    parked_rows: list[str],
) -> str:
    lines: list[str] = [
        f"# Specification: {title}",
        "",
        f"**Mode:** `{mode}` | **Refereed Findings Locked:** {len(resolved)}",
        "",
        "## Purpose",
        "",
        draft_text.strip(),
        "",
        "## User Journeys & Failure-Boundary Scenarios",
        "",
    ]
    for item in resolved:
        lines.append(
            f"- **[{item['id']}] {item['title']} (`{item['exploit_class']}`):** "
            f"Prevents literal-agent failure mode where _{item['monkeys_paw_grant']}_ "
            f"Product impact: {item['pm_tradeoff']}"
        )

    lines.extend(["", "## Requirements", ""])
    for item in resolved:
        for clause in item["ears_clauses"]:
            lines.append(f"- **[{item['id']}]** {clause}")
        if item["citations"]:
            lines.append(f"  - *Touchpoints:* {_format_citations(item['citations'], mode)}")

    lines.extend(["", "## Architectural Decisions & Rejected Alternatives", ""])
    for item in resolved:
        lines.append(f"### {item['id']}: {item['title']}")
        lines.append(f"- **Selected ({item['chosen_tag']}):** {item['chosen_design']}")
        lines.append(f"- **Rejected:** {item['rejected_summary']}")
        if item["rationale"]:
            lines.append(f"- **Rationale:** {item['rationale']}")
        lines.append("")

    lines.extend(["## Acceptance Criteria", ""])
    for item in resolved:
        for clause in item["ears_clauses"]:
            lines.append(f"- [ ] `[{item['id']}]` {clause}")

    if parked_rows:
        lines.extend(["", "## Non-Goals / Parked Items (`PARKING-LOT.md`)", ""])
        lines.extend(parked_rows)

    lines.append("")
    return "\n".join(lines)


def render_openspec(
    title: str,
    draft_text: str,
    mode: str,
    resolved: list[dict[str, Any]],
    parked_rows: list[str],
) -> str:
    lines: list[str] = [
        f"# Spec Delta: {title}",
        "",
        "## Purpose",
        "",
        draft_text.strip(),
        "",
        "## ADDED Requirements",
        "",
    ]

    for item in resolved:
        lines.append(f"### Requirement {item['id']}: {item['title']} ({item['exploit_label']})")
        lines.append("")
        for clause in item["ears_clauses"]:
            lines.append(f"{clause}")
            lines.append("")
        lines.append(f"- **Scenario:** Malicious compliance boundary on \"{item['spec_quote']}\"")
        lines.append(f"  - **GIVEN** repository mode `{mode}` ({_format_citations(item['citations'], mode)})")
        lines.append(f"  - **WHEN** an execution path encounters the `{item['exploit_class']}` boundary")
        lines.append(f"  - **THEN** the system enforces {item['chosen_tag']}: {item['chosen_design']}")
        lines.append(f"  - **AND** preserves product contract: {item['pm_tradeoff']}")
        lines.append("")

    if parked_rows:
        lines.extend(["## Deferred / Out-of-Scope Changes", ""])
        lines.extend(parked_rows)
        lines.append("")

    return "\n".join(lines)


def render_jira(
    title: str,
    draft_text: str,
    mode: str,
    resolved: list[dict[str, Any]],
    parked_rows: list[str],
) -> str:
    lines: list[str] = [
        f"# [LOCKED SPEC] {title}",
        "",
        "## Summary / Original Request",
        "",
        draft_text.strip(),
        "",
        "## Locked Engineering Decisions",
        "",
        "| Finding | Loophole Blocked | Selected Design | PM Trade-off |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for item in resolved:
        lines.append(
            f"| **{item['id']}** ({item['title']}) | `{item['exploit_class']}` | "
            f"**{item['chosen_tag']}:** {item['chosen_design']} | {item['pm_tradeoff']} |"
        )

    lines.extend(["", "## Acceptance Criteria Checklist", ""])
    for item in resolved:
        cits = f" _(Refs: {_format_citations(item['citations'], mode)})_" if item["citations"] else ""
        for clause in item["ears_clauses"]:
            lines.append(f"- [ ] **[{item['id']}]** {clause}{cits}")

    all_citations: list[str] = []
    for item in resolved:
        for cit in item["citations"]:
            if cit not in all_citations:
                all_citations.append(cit)

    if all_citations:
        lines.extend(["", "## Brownfield Codebase Touchpoints", ""])
        for cit in all_citations:
            lines.append(f"- `{cit}`")

    if parked_rows:
        lines.extend(["", "## Out of Scope (`PARKING-LOT.md`)", ""])
        lines.extend(parked_rows)

    lines.append("")
    return "\n".join(lines)


def compile_specification(
    draft_text: str,
    findings_doc: Any,
    *,
    output_format: str = "ears",
    title_override: str | None = None,
    mode_override: str | None = None,
    surface_data: dict[str, Any] | None = None,
    parking_lot_text: str | None = None,
) -> str:
    """Validate resolved findings and compile a locked specification markdown string."""
    if output_format not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format {output_format!r}; expected one of {SUPPORTED_FORMATS}.")

    is_valid, errors, meta = validate_findings_data(
        findings_doc,
        mode_override=mode_override,
        surface_data=surface_data,
        require_resolved=True,
    )
    if not is_valid:
        joined = "\n  - ".join(errors)
        raise ValueError(f"Cannot compile locked spec; findings failed validation:\n  - {joined}")

    raw_findings = findings_doc["findings"] if isinstance(findings_doc, dict) else findings_doc
    resolved = [resolve_finding_choice(f) for f in raw_findings]
    title = title_override.strip() if title_override and title_override.strip() else infer_title(draft_text, findings_doc)
    parked_rows = _extract_parked_summary(parking_lot_text)
    mode = meta["mode"]

    if output_format == "ears":
        return render_ears(title, draft_text, mode, resolved, parked_rows)
    if output_format == "spec-kit":
        return render_spec_kit(title, draft_text, mode, resolved, parked_rows)
    if output_format == "openspec":
        return render_openspec(title, draft_text, mode, resolved, parked_rows)
    return render_jira(title, draft_text, mode, resolved, parked_rows)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compile_locked_spec.py",
        description="Merge resolved monkey-paw findings + draft ticket into Spec-Kit, OpenSpec, EARS, or Jira markdown.",
    )
    parser.add_argument(
        "--draft",
        required=True,
        help="Path to original draft spec / ticket markdown or text file.",
    )
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to resolved findings JSON file.",
    )
    parser.add_argument(
        "--surface",
        default=None,
        help="Optional path to .monkey-paw/surface.json for mode enforcement.",
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=SUPPORTED_FORMATS,
        default="ears",
        help="Target specification format (default: ears).",
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Optional explicit title for the compiled specification.",
    )
    parser.add_argument(
        "--parking-lot",
        default=None,
        help="Optional path to PARKING-LOT.md to link deferred out-of-scope items.",
    )
    parser.add_argument(
        "--out",
        default="SPEC.md",
        help="Output markdown path (default: SPEC.md; pass '-' for stdout).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    draft_path = Path(args.draft)
    try:
        draft_text = draft_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: Unable to read draft file '{draft_path}': {exc}", file=sys.stderr)
        return 1

    try:
        findings_doc = load_json_file(Path(args.findings), "findings")
        surface_doc = load_json_file(Path(args.surface), "surface") if args.surface else None
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    parking_text: str | None = None
    if args.parking_lot:
        pl_path = Path(args.parking_lot)
        if pl_path.is_file():
            parking_text = pl_path.read_text(encoding="utf-8", errors="replace")
    elif args.out != "-":
        sibling_pl = Path(args.out).resolve().parent / "PARKING-LOT.md"
        if sibling_pl.is_file():
            parking_text = sibling_pl.read_text(encoding="utf-8", errors="replace")

    try:
        compiled = compile_specification(
            draft_text,
            findings_doc,
            output_format=args.output_format,
            title_override=args.title,
            surface_data=surface_doc,
            parking_lot_text=parking_text,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.out == "-":
        sys.stdout.write(compiled)
        return 0

    out_path = Path(args.out)
    if is_sensitive_path(out_path.as_posix(), out_path.name):
        print(f"ERROR: Refusing to write output to sensitive path: {out_path}", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(compiled, encoding="utf-8")
    print(f"OK: Compiled '{args.output_format}' specification to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
