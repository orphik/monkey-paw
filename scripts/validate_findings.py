#!/usr/bin/env python3
"""Deterministic schema, citation, and anti-slop validator for monkey-paw findings.

Enforces:
- Hard cap of 1..5 findings (no empty audits, no 20-item nitpick dumps).
- Valid `exploit_class` enum membership across the 6 production loophole classes.
- Concrete `spec_quote`, `monkeys_paw_grant`, distinct `eng_options` (`option_a`, `option_b`),
  and plain-language `pm_tradeoff`.
- Non-empty `repo_citations` whenever operating in `brownfield` mode.
- Automatic rejection of generic AI filler ("add proper error handling", "follow best practices", etc.).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

MIN_FINDINGS = 1
MAX_FINDINGS = 5

VALID_EXPLOIT_CLASSES: frozenset[str] = frozenset(
    {
        "orphaned_state",
        "partial_mutation",
        "auth_boundary_leak",
        "concurrency_race",
        "blast_radius_scale",
        "silent_fallback",
    }
)

VALID_MODES: frozenset[str] = frozenset({"brownfield", "greenfield"})
VALID_SELECTED_OPTIONS: frozenset[str] = frozenset({"option_a", "option_b", "custom"})

GENERIC_FILLER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "generic filler ('proper/appropriate error handling, validation, logging, or security')",
        re.compile(
            r"\b(?:add|implement|ensure|include|use|provide|apply)\s+"
            r"(?:proper|appropriate|better|good|robust|adequate|comprehensive|standard|sufficient)\s+"
            r"(?:error\s+handling|exception\s+handling|validation|input\s+validation|logging|"
            r"monitoring|security|testing|checks|safeguards)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "generic filler ('proper error handling')",
        re.compile(r"\bproper\s+error\s+handling\b", re.IGNORECASE),
    ),
    (
        "generic filler ('handle errors/edge cases gracefully/properly')",
        re.compile(
            r"\bhandle\s+(?:all\s+)?(?:errors|exceptions|edge\s+cases|failures)\s+"
            r"(?:properly|gracefully|appropriately|cleanly|correctly)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "generic filler ('follow best practices')",
        re.compile(r"\b(?:follow|adhere\s+to|apply|use)\s+(?:industry\s+|security\s+)?best\s+practices\b", re.IGNORECASE),
    ),
    (
        "generic filler ('make it scalable / production-ready')",
        re.compile(r"\bmake\s+(?:it|the\s+system)\s+(?:more\s+)?(?:scalable|secure|production[- ]ready|robust)\b", re.IGNORECASE),
    ),
    (
        "unfinished placeholder token",
        re.compile(r"\b(?:to" r"do|fix" r"me|tb" r"d|lorem\s+ipsum)\b", re.IGNORECASE),
    ),
    (
        "standalone vague testing/optimization cliché",
        re.compile(
            r"^\s*(?:add|write)\s+(?:more\s+|unit\s+|comprehensive\s+)?tests\.?\s*$"
            r"|^\s*(?:improve|optimize)\s+(?:performance|database\s+queries)\.?\s*$",
            re.IGNORECASE,
        ),
    ),
)

PLACEHOLDER_CITATIONS: frozenset[str] = frozenset(
    {"none", "n/a", "na", "null", "nil", "unknown", "tbd", " file", "-"}
)


def extract_option_text(opt_value: Any) -> tuple[str, str]:
    """Normalize an engineering option (string or dict) into `(label, body_text)`."""
    if isinstance(opt_value, str):
        return "", opt_value.strip()
    if isinstance(opt_value, dict):
        label = str(opt_value.get("label") or opt_value.get("title") or "").strip()
        body = str(
            opt_value.get("design")
            or opt_value.get("summary")
            or opt_value.get("description")
            or opt_value.get("mechanism")
            or ""
        ).strip()
        extra_parts = [
            str(opt_value[k]).strip()
            for k in ("pros_cons", "tradeoff", "impact")
            if isinstance(opt_value.get(k), str) and opt_value[k].strip()
        ]
        combined = " ".join(part for part in (body, *extra_parts) if part).strip()
        return label, combined
    return "", ""


def extract_pm_tradeoff_text(pm_value: Any) -> str:
    """Normalize `pm_tradeoff` (string or structured dict) into plain text."""
    if isinstance(pm_value, str):
        return pm_value.strip()
    if isinstance(pm_value, dict):
        parts: list[str] = []
        for key in ("summary", "ux", "ux_impact", "latency", "latency_impact", "scope", "scope_impact", "risk"):
            val = pm_value.get(key)
            if isinstance(val, str) and val.strip():
                parts.append(f"{key}: {val.strip()}")
        if not parts:
            for key, val in pm_value.items():
                if isinstance(val, str) and val.strip():
                    parts.append(f"{key}: {val.strip()}")
        return " | ".join(parts)
    return ""


def check_for_filler(text: str, field_label: str) -> list[str]:
    """Return validation error messages if `text` contains banned generic filler phrases."""
    errors: list[str] = []
    for reason, pattern in GENERIC_FILLER_PATTERNS:
        match = pattern.search(text)
        if match:
            snippet = match.group(0).strip()
            errors.append(f"{field_label} contains {reason}: '{snippet}'")
    return errors


def _is_plausible_repo_citation(citation: str) -> bool:
    cleaned = citation.strip()
    if len(cleaned) < 3:
        return False
    if cleaned.lower() in PLACEHOLDER_CITATIONS:
        return False
    # Must look like a file path, module.symbol, or path:line reference
    return any(sep in cleaned for sep in ("/", "\\", ".", ":"))


def validate_findings_data(
    data: Any,
    *,
    mode_override: str | None = None,
    surface_data: dict[str, Any] | None = None,
    require_resolved: bool = False,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Validate parsed findings JSON structure.

    Returns `(is_valid, errors, normalized_meta)`.
    """
    errors: list[str] = []

    doc_mode: str | None = None
    if isinstance(data, dict):
        raw_mode = data.get("mode")
        if raw_mode is not None:
            if not isinstance(raw_mode, str) or raw_mode not in VALID_MODES:
                errors.append(f"Top-level 'mode' must be one of {sorted(VALID_MODES)}, got {raw_mode!r}.")
            else:
                doc_mode = raw_mode
        findings = data.get("findings")
        if not isinstance(findings, list):
            errors.append("Top-level object must contain a 'findings' list.")
            return False, errors, {"mode": doc_mode or "brownfield", "count": 0}
    elif isinstance(data, list):
        findings = data
    else:
        errors.append("Findings JSON root must be an object with 'findings' or a JSON array.")
        return False, errors, {"mode": "brownfield", "count": 0}

    surface_mode: str | None = None
    if isinstance(surface_data, dict):
        sm = surface_data.get("mode")
        if isinstance(sm, str) and sm in VALID_MODES:
            surface_mode = sm

    if mode_override is not None:
        if mode_override not in VALID_MODES:
            errors.append(f"Invalid mode override {mode_override!r}; expected one of {sorted(VALID_MODES)}.")
        effective_mode = mode_override
    elif surface_mode is not None:
        if doc_mode is not None and doc_mode != surface_mode:
            errors.append(
                f"Mode mismatch: findings JSON declares mode='{doc_mode}' while surface.json is mode='{surface_mode}'."
            )
        effective_mode = surface_mode
    elif doc_mode is not None:
        effective_mode = doc_mode
    else:
        effective_mode = "brownfield"

    count = len(findings)
    if count < MIN_FINDINGS or count > MAX_FINDINGS:
        errors.append(
            f"Findings count must be between {MIN_FINDINGS} and {MAX_FINDINGS} inclusive (got {count})."
        )

    seen_ids: set[str] = set()
    required_keys = (
        "id",
        "exploit_class",
        "spec_quote",
        "monkeys_paw_grant",
        "repo_citations",
        "eng_options",
        "pm_tradeoff",
    )

    for idx, item in enumerate(findings):
        prefix = f"findings[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: each finding must be a JSON object.")
            continue

        fid_raw = item.get("id")
        if isinstance(fid_raw, str) and fid_raw.strip():
            fid = fid_raw.strip()
            prefix = f"findings[{idx}] ({fid})"
            if fid in seen_ids:
                errors.append(f"{prefix}: duplicate finding id '{fid}'.")
            seen_ids.add(fid)
        else:
            errors.append(f"{prefix}: 'id' must be a non-empty string.")

        for req in required_keys:
            if req not in item:
                errors.append(f"{prefix}: missing required field '{req}'.")

        # 1. exploit_class
        ec = item.get("exploit_class")
        if "exploit_class" in item:
            if not isinstance(ec, str) or ec not in VALID_EXPLOIT_CLASSES:
                errors.append(
                    f"{prefix}: 'exploit_class' must be one of {sorted(VALID_EXPLOIT_CLASSES)}, got {ec!r}."
                )

        # 2. spec_quote
        sq = item.get("spec_quote")
        if "spec_quote" in item:
            if not isinstance(sq, str) or len(sq.strip()) < 8:
                errors.append(f"{prefix}: 'spec_quote' must be a concrete quote or omission marker (>= 8 chars).")
            else:
                errors.extend(check_for_filler(sq, f"{prefix}.spec_quote"))

        # 3. monkeys_paw_grant
        grant = item.get("monkeys_paw_grant")
        if "monkeys_paw_grant" in item:
            if not isinstance(grant, str) or len(grant.strip()) < 20:
                errors.append(
                    f"{prefix}: 'monkeys_paw_grant' must concretely describe the literal-agent failure mode (>= 20 chars)."
                )
            else:
                errors.extend(check_for_filler(grant, f"{prefix}.monkeys_paw_grant"))

        # 4. repo_citations
        citations = item.get("repo_citations")
        if "repo_citations" in item:
            if not isinstance(citations, list) or not all(isinstance(c, str) for c in citations):
                errors.append(f"{prefix}: 'repo_citations' must be a list of strings.")
            else:
                if effective_mode == "brownfield" and len(citations) == 0:
                    errors.append(
                        f"{prefix}: 'repo_citations' must be non-empty when mode is 'brownfield'."
                    )
                for c_idx, cit in enumerate(citations):
                    if not _is_plausible_repo_citation(cit):
                        errors.append(
                            f"{prefix}.repo_citations[{c_idx}]: invalid or placeholder citation {cit!r} "
                            "(expected file path or symbol reference like 'app/routes/refunds.py:42')."
                        )
                    errors.extend(check_for_filler(cit, f"{prefix}.repo_citations[{c_idx}]"))

        # 5. eng_options
        eng = item.get("eng_options")
        if "eng_options" in item:
            if not isinstance(eng, dict):
                errors.append(f"{prefix}: 'eng_options' must be an object containing 'option_a' and 'option_b'.")
            else:
                for opt_key in ("option_a", "option_b"):
                    if opt_key not in eng:
                        errors.append(f"{prefix}.eng_options: missing required '{opt_key}'.")
                        continue
                    label, body = extract_option_text(eng[opt_key])
                    full_opt = f"{label}: {body}".strip(": ")
                    if len(body) < 15:
                        errors.append(
                            f"{prefix}.eng_options.{opt_key}: engineering design must be concrete (>= 15 chars)."
                        )
                    else:
                        errors.extend(check_for_filler(full_opt, f"{prefix}.eng_options.{opt_key}"))

                if "option_a" in eng and "option_b" in eng:
                    _, body_a = extract_option_text(eng["option_a"])
                    _, body_b = extract_option_text(eng["option_b"])
                    if body_a and body_b and body_a.lower() == body_b.lower():
                        errors.append(
                            f"{prefix}.eng_options: 'option_a' and 'option_b' must present distinct engineering designs."
                        )

        # 6. pm_tradeoff
        pm = item.get("pm_tradeoff")
        if "pm_tradeoff" in item:
            pm_text = extract_pm_tradeoff_text(pm)
            if len(pm_text) < 15:
                errors.append(
                    f"{prefix}: 'pm_tradeoff' must explain UX, latency, or scope trade-offs (>= 15 chars)."
                )
            else:
                errors.extend(check_for_filler(pm_text, f"{prefix}.pm_tradeoff"))

        # 7. Optional / Required Resolution check
        resolution = item.get("resolution")
        selected_top = item.get("selected_option")
        if require_resolved and resolution is None and selected_top is None:
            errors.append(
                f"{prefix}: missing locked decision ('resolution' object or 'selected_option' required to compile)."
            )

        if resolution is not None:
            if not isinstance(resolution, dict):
                errors.append(f"{prefix}.resolution: must be an object.")
            else:
                sel = resolution.get("selected") or resolution.get("selected_option")
                if not isinstance(sel, str) or sel not in VALID_SELECTED_OPTIONS:
                    errors.append(
                        f"{prefix}.resolution: 'selected' must be one of {sorted(VALID_SELECTED_OPTIONS)}, got {sel!r}."
                    )
                if sel == "custom":
                    cdesign = str(
                        resolution.get("custom_design")
                        or resolution.get("decision_summary")
                        or resolution.get("summary")
                        or ""
                    ).strip()
                    if len(cdesign) < 15:
                        errors.append(
                            f"{prefix}.resolution: when selected='custom', provide 'custom_design' or 'decision_summary' (>= 15 chars)."
                        )
                    else:
                        errors.extend(check_for_filler(cdesign, f"{prefix}.resolution.custom_design"))

                clauses = resolution.get("ears_clauses")
                if clauses is not None:
                    if not isinstance(clauses, list) or not clauses or not all(isinstance(c, str) for c in clauses):
                        errors.append(f"{prefix}.resolution.ears_clauses: when present, must be a non-empty list of strings.")
                    else:
                        for c_idx, clause in enumerate(clauses):
                            if "SHALL" not in clause:
                                errors.append(
                                    f"{prefix}.resolution.ears_clauses[{c_idx}]: EARS requirement must contain 'SHALL'."
                                )
                            errors.extend(check_for_filler(clause, f"{prefix}.resolution.ears_clauses[{c_idx}]"))
        elif selected_top is not None:
            if not isinstance(selected_top, str) or selected_top not in VALID_SELECTED_OPTIONS:
                errors.append(
                    f"{prefix}.selected_option: must be one of {sorted(VALID_SELECTED_OPTIONS)}, got {selected_top!r}."
                )
            elif selected_top == "custom":
                cdesign = str(item.get("custom_design") or item.get("decision_summary") or "").strip()
                if len(cdesign) < 15:
                    errors.append(
                        f"{prefix}: when selected_option='custom', provide 'custom_design' (>= 15 chars)."
                    )
                else:
                    errors.extend(check_for_filler(cdesign, f"{prefix}.custom_design"))

    meta = {
        "mode": effective_mode,
        "count": count,
        "valid": len(errors) == 0,
    }
    return len(errors) == 0, errors, meta


def load_json_file(path: Path, label: str) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Unable to read {label} file '{path}': {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {label} file '{path}': {exc}") from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validate_findings.py",
        description="Validate monkey-paw findings JSON against schema, citation, and anti-filler rules.",
    )
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to findings JSON file (e.g., .monkey-paw/findings.json).",
    )
    parser.add_argument(
        "--surface",
        default=None,
        help="Optional path to .monkey-paw/surface.json to enforce repository mode consistency.",
    )
    parser.add_argument(
        "--mode",
        choices=sorted(VALID_MODES),
        default=None,
        help="Explicitly override repository mode ('brownfield' or 'greenfield').",
    )
    parser.add_argument(
        "--require-resolved",
        action="store_true",
        help="Require every finding to contain a locked resolution decision.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit validation report as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        findings_data = load_json_file(Path(args.findings), "findings")
        surface_data = load_json_file(Path(args.surface), "surface") if args.surface else None
    except ValueError as exc:
        if args.json_output:
            print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2))
        else:
            print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        return 1

    is_valid, errors, meta = validate_findings_data(
        findings_data,
        mode_override=args.mode,
        surface_data=surface_data,
        require_resolved=args.require_resolved,
    )

    if args.json_output:
        print(json.dumps({**meta, "errors": errors}, indent=2))
    elif is_valid:
        print(
            f"OK: Validated {meta['count']} finding(s) in '{meta['mode']}' mode with zero errors."
        )
    else:
        print(f"VALIDATION FAILED ({len(errors)} error(s)):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)

    return 0 if is_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
