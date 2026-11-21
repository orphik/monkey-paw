from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.validate_findings import VALID_EXPLOIT_CLASSES, validate_findings_data  # noqa: E402


def _make_valid_finding(fid: str = "MP-001", exploit_class: str = "concurrency_race") -> dict[str, Any]:
    return {
        "id": fid,
        "title": "Concurrent Refund Double-Spend",
        "exploit_class": exploit_class,
        "spec_quote": "Prevent refunding more than the original charge amount.",
        "monkeys_paw_grant": "Agent reads refunded_cents in Python memory without locking; parallel clicks both pass and refund 200%.",
        "repo_citations": ["services/billing/charges.py:42"],
        "eng_options": {
            "option_a": "Acquire SELECT FOR UPDATE NOWAIT row lock on charges and enforce SQL CHECK constraint.",
            "option_b": "Require client Idempotency-Key header backed by optimistic version CAS update.",
        },
        "pm_tradeoff": "Option A rejects simultaneous clicks with HTTP 409 immediately; Option B replays prior receipt (+1 DB table).",
    }


class TestValidateFindings(unittest.TestCase):
    def test_sample_fintech_fixture_is_valid(self) -> None:
        fixture = REPO_ROOT / "assets" / "examples" / "sample-fintech-refund" / "findings.json"
        doc = json.loads(fixture.read_text(encoding="utf-8"))
        ok, errors, meta = validate_findings_data(doc, require_resolved=True)
        self.assertTrue(ok, msg=f"Sample fixture failed validation: {errors}")
        self.assertEqual(meta["mode"], "brownfield")
        self.assertEqual(meta["count"], 4)

    def test_all_six_exploit_classes_accepted(self) -> None:
        self.assertEqual(
            VALID_EXPLOIT_CLASSES,
            {
                "orphaned_state",
                "partial_mutation",
                "auth_boundary_leak",
                "concurrency_race",
                "blast_radius_scale",
                "silent_fallback",
            },
        )
        for ec in sorted(VALID_EXPLOIT_CLASSES):
            doc = {"mode": "brownfield", "findings": [_make_valid_finding("MP-001", ec)]}
            ok, errors, _ = validate_findings_data(doc)
            self.assertTrue(ok, msg=f"Expected {ec} to pass, got {errors}")

    def test_count_bounds_one_to_five_enforced(self) -> None:
        empty_doc = {"mode": "brownfield", "findings": []}
        ok, errors, _ = validate_findings_data(empty_doc)
        self.assertFalse(ok)
        self.assertTrue(any("between 1 and 5" in e for e in errors))

        five_doc = {
            "mode": "brownfield",
            "findings": [_make_valid_finding(f"MP-00{i}") for i in range(1, 6)],
        }
        ok5, errors5, _ = validate_findings_data(five_doc)
        self.assertTrue(ok5, msg=errors5)

        six_doc = {
            "mode": "brownfield",
            "findings": [_make_valid_finding(f"MP-00{i}") for i in range(1, 7)],
        }
        ok6, errors6, _ = validate_findings_data(six_doc)
        self.assertFalse(ok6)
        self.assertTrue(any("between 1 and 5" in e for e in errors6))

    def test_brownfield_requires_non_empty_citations_while_greenfield_allows_empty(self) -> None:
        finding = _make_valid_finding()
        finding["repo_citations"] = []

        ok_bf, errs_bf, _ = validate_findings_data({"mode": "brownfield", "findings": [finding]})
        self.assertFalse(ok_bf)
        self.assertTrue(any("non-empty when mode is 'brownfield'" in e for e in errs_bf))

        ok_gf, errs_gf, _ = validate_findings_data({"mode": "greenfield", "findings": [finding]})
        self.assertTrue(ok_gf, msg=errs_gf)

        # Prevent spoofing greenfield when surface.json is brownfield
        ok_spoof, errs_spoof, _ = validate_findings_data(
            {"mode": "greenfield", "findings": [finding]},
            surface_data={"mode": "brownfield"},
        )
        self.assertFalse(ok_spoof)
        self.assertTrue(any("Mode mismatch" in e for e in errs_spoof))

    def test_missing_required_fields_and_identical_options_rejected(self) -> None:
        required = (
            "id",
            "exploit_class",
            "spec_quote",
            "monkeys_paw_grant",
            "repo_citations",
            "eng_options",
            "pm_tradeoff",
        )
        for field in required:
            broken = _make_valid_finding()
            del broken[field]
            ok, errors, _ = validate_findings_data({"mode": "brownfield", "findings": [broken]})
            self.assertFalse(ok, msg=f"Deleting {field} should fail validation")
            self.assertTrue(any(field in e for e in errors))

        dup_opts = _make_valid_finding()
        dup_opts["eng_options"]["option_b"] = dup_opts["eng_options"]["option_a"]
        ok_dup, errs_dup, _ = validate_findings_data({"mode": "brownfield", "findings": [dup_opts]})
        self.assertFalse(ok_dup)
        self.assertTrue(any("distinct engineering designs" in e for e in errs_dup))

    def test_generic_filler_and_placeholders_rejected(self) -> None:
        filler_phrases = [
            "Add proper error handling to the refund endpoint so requests do not fail.",
            "Implement robust input validation and follow industry best practices.",
            "Handle edge cases gracefully when calling the payment provider.",
            "Make the system production-ready before launch.",
            "TO" + "DO: specify locking strategy later",
        ]
        for phrase in filler_phrases:
            bad = copy.deepcopy(_make_valid_finding())
            bad["eng_options"]["option_a"] = phrase
            ok, errors, _ = validate_findings_data({"mode": "brownfield", "findings": [bad]})
            self.assertFalse(ok, msg=f"Expected filler phrase to be rejected: {phrase!r}")
            self.assertTrue(len(errors) >= 1)

    def test_cli_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "bad.json"
            bad_finding = _make_valid_finding()
            bad_finding["exploit_class"] = "not_a_real_class"
            bad_path.write_text(json.dumps({"mode": "brownfield", "findings": [bad_finding]}), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "validate_findings.py"),
                    "--findings",
                    str(bad_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("exploit_class", proc.stderr)


if __name__ == "__main__":
    unittest.main()
