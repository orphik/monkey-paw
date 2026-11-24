from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _parse_simple_frontmatter(md_text: str) -> tuple[dict[str, object], str]:
    """Minimal deterministic YAML frontmatter parser for agentskills.io compliance checks."""
    if not md_text.startswith("---\n"):
        raise AssertionError("SKILL.md must begin with YAML frontmatter delimiter '---'")
    end_idx = md_text.find("\n---\n", 4)
    if end_idx == -1:
        raise AssertionError("SKILL.md frontmatter missing closing '---'")
    yaml_block = md_text[4:end_idx]
    body = md_text[end_idx + 5 :]

    parsed: dict[str, object] = {}
    current_map_key: str | None = None
    for raw_line in yaml_block.splitlines():
        if not raw_line.strip() or raw_line.strip().startswith("#"):
            continue
        if not raw_line.startswith(" "):
            current_map_key = None
            key, sep, val = raw_line.partition(":")
            if not sep:
                raise AssertionError(f"Invalid frontmatter line: {raw_line!r}")
            k = key.strip()
            v = val.strip()
            if not v:
                parsed[k] = {}
                current_map_key = k
            else:
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                parsed[k] = v
        else:
            if current_map_key is None or not isinstance(parsed.get(current_map_key), dict):
                raise AssertionError(f"Unexpected indented frontmatter line: {raw_line!r}")
            sub_k, sep, sub_v = raw_line.strip().partition(":")
            if not sep:
                raise AssertionError(f"Invalid nested metadata line: {raw_line!r}")
            sv = sub_v.strip()
            if (sv.startswith('"') and sv.endswith('"')) or (sv.startswith("'") and sv.endswith("'")):
                sv = sv[1:-1]
            parsed[current_map_key][sub_k.strip()] = sv  # type: ignore[index]
    return parsed, body


class TestSkillAndRepoSpecCompliance(unittest.TestCase):
    def test_skill_md_agentskills_io_compliance(self) -> None:
        skill_path = REPO_ROOT / "SKILL.md"
        self.assertTrue(skill_path.is_file(), "Root SKILL.md is required")
        text = skill_path.read_text(encoding="utf-8")
        lines = text.splitlines()
        self.assertLess(len(lines), 300, f"SKILL.md must be <300 lines (got {len(lines)})")

        fm, _ = _parse_simple_frontmatter(text)
        allowed_keys = {"name", "description", "license", "compatibility", "metadata"}
        self.assertEqual(
            set(fm.keys()),
            allowed_keys,
            msg=f"SKILL.md frontmatter must contain ONLY agentskills.io keys {allowed_keys}, got {set(fm.keys())}",
        )
        self.assertEqual(fm["name"], "monkey-paw")
        self.assertEqual(fm["license"], "MIT")

        desc = str(fm["description"])
        self.assertLessEqual(len(desc), 1024)
        first_200 = desc[:200].lower()
        # Purpose + natural-language triggers must both appear in first 200 characters
        self.assertIn("malicious compliance referee", first_200)
        self.assertTrue(
            any(trigger in first_200 for trigger in ("use when", "stress-test", "loopholes", "refine")),
            msg=f"Natural-language triggers missing from first 200 chars of description: {first_200!r}",
        )

        compat = str(fm["compatibility"])
        self.assertTrue(10 <= len(compat) <= 500)

        meta = fm["metadata"]
        self.assertIsInstance(meta, dict)
        assert isinstance(meta, dict)
        self.assertTrue(len(meta) >= 1)
        for mk, mv in meta.items():
            self.assertIsInstance(mk, str)
            self.assertIsInstance(mv, str)

        # Must contain zero hardcoded slash or dollar invocations
        slash_lock = "/" + "monkey-paw"
        dollar_lock = "$" + "monkey-paw"
        self.assertNotIn(slash_lock, text, "SKILL.md must not hardcode slash command invocations")
        self.assertNotIn(dollar_lock, text, "SKILL.md must not hardcode dollar command invocations")

    def test_portable_repo_files_and_no_vendor_lock_files(self) -> None:
        self.assertTrue((REPO_ROOT / "AGENTS.md").is_file())
        self.assertFalse((REPO_ROOT / "GEMINI.md").exists(), "Use AGENTS.md instead of GEMINI.md")
        self.assertFalse((REPO_ROOT / "CLAUDE.md").exists(), "Use AGENTS.md instead of CLAUDE.md")
        self.assertTrue((REPO_ROOT / "LICENSE").is_file())
        self.assertIn("MIT License", (REPO_ROOT / "LICENSE").read_text(encoding="utf-8"))

        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".monkey-paw/", gitignore)

    def test_python_scripts_use_stdlib_only(self) -> None:
        scripts_dir = REPO_ROOT / "scripts"
        studio_dir = REPO_ROOT / "studio"
        local_modules = (
            {p.stem for p in scripts_dir.glob("*.py")}
            | {p.stem for p in studio_dir.glob("*.py")}
            | {"scripts", "studio"}
        )
        stdlib_names = set(sys.stdlib_module_names) | {"__future__"}

        py_files = sorted(scripts_dir.glob("*.py")) + sorted(studio_dir.glob("*.py"))
        for py_file in py_files:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root_mod = alias.name.split(".")[0]
                        self.assertIn(
                            root_mod,
                            stdlib_names | local_modules,
                            msg=f"Non-stdlib import '{alias.name}' found in {py_file.name}",
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root_mod = node.module.split(".")[0]
                    self.assertIn(
                        root_mod,
                        stdlib_names | local_modules,
                        msg=f"Non-stdlib import '{node.module}' found in {py_file.name}",
                    )

    def test_zero_unfinished_markers_across_repository(self) -> None:
        marker_re = re.compile(r"\b(?:" + "TO" + "DO|" + "FIX" + "ME|" + "X" + "XX" + r")\b")
        checked = 0
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel.startswith((".git/", ".monkey-paw/")) or "__pycache__" in rel:
                continue
            text = path.read_text(encoding="utf-8")
            checked += 1
            match = marker_re.search(text)
            self.assertIsNone(match, msg=f"Unfinished placeholder '{match.group(0) if match else ''}' in {rel}")
        self.assertGreaterEqual(checked, 18)

    def test_readme_and_interactive_simulator_completeness(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("npx skills add", readme)
        self.assertIn("```mermaid", readme)
        self.assertIn("WHEN", readme)
        self.assertIn("THE SYSTEM SHALL", readme)
        for agent in (
            "Antigravity",
            "Claude Code",
            "Cursor",
            "Codex",
            "Copilot",
            "Windsurf",
            "Kiro",
            "Gemini CLI",
        ):
            self.assertIn(agent, readme, msg=f"README multi-agent table missing {agent}")

        banned_buzzwords = ("revolutionary", "paradigm-shifting", "synergy", "game-changer", "supercharge")
        for buzz in banned_buzzwords:
            self.assertNotIn(buzz, readme.lower(), msg=f"Buzzword {buzz!r} found in README.md")

        html_path = REPO_ROOT / "docs" / "index.html"
        self.assertTrue(html_path.is_file())
        html = html_path.read_text(encoding="utf-8")
        for ticket_title in ("SaaS Billing Pause", "Blind Bid Withdrawal", "Webhook Payout Retry"):
            self.assertIn(ticket_title, html)
        self.assertIn("PARKING-LOT.md", html)
        self.assertIn("THE SYSTEM SHALL", html)
        self.assertNotIn("<script src=", html.lower())


if __name__ == "__main__":
    unittest.main()
