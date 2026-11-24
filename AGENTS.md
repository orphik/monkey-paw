# AGENTS.md — Repository & Cross-Agent Rules

This repository implements **`monkey-paw`**, a portable, zero-dependency pre-code specification referee packaged under the open [`agentskills.io`](https://agentskills.io) specification.

`AGENTS.md` is used intentionally instead of vendor-specific rule filenames so identical constraints apply across Antigravity, Claude Code, Cursor, Codex, GitHub Copilot, Windsurf, Kiro, and Gemini CLI.

---

## 1. Non-Negotiable Architecture Constraints

1. **Python 3.10+ Standard Library Only:**
   - Every module in `scripts/` and `tests/` must import exclusively from Python's built-in standard library (`sys.stdlib_module_names` plus local `scripts/` siblings).
   - Zero `pip` packages, zero `pyproject.toml` runtime dependencies, zero `PyYAML` or `pydantic` imports.
2. **Read-Only Referee Guarantee:**
   - When `monkey-paw` runs against a target codebase, it must **never** create, modify, or delete application source files.
   - Ephemeral scan/audit artifacts belong strictly inside `.monkey-paw/` (gitignored).
   - User-visible specification outputs write only to `SPEC.md`, `PARKING-LOT.md`, or an explicit `--out` argument.
3. **Secret-Zero Surface Scanning:**
   - `scripts/extract_repo_surface.py` must reject `.env*`, `*.pem`, `*.key`, `*.p12`, `id_rsa*`, `*credentials*.json`, `*service-account*.json`, `.npmrc`, `.pypirc`, and `.netrc` **before** opening the file descriptor, and must scrub inline token patterns (`sk-...`, `AKIA...`, `ghp_...`, PEM headers, credentialed URIs) before emitting JSON.
4. **Portability & Frontmatter Hygiene:**
   - Root `SKILL.md` must stay under 300 lines, use only standard `agentskills.io` frontmatter (`name`, `description`, `license`, `compatibility`, `metadata`), place purpose and natural-language trigger phrases within the first 200 characters of `description`, and contain zero hardcoded slash or dollar invocations.

---

## 2. Repository Map

- `SKILL.md` — Portable agent runbook discovered by `npx skills add orphik/monkey-paw`.
- `scripts/extract_repo_surface.py` — Polyglot AST/regex scanner (`models`, `enums`, `routes`, `auth`, `workers`, `entrypoints`) -> `.monkey-paw/surface.json`.
- `scripts/validate_findings.py` — Enforces `1..5` findings cap, 6 `exploit_class` enums, brownfield `repo_citations`, distinct A/B options, and anti-filler rejection.
- `scripts/compile_locked_spec.py` — Compiles resolved findings + draft into `ears`, `spec-kit`, `openspec`, or `jira` markdown.
- `scripts/park_tangent.py` — Appends deferred scope tangents (`PL-001`, `PL-002`, ...) to `PARKING-LOT.md`.
- `scripts/mcp_stdio_server.py` — Zero-dependency JSON-RPC 2.0 `stdio` MCP server exposing all four tools.
- `references/` — Progressive-disclosure manuals (`loophole-taxonomy.md`, `export-formats.md`, `facilitation-protocol.md`).
- `assets/` — Card/parking-lot templates and `examples/sample-fintech-refund/` end-to-end fixture.
- `studio/` — Zero-dependency web service (`python3 -m studio` / Railway Docker) for PRD ingestion, ephemeral GitHub scanning, inline-editable Epic/Capability/Feature/User Story hierarchies, and Jira CSV exports.
- `docs/index.html` — Single-file offline-capable GitHub Pages simulator (zero API keys).
- `docs/USER-GUIDE.md` — End-to-end guide for Product Owners, TPMs, and Engineers.
- `tests/` — `unittest` suite covering surface scanning, secret redaction, validator rules, compiler formats, MCP framing, Studio HTTP service, and `agentskills.io` spec compliance.

---

## 3. Verification Commands

Run the full test suite before committing any change to `monkey-paw`:

```bash
python3 -m unittest discover -s tests -v
```

Smoke-test the CLI pipeline against the bundled fintech fixture:

```bash
python3 scripts/validate_findings.py --findings assets/examples/sample-fintech-refund/findings.json --require-resolved
python3 scripts/compile_locked_spec.py --draft assets/examples/sample-fintech-refund/raw-ticket.md --findings assets/examples/sample-fintech-refund/findings.json --format ears --out -
```
