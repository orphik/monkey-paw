---
name: monkey-paw
description: "Pre-code malicious compliance referee for specs, PRDs, and tickets. Use when asked to stress-test a spec, find loopholes, refine requirements, review a ticket, or pre-flight before coding. Scans brownfield repo surface read-only, exposes 3-5 literal-agent production exploits, deals Bilingual Decision Cards, parks tangents to PARKING-LOT.md, and compiles locked EARS, Spec-Kit, OpenSpec, or Jira specs."
license: MIT
compatibility: "Python 3.10+ standard library only (zero pip dependencies). Read-only on git/brownfield repos and greenfield folders across Antigravity, Claude Code, Cursor, Codex, Copilot, Windsurf, Kiro, and Gemini CLI."
metadata:
  version: "1.0.0"
  domain: "spec-driven-development"
  mode: "read-only-referee"
  author: "monkey-paw contributors"
---

# Monkey's Paw — Pre-Code Malicious Compliance Referee

Coding agents optimize for the shortest diff that satisfies the literal words of a prompt. Whenever a draft ticket or PRD leaves concurrency, partial-failure rollback, tenant auth, orphaned state, or batch blast radius implicit, a literal agent grants the wish like **The Monkey's Paw**: happy-path tests pass while production state corrupts.

Run this workflow **before writing application code** to lock an unambiguous specification in under 10 minutes.

## Hard Safety & Read-Only Invariants

1. **Never edit application source code** during this workflow.
2. **Scratch files** go strictly inside `.monkey-paw/` (for example, `.monkey-paw/surface.json` and `.monkey-paw/findings.json`).
3. **Final human-facing outputs** write only to `SPEC.md`, `PARKING-LOT.md`, or an explicit `--out` path requested by the user.
4. **Never read or emit secrets** (`.env*`, `*.pem`, `*.key`, credentials, or tokens).
5. Resolve `<SKILL_DIR>` below as the directory containing this `SKILL.md` file. Use `python3` (or `python` on Windows environments without a `python3` alias).

---

## 5-Step Referee Workflow

### Step 1: Deterministic Repo Surface Scan

Scan the target workspace read-only to ground every finding in real models, tables, enums, routes, auth guards, and background workers:

```bash
python3 "<SKILL_DIR>/scripts/extract_repo_surface.py" \
  --repo . \
  --out .monkey-paw/surface.json
```

Read `.monkey-paw/surface.json` and check `"mode"`:
- `"brownfield"`: Every finding you draft **must** cite concrete `path:line` or symbol touchpoints from `surface.json`. Align engineering options with the existing stack (do not propose foreign ORMs or message brokers).
- `"greenfield"`: Empty or non-code workspace (exits `0` cleanly). Set `"repo_citations": []` and focus on state-machine invariants, tenancy boundaries, and idempotency contracts.

### Step 2: Adversarial Audit (Monkey's Paw + Staff TPM)

Read [`references/loophole-taxonomy.md`](./references/loophole-taxonomy.md) for exploit patterns and [`references/export-formats.md`](./references/export-formats.md) for the exact JSON schema.

Adopt two paired roles:
- **The Monkey's Paw (Internal Adversary):** Identify the top **3 to 5** (hard cap `1..5`) ways a literal-minded, lazy coding agent could satisfy every word of the draft while breaking production across the six allowed `exploit_class` values:
  - `orphaned_state`
  - `partial_mutation`
  - `auth_boundary_leak`
  - `concurrency_race`
  - `blast_radius_scale`
  - `silent_fallback`
- **Staff TPM Referee (Facilitator):** Translate each exploit into two distinct, concrete engineering designs (`eng_options.option_a` vs. `eng_options.option_b`) paired with a jargon-free `pm_tradeoff` covering UX, latency, and delivery scope.

Write the candidate audit to `.monkey-paw/findings.json` and **gate it through the deterministic validator before showing anything to the user**:

```bash
python3 "<SKILL_DIR>/scripts/validate_findings.py" \
  --findings .monkey-paw/findings.json \
  --surface .monkey-paw/surface.json
```

If `validate_findings.py` exits non-zero (missing citations, invalid enum, count outside `1..5`, or generic filler such as *"add proper error handling"*), rewrite `.monkey-paw/findings.json` and re-run until validation passes with zero errors.

### Step 3: Deal Bounded Bilingual Decision Cards

Read [`references/facilitation-protocol.md`](./references/facilitation-protocol.md) and render the validated findings using [`assets/decision-card.template.md`](./assets/decision-card.template.md).

Facilitation rules:
- Present all 3–5 cards cleanly so a PM or tech lead can reply in shorthand (for example, `"MP-001: A, MP-002: B, MP-003: A"` or `"MP-002: custom — cap support refunds at $100"`).
- Keep Engineering mechanics (`option_a` / `option_b`) concrete: name exact locks, HTTP status codes, RBAC roles, idempotency keys, or queue bounds.
- Keep Product trade-offs (`pm_tradeoff`) free of database/ORM jargon: explain what the user sees on screen, how fast it responds, and how much scope it adds.

### Step 4: Operate the Tangent Trap (`PARKING-LOT.md`)

Whenever the user or a stakeholder raises off-scope refactoring, Phase-2 features, or unrelated tech debt during refinement, do **not** let the thread derail. Immediately park it via `park_tangent.py`:

```bash
python3 "<SKILL_DIR>/scripts/park_tangent.py" \
  --item "<concise summary of off-scope item>" \
  --category <phase-2|tech-debt|ux-polish|infra|open-question> \
  --reason "<why deferred or trigger to revisit>" \
  --spec "<draft title>" \
  --out PARKING-LOT.md
```

Confirm the assigned `PL-NNN` ID in one sentence (see [`assets/parking-lot.template.md`](./assets/parking-lot.template.md)) and return focus immediately to any remaining unresolved Decision Cards.

### Step 5: Lock Resolutions & Compile Specification

Once every finding has a human decision:
1. Update each finding in `.monkey-paw/findings.json` with a `"resolution"` block:
   ```json
   "resolution": {
     "selected": "option_a",
     "rationale": "Desktop workflow favors immediate 409 lock conflict over extra table.",
     "ears_clauses": [
       "WHEN POST /v1/charges/{charge_id}/refund is called, THE SYSTEM SHALL acquire a FOR UPDATE NOWAIT lock on charges before checking refundable balance."
     ]
   }
   ```
   *(Use `"selected": "custom"` plus `"custom_design": "..."` when the user specifies a hybrid or custom constraint.)*
2. Re-verify with `--require-resolved`:
   ```bash
   python3 "<SKILL_DIR>/scripts/validate_findings.py" \
     --findings .monkey-paw/findings.json \
     --surface .monkey-paw/surface.json \
     --require-resolved
   ```
3. Compile the locked specification into the user's preferred format (`ears`, `spec-kit`, `openspec`, or `jira`; default `ears`):
   ```bash
   python3 "<SKILL_DIR>/scripts/compile_locked_spec.py" \
     --draft <path_to_draft_file> \
     --findings .monkey-paw/findings.json \
     --surface .monkey-paw/surface.json \
     --format ears \
     --out SPEC.md
   ```
   *(If the user pasted the draft inline in chat rather than referencing a file, save the raw text to `.monkey-paw/draft.md` first and pass `--draft .monkey-paw/draft.md`.)*

---

## Reference & Example Index

- **Exploit classes & anti-slop rules:** [`references/loophole-taxonomy.md`](./references/loophole-taxonomy.md)
- **JSON schema & export formats:** [`references/export-formats.md`](./references/export-formats.md)
- **<10-minute facilitation & Tangent Trap:** [`references/facilitation-protocol.md`](./references/facilitation-protocol.md)
- **End-to-end sample fixture:** [`assets/examples/sample-fintech-refund/`](./assets/examples/sample-fintech-refund/) (`raw-ticket.md` -> `findings.json` -> `SPEC.md`)
