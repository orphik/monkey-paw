# Findings Schema & Locked Specification Export Formats

This reference defines the JSON contract validated by `scripts/validate_findings.py` and the four markdown specification targets produced by `scripts/compile_locked_spec.py`.

---

## 1. Findings JSON Contract (`.monkey-paw/findings.json`)

```json
{
  "schema_version": "1.0",
  "mode": "brownfield",
  "draft_title": "Merchant Dashboard — Self-Serve Charge Refunds",
  "findings": [
    {
      "id": "MP-001",
      "title": "Double-Refund Race on Concurrent Clicks",
      "exploit_class": "concurrency_race",
      "spec_quote": "Allow merchants to issue full or partial refunds up to the charge amount.",
      "monkeys_paw_grant": "Agent checks `charge.refunded_cents + amount <= charge.amount_cents` in application memory before calling Stripe; two concurrent POST requests both pass the check and refund 200% of the original payment.",
      "repo_citations": [
        "app/models/payment.py:18",
        "app/api/routes/charges.py:64"
      ],
      "eng_options": {
        "option_a": {
          "label": "Pessimistic Row Lock + SQL Check",
          "design": "Acquire `SELECT ... FOR UPDATE NOWAIT` on `charges` row inside transaction and enforce `CHECK (refunded_cents <= amount_cents)` before issuing deterministic Stripe idempotency key."
        },
        "option_b": {
          "label": "Client Idempotency Key + Optimistic Version CAS",
          "design": "Require `Idempotency-Key` request header persisted in `idempotency_keys` table and execute atomic conditional `UPDATE charges SET refunded_cents = refunded_cents + :amt, version = version + 1 WHERE id = :id AND version = :ver AND refunded_cents + :amt <= amount_cents`."
        }
      },
      "pm_tradeoff": "Option A rejects simultaneous clicks immediately with a clear 'Refund already in progress' toast (<15ms DB lock, smaller scope). Option B transparently deduplicates retries across flaky mobile networks (+1 migration table).",
      "resolution": {
        "selected": "option_a",
        "rationale": "Internal dashboard users are on stable desktop connections; fast lock fail + Stripe idempotency key ships in half a day.",
        "ears_clauses": [
          "WHEN a POST /v1/charges/{charge_id}/refunds request is received, THE SYSTEM SHALL acquire a row-level `FOR UPDATE NOWAIT` lock on the target `charges` record before evaluating `refunded_cents + request_amount_cents <= amount_cents`.",
          "IF a concurrent lock is already held on the target `charges` record, THEN THE SYSTEM SHALL return HTTP 409 Conflict without invoking the Stripe Refunds API."
        ]
      }
    }
  ]
}
```

### Field Invariants
- **`findings` length:** `1 <= len(findings) <= 5`.
- **`exploit_class`:** Strictly one of `orphaned_state`, `partial_mutation`, `auth_boundary_leak`, `concurrency_race`, `blast_radius_scale`, `silent_fallback`.
- **`repo_citations`:** Must be a non-empty list of file/symbol references when `mode == "brownfield"`. May be `[]` only when `mode == "greenfield"`.
- **`eng_options`:** `option_a` and `option_b` may be either `{ "label": "...", "design": "..." }` objects or plain strings (`>= 15` chars), and must be distinct.
- **`resolution`:** Added once the human locks choices during the Decision Card session (`selected`: `"option_a"`, `"option_b"`, or `"custom"` with `custom_design`). Required before calling `compile_locked_spec.py`.

---

## 2. Export Format Targets (`compile_locked_spec.py --format`)

### A. `ears` (Easy Approach to Requirements Syntax — Default)
Transforms ambiguous prose into deterministic, testable RFC 2119 + EARS clauses:
- **Event-Driven:** `WHEN <trigger>, THE SYSTEM SHALL <system response>.`
- **Unwanted Behavior:** `IF <precondition / failure>, THEN THE SYSTEM SHALL <mitigation>.`
- **State-Driven:** `WHILE <system state>, THE SYSTEM SHALL <constraint>.`

Best for feeding directly into coding agents as a root `SPEC.md` implementation contract.

### B. `spec-kit` (GitHub Spec-Kit `spec.md`)
Follows the Spec-Kit specification layout (`Purpose`, `User Journeys & Failure-Boundary Scenarios`, `Requirements`, `Architectural Decisions & Rejected Alternatives`, `Acceptance Criteria`). Drop directly into `specs/<NNN>-<feature>/spec.md` prior to plan/task generation.

### C. `openspec` (OpenSpec Delta Specification)
Emits `# Spec Delta: <Title>` with `## ADDED Requirements`, `### Requirement MP-00X`, formal `SHALL` statements, and structured `- **Scenario:**` (`GIVEN` / `WHEN` / `THEN` / `AND`) blocks ready for `openspec/changes/<change>/specs/`.

### D. `jira` (Jira / Linear Ticket Markdown)
Emits a compact summary table of locked engineering choices + PM trade-offs, a `- [ ]` checkbox list with inline file citations, brownfield codebase touchpoints, and deferred `PARKING-LOT.md` items ready to paste into an issue tracker.
