# Malicious Compliance Loophole Taxonomy

When an AI coding agent or time-pressed engineer implements a specification, they optimize for the shortest diff that satisfies the literal prompt text and passes happy-path tests. Every omitted invariant becomes an invitation for **The Monkey's Paw**: the request is technically granted, and production breaks at 2:00 AM.

`monkey-paw` restricts every finding's `exploit_class` to six orthogonal production failure classes enforced by `scripts/validate_findings.py`.

---

## 1. `orphaned_state`

### Mechanism
A parent record is soft-deleted, paused, canceled, or downgraded, while dependent state—scheduled cron jobs, active sessions, API keys, webhook subscriptions, escrow holds, cache keys, or child entitlements—remains live.

### Brownfield Surface Clues
- Foreign keys without `ON DELETE CASCADE` or explicit lifecycle hooks (`models`).
- Background queues/workers (`workers`) scheduled ahead of time by entity ID without re-checking parent status at execution time.
- Dual-store state (Postgres status column + Redis session/entitlement cache).

### Example Monkey's Paw Exploit
- **Draft Quote:** *"Allow workspace owners to pause their subscription for up to 90 days."*
- **Monkey's Paw Grant:** Agent sets `Subscription.status = 'PAUSED'` and hides the web dashboard, but leaves existing `ApiKey` records active and `BullMQ` scheduled export workers firing hourly—allowing paused customers to consume compute and egress for 90 days at `$0`.

### Canonical A/B Engineering Options
- **Option A (Execution-Time Guard):** Keep child jobs/keys intact in storage so resuming is instant, but enforce `subscription.status == 'ACTIVE'` inside `api_key_auth` middleware and worker entrypoints (returning `402 Payment Required` / skipping job run).
- **Option B (Explicit Teardown + Re-hydration):** Revoke active session tokens, cancel queued BullMQ repeatable jobs on pause, and re-register schedules upon resume.

---

## 2. `partial_mutation`

### Mechanism
An operation mutates state across two or more failure domains (e.g., local SQL database + Stripe API + S3 object + outbound webhook/email) sequentially without idempotency keys, transactional outbox, or compensating rollback. A network timeout mid-flight leaves split-brain state.

### Brownfield Surface Clues
- Route handlers (`routes`) calling third-party SDKs (`stripe`, `sendgrid`, `boto3`, HTTP `fetch`) alongside ORM `session.commit()` / `prisma.$transaction`.
- Missing state-machine intermediate statuses (`PENDING_EXTERNAL`, `FAILED_RECONCILIATION`).

### Example Monkey's Paw Exploit
- **Draft Quote:** *"Refund the charge in Stripe and mark the order as refunded in our database."*
- **Monkey's Paw Grant:** Agent calls `stripe.refunds.create(charge=ch_id)` first and then runs `db.commit()`. When Postgres hits a connection pool timeout after Stripe succeeds, the customer receives real money back while the internal ledger still shows `PAID`, allowing a second support agent to click Refund again.

### Canonical A/B Engineering Options
- **Option A (Two-Phase Ledger State + Deterministic Idempotency Key):** Persist a `RefundAttempt` row in `PENDING` state inside a DB transaction first; call Stripe using `idempotency_key=f"refund:{refund_attempt.id}"`; finalize status via both synchronous response and `charge.refunded` webhook reconciliation.
- **Option B (Transactional Outbox Worker):** Commit `REFUND_REQUESTED` + outbox row atomically in Postgres and return `202 Accepted`; execute the Stripe refund asynchronously via retryable worker with dead-letter alerting.

---

## 3. `auth_boundary_leak`

### Mechanism
An endpoint or mutation authenticates *who* the caller is (`is_logged_in`), but fails to verify tenant ownership (IDOR), role ceiling (member vs. billing owner, read-only support vs. finance admin), or row-level scoping.

### Brownfield Surface Clues
- `auth` guards that only return `current_user` (`Depends(get_current_user)`, `requireAuth`) without checking `organization_id` / `merchant_id` or role enums (`enums`).
- Routes accepting raw resource UUIDs/integers (`POST /api/charges/{charge_id}/refund`) where queries filter by `id = :charge_id` alone.

### Example Monkey's Paw Exploit
- **Draft Quote:** *"Add `POST /v1/refunds` so logged-in dashboard users can refund a payment by `charge_id`."*
- **Monkey's Paw Grant:** Agent adds `Depends(get_current_user)` and looks up `Charge.get(charge_id)` without constraining `Charge.merchant_id == current_user.merchant_id` or checking `current_user.role in ('OWNER', 'FINANCE_ADMIN')`—letting any read-only viewer or external merchant refund arbitrary charges across tenants.

### Canonical A/B Engineering Options
- **Option A (Tenant-Scoped Query + Role Decorator):** Enforce `WHERE id = :charge_id AND merchant_id = :actor_merchant_id` in the repository query (returning `404` on cross-tenant mismatch) and restrict access to `OWNER` / `FINANCE_ADMIN` roles.
- **Option B (Tiered Threshold + Dual Approval):** Scope queries by `merchant_id`, allow `SUPPORT_AGENT` immediate refunds up to a configurable cap (e.g., `$100`), and route larger refunds into a `PENDING_APPROVAL` queue requiring `FINANCE_ADMIN` sign-off.

---

## 4. `concurrency_race`

### Mechanism
Check-then-act logic (`SELECT` balance/clock/status in application memory, then `UPDATE`/`INSERT`) executes without row-level locking (`SELECT ... FOR UPDATE`), optimistic version comparison (`WHERE version = :expected`), or unique database constraints—failing under double-clicks, parallel retries, or clock boundaries.

### Brownfield Surface Clues
- Financial balances, inventory counts, auction bids, coupon redemptions, or state-transition columns in `models` lacking `UNIQUE` partial indexes or version columns.
- Webhook endpoints (`routes`) and retry workers (`workers`) capable of processing the same event concurrently.

### Example Monkey's Paw Exploit
- **Draft Quote:** *"Prevent refunding more than the original charge amount."*
- **Monkey's Paw Grant:** Agent reads `if charge.refunded_cents + req.amount_cents <= charge.amount_cents:` in Python, calls Stripe, and increments `charge.refunded_cents`. Two parallel browser tabs pass the `if` check simultaneously at `t=0ms` and issue a 200% double refund.

### Canonical A/B Engineering Options
- **Option A (Pessimistic Row Lock + DB Check Constraint):** Acquire `SELECT ... FOR UPDATE NOWAIT` on the `charges` row before computing remaining refundable balance, backed by `CHECK (refunded_cents <= amount_cents)` in SQL.
- **Option B (Optimistic CAS + Client Idempotency Header):** Require an `Idempotency-Key` header stored in a unique table and execute `UPDATE charges SET refunded_cents = refunded_cents + :amt, version = version + 1 WHERE id = :id AND version = :v AND refunded_cents + :amt <= amount_cents`.

---

## 5. `blast_radius_scale`

### Mechanism
Phrases like *"for all matching records"*, *"export history"*, *"retry failed payouts"*, or *"notify followers"* are implemented as synchronous `O(N)` loops inside an HTTP request cycle, unbounded `SELECT *` queries, or unthrottled downstream API bursts.

### Brownfield Surface Clues
- Batch endpoints in `routes` when async workers (`workers`) already exist in the repo.
- Missing pagination cursors, rate-limit buckets, or chunked worker fan-out patterns.

### Example Monkey's Paw Exploit
- **Draft Quote:** *"Add a 'Retry Failed Payouts' button for operations."*
- **Monkey's Paw Grant:** Agent runs `SELECT * FROM payouts WHERE status = 'FAILED'` and loops `for p in payouts: bank_api.transfer(p)` inside `POST /admin/payouts/retry`. After an upstream bank outage leaves 8,000 failed rows, clicking the button blocks the web worker, times out the load balancer at 30s after 412 transfers, and invites the operator to click Retry again.

### Canonical A/B Engineering Options
- **Option A (Bounded Sync Batch Cap):** Restrict synchronous execution to explicit selection (`<= 50` payout IDs per request) with deterministic HTTP `413` rejection above the cap.
- **Option B (Chunked Async Job + Rate-Limited Worker):** Create a `BatchRetryJob` record, enqueue cursor-paginated chunks of 100 IDs onto the background worker queue throttled to downstream RPS limits, and expose progress polling.

---

## 6. `silent_fallback`

### Mechanism
Upstream errors, `429 Too Many Requests`, null fields, stale caches, or schema mismatches are caught with broad `try/except` or default fallbacks (`or 0`, `?? false`, returning HTTP `200 OK`), hiding data loss or billing failures behind green status codes.

### Brownfield Surface Clues
- Webhook handlers, pricing calculators, permission checks, or scheduled renewal tasks where exceptions or missing fields could default to permissive or destructive outcomes.

### Example Monkey's Paw Exploit
- **Draft Quote:** *"Automatically resume paused subscriptions after 90 days and charge the customer's card."*
- **Monkey's Paw Grant:** Agent catches Stripe `CardError` during the day-90 cron job, logs a warning, and still flips `Subscription.status = 'ACTIVE'` (free service forever) *or* immediately hard-deletes the workspace on transient network failure.

### Canonical A/B Engineering Options
- **Option A (Explicit Dunning State):** On payment failure at auto-resume, transition subscription to `PAST_DUE` (keeping workspace read-only), emit customer payment-update notification, and schedule 3 bounded retries over 7 days before `CANCELED`.
- **Option B (Pre-Resume Authorization Hold / Strict Fail-Closed):** Run card check 48h prior; if resume charge fails at day 90, keep workspace in `PAUSED_PAYMENT_REQUIRED` without restoring paid compute quotas until manual payment succeeds.

---

## Anti-Slop Rejection Rules

`scripts/validate_findings.py` deterministically rejects vague filler disguised as architectural options. Never write:
- *"Add proper error handling"* -> Specify exact HTTP status code, rollback state, retry backoff, or dead-letter queue.
- *"Implement appropriate input validation"* -> Name the exact schema/model, field invariant, and rejection contract.
- *"Follow security best practices"* -> Name the exact tenant predicate, RBAC role enum, or row lock.
