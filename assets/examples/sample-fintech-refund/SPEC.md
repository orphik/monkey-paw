# Locked Specification (EARS): Merchant Dashboard: Self-Serve Customer Refunds

> **Status:** LOCKED · **Mode:** `brownfield` · **Resolved Guardrails:** 4

## 1. Original Draft Baseline

```text
# Merchant Dashboard: Self-Serve Customer Refunds

We're getting too many Zendesk tickets asking support to refund accidental or disputed orders.

Add a "Refund Payment" button on the Charge Details page (`POST /v1/charges/{charge_id}/refund`) in the Merchant Dashboard so merchants and support agents can issue full or partial refunds via Stripe, update the order status to `REFUNDED`, and send the customer a confirmation email. Make sure we don't refund more than the original charge.
```

## 2. Locked EARS Requirements

### [MP-001] Double-Refund Race on Concurrent Requests (`concurrency_race`)

- **Ambiguous Draft Trigger:** "Make sure we don't refund more than the original charge."
- **Blocked Monkey's Paw Exploit:** A literal agent reads `charge.refunded_cents` in Python memory, checks `refunded_cents + request.amount_cents <= amount_cents`, calls Stripe, and writes back. Double-clicking the Refund button or parallel tabs both pass the read check at t=0ms and issue two Stripe refunds totaling 200% of the payment.
- **Locked Engineering Choice — Option A (Pessimistic Row Lock + SQL Check Constraint):** Acquire `SELECT ... FOR UPDATE NOWAIT` on `charges` inside a DB transaction, enforce `CHECK (refunded_cents <= amount_cents)` on `charges`, and derive a deterministic Stripe idempotency key from `(charge_id, refund_seq)`.
- **Product / PM Trade-off Accepted:** Option A blocks simultaneous double-clicks immediately with a clear 'Refund already in progress' banner and zero extra UI state (ships 1 day faster). Option B silently replays the same receipt on network retries without error banners (+1 schema table).
- **Repo Surface Citations:** `services/billing/models/charge.py:29`, `services/billing/api/charges.py:88`

- **Requirement:** WHEN `POST /v1/charges/{charge_id}/refund` is invoked, THE SYSTEM SHALL acquire a `SELECT ... FOR UPDATE NOWAIT` lock on `charges` before evaluating `refunded_cents + refund_amount_cents <= amount_cents`.
- **Requirement:** IF a concurrent transaction holds the row lock on `charges` or `refunded_cents + refund_amount_cents > amount_cents`, THEN THE SYSTEM SHALL abort before calling Stripe and return HTTP 409 Conflict or HTTP 422 Unprocessable Entity respectively.

### [MP-002] Split-Brain Ledger When DB Commit Fails Post-Stripe Refund (`partial_mutation`)

- **Ambiguous Draft Trigger:** "issue full or partial refunds via Stripe, update the order status to `REFUNDED`, and send the customer a confirmation email."
- **Blocked Monkey's Paw Exploit:** Agent calls `stripe.Refund.create()` synchronously inside the route handler, then updates `Order.status = 'REFUNDED'` and calls SendGrid. First, a partial refund wrongly marks the entire order `REFUNDED`; second, if Postgres or SendGrid times out after Stripe succeeds, money leaves the platform while the ledger still shows `PAID`.
- **Locked Engineering Choice — Option A (Two-Phase RefundAttempt Ledger + Webhook Reconciliation):** Commit a `refund_attempts` row (`status='PENDING'`) with deterministic key `refund:{attempt_id}` before calling Stripe; transition order to `PARTIALLY_REFUNDED` when `0 < refunded_cents < amount_cents` and `REFUNDED` only at full amount; enqueue email via worker on `charge.refunded`.
- **Product / PM Trade-off Accepted:** Option A gives the merchant an instant confirmed/failed receipt in ~600ms while distinguishing 'Partially Refunded' from 'Refunded'. Option B returns a 'Processing refund...' spinner for 2-5 seconds and requires polling on the Charge Details page.
- **Repo Surface Citations:** `services/billing/models/order.py:44`, `services/billing/workers/stripe_webhooks.py:112`, `services/notifications/mailer.py:19`

- **Requirement:** WHEN a refund request passes validation, THE SYSTEM SHALL persist a `refund_attempts` record in `PENDING` status prior to invoking `stripe.Refund.create(idempotency_key=attempt_id)`.
- **Requirement:** WHEN `refunded_cents` is greater than `0` and less than `amount_cents`, THE SYSTEM SHALL set `Order.status` to `PARTIALLY_REFUNDED`, transitioning `Order.status` to `REFUNDED` only when `refunded_cents == amount_cents`.
- **Requirement:** WHEN the `refund_attempts` record transitions to `SUCCEEDED` (synchronously or via `charge.refunded` webhook), THE SYSTEM SHALL enqueue the customer confirmation email asynchronously so SMTP latency cannot roll back ledger persistence.

### [MP-003] Cross-Merchant IDOR and Uncapped Support Agent Refunds (`auth_boundary_leak`)

- **Ambiguous Draft Trigger:** "Add a 'Refund Payment' button on the Charge Details page (`POST /v1/charges/{charge_id}/refund`) in the Merchant Dashboard so merchants and support agents can issue full or partial refunds"
- **Blocked Monkey's Paw Exploit:** Agent attaches generic `Depends(get_current_user)` and fetches `Charge.by_id(charge_id)`. Any authenticated merchant viewer can guess or enumerate `charge_id` values belonging to other merchants, and tier-1 support contractors can drain `$50,000` enterprise charges unilaterally.
- **Locked Engineering Choice — Option A (Strict Tenant Scoping + Owner/Finance RBAC Gate):** Scope charge lookup by `(id = :charge_id AND merchant_id = :actor.merchant_id)` for merchant tokens (returning 404 on mismatch), restrict merchant roles to `MERCHANT_OWNER` / `MERCHANT_FINANCE`, and cap `INTERNAL_SUPPORT` single-charge refunds at `$250` with audit log actor recording.
- **Product / PM Trade-off Accepted:** Option A ships immediately: support resolves 95% of everyday tickets (<=$250) in one click and escalates high-value refunds to Finance. Option B adds an approval inbox UI (+3 days engineering scope).
- **Repo Surface Citations:** `services/auth/dependencies.py:37`, `services/auth/enums.py:12`, `services/billing/api/charges.py:88`

- **Requirement:** WHEN a merchant-scoped caller invokes `POST /v1/charges/{charge_id}/refund`, THE SYSTEM SHALL filter the target charge by `id = charge_id AND merchant_id = caller.merchant_id` and require role `MERCHANT_OWNER` or `MERCHANT_FINANCE`, returning HTTP 404 on tenant mismatch and HTTP 403 on insufficient role.
- **Requirement:** WHEN a caller with role `INTERNAL_SUPPORT` requests a refund exceeding `25000` cents ($250.00), THE SYSTEM SHALL reject the request with HTTP 403 Forbidden and record the blocked attempt in `audit_events`.

### [MP-004] Refunded Subscription Charge Leaves Paid Entitlements Active (`orphaned_state`)

- **Ambiguous Draft Trigger:** "update the order status to `REFUNDED`, and send the customer a confirmation email."
- **Blocked Monkey's Paw Exploit:** Agent updates `orders.status = 'REFUNDED'` while leaving the linked `entitlements` cache and `api_quotas` row active until next year's renewal—allowing users to buy an annual plan, claim an immediate full refund, and retain paid Pro seats for 12 months.
- **Locked Engineering Choice — Option B (Explicit `revoke_access` Boolean Toggle on Refund Request):** Add required `revoke_entitlements: bool` field to `RefundRequestSchema` (default `true` for full refunds, `false` for partial refunds) so operators explicitly choose whether goodwill credit keeps access active.
- **Product / PM Trade-off Accepted:** Option A has zero extra form clutter—full refunds revoke paid seats automatically while partial refunds keep the customer active. Option B adds a checkbox to the Refund modal so support can grant a 100% outage refund without cutting off access.
- **Repo Surface Citations:** `services/entitlements/models.py:21`, `services/entitlements/cache.py:53`

- **Requirement:** WHEN `POST /v1/charges/{charge_id}/refund` is submitted, THE SYSTEM SHALL accept an explicit `revoke_entitlements` boolean (defaulting to `true` when `refund_amount_cents == remaining_refundable_cents` and `false` otherwise).
- **Requirement:** WHEN a refund succeeds with `revoke_entitlements == true`, THE SYSTEM SHALL set linked `entitlements.status = 'REVOKED_REFUND'` and evict the tenant's cached entitlement entry within the same workflow.

## 3. Decision Traceability Matrix

| ID | Exploit Class | Locked Option | Cited Touchpoints |
| :--- | :--- | :--- | :--- |
| `MP-001` | `concurrency_race` | Option A (Pessimistic Row Lock + SQL Check Constraint) | `services/billing/models/charge.py:29`, `services/billing/api/charges.py:88` |
| `MP-002` | `partial_mutation` | Option A (Two-Phase RefundAttempt Ledger + Webhook Reconciliation) | `services/billing/models/order.py:44`, `services/billing/workers/stripe_webhooks.py:112`, `services/notifications/mailer.py:19` |
| `MP-003` | `auth_boundary_leak` | Option A (Strict Tenant Scoping + Owner/Finance RBAC Gate) | `services/auth/dependencies.py:37`, `services/auth/enums.py:12`, `services/billing/api/charges.py:88` |
| `MP-004` | `orphaned_state` | Option B (Explicit `revoke_access` Boolean Toggle on Refund Request) | `services/entitlements/models.py:21`, `services/entitlements/cache.py:53` |
