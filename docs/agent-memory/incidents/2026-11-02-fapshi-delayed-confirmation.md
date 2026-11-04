# Fapshi delayed confirmation and recovery

Status: permanent repair implemented and tested locally; not deployed. Dennis separately authorized immediate recovery of the reported customer, completed through the existing deployed confirmation workflow as described below.

## Incident evidence and limits

The production investigation found authoritative provider SUCCESSFUL transactions that remained locally PENDING after the last browser poll. Transaction 130 confirmed 65 seconds after its last poll. The customer later received a voucher, so replaying that transaction against today's plan would be unsafe. Transaction 143 is a separately receipt-matched delayed confirmation with no linked customer-payment ledger at the investigation time. Production source matched integration commit 803492544d54b3a2f33564618c47ba4d27b36204.

Provider status metadata returned webhook:null when checked. The integration's initial 31 August 2026 commit already documented manual webhook configuration in PAYMENT_METHODS_API.md. Source history and current provider status metadata do not establish whether a callback URL was previously configured or removed; dashboard configuration history was unavailable. [Fapshi states callbacks are not retried](https://docs.fapshi.com/en/api-reference/endpoint/webhook), and recommends periodic status checks. The old code depended on a callback or an open browser and had no durable status recheck.

## Changed behavior

New purchases persist their service terms, reseller/customer/router identity, baseline entitlement and last completed ledger before Direct Pay. Payer identity is separate from the device receiving access. Cosmetic plan labels do not invalidate a purchase; price, duration, speed, connection type, FUP/sharing terms and router eligibility do.

A 30-second scheduler and both notification/poll adapters share a persisted lease. Queries are at least 15 seconds apart per transaction, below the provider's 6/minute limit, and back off to 15 minutes. A batch takes at most 10 due rows and stops starting work after 45 seconds; an in-flight call can finish beyond that budget. Expired process leases recover after 5 minutes. Unresolved confirmation or delivery retries enter an explicit review hold after 7 days or 720 checks. A review hold keeps provider and local fulfillment states separate; it does not invent a failed provider result.

Exact provider transaction ID, external ID, collection type, finite amount and returned customer ID must match. SUCCESSFUL is committed only with one ledger row, the exact minute/hour/day entitlement and a durable customer_payment provisioning attempt. That transaction performs no provider or RouterOS I/O. Nested renewal DB failures roll everything back; FUP restoration happens after commit. A failed/expired attempt never revokes a later entitlement.

Fapshi owns retries for its linked attempts and revalidates the target, purchased plan, expiry and latest ledger before delivery and after RouterOS completion. It uses existing provisioning functions and their persisted result handling. Its manual_transaction_provision entrypoint intentionally uses direct delivery instead of the check-in-only deferral experiment; generic hotspot/PPPoE retry workers exclude these attempts. A delivery failure retries without crediting or querying the provider again.

A Direct Pay timeout or ambiguous provider failure retains the provisional row and external ID, blocks another prompt and requires review. There is no automatic initiation retry. A fast authoritative callback that commits before the initiation response times out wins: the caller returns that accepted transaction instead of restoring the old customer state. Fapshi offers no idempotency keys and does not guarantee externalId uniqueness; any manual uncertain-initiation recovery must search the provider's customer transaction history and match the exact correlation and amount before attaching an ID or considering another prompt. This patch does not implement that manual lookup workflow.

## Public polling contract

The existing /api/hotspot/payment-status/{customerId} response adds payment_status, payment_review_required and payment_fulfillment_status for the latest Fapshi attempt. No new credential/provider-ID fields are added there. A provider success held before atomic credit remains locally pending. Fulfillment is pending, delivered or review_required; stale linked fulfillment is suppressed when a later ledger/expiry/target supersedes it. Customer access status remains independent so a later valid voucher remains usable.

Delivered means provisioning accepted the configuration, not proof of customer internet. Existing online verification remains separate. RADIUS completion is database-backed credential provisioning. Static-IP payment credit is preserved but delivery enters static_delivery_requires_review; this repair does not claim a safe static delivery/target retry contract. Existing independent static enforcement is unchanged.

## Deployment and legacy recovery boundary

The idempotent run_payment_method_migrations startup path adds the queue/snapshot/ledger-link columns and indexes. Existing rows keep NULL snapshots. Test coverage executes the actual migration twice against a legacy table. Deploy backend schema/service and the companion portal pending-confirmation UI together after review. The portal must not encourage a second charge when confirmation is pending or unknown.

Legacy transactions will not automatically heal after deployment. No purchase terms are guessed or backfilled. A separately authorized recovery requires a fresh bounded preflight of the exact provider payment, customer, owner, router, purchased plan, amount and receipt identity. Refuse recovery if any later ledger/voucher, expiry, owner, plan, router or device target differs. Only then may an explicitly reviewed snapshot be supplied and the common leased reconciliation path run. This note grants no recovery authority and adds no admin write endpoint. Do not recover 130 automatically: its later 29-day voucher makes entitlement history different.

### Reported customer recovered before the permanent release

Dennis explicitly instructed root to restore the specific paid customer first. A fresh authoritative Fapshi response, receipt financial identity, 1100 XAF amount, owner487/customer50237/router446/plan1997, two-day contract, unchanged prior expiry2026-11-02T16:52:08.802208Z and absence of any customer ledger/voucher were checked. Root then used the existing deployed confirmation workflow once, without a new charge or code deployment. Transaction143 became successful and payment337119 was recorded once; the customer became active through2026-11-04T20:10:38.751479Z. Its queued provisioning task completed without an exception.

Independent read-only Router-1088 verification found exactly one matching enabled hotspot user with a profile. The device was absent from hotspot hosts and active sessions, so customer internet was not claimed. Customer Wi-Fi reconnection remains the client-side check. This completed recovery must never be replayed or included in a legacy backfill. Minimal evidence is in root's chat work folder: bignebs-143-recovery-result.json and bignebs-143-router-verification.json. No customer message had been sent at this checkpoint.

For an ambiguous initiation hold, verify one unique exact provider match for the stored customer/external/amount before attaching a provider transaction ID. Multiple matches or missing evidence require continued review, never another blind Direct Pay request. Review codes and linked-ledger IDs are persisted for operator inspection; no new automated financial backfill is included.

Code rollback may leave these additive nullable columns/indexes in place. Do not delete ledgers, reverse expiry, drop snapshots or replay a payment as a code rollback. Disabling the scheduler restores dependence on callbacks/browser polls; any rollback needs an explicit reconciliation-monitoring plan.

## Verification

Base: 803492544d54b3a2f33564618c47ba4d27b36204; branch fix/fapshi-reliable-confirmation. Python 3.13.14, SQLAlchemy 2.0.43, pytest 9.0.3. Local PostgreSQL 17.4 is isolated on loopback; production PostgreSQL 15 remains a version difference. Provider HTTP tests use a ThreadingHTTPServer on 127.0.0.1 with the real Fapshi HTTP client. Router I/O is mocked. No real provider, customer, router, payment or deployment calls were executed by the implementation worker.

Shared Postgres suite: 120 passed in 278.33s. It includes existing Fapshi/schema/standby/session-release/renewal/sharing/hotspot-usage/FUP/PPPoE-FUP/daily-FUP tests plus focused reliability cases. The final changed-source reliability/Fapshi/schema gate passed 58 tests in 76.25s, including real Postgres row-lock concurrency, leases, real HTTP retries, startup migration twice, and the final callback/delivery races. An earlier SQLite reliability run passed 38 tests and skipped 3 PostgreSQL-specific cases in 36.47s. The final Postgres run additionally covers the last delivery-budget regression. Exact commands and JUnit paths are in the accompanying local review report. The source has no new dependency or configuration-secret changes.

## Follow-up 2026-11-04: pending guard locked customers out

The #295 initiation guard refused a new prompt while ANY CREATED/PENDING row existed. Rows the sweep parked (`legacy_purchase_snapshot_missing`, `reconciliation_window_exhausted`) stayed PENDING forever with a NULL snapshot that never matched, so 12 customers (Big Nebs 487, DHS LAN 677) could not pay by Fapshi at all; one was refused 30 times.

Now: only an attempt younger than `IN_FLIGHT_WINDOW` (30 min) that is unheld (or held as `initiation_outcome_unknown`) blocks or is reused. Held and stale rows never block and stay visible as `payment_status: review_hold` (no new enum value, no migration: the hold is `review_reason` on an open row). A row reaching the 7-day/720-check limit gets one final provider check: FAILED/EXPIRED closes it, anything else parks it. Explicit checks (webhook, status endpoint) may still close a held row that has a provider ID and no recorded provider success; the sweep never re-queries held rows. A provider success outside the automatic path is recorded but never credited.

`scripts/close_provider_failed_fapshi.py` closes listed rows only after a fresh read-only provider check says FAILED/EXPIRED (dry-run by default, idempotent). Rows 125 and 143 are SUCCESSFUL with an empty `customer_payment_id`; nothing here keys on that link.
