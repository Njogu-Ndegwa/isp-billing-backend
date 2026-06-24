# Backlog

Project-level items that should survive across agent sessions.

## Reliability And Architecture

### M-Pesa Callback Handler Atomic Completion Claim

- Status: planned
- Problem: the STK callback handler (`mpesa_direct_callback`) marks transactions completed via read-check-write (ORM read, then unconditional write), while the reconcile sweep and on-demand check use an atomic `UPDATE ... WHERE status = 'pending'` claim (`complete_and_provision_transaction`). A success callback racing the on-demand/sweep claim in a millisecond window can record a duplicate CustomerPayment (doubled expiry extension — money moves only once).
- Why it matters: the 2026-06 payment-resilience branch added the on-demand rescue path, which marginally increases how often a late callback and a query resolution can coincide.
- Proposed next step: route the callback's pending→completed transition through the same atomic claim (or an UPDATE guarded on `status = 'pending'`), keeping the revival branch's failed/expired→completed transition as a separate guarded claim.

### M-Pesa Transactions Customer Index

- Status: planned
- Problem: the duplicate-payment guard and on-demand check filter `mpesa_transactions` by `customer_id` + `status` + `created_at`, but the table has no index on `customer_id` (only PK and `checkout_request_id`).
- Why it matters: the guard runs on every repeat payment attempt; at ~1,600 txns/day the table reaches ~600k rows/year and each lookup becomes a sequential scan.
- Proposed next step: apply manually in production (no migrations framework): `CREATE INDEX CONCURRENTLY ix_mpesa_txn_customer_pending ON mpesa_transactions (customer_id, status, created_at DESC) WHERE status = 'pending';`

### Router Command Outbox

- Status: planned
- Problem: direct MikroTik API calls are still spread across multiple routes/services.
- Why it matters: every router operation should have consistent timeout, retry, locking, idempotency, and audit behavior.
- Proposed next step: add a generic `router_commands` table and worker. Request handlers should write commands and return quickly when synchronous confirmation is not required.

### Central Router I/O Gateway

- Status: planned
- Problem: `MikroTikAPI` is imported in many modules.
- Why it matters: scattered imports make it easy to bypass DB-release, timeout, concurrency, and logging rules.
- Proposed next step: introduce a central service layer for router calls, then gradually route existing direct calls through it.

### DB Pool And Router I/O Observability

- Status: started
- Problem: production pool exhaustion was hard to attribute quickly.
- Why it matters: future incidents need router ID, endpoint, background job, DB pool status, and router-call duration in one trail.
- Done so far: backend exposes `GET /api/admin/db-pool` for live SQLAlchemy pool counters, observed checkout peaks, recent 5-minute peak pressure, and an optional Postgres `pg_stat_activity` summary.
- Proposed next step: add structured logs and lightweight metrics for request duration, background job duration, and MikroTik call duration by router ID.

### Expired Cleanup Job Health

- Status: planned
- Problem: expired hotspot cleanup can fall behind when RouterOS calls are slow, and APScheduler only logs `max_instances` skips.
- Why it matters: expired billing state must not depend on live router availability, and operators need an early signal before stale router access accumulates.
- Proposed next step: record cleanup job duration, skipped-run count, expired rows deactivated, router cleanup failures, and retry backlog age in a DB-backed or metrics-backed health record.

### Hotspot Queue Repair Metrics

- Status: planned
- Problem: hotspot speed enforcement depends on removing RouterOS dynamic `hs-*` / `<hs-*>` parent queues and keeping per-customer `plan_<mac>` queues current, but the queue repair job currently only logs its activity.
- Why it matters: operators need an early signal when parent queues are repeatedly regenerated or queue repair falls behind, before customers report unlimited speeds.
- Proposed next step: record queue repair duration, routers processed, parent queues removed, queues created, queues updated, skipped recently-offline routers, and errors in job metrics or a small health endpoint.

### RADIUS Expansion

- Status: planned
- Problem: direct API provisioning couples customer access lifecycle to live router availability.
- Why it matters: RADIUS is a better long-term fit for subscriber auth/accounting, while direct API should remain for router administration.
- Proposed next step: review which customer flows can safely move to RADIUS first without disrupting existing direct-api routers.

### Scheduler Isolation

- Status: planned
- Problem: APScheduler jobs run inside the web process.
- Why it matters: this is acceptable for one backend worker, but unsafe if multiple app instances/workers start the same jobs.
- Proposed next step: document deployment assumptions and consider moving scheduler work to a separate worker process before horizontal scaling.

## Operational Hygiene

### Incident Note Discipline

- Status: active
- Problem: learnings can disappear between agent sessions.
- Why it matters: repeated debugging wastes time and risks regressions.
- Proposed next step: after significant production incidents, add a note under `docs/agent-memory/incidents/` and link follow-ups here.

### B2B initiate_b2b_payment Session Across Safaricom Call

- Status: planned
- Problem: `initiate_b2b_payment` holds its DB session open across the Safaricom B2B HTTP call (httpx POST), violating the Database Session Discipline pattern; the 2026-06-10 payout fix limited the blast radius to one reseller per session but did not remove the cross-I/O hold.
- Why it matters: a slow Safaricom response pins one pool connection per in-flight payout; under provider outages (e.g. their nightly 23:00-01:00 UTC window) this still wastes pool capacity.
- Proposed next step: restructure to read inputs and commit before the HTTP call, then persist the result in a fresh session (same pattern as `kick_pending_payment_check`). Also consider moving the daily payout schedule out of 23:59 UTC, which sits inside Safaricom's recurring maintenance window.

## Messaging / Onboarding

### SMS Body Column Shorter Than Editable Body

- Status: planned
- Problem: `SmsMessage.body` is `VARCHAR(1000)` but both the admin inbox body and the new `messaging_settings.welcome_message_body` are `VARCHAR(2000)`. An admin who sets a welcome body (or sends a manual `send_inbox` SMS) over 1000 chars would have the SMS row insert exceed the column on Postgres.
- Why it matters: for the reseller welcome path the SMS row is created inside the registration hook's non-fatal try/except, so an oversized body would silently suppress the entire welcome (inbox + SMS) for that signup rather than erroring loudly. Pre-existing for the manual `send_inbox` path too.
- Proposed next step: either validate/clamp the SMS body to 1000 chars where SMS rows are created (`reseller_welcome.queue_reseller_welcome` and `admin_messaging_routes.send_inbox`), or widen `sms_messages.body` to 2000 via an idempotent startup migration. Prefer clamping the SMS copy, since a multi-segment welcome SMS is undesirable anyway.

### Welcome Message Not Sent On Lead Conversion

- Status: planned
- Problem: the reseller welcome message fires only from self-service `register_user_api`. `convert_lead` (`app/api/lead_routes.py`) also creates a `RESELLER` account but has no welcome hook.
- Why it matters: admin-initiated lead conversions never receive the onboarding welcome/router-setup offer. This was a deliberate scope boundary ("signup" = self-service), but may be desired.
- Proposed next step: if welcome-on-conversion is wanted, call `reseller_welcome.queue_reseller_welcome` + schedule `sms_dispatch.dispatch_admin_sms_messages` in `convert_lead`, reusing the same non-fatal, commit-before-dispatch pattern as `register_user_api`.
