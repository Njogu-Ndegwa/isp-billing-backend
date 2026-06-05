# 2026-06-05 DB Pool Lock Convoy From Router Availability Writes

## Summary

The DB pool `checked_out` gauge climbed **monotonically** after every restart
(0% → ~50% over hours) and only ever reset on a restart — not the up-and-down
oscillation of healthy concurrency. No `QueuePool limit` timeouts had fired yet;
the climb was caught early via `GET /api/admin/db-pool`.

`pg_stat_activity` (via `?include_activity=true`) showed the real shape:

```text
states: active=13, idle=7, idle in transaction=2
wait_events: Lock/tuple=11, Client/ClientRead=9, Lock/transactionid=1
```

- One session was **`idle in transaction` for ~43 minutes**, last query
  `INSERT INTO router_availability_checks (...)`.
- **11 sessions were blocked on `Lock: tuple`**, every one running
  `UPDATE routers SET last_checked_at=…, availability_checks=…`.

A classic lock convoy: one wedged transaction held a `routers` row lock; every
other availability writer queued behind it, each pinning a pooled connection
while it waited. New dashboard polls kept re-queuing, so `checked_out` ratcheted
up and never drained until a restart killed the wedged backend.

## Symptoms

- `checked_out_percent` rises one-way and only resets on restart.
- `pg_stat_activity` shows a long-lived `idle in transaction` session plus many
  `Lock: tuple` waiters all running `UPDATE routers …`.
- The five ancient `idle` connections from the FreeRADIUS container
  (`client_addr` differs from the app) are unrelated and harmless.

## Root Cause

`app/services/router_availability.py::record_router_availability` mutated the
shared `routers` summary row + `INSERT`ed an availability sample, then only
`flush()`-ed — it relied on the **caller** to commit. It is called from ~40
request and background paths (every health / pppoe / hotspot monitor endpoint
the dashboard polls, plus the bandwidth job), all targeting the **same hot
`routers` rows**.

Because the write rode the caller's transaction, any caller that stalled after
the flush (waiting on slow/blocking RouterOS I/O, or cancelled mid-flight) held
the `routers` row lock open. With dozens of concurrent availability writers, that
one stall fanned out into a convoy that consumed the connection pool.

There was also no DB-side bound on how long a transaction could sit
idle-in-transaction, so a wedged session held its lock + connection indefinitely.

## Fix Applied

- `app/services/router_availability.py`
  - `record_router_availability` now writes in its **own short, immediately
    committed session** (`database.async_session()`), fully decoupled from the
    caller's transaction. The `routers` row lock is now held for milliseconds.
    The `db` parameter is retained for call-site compatibility but is unused.
- `app/db/database.py` + `app/config.py`
  - Added app-scoped asyncpg `connect_args` guardrails:
    `idle_in_transaction_session_timeout` (`DB_IDLE_TX_TIMEOUT_MS`, default 30s)
    and `lock_timeout` (`DB_LOCK_TIMEOUT_MS`, default 5s). A future wedged
    transaction self-aborts at 30s instead of marching to exhaustion, and lock
    waiters bail at 5s instead of pinning a connection. Scoped to the app role in
    code, so it survives DB volume recreation and never affects FreeRADIUS.
- Live mitigation already applied on the running DB (kept as defense-in-depth):
  ```sql
  ALTER DATABASE isp_billing_db SET idle_in_transaction_session_timeout = '30s';
  ALTER DATABASE isp_billing_db SET lock_timeout = '5s';
  ```
- `tests/test_router_availability_isolation.py`
  - Regression test: availability persists even when the caller rolls back, and
    recording for a missing router is a no-op.

## Verification

- TDD: the isolation test failed first (`assert 0 == 1` — write discarded with
  the caller's rollback), then passed after the fix.
- Full suite shows no new failures from this change (6 unrelated, pre-existing
  failures remain: `test_c2b_routes` ×4, `test_pppoe_cleanup` missing
  `radius_check` table in the harness, `test_pppoe_customer_import` string
  assertion — all fail identically on a clean baseline).
- `py_compile` clean for `config.py`, `database.py`, `router_availability.py`.
- Production: terminated the wedged backend (`pg_terminate_backend`), convoy
  drained, gauge dropped immediately.

## Audit — is the pattern repeated elsewhere?

The convoy required three things together: (1) a **hot shared row**, (2) **fan-in
from many high-frequency callers**, (3) **flush-without-own-commit** so the lock
rode a possibly-stalled caller transaction. A scan of all ~60 `flush()` sites
found only `record_router_availability` with all three. Every other flush
operates on a per-entity row (a specific payment / customer / lead / voucher)
inside a request handler that commits promptly — low contention, no fan-in.

The `connect_args` timeouts are defense-in-depth: even if a similar pattern is
introduced later, a wedged transaction now self-clears at 30s instead of
exhausting the pool.

## Follow-Up Work

- Optional: throttle availability writes (skip same-status records within ~60s)
  to cut redundant write volume on the 1 GB box. Not required to fix the convoy.
- Consider whether read-path dashboard polling should record availability at all,
  vs. relying on the background bandwidth job as the authoritative recorder.
- Pre-existing test harness gap: `radius_check` table not created in the SQLite
  test schema (breaks `test_pppoe_cleanup`) — unrelated, worth fixing separately.
