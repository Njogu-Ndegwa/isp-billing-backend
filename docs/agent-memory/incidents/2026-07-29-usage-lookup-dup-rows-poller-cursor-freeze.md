# 2026-07-29 Usage-Row Duplicates Froze the Bandwidth Poller's Rotation

## Summary

From ~00:33 EAT every router-level dashboard metric (live bandwidth, active user
counts, bandwidth history, hourly breakdown) froze at its last value, fleet-wide.
Payments, provisioning, FUP and the new push-usage channel kept working. Reported
by Dennis at ~11:30 EAT from the Wangige dashboard ("updated 650m ago"). Root
cause was a bug in PR #20 (deployed 20:15 EAT the previous evening) — the same PR
that shipped the usage-push channel. Fixed by PR #22, deployed 12:00 EAT;
rotation confirmed recovering within minutes.

## Symptoms

- Dashboard: live bandwidth ~0 Mbps, hotspot count stale ("updated 650m ago"),
  bandwidth-history graph flatlined after 12:37 AM, daily-breakdown bars absent.
- `bandwidth_snapshots`: coverage dropped from ~40 routers/hour to 6–19; busy
  routers (Wangige id 10, Central kiddoh 247, Major1 net 118) unvisited for 12h+
  while the same small window was re-snapshotted 2–4×/hour.
- Logs, every run: `[BANDWIDTH] Processing 8/N ... cursor=83` — **cursor frozen**;
  `Error collecting bandwidth from router X: Multiple rows were found when one or
  none was required`; then `Error collecting bandwidth snapshot: greenlet_spawn
  has not been called...` and the run ends before the cursor update.

## Cause — three links in a chain

1. **PR #20's cross-tenant fix looked usage rows up by customer first.** A
   customer legitimately owns one `user_bandwidth_usage` row per device key ever
   used (randomised phone MACs; one prod customer owns 25). For multi-row
   customers the lookup grabbed an arbitrary row and rewrote its `mac_address`
   to the current key — silently manufacturing duplicate rows per MAC. 19
   duplicate groups accumulated over ~4h via the cap sampler and push.
2. **The poller's hotspot lookup expected exactly one row per MAC**
   (`scalar_one_or_none`). On the first duplicated MAC it raised
   `MultipleResultsFound`; the failure escaped the per-router handler as a
   `MissingGreenlet` error and aborted the run.
3. **The rotation cursor was advanced after the loop**, so the aborted runs never
   moved it. Frozen at 83 → same 8 routers forever → everyone else starved.

## Fix Applied (PR #22, `e98ca1a`)

- `record_queue_usage_sample`: lookup scoped to THE KEY BEING SAMPLED, and within
  it to this customer or an unclaimed legacy row (claimed preferred). Never
  another customer's row; never another key's row.
- Poller hotspot lookup made duplicate-tolerant (several rows per MAC are
  legitimate under per-customer separation): this customer's row, else unclaimed.
- **Rotation cursor advances BEFORE processing.** A crash now costs one repeat
  visit, never a frozen rotation — this closes the whole failure class.
- Data repair (post-deploy, approved): 19 same-(mac,customer) duplicates deleted
  keep-newest; 0 shadowed-NULL rows; 0 duplicate groups remain.

## Verification

- Tests written first; both reproduced the incident (the poller one to the
  literal production error message). `tests/test_usage_counters_multirow.py`.
- Post-deploy: cursor advancing (0→8→24→32→48→56 across observation ticks),
  `greenlet=0 multirow=0` in logs, snapshot coverage 22–23 routers/30min and
  climbing as the walk proceeds.
- Permanent gap in history data ~00:37–12:00 EAT: never collected, expected.

## Why 723 green tests didn't catch it

- **Fixtures were cleaner than production.** Every test made one customer with
  one usage row; the bug needs the multi-row shape that only develops over time.
- **A shared helper was changed but only the new caller was tested thoroughly.**
  Push had 30+ tests; the poller's interaction with the new write pattern had
  none with realistic state.
- **The bug corrupts state silently; a different component crashes later.**
  Component tests on fresh databases are structurally blind to this class.
- **The one-row-per-(mac,customer) invariant lived in assumptions, not in the
  schema.** A unique index would have made the first duplicate write explode
  loudly instead of accumulating for hours.

## Follow-Up Work

1. Partial unique index on `user_bandwidth_usage (mac_address, customer_id)`
   (idempotent migration in `main.py` + schema-snapshot refresh) — makes this
   bug class impossible. **Planned next.**
2. "Dirty fixtures" factory for tests: multi-row customers, legacy NULL rows,
   MACs shared across resellers — run key paths against production-shaped state.
3. Eligible-router list has no ORDER BY, so rotation fairness depends on
   Postgres's returned order; add a stable ordering (e.g. by id) so the cursor
   walk is deterministic.
4. Pre-existing, unrelated: `greenlet_spawn` errors in
   `app.api.payment_routes` ("Failed to record STK push failure") predate PR #20
   — worth their own look.
