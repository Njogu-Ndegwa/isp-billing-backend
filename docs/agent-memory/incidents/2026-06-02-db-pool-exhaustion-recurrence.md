# 2026-06-02 DB Pool Exhaustion Recurrence From Background Fan-Out

## Summary

Pool exhaustion recurred with:

```text
QueuePool limit of size 15 overflow 15 reached, connection timed out, timeout 10.00
```

The captured log in `pool-exhausted.md` showed failures across login, public portal, reconnect, M-Pesa reconciliation, subscription reconciliation, expired-user cleanup, and hotspot provisioning retry.

## Symptoms

- SQLAlchemy reported `Current Checked out connections: 30`.
- The first visible failed background paths were cleanup's access credential reaper and hotspot provisioning retry.
- `Collect bandwidth statistics` was already long-running; APScheduler skipped its next run because `max_instances=1` was still occupied.
- Many RouterOS calls were failing or timing out against offline/unreachable routers before the pool errors.
- A point-in-time `/api/admin/db-pool` check can look healthy before or after the spike, even when a recent spike reached exhaustion.
- A later recurrence showed the pool at about `90%` while normal app requests degraded. The logs showed expired-user cleanup repeatedly finding about `98-99` expired customers and hitting many of the same unreachable routers every `67s`.

## Suspected Cause

The recurrence was not explained by normal user traffic alone. The likely trigger was scheduler alignment plus fan-out:

- safety-net bypass cleanup scanned many routers and rechecked orphan candidates with fresh DB sessions inside each concurrent router task;
- hotspot provisioning retry could process up to 25 work items across many router groups at once, with each item opening short DB sessions before and after RouterOS work;
- bandwidth collection kept the background process busy by repeatedly probing recently-offline routers.
- the expired-user cleanup job kept retrying recently failed routers too quickly, so failures against the same offline routers were amplified every minute.
- bandwidth collection still did full-fleet polling, so a growing router fleet could keep the job running longer than its scheduler interval even after offline-router backoff.
- the frontend customer list was also polling PPPoE users for every router in the account every 30 seconds, which turned normal dashboard browsing into repeated live RouterOS fleet scans.

Each individual DB session was short-lived, but the concurrent burst could hit all 30 configured application connections.

## Fix Applied

- `app/services/mikrotik_background.py`
  - safety-net cleanup now scans routers first, performs one batched DB authorization recheck for all candidate MACs, then removes confirmed orphans;
  - expired-user cleanup records failed router connections as offline and skips recently-offline routers for 30 minutes;
  - safety-net cleanup skips recently-offline routers, runs at most every 10 minutes, and is skipped when DB pool checkout is already high;
  - idle access credential reaping skips recently-offline routers, runs at most every 5 minutes, and is skipped together with safety-net cleanup under DB pressure;
  - bandwidth collection skips when DB pool checkout is high and skips routers marked offline within the last 30 minutes;
  - shared background router concurrency was lowered from 6 to 3.
- `app/services/hotspot_provisioning.py`
  - retry provisioning router groups are capped at 4 concurrent groups;
  - background retry skips when DB pool checkout is already high.
- `app/api/pppoe_monitor.py`
  - PPPoE users responses are cached longer for dashboard polling;
  - normal requests serve stale cache, or a DB-only fallback, when the router was recently offline or DB pool checkout is high;
  - live RouterOS refresh remains available through explicit refresh requests.
- `app/db/database.py`
  - pool checkout/checkin events now track observed peak checked-out connections and recent 5-minute peak;
  - `/api/admin/db-pool` can now report a recent exhaustion peak even if current usage has dropped.
- Frontend customer list
  - PPPoE live-status polling is scoped to routers represented by the currently visible customer rows instead of every router in the account.
- `tests/test_safety_net_bypass_cleanup.py` and `tests/test_hotspot_retry_concurrency.py`
  - added focused regression coverage for the batched recheck and retry concurrency cap.

## Verification

- Compile check passed for:
  - `app/db/database.py`
  - `app/services/mikrotik_background.py`
  - `app/services/hotspot_provisioning.py`
- Direct Python smoke checks passed for:
  - retry group concurrency cap (`7` groups queued, max concurrent observed `4`);
  - safety-net batching path (two router candidate sets, one recheck call).
- Focused pytest could not run locally because `myEnv` does not have `pytest` installed.

## Follow-Up Work

- Add durable job-level metrics for scheduler duration, DB checkout peak, and RouterOS call counts per job run.
- Consider moving high-latency RouterOS jobs to a separate worker process or queue.
- Add deployment guidance for scheduler isolation if multiple backend workers are ever used.
