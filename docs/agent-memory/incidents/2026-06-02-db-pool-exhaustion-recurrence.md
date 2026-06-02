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

## Suspected Cause

The recurrence was not explained by normal user traffic alone. The likely trigger was scheduler alignment plus fan-out:

- safety-net bypass cleanup scanned many routers and rechecked orphan candidates with fresh DB sessions inside each concurrent router task;
- hotspot provisioning retry could process up to 25 work items across many router groups at once, with each item opening short DB sessions before and after RouterOS work;
- bandwidth collection kept the background process busy by repeatedly probing recently-offline routers.

Each individual DB session was short-lived, but the concurrent burst could hit all 30 configured application connections.

## Fix Applied

- `app/services/mikrotik_background.py`
  - safety-net cleanup now scans routers first, performs one batched DB authorization recheck for all candidate MACs, then removes confirmed orphans;
  - bandwidth collection skips routers marked offline within the last 5 minutes.
- `app/services/hotspot_provisioning.py`
  - retry provisioning router groups are capped at 4 concurrent groups.
- `app/db/database.py`
  - pool checkout/checkin events now track observed peak checked-out connections and recent 5-minute peak;
  - `/api/admin/db-pool` can now report a recent exhaustion peak even if current usage has dropped.
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
