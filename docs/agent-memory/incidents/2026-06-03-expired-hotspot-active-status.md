# 2026-06-03 Expired Hotspot Customers Remained Active

## Summary

Expired hotspot customers continued appearing in the active-customer list after expiry. The affected rows had `status='active'`, past `expiry` values, and `hours_remaining=0`, so dashboard/API consumers still treated them as active even though billing time had elapsed.

## Symptoms

- `GET /api/customers/active` returned expired customers for router 10.
- Example expiry values were `2026-06-03T14:50:47` through `2026-06-03T17:09:24` UTC, which is about `17:50` through `20:09` Africa/Nairobi time.
- Logs showed `Remove expired hotspot users from MikroTik` being skipped because `maximum number of running instances reached`.
- Router calls around the same period showed circuit breakers and `No route to host` errors for several MikroTik routers.

## Suspected Cause

The expired cleanup job only marked a customer inactive after router-side MikroTik removal succeeded. After the pool-pressure changes, router cleanup was more conservative around slow/offline routers, which protected DB connections but exposed the latent coupling: when router cleanup was delayed, skipped, or failed, the billing row remained `ACTIVE`.

The active-customer endpoint also filtered by `status` only, not `expiry`, so any stale `ACTIVE` row with a past expiry was returned.

## Fix Applied

- `app/services/mikrotik_background.py`
  - Mark expired `ACTIVE` customers `INACTIVE` before any RouterOS cleanup.
  - Retry MikroTik cleanup for recently expired inactive hotspot/PPPoE customers for a bounded 7-day window.
  - Cap scheduled router cleanup work to 60 customers per run and 15 customers per router per run, while still deactivating all expired DB rows immediately.
  - Recheck expiry before router cleanup and restore `ACTIVE` if a customer renewed during the cleanup race window.
  - Update logs so failed router cleanup no longer says customers are kept active.
- `app/api/customer_routes.py`
  - Exclude expired rows from `/api/customers/active` even if status is stale.
- `app/api/router_operations.py`
  - Apply the same status-first behavior to manual per-router expired cleanup.
- `tests/test_expired_hotspot_cleanup.py`
  - Added regression tests for failed router cleanup, retrying inactive expired rows, router cleanup batching, and active-list filtering.

## Verification

- `python -m pytest tests/test_expired_hotspot_cleanup.py -q`
- `python -m pytest tests/test_safety_net_bypass_cleanup.py -q`
- `python -m pytest tests/test_hotspot_retry_concurrency.py -q`
- `.\myEnv\Scripts\python.exe -m compileall app\services\mikrotik_background.py app\api\customer_routes.py app\api\router_operations.py tests\test_expired_hotspot_cleanup.py`

The project venv lacked `pytest`, so pytest was run with system Python.

## Follow-Up Work

- Add job-duration metrics for expired cleanup and alert when APScheduler skips it because `max_instances` is reached.
- Add a router cleanup outbox so billing status changes and router removal attempts are tracked separately and durably.
