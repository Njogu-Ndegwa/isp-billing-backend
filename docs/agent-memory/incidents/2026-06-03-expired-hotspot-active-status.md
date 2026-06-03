# 2026-06-03 Expired Hotspot Customers Remained Active

## Summary

Expired hotspot customers continued appearing in the active-customer list after expiry. In this project `status='active'` is intended to mean the customer is still present/allowed on MikroTik; `INACTIVE` should only be set after router-side removal is confirmed.

## Symptoms

- `GET /api/customers/active` returned expired customers for router 10.
- Example expiry values were `2026-06-03T14:50:47` through `2026-06-03T17:09:24` UTC, which is about `17:50` through `20:09` Africa/Nairobi time.
- Logs showed `Remove expired hotspot users from MikroTik` being skipped because `maximum number of running instances reached`.
- Router calls around the same period showed circuit breakers and `No route to host` errors for several MikroTik routers.

## Suspected Cause

The expired cleanup job correctly marked a customer inactive only after router-side MikroTik removal succeeded, but cleanup could fall behind when RouterOS work exceeded the 67-second interval or a router was slow/offline. The bug to investigate is router-side cleanup reliability, not changing the meaning of `ACTIVE`/`INACTIVE`.

## Fix Applied

- `app/services/mikrotik_background.py`
  - Preserve `ACTIVE` until router cleanup succeeds.
  - Cap scheduled router cleanup work to 60 customers per run and 15 customers per router per run so automatic cleanup cannot overload routers/server.
  - Recheck expiry/status before router cleanup so a renewed or already-deactivated customer is not removed with stale data.
  - Keep failed/deferred customers `ACTIVE` for retry and operator visibility.
- `app/api/router_operations.py`
  - Preserve the same success-gated inactive transition for manual per-router expired cleanup.
- `tests/test_expired_hotspot_cleanup.py`
  - Added regression tests for failed router cleanup staying active, successful router cleanup marking inactive, router cleanup batching, and active-list visibility for expired active rows.

## Verification

- `python -m pytest tests/test_expired_hotspot_cleanup.py -q`
- `python -m pytest tests/test_safety_net_bypass_cleanup.py -q`
- `python -m pytest tests/test_hotspot_retry_concurrency.py -q`
- `.\myEnv\Scripts\python.exe -m compileall app\services\mikrotik_background.py app\api\customer_routes.py app\api\router_operations.py tests\test_expired_hotspot_cleanup.py`

The project venv lacked `pytest`, so pytest was run with system Python.

## Follow-Up Work

- Add job-duration metrics for expired cleanup and alert when APScheduler skips it because `max_instances` is reached.
- Add a router cleanup outbox so billing status changes and router removal attempts are tracked separately and durably.
