# 2026-06-14 Hotspot Speeds Bypassed By Dynamic Parent Queues

## Summary

Hotspot customers reported receiving higher speeds than their selected plans.
Operators observed MikroTik simple queues named like `<hs-unlimite>`, indicating
RouterOS dynamic hotspot parent queues were present and could shadow the app's
per-customer `plan_<mac>` queues.

## Symptoms

- Customers on hotspot plans complained that speed regulation was not applied.
- MikroTik queue lists showed hotspot dynamic queues named like `<hs-...>`.
- Existing code only matched parent queues named `hs-...`, so angle-bracketed
  RouterOS names could survive provisioning and background repair.
- The active-user queue sync job existed but was not scheduled, so already-active
  customers with missing/stale queues or regenerated parent queues had no bounded
  automatic repair path.

## Suspected Cause

Two issues combined:

- RouterOS can report dynamic hotspot parent queues as `<hs-...>`, but cleanup
  logic only checked `name.startswith("hs-")`.
- Direct API provisioning treated a missing per-customer queue as success when
  the bypass binding existed, leaving the customer online but potentially
  unlimited until a repair ran.

## Fix Applied

- `app/services/mikrotik_api.py`
  - Added shared `is_hotspot_parent_queue_name()` detection for both `hs-...`
    and `<hs-...>` queue names.
  - Reused that detection during provisioning-time parent queue cleanup.
- `app/services/hotspot_provisioning.py`
  - Treat queue creation errors or pending queue creation as retryable
    provisioning failures instead of successful delivery.
- `app/services/mikrotik_background.py`
  - Re-enabled active hotspot queue repair as a bounded rotating batch:
    max 4 routers per run, shared router locks, DB-pool pressure skip,
    recently-offline router skip, and DB session closed before RouterOS I/O.
- `main.py`
  - Scheduled queue repair every 313 seconds with `max_instances=1`.
- `app/api/router_operations.py`
  - Fixed `/api/routers/{router_id}/bandwidth-check` queue analysis indentation.
  - Added explicit hotspot parent queue reporting and shadowing detection.

## Verification

- `.\myEnv\Scripts\python.exe -m pytest tests\test_hotspot_queue_enforcement.py -q`
- `.\myEnv\Scripts\python.exe -m pytest tests\test_hotspot_queue_enforcement.py tests\test_hotspot_retry_concurrency.py tests\test_expired_hotspot_cleanup.py -q`
- `.\myEnv\Scripts\python.exe -m pytest tests\test_mpesa_callback_hotspot.py tests\test_voucher_redeem_retry.py -q`
- `.\myEnv\Scripts\python.exe -m compileall app\api\router_operations.py app\services\mikrotik_api.py app\services\hotspot_provisioning.py app\services\mikrotik_background.py main.py tests\test_hotspot_queue_enforcement.py`

## Follow-Up Work

- After deploy, use `/api/routers/{router_id}/bandwidth-check` on affected
  routers and watch for `has_shadowing_hotspot_parent_queues=true`.
- Add job metrics for queue repair duration, routers processed, parent queues
  removed, queues created, and queues updated.
