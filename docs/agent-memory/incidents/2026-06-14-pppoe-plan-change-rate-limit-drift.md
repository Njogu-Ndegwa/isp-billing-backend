# 2026-06-14 PPPoE Plan Changes Could Leave Old Rate Limits

## Summary

The PPPoE activation path correctly creates/updates a PPP profile with the
plan speed, assigns the customer secret to that profile, ensures FastTrack
bypass for the PPPoE pool, and disconnects the active PPPoE session so the new
profile applies. A separate manual edit path could leave an active PPPoE
customer on the old router profile after changing only `plan_id`.

## Symptoms

- A customer whose plan was changed manually in the admin UI could remain on
  the previous PPP profile until a payment/provisioning flow ran again.
- The PPPoE presence endpoint returned profile details but did not compare the
  profile `rate-limit` with the selected plan speed.

## Suspected Cause

`app/api/customer_routes.py` only treated PPPoE username, password, or router
changes as requiring reprovisioning. It did not include `plan_id`, even though
the plan determines the PPP profile rate-limit.

## Fix Applied

- `app/api/customer_routes.py`
  - Active PPPoE customer edits now reprovision when `plan_id` changes.
  - The old router secret is removed only when username/router location changes,
    not for a same-router speed change.
- `app/services/mikrotik_api.py`
  - Speed parsing now preserves explicit `upload/download` plan strings such as
    `2M/5M` instead of collapsing them to a symmetric rate.
- `app/api/pppoe_monitor.py`
  - `GET /api/pppoe/customers/{customer_id}/presence` now returns
    `speed_enforcement` and reports `rate_limit_mismatch` or
    `active_queue_rate_mismatch` when router state does not match the plan.

## Verification

- `.\myEnv\Scripts\python.exe -m pytest tests\test_pppoe_router_defaults.py tests\test_pppoe_cleanup.py -q`
- `.\myEnv\Scripts\python.exe -m pytest tests\test_c2b_handler.py -q`
- `.\myEnv\Scripts\python.exe -m pytest tests\test_mpesa_callback_hotspot.py -q`
- `.\myEnv\Scripts\python.exe -m compileall app\services\mikrotik_api.py app\api\customer_routes.py app\api\pppoe_monitor.py tests\test_pppoe_router_defaults.py tests\test_pppoe_cleanup.py`

## Follow-Up Work

- After deploy, spot-check complained-about PPPoE customers with
  `/api/pppoe/customers/{customer_id}/presence?refresh=true` and inspect
  `speed_enforcement`.
