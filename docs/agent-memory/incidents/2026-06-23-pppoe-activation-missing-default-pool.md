# 2026-06-23 PPPoE Activation Fails Before Default Pool Exists

## Summary

Manual PPPoE activation could mark a customer active and schedule retries, but
fail to add the PPP secret/profile on a direct-api router when the router did not
already have the standard `pppoe-pool` IP pool. Customer `8112` on router `227`
was the concrete example: billing state was active, but router provisioning kept
failing.

## Symptoms

- `POST /api/customers/8112/activate-pppoe` returned `200 OK`.
- Production logs showed repeated:
  `Profile creation failed: invalid value for argument remote-address:`
- Logs showed the attempt targeted router `10.0.0.23`.
- A later `Dual port sync for router 227 completed` line indicates router PPPoE
  infrastructure was configured after the failed activation attempts.
- The same customer was later edited so `pppoe_username` became an empty string,
  which removed it from retry eligibility.

## Suspected Cause

`app/services/pppoe_provisioning.py` fell back to `remote-address=pppoe-pool`
when no active PPPoE server profile could be resolved. That fallback was intended
to cover timing windows, but it assumed the `pppoe-pool` already existed. On a
router where activation ran before PPPoE infrastructure setup, RouterOS rejected
the profile because the referenced pool did not exist.

A second data-integrity gap made recovery worse: `PUT /api/customers/{id}` could
save `pppoe_username=""` for an active PPPoE customer. Retry queries check for a
truthy username before provisioning, so a blank username strands the active row.

## Fix Applied

- `app/services/mikrotik_api.py`
  - Added idempotent `ensure_ip_pool(pool_name, pool_range)`.
- `app/services/pppoe_provisioning.py`
  - Before creating a PPP profile that references the default `pppoe-pool`,
    ensure the default pool exists.
- `app/api/customer_routes.py`
  - Normalize PPPoE usernames at registration.
  - Reject blank PPPoE username/password edits when the target plan is PPPoE.
- Tests:
  - `tests/test_pppoe_router_defaults.py`
  - `tests/test_pppoe_cleanup.py`

No production deploy or manual production DB repair was performed during this
diagnosis.

## Verification

- Production logs confirmed the repeated `remote-address` RouterOS error for the
  failing activation.
- Focused tests passed:
  `.\myEnv\Scripts\python.exe -m pytest tests/test_pppoe_cleanup.py tests/test_pppoe_router_defaults.py -q`

## Follow-Up Work

- Deploy the code fix.
- With explicit operator approval, repair the existing stranded production row
  for customer `8112` by restoring its intended PPPoE username and then
  re-triggering provisioning.
- Consider surfacing `retry_pending`/`failed` provisioning state prominently in
  the admin customer view so `200 OK` activation responses are not mistaken for
  confirmed router delivery.
