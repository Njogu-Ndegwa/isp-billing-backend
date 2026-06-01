# 2026-06-01 PPPoE Orphan Secret Stayed Online

## Summary

A PPPoE user appeared in the PPPoE Monitor for router `ANTO #2` but was missing from the customer list. The router still had an enabled PPPoE secret and an active session, while the app database no longer had a matching customer row.

## Symptoms

- `GET /api/pppoe/{router_id}/users` returned a user with `customer: null`.
- Router secret comment still contained a historical customer id, for example `CID:956|Festus |2026-05-20`.
- The same entry had `online: true` and `disabled: false`, proving this was live RouterOS state rather than only stale DB data.

## Suspected Cause

Customer deletion only attempted PPPoE router cleanup for active DB customers and continued deleting the DB row even if router cleanup failed. Inactive PPPoE customers, router timeouts, or failed cleanup calls could therefore leave orphaned RouterOS secrets/sessions.

## Fix Applied

- `app/api/customer_routes.py`: customer deletion now attempts PPPoE cleanup for any customer with `pppoe_username`, regardless of DB status, and refuses to delete the DB row if RouterOS cleanup fails.
- `app/api/pppoe_monitor.py`: added `DELETE /api/pppoe/{router_id}/users/{username}` to disconnect and remove orphan PPPoE users from a router. It refuses DB-owned usernames unless `force=true`.
- `app/services/pppoe_provisioning.py`: PPPoE removal now treats session-disconnect failures and secret-removal failures as cleanup errors.
- `tests/test_pppoe_cleanup.py`: added focused tests for deletion cleanup and orphan cleanup endpoint behavior.

## Verification

- Static diff check passed with `git diff --check`.
- Python/pytest could not be run in this workspace because both `python` and `myEnv\Scripts\python.exe` fail with `The file cannot be accessed by the system`.

## Follow-Up Work

- Add a scheduled safety-net job for orphan PPPoE secrets by comparing router comments/usernames against current DB customers.
- Add UI action in PPPoE Monitor for `customer: null` rows to call the cleanup endpoint after confirmation.
