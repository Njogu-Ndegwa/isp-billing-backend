# 2026-08-29 Inactive PPPoE Customer Still Online

## Summary

An expired PPPoE customer was `INACTIVE` in the billing database but still had
an enabled RouterOS secret and an active session. The dashboard correctly showed
both states at once: billing inactive and router online. The customer retained
internet access after expiry because RouterOS cleanup failures were incorrectly
reported as success.

## Symptoms

- Customer 15089 expired at `2026-08-28 20:00 UTC` (`23:00 EAT`).
- On `2026-08-29` the database status was `inactive`, while PPPoE username
  `FRANK` had an enabled secret and a live session on router 293.
- The session had transferred more than 1 GB and its byte counters continued to
  increase during the read-only diagnosis.
- The first enforcement attempt removed the active session, after which the
  RouterOS API connection became stale. `remove_pppoe_secret()` returned
  `success/not_found` even though its `/ppp/secret/print` call had failed and the
  secret still existed.

## Suspected Cause

This was a confirmed false-success path in `MikroTikAPI`:

1. `disconnect_pppoe_session()` incremented its success counter without checking
   whether `/ppp/active/remove` succeeded.
2. `remove_pppoe_secret()` treated any unsuccessful secret-list response as an
   empty list and returned `not_found`.
3. Expiry cleanup saw two apparent successes and marked the customer `INACTIVE`.
4. Future expiry scans select only `ACTIVE` rows, so the split state became
   invisible to automatic retries while the enabled secret allowed re-auth.

The manual PPPoE deactivation endpoint had the same invariant gap: it changed
the database status to `INACTIVE` even when `call_pppoe_remove()` failed.

## Fix Applied

- Production workaround: disconnected the live session and removed the PPPoE
  secret using a fresh RouterOS connection; independently verified both absent.
- `app/services/mikrotik_api.py`: propagate list/remove errors and count a
  disconnect only after RouterOS acknowledges the remove command.
- `app/api/customer_routes.py`: refuse to mark a router-owned PPPoE customer
  inactive unless router cleanup returns confirmed success.
- `app/services/mikrotik_background.py` and `main.py`: add a 10-minute PPPoE
  safety net for older inactive rows that lack cleanup proof. It rotates through
  at most 20 customers per run, caps work at five customers per router, skips
  recently-offline routers, sheds work under DB-pool pressure, uses the shared
  three-router concurrency limiter, and releases DB sessions before RouterOS I/O.
- Successful manual, expiry, and safety-net cleanup now records durable
  `pppoe_deactivation` proof so confirmed customers are not scanned repeatedly.
- `app/services/billing.py` and all payment-provider failure handlers preserve
  `ACTIVE` status when a failed renewal still has paid time remaining. This
  closes a separate database-only path that could label a connected customer
  inactive without attempting router enforcement.
- `tests/test_pppoe_cleanup.py`: cover failed list calls, failed remove calls,
  failed deactivation, and the successful status transition.
- `tests/test_expired_pppoe_cleanup.py`: cover safety-net success, durable
  one-time processing, retry after router failure, pool-pressure shedding,
  per-router caps, and expiry cleanup proof.
- `tests/test_mpesa_callback_hotspot.py`: cover failed-renewal preservation of
  already-paid access.

## Verification

- Live production verification after the workaround:
  `session_absent=true`, `secret_absent=true`.
- Focused tests:
  `python -m pytest tests/test_pppoe_cleanup.py tests/test_expired_pppoe_cleanup.py -q`.
- Full backend regression suite: `python -m pytest -q` completed at 100% with
  no failures.

## Follow-Up Work

- Add operational metrics for expiry cleanup false/failed enforcement and retry
  backlog age, as already tracked under "Expired Cleanup Job Health" in the
  backlog.
- Monitor the bounded inactive-PPPoE reconciliation logs and add a small health
  metric if operators need backlog age/count without reading application logs.
