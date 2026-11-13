# 2026-10-16 Expired hotspot sessions survived cleanup

## Summary

An audit at about 19:52 EAT found 30 expired, INACTIVE customer records with
authorized live hotspot sessions on 16 reachable routers. The admin dashboard
counted billing status, so it did not expose this router/database mismatch.
Nine further expired customer MACs had separate active access credentials and
bypassed bindings; these were a distinct access path.

## Symptoms

- Hotspot user and expiry-tagged binding were absent, while `/ip hotspot active`
  and an authorized host still contained the customer's MAC.
- The router reaper scheduler was enabled and running on affected router-mode
  devices. One server-mode router re-added an expired MAC-login user after cleanup.
- The oldest confirmed stranded session was for customer 10284, about 27 hours
  past expiry at the audit.
- Nine candidate routers could not be verified in the broad fleet scan.

## Cause

The router script removed the binding, active session and host before removing
the hotspot user. A client could log back in while that user still existed. The
script then reported removal without checking whether an active session survived.
The server cleanup likewise treated binding removal as sufficient proof, even
when a hotspot session remained. The scheduled MAC-login reconcile could use a
paid-customer snapshot taken before expiry and recreate a user after cleanup.

## Fix

- Router reaper v3 disables login users before kicking sessions, retains the
  expiry tag until router access is verified gone, and reports completion only
  after verification. Existing routers receive v3 through the version upgrade.
- Server cleanup removes login users before sessions and verifies binding, user
  and active tables before marking a customer INACTIVE.
- Queue sync rechecks billing entitlement under the router lock immediately
  before reconciling MAC-login users.
- An admin-only live audit compares expired billing records with authorized
  RouterOS sessions, reports unreachable routers separately, and is displayed
  on the admin dashboard.

## Verification

Focused regression tests cover the script order, a RouterOS removal that claims
success but leaves a session, the stale reconcile snapshot, and live audit
classification. After deployment, recheck affected routers, safely clear
stranded sessions that have no expiry tag, and compare later audits to confirm
new expiries do not recreate the mismatch.
