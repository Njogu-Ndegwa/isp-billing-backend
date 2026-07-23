# 2026-07-23 Status-Alert Backfill Sent 99 Alerts For Ancient Outages (Zombie Router Rows)

## Summary

Flipping router status alerts from opt-in to default-on (commit `e6abd61`,
backfilled 183 routers) triggered a one-time burst of 112 "went offline"
notices at 14:46 UTC. 99 of them were for outages older than 7 days — almost
all zombie router rows left behind when a physical router was re-registered
under a new account. One reseller received a paid SMS about a row dead for 32
days and reported it as a false alarm ("my router is up, I only have one").

## Symptoms

- Reseller reports "router down" alert for a router that is visibly serving
  customers; their live router row is online in the DB.
- The alert names a router on a *different* (older) account of the same person
  — near-duplicate emails, e.g. `dennisayoyi@` vs `dennodennyz@gmail.com`.
- `reseller_inbox_messages` burst at 2026-07-23 14:46 UTC;
  `sms_messages.category = 'router_status_alert'`: 13 sent, 19 credits.

## Suspected Cause

Two facts compounding:

1. Re-registration leaves the old router row behind: offline forever,
   still owned by the old account. ~99 such stale rows existed fleet-wide.
2. The offline-alert candidate filter had a minimum outage duration (15 min)
   and a status-freshness window (90 min; offline rows keep being re-probed)
   but no MAXIMUM outage age — so a month-dead row alerted the moment the
   backfill enabled it.

## Fix Applied

- `MAX_OUTAGE_AGE_FOR_ALERTS = 48h` added to the shared candidate filter in
  `app/services/router_status_alerts.py` (commit `7f3a452`, deployed): "went
  offline" is only announced while the outage is recent. Recovery notices are
  deliberately uncapped — a transition back online is always fresh news.
- No repeat risk from the burst itself: the once-per-outage stamps are set.

## Verification

- `tests/test_router_status_alerts.py`: `test_offline_scan_skips_ancient_outage`
  and `test_offline_scan_alerts_just_inside_max_age` (21 tests green).
- Deploy verified on prod (`7f3a452`, workflow run 30018383210).

## Follow-Up Work

- Zombie router rows are a data-hygiene problem beyond alerts (inflate router
  counts, will send a "back online after N days" notice if ever re-probed
  successfully). Consider a decommission/merge flow when a router is
  re-registered — backlog candidate.
- When enabling a notification feature for an existing fleet, audit what the
  backfilled state will fire BEFORE flipping the switch (here: 99 of 112
  alerts were noise). Dry-run the candidate query first.
