# 2026-08-23 — Dashboard simple queues mislabelled as active PPPoE users

## Symptoms

The Bitwave Wangige dashboard showed about 80 active PPPoE users even though
the reseller had no PPPoE customers and the router had no PPPoE secrets or
active PPPoE sessions.

## Root cause

The usage-push router block reports three separate values:
`hotspot_active`, `pppoe_active`, and `queue_count`. The push snapshot writer
persisted `queue_count` in the legacy `active_queues` field. Dashboard readers
correctly interpret that field as the combined active Hotspot + PPPoE count and
derive PPPoE as `active_queues - active_hotspot_users`. Consequently, every
configured simple queue that was not also an active Hotspot session appeared
as an active PPPoE user.

The background poller already preserved the intended contract by writing
`active_queues = active_hotspot_users + active_pppoe_users`; only the push
writer violated it.

## Fix

The push writer now stores `hotspot_active + pppoe_active` in
`active_queues`. `queue_count` remains validated as input telemetry but is not
used as an active-user count. No router script update or database migration is
required because routers already push the real active PPPoE count.

## Verification

Regression tests cover Hotspot-only, PPPoE-only, mixed, and zero-active-user
routers while deliberately making simple-queue count differ from active-user
count. They assert both the stored snapshot and the dashboard health payload.

Read-only production comparisons before deployment confirmed the distinction:

| router | simple queues | live Hotspot | live PPPoE | old displayed PPPoE | corrected PPPoE |
|---|---:|---:|---:|---:|---:|
| Bitwave Wangige | 78 | 0 | 0 | 78 | 0 |
| AMANI APARTMENT #2 | 6 | 0 | 7 | 7 | 7 |
| Kennice Networks #6 | 55 | 0 | 16 | 16 | 16 |

## Follow-up

Old snapshots retain the old interpretation. The dashboard corrects itself
when each router's next throttled metrics snapshot is accepted; no historical
rewrite is necessary.
