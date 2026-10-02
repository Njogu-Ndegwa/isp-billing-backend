# 2026-09-29 Host metering re-banked whole device counters (ghost host entries)

## Summary

From the real-time pilot (router 10, 2026-09-25) and the fleet rollout of v3 push
(2026-09-26 12:43 UTC), hotspot usage on push routers was booked from
`/ip hotspot host` counters under one row per MAC (`host:<MAC>`). A device can
hold two host entries at once, and when it did, its whole running counter was
re-credited every push. Usage ledgers, reseller "top users", and period totals
were inflated 10-36x for affected devices. FUP could throttle capped customers
on usage they never had.

## Symptoms

- Customer 630 (254799137821, Bitwave Wangige, 10 Mbps / 3 h plan): 731 GB in
  the 09:36-15:36 period on 2026-09-29. A 10 Mbps line can move ~27 GB in 6 h.
- Router 10 ledger: 795 GB on 2026-09-29. Router ether1 counter and Starlink
  both say ~80-89 GB.
- 5-minute router buckets grow in a straight line (3 -> 6 -> 9 ... 40 GB):
  each bucket is ~N pushes x the device's running total, not traffic.
- Fleet, 30 days to 2026-09-29: 249 customer-hours above the plan's line rate,
  122 customers, 34 routers, 4,286 GB of 14,563 GB booked. None before
  2026-09-25.

## Cause

A phone on mobile data or a VPN gets a second hotspot host entry for its stray
source address next to its real LAN entry. Seen live on router 118:
`72:7B:64:EB:A4:72` at 192.168.88.233 (671 MB) and at 10.47.135.116 (28 KB),
both authorized. Both were reported under key `host:<MAC>`. Each push the row
saw 671 MB, then 28 KB. `usage_counter_delta` treats any decrease as a counter
reset and credits the new value in full, then the next big reading credits
(671 MB - 28 KB). Net: the whole counter once per push.

Also: with autoflush off, two reports for one new key in the same batch created
two `user_bandwidth_usage` rows (41 customers had duplicate `host:` rows).

## Fix Applied

- `app/services/usage_push.py`: host rows are keyed per entry,
  `host:<MAC>@<address>` (`host_usage_key`), and a host listed twice in one
  report is counted once.
- `app/services/usage_counters.py`: new rows are flushed immediately (no
  duplicate rows per batch). New line-rate guard `clamp_to_line_rate`: no sample
  may credit more than 2x the plan's fastest direction over the time since the
  last sample (60 s floor, 8 MB slack). Clamps log `[USAGE] Clamped impossible
  delta`, which should stay rare. Applied on the push/cap-sampler path and in
  both branches of the bandwidth poller (`mikrotik_background.py`).
- `app/services/realtime_state.py`: live view uses the busiest host entry per
  MAC instead of whichever came last.
- Tests: `tests/test_host_metering_ghost_entries.py` replays the prod pattern.
  Under the old keying it books 655 MB for 50 MB of traffic.

Old `host:<MAC>` rows are no longer read. Each device loses at most one push
interval of usage at deploy while its new row takes a baseline.

## Data repair

Historic buckets and periods since 2026-09-25 still hold the inflated values
until they are repaired. The agreed approach: cap each customer-hour at the
plan line rate x 3600 s, take the same bytes off the owning period and pro rata
off the router's 5-minute buckets, and back up touched rows first. Re-check FUP
periods that fall back under cap while still open.

## Verification

- `grep "Clamped impossible delta"` in app logs after deploy: expect near zero.
- No new customer-hour above plan line rate (query in this note's history /
  the repair script's "after" check).
- Router 10 daily ledger should sit below its ether1 WAN total again (~55-75%).

## Follow-Up Work

- A periodic ops check that flags any customer-hour above line rate, so a
  future metering bug shows up in hours, not days.
- `usage_counter_delta`'s "any decrease = reset" rule is the amplifier. Any
  future source that can interleave two counters under one key will repeat
  this. Keep one monotonic counter per row.

## Follow-up 2026-10-02: guard misread unit-less plan speeds

The first line-rate guard parsed `plan.speed` itself and read a bare number as
bit/s, so `5/5`, `10`, `15`, `5mbps` plans got an ~8 MB ceiling per sample.
From the #159 deploy (2026-09-29 19:05 UTC) it clipped genuine usage on those
plans (2,664 clamp warnings in 30 h). The guard now reads speeds through
provisioning's own `_normalize_mikrotik_rate_part` (bare number = Mbps;
unreadable = guard off). The clipped bytes are not recoverable: the counter
baselines moved on.

Lesson: never write a second parser for a field the app already interprets.
Any historic-data repair must use the same parser too. A first SQL dry run with
the naive parse flagged 7,471 "impossible" hours, most of them false.
