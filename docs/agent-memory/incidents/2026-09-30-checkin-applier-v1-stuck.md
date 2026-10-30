# 2026-09-30 Check-in applier stuck on v1 after MAC login went fleet-wide

## Summary

Kaloleni SkyNet Pro.1-KLN (router 75, Router-0145, reseller festusyaa30) had paying
clients added late or not at all. Two faults stacked:

1. The router's RouterOS API was flaky (RB951Ui-2HnD, 128 MB, CPU 70-83 %, an unclean
   reboot at ~08:17 UTC). Payment-time pushes kept failing and retrying. Over 48 h, 228
   deliveries averaged 1.4 min (max 50 min) against 0.1 min on the same reseller's router 189.
   Customer 25321 (Guest 3667) paid for 1 hour at 07:09 UTC and was never delivered before
   expiry.
2. The check-in, which should rescue failed pushes, delivered nothing there. The router
   still ran check-in applier **v1**. With `HOTSPOT_MAC_LOGIN_ROUTER_IDS=all`, `decide()` forces
   a MAC-login router with a v1 applier into `push_only`, which the logs show as
   `[CHECKIN] push_only router 75: not sending N add line(s)`. The env lists
   `CHECKIN_PUSH_ONLY_ROUTER_IDS` / `CHECKIN_ONLY_ROUTER_IDS` were both empty.

## Symptoms

- `Connection to 10.0.0.4:8728 timed out`, `Login failed to 10.0.0.4: []`, `Read timeout`
  every hour; ping over wg2 fine (~230 ms, 0 % loss).
- `push_only router 75` every minute while no router was listed as push_only.
- The "missing" MACs listed there were actually present as MAC-login hotspot users (a v1
  applier does not report them).

## Cause

Applier v2 (commit 0d879b0, 2026-09-28 23:53 +03) was only installed by
`scripts/hotspot_mac_login_convert.py` (per-router conversion). Routers moved to MAC login by
the `all` flag never ran it, and `standard_runtime_enrol` only installs where
`checkin_installed_at IS NULL`, so it never revisits an installed router. Six routers were
left on v1: 75, 241, 378, 539, 544, 545 (all installed 2026-09-28, before v2).

## Fix Applied

- Ops, 2026-09-30 ~08:35 UTC: `install_checkin_applier` re-run on the six routers (identity
  checked, CPU < 90 %). The next reports were v2 and every flagged MAC resolved `present`.
- Code: `checkin_delivery` records each router's latest report `v=` and exposes
  `outdated_applier_router_ids()`; `standard_runtime_enrol.load_candidates` also picks
  installed routers whose applier is older than `CURRENT_APPLIER_VERSION`. **Bump
  `CURRENT_APPLIER_VERSION` with every applier template change** so the fleet follows.

## Verification

- `tests/test_standard_runtime_enrol.py::test_outdated_applier_is_upgraded_in_place`, plus the
  check-in and MAC-login suites.
- Prod logs after the upgrade: `[CHECKIN] router 75: ... resolved (present)`.

## Follow-Up Work

- Router 75 hardware/power: unclean reboot, high CPU. Suggest a UPS or a hAP ac2/ax lite.
- 13 check-in routers were unreachable during the sweep (155, 162, 224, 275, 333, 369, 393,
  396, 446, 451, 452, 538, 543). With this fix, the enrol job upgrades them after they come
  back and report v1.
- Customer 25321 still needs its lost hour credited (outage compensation for router 75,
  window 07:09-08:09 UTC, everyone else excluded).
