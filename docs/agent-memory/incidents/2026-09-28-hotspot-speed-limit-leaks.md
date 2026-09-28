# 2026-09-28 Hotspot customers exceed their plan speed (fleet-wide)

## Summary

Resellers saw hotspot customers on their dashboards running faster than the
plan they paid for. Several routers were affected. The bypass delivery model
(`ip-binding type=bypassed` + a static `plan_<MAC>` simple queue aimed at the
device's IP at payment time) leaks speed in several independent ways. Fix
direction chosen: MAC login (`login-by=mac`, user named after the MAC, speed in
the user profile), so RouterOS owns a per-session queue that follows the device.
Pilot router: 10 (Bitwave Wangige, RB4011, ROS 7.14).

## Symptoms

- Dashboard live rates above plan speed.
- Router 10 (read-only snapshot, 2026-09-28): 24 paid bypassed customers; 4 of
  the 24 `plan_` queues were **disabled** (= no limit), one targeted
  `10.40.32.111/32`, not on the hotspot LAN; 64 hotspot users vs 24 bindings
  (expired customers' users are never deleted: harmless under bypass, free
  internet under MAC login).

## Suspected Cause

Code-level findings (a fleet-wide live survey was not run yet):

1. `ensure_queue_fasttrack_bypass` (mikrotik_api.py) **removes then re-adds**
   the FastTrack-exempt accept rules on every sync. In the gap, every live
   connection hits `fasttrack-connection` and stays FastTracked (queue-free)
   until it closes.
2. Queue sync compares `"5M/5M"` with RouterOS's `"5000000/5000000"`
   (`_sync_single_router_queues_sync`), so every queue is rewritten every run;
   the 50-op per-router budget runs out and customers past #50 never get a
   queue or a re-target.
3. Static queues target an IP; a DHCP renewal/new IP leaves the device
   unlimited until the router's next sync turn (4 routers / 313 s rotation).
4. Several delivery paths bypass with no queue or no FastTrack exemption
   (access credentials, router transfer, legacy public routes, queue pending).
5. Plan queues are appended at the bottom; any broader queue above wins, and
   the `hs-` parent queue returns after every hotspot restart.

External research: PHPNuxBill and RADIUS-based systems (Splynx) log devices in
as hotspot users with a rate-limited profile; MikroTik documents that FastTrack
skips simple queues and that a FastTracked connection stays so until it closes.

## Fix Applied

- `app/services/hotspot_mac_login.py` (new): router setup (adds `mac` to
  `login-by`; interface-list based FastTrack exemption, add/move only),
  provision/verify/FUP/remove per customer, `reconcile_router` (provisions
  missing users, deletes tagged users with no paid customer after a 15-min
  grace, leaves not-yet-converted bypass customers alone).
- Enabled per router by `HOTSPOT_MAC_LOGIN_ROUTER_IDS`. Payment provisioning,
  queue sync (always runs for these routers), check-in (forced push-only, so no
  A lines re-add bindings), FUP, real-time repair (skipped) and the live
  dashboards are MAC-login aware. All user-removal paths match MAC-login users.
- `scripts/hotspot_mac_login_convert.py`: dry-run / apply / revert, with
  `ONLY_MACS` for a canary device.

## Verification

- `tests/test_hotspot_mac_login.py` against a fake RouterOS.
- On router 10 after apply: `/ip hotspot active` shows `login-by=mac` sessions,
  `<hotspot-AA:BB:..>` dynamic queues with `max-limit=5000000/5000000`, no
  bypassed `USER:` bindings, live rates at or below 5 Mbps.

## Follow-Up Work

- Router-side expiry: the expiry reaper only reaps bindings; MAC-login users
  carry `EXP:<epoch>` in their comment so the reaper can be extended to them
  (today they expire only via the server while the tunnel is up).
- Push script: report `<hotspot-*>` dynamic queues so the live view shows the
  real limit instead of `router_managed`.
- Move the other bypass paths (access credentials, router transfer, comped
  devices, pull/agent routers, new-router bootstrap) to MAC login before a
  fleet-wide flip; Level-4 licence routers allow only 200 logged-in users.
- Independent of the pilot, fix the bypass path for the rest of the fleet:
  compare `max-limit` in bps, stop the FastTrack rule remove/re-add.
