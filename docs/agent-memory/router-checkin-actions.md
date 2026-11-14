# Router actions over check-in + pending access credentials (2026-11-14)

Why: router 118 (Major1 net #1, L009, ROS 7.16.2) lost its WireGuard
management tunnel from 11 Nov ~2:08pm EAT to 14 Nov, but kept internet and
kept checking in over public HTTPS. Hotspot purchases still arrived (386 via
check-in). Everything that needed the RouterOS API failed silently:
access credentials 330/331 were never added to the router, and the revokes of
322/314/303 were marked revoked while the logins stayed live on it.

## What exists now

- `router_checkin_actions` table and `app/services/router_checkin_actions.py`.
  It is a strict allowlist: `reboot`, `heal_tunnel`, `sync_access_credentials`.
  The reply carries an action letter and numbers only. The applier owns
  every RouterOS command it runs.
- Applier v3 (`checkin_applier_script.render_checkin_applier_source(actions=True)`)
  reports `u=` uptime and `h=` heal-script presence, applies `R/H/C/D` lines,
  posts a small `ack=1&k=..&f=..` right after, and restarts last. It refuses
  to restart when the router has been up for under 5 minutes. Its policy needs
  `reboot` (`POLICY_ACTIONS`). `bitwave-heal-tunnel` is installed next to it,
  one fixed source per tunnel kind (wg/sstp). It is not gated, because it
  runs inside the applier's own gated run.
- Reboot is sent at most once and never re-sent. The state goes from
  `delivered` to `accepted` (ack) to `done` (the next uptime is shorter than
  the time since delivery). With no confirmation in 20 min it becomes
  `unconfirmed`, with no retry. There is a 10-minute cooldown between reboots.
- `POST /api/routers/{id}/reboot` reboots over the API when the router answers.
  When the connect fails and the router has made a v3 check-in in the last
  15 min, it queues the reboot and answers `status: queued` with the message
  "queued: the router will restart on its next check-in (about N min)". A
  timeout is not queued, because the command may already have reached the
  router.
- `POST /api/routers/{id}/checkin-actions` (`reboot`/`heal_tunnel`, staff
  `routers.manage`) and `GET` (state list, `routers.view`). These are
  backend-only. There is no UI button: Dennis dropped the Restart button
  from the scope on 14 Nov.
- Access credentials (`app/services/access_credential_sync.py`): if a router
  call fails, the DB change stands and `access_credentials.router_sync` =
  `add`/`remove`/`delete` (plus `_since`, `_error`, `_mac`). Revoke answers
  `router_removed: false, pending: true`. Delivery happens either through the
  API retry job (every 3 min, per-router back-off of 3 to 30 min) or over
  check-in (v3). Both are compare-and-set on `router_sync`. The admin UI shows
  "Pending: router unreachable".

## Rollout (the router side)

- The current applier (v2) is fixed code. It never fetches or imports
  anything (no `/import`, `:parse`, `:execute`), so **it cannot bootstrap a
  new script over check-in**. The only bootstrap path in the fleet would be
  the old command agent (`/import` of server text). It is off everywhere and
  is not on 118.
- So every router gets v3 over the API through `scripts/checkin_actions_rollout.py`
  (dry run by default, `ROUTER_IDS` canary, then `ALL_CHECKIN=1 MAX_UPDATES=20`
  batches, `ROLLBACK=1`). It only touches routers that already run
  `bitwave-checkin`, keeps their endpoint, certificate check and tunnel
  transport, and checks the identity.
- `standard_runtime_enrol` installs v3 on new routers only when
  `CHECKIN_APPLIER_ACTIONS=true`. Leave it off until the canary has run for
  a day.
- A router whose tunnel is down at rollout time cannot be upgraded until the
  tunnel returns (or someone pastes the script on site). After that, its
  next outage is covered.

## Not done / follow-ups

- The public access-login (`/api/public/access-login`) still binds the MAC
  over the API, so while a tunnel is down a credential user cannot log in
  through our portal page even when the hotspot user exists. Delivering that
  binding over check-in is the next step.
- `heal_tunnel` is manual only. Auto-queueing it when a router checks in
  over public HTTPS with its tunnel down for N minutes is a natural
  follow-up (it changes behaviour fleet-wide, so ask Dennis).
- v3 has static tests only. It has not been benched on a real RouterOS 6 or 7
  router yet: the canary is that bench.
