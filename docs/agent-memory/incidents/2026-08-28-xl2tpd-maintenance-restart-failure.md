# 2026-08-28 L2TP Fleet Management Outage

## Summary

The production L2TP server stopped accepting management tunnels while affected
MikroTik routers retained normal WAN internet. RouterOS v6 routers therefore
looked healthy to customers but could not reach the management gateway at
`10.0.0.1`, and the application could not administer them.

The registered blast radius was 59 L2TP routers. Seven were confirmed online in
the hour before the outage and ten in the preceding 24 hours; those are lower
bounds on routers that lost an active management path. Router 330
(`Router-0839`, `10.0.100.9`) was the reported case.

A second report was matched to MSANII's Router 224 (`Router-0582`,
`10.0.100.35`). Its L2TP route returned automatically as `ppp9` after the
shared service recovery, confirming this was the same fleet incident rather
than an unrelated router fault.

## Symptoms

- At 2026-08-28 09:17:55 EAT (06:17:55 UTC), `xl2tpd.service` entered `failed`.
- The host had no UDP 1701 listener, no PPP sessions, and no `/32` route to the
  reported router.
- The router could ping the public internet but timed out pinging `10.0.0.1`.
- The application's last successful contact with router 330 was 08:32 EAT.
- No shared-tunnel health was exposed in the admin frontend, so the failure was
  discovered from a customer-router symptom rather than a fleet alert.

## Suspected Cause

The system journal and unattended-upgrade log align the failure with automatic
package maintenance. During the service restart cascade, systemd reported PPP
processes remaining after `xl2tpd` stopped and then found leftover processes
while starting it again. The start exited with status 1.

Debian generated the unit from the SysV init script with `Restart=no`,
`GuessMainPID=no`, `RemainAfterExit=yes`, and `KillMode=process`. That combination
did not track the daemon reliably, did not stop its PPP child processes as a
unit, and made no recovery attempt after the failed start.

## Fix Applied

- Started the already-failed `xl2tpd` service once; no server or router reboot
  was performed.
- Router 330 re-established `ppp0` automatically and regained its
  `10.0.100.9/32` route.
- Router 224 re-established `ppp9` and regained its `10.0.100.35/32` route;
  no router-side change was needed.
- Added a combined WireGuard/L2TP manager health response and admin API.
- Added an admin frontend monitor with 30-second polling, a detailed dashboard
  view, and a critical alert across admin pages.
- Added `ops/systemd/xl2tpd-recovery.conf` for daemon tracking, child-process
  cleanup, and automatic retry. It still requires a controlled production
  installation.

## Verification

- UDP 1701 listened after recovery and 16 PPP sessions returned immediately.
- Router 330 passed the full read-only router diagnostic.
- Router-originated ping to `10.0.0.1`: 4/4 replies, 0% packet loss.
- Router 224 also returned 4/4 replies to `10.0.0.1` with 0% packet loss.
- Backend focused tests: `5 passed`.
- Frontend Vitest suite: `81 passed`; production build succeeded.
- Focused desktop/mobile Playwright checks: `2 passed`.

## Follow-Up Work

- Install and inspect the systemd recovery drop-in on production without
  restarting the live service.
- Deploy the manager/API/frontend health feature through the normal release
  path.
- Add an out-of-band notification channel if admin-page visibility alone is not
  sufficient; the health endpoint now supplies the source signal.
