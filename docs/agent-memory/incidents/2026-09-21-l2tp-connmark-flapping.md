# 2026-09-21 L2TP/IPsec connmark flapping

## Summary

Several RouterOS 6 management tunnels repeatedly disconnected even though the
routers' WAN links and the L2TP/IPsec listener were up.  Router-1139 was the
first confirmed case; a fleet audit found the same server-side failure shape on
other L2TP routers.

## Symptoms

- Router logs repeated `session closed`, `disconnected`, and occasionally
  `peer is not responding` every 30–120 seconds.
- The AWS host had multiple `iptables-legacy` mangle `MARK` rules for the exact
  same public-IP/source-port/server tuple.
- `ipsec statusall` showed long chains of IKEv1 CHILD_SAs in `REKEYED` state;
  some were retained for days with an effective 200-day expiry.
- Router-1153 also had independent hardware/power restarts.  A management
  tunnel repair cannot fix that class of outage.

## Cause

The strongSwan connmark plugin inserted a new PREROUTING mark rule for each
MikroTik CHILD_SA rekey.  `charon.delete_rekeyed` was left at its default `no`,
so superseded IKEv1 CHILD_SAs and their mark rules accumulated.  MARK rules do
not stop chain traversal: for an identical NAT-T tuple, the newest rule ran
first and a stale rule later overwrote its mark.  The packet then could not
match the live XFRM state (`Required key not available`), forcing another
reconnect/rekey cycle.

Not every similarly configured router was affected.  Routers whose upstream
NAT translated UDP 4500 to a unique public source port had distinct tuples, so
their old rules did not collide.  Routers whose NAT preserved/reused source port
4500 were vulnerable.  Shared public NAT can make the collision more likely.

## Fix Applied

- Enabled `charon.delete_rekeyed = yes` and reloaded charon settings with HUP;
  the daemon and tunnels were not restarted.
- Removed 72 superseded connmark rules across 15 exact duplicate tuples while
  keeping the newest rule for each tuple.  The pre-change ruleset is stored at
  `/var/backups/iptables-before-ipsec-mark-cleanup-20260921T143205Z.rules`.
- Disabled the enabled-but-dead `l2tp-aws2` profile pointing to retired endpoint
  `35.170.199.141` on seven reachable routers.  Primary AWS and current Hetzner
  profiles were left enabled.
- Added debounced flap/outage interpretation to the existing 30-day router
  availability store and exposed fleet and per-router history in the admin UI.

## Verification

- Duplicate exact-tuple connmark groups dropped from 15 to 0 immediately after
  cleanup.
- Router-1139 remained reachable with no new primary L2TP churn.
- Focused backend tunnel/flap tests and frontend Playwright tests passed; the
  frontend production build passed.
- Continue watching for renewed duplicate rules after MikroTik rekeys and for
  unreachable routers returning through either management path.

## Follow-Up Work

- Deploy the backend before the frontend so the UI receives the new `flapping`
  response fields.
- Add an operator alert based on repeated debounced transitions, not a single
  failed probe.
- Retry the exact retired-profile cleanup when unreachable Router-0826 returns.
- Diagnose Router-1153's reboot/power fault locally; it is independent of the
  IPsec mark collision.
