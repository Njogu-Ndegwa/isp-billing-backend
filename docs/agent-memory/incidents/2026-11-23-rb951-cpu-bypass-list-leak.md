# 2026-11-23 RB951 CPU: queue-bypass address list leak, dead wg-aws watchdog slow path

## Summary

A fleet pass over the 69 online RB951s found our own router scripts holding
several boards at 100% CPU for 20-40 s of every minute. The amplifier was the
`isp_queue_limited_clients` address list, which only ever grew; a dead `wg-aws`
peer pushed the WireGuard watchdog down its slow path every minute; and every
check-in paid a TLS handshake. All three were relieved on the routers the same
day; this change keeps them from coming back.

One self-inflicted management blip happened during the pilot (see below).

## Symptoms

- Router 75 (Kaloleni, RB951, ~25 Mbps, 30 users): 90% average CPU, 55% of
  seconds at 100%, peaks lined up with the Bitwave schedulers at :40 each
  minute. `/tool profile`: management + console ~47% of the CPU.
- Router 221 (KARAMA, load-balanced): 86 Bitwave script runs refused in 80 min
  with `bw-gate: deferred while an earlier Bitwave job is still running`.
- Watchdog jobs alive 60-70 s out of every 120 s on 75 and 221.
- The pushed CPU figure (dashboard dial, `router_health`) read high on idle
  boards (router 303: 62% pushed vs 8% profiled) because it is sampled inside
  the usage-push run, right after the other gated scripts.

## Suspected Cause

- `ensure_queue_fasttrack_bypass` (and the check-in applier) add every queued
  customer IP to `isp_queue_limited_clients` and nothing ever removes one. 75
  had 1,551 entries (110 live), 221 had 2,241 (217 live). Every
  `/ip firewall address-list find where list=...` in the watchdog, reaper and
  check-in scans the whole table; on a 600 MHz single-core board under traffic
  each run took tens of seconds, and the one-at-a-time gate deferred the rest.
- `wg-aws` peers to the retired AWS box have no handshake on many routers, so
  the WireGuard watchdog v5 fast path ("every watched peer fresh") never held.
- Check-in posted over public HTTPS (`ssld`/`certificate` in profiles).

## Fix Applied

Router side, 2026-11-23 12:50-13:50 UTC, 64 RB951s (script kept in the session
scratchpad, not committed): pruned ~6,840 stale list entries; added a wg-hz
fast path to `bw-mgmt-watchdog-wg` (backup `bw-mgmt-watchdog-wg-prev`); wrapped
the check-in fetch with the existing tunnel transport on RouterOS 7 (backup
`bitwave-checkin-prev`). 195, 210, 396, 619, 678, 681 were offline.

Code (this change):
- `MikroTikAPI.prune_queue_fasttrack_bypass_list` + `live_router_ips`; the queue
  sync prunes with its own reads (only when all of them succeeded), MAC-login
  routers read their own live IPs. Floors/caps in `mikrotik_api.py`.
- WireGuard watchdog v6 template: exit while a wg-hz peer handshook < 4 min.
- `CHECKIN_TUNNEL_ROUTER_IDS=ros7`: tunnel-first check-in for every RouterOS 7
  router installed by the standard runtime enrolment.
- PPPoE FastTrack bypass: one covering network per tight pool range instead of
  13 blocks (26 rules every forwarded packet walked on 354/537/737); superseded
  block rules are removed after the new pair exists.

## Verification

- Router 75: average CPU 90% -> 63% after the prune alone (time at 100%
  55% -> 4%); scripts' share ~47% -> ~9% (60 s profile). 221: 70% -> 25%.
- Fleet re-check after rollout: 59/59 reachable routers kept every Bitwave
  scheduler advancing, no new script errors.
- Tests: `tests/test_rb951_cpu_relief.py` plus the existing watchdog, enrolment,
  PPPoE, queue sync and check-in tunnel suites.

## The pilot blip: never disable wg-aws

Disabling `wg-aws` on router 75 (to restore the watchdog fast path) cut it off
from management for ~4 min: the router's DB address `10.0.0.4/16` is assigned ON
`wg-aws`, and Hetzner routes `10.0.X.Y` into wg2 via the peer's allowed-ips.
Recovered over the router's wg-hz address (`wg show wg2 allowed-ips | grep
10.0.X.Y/32` gives `10.251.X.Y`). No payments in the window. The wg-aws
retirement work moves the address to a loopback bridge before disabling.

## Follow-Up Work

- After deploy: set `CHECKIN_TUNNEL_ROUTER_IDS=ros7` in `.env.hetzner`.
- Pushed CPU: sample it outside the script burst (or label it) before using it
  for alerts or reseller advice.
- `bitwave-command-agent` fails every 2 min with `:return` on 449/454/471
  (RouterOS 7.19+): disable it there or ship the fixed agent.
- Traffic-bound RB951s (737 ~60 Mbps at 67%, 542, 374, 75): upgrade advice to
  resellers (hEX / L009 class).
- 590: load balancing on with a dead WAN2 (no link, DHCP stopped).
