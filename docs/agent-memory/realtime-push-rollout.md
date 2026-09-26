# Real-time usage push (v2) — rollout record and rules

Single source of truth for the router push agent (`bitwave-usage-push`). **Read
this before installing, editing or copying any push script on a router.**

Owner: the "Real-time customer metrics" session (handed over 2026-09-25 from
"Billing system monitoring", which keeps the dashboard health card).

## What v2 is

- One RouterOS script + scheduler, `bitwave-usage-push`, rendered by
  `app/services/usage_push_script.py::render_realtime_push_script` — never
  hand-edited, never copied from another router (the token and identity are
  per router).
- Every report: queues in router order (target, max-limit, disabled), bypassed
  and authorized `/ip hotspot host` entries, `/ppp active`, and router health
  (CPU, memory, storage, uptime, version, board) read **before** the queue walk.
- Transport: plain HTTP **inside the router's encrypted management tunnel** to
  `http://10.251.0.1:8088/api/router/usage-push` (Caddy binds that address
  only; only the push path; only from 10.0.0.0/8; tags
  `X-Bitwave-Push-Channel: tunnel`). Port 8088 because routers carry
  `ISP_BILLING_PROXY_RELAY_BLOCK` (rejects the router's own outbound tcp
  80/3128/8080) — that rule stays. No encrypted tunnel → public HTTPS.
- Cadence is set by the server in each reply (`next_push_seconds`) and the
  script retunes its own scheduler: **60 s** for everyone; small boards that
  fall back to HTTPS 120 s; any router reporting CPU ≥ 80% backs off to 120 s
  for 10 min.
- While a tunnel is down no live data arrives; counters are cumulative, so the
  next report catches up. (The old internet push reported through tunnel
  outages — known trade-off, accepted by Dennis.)

## Server behaviour for pilot routers (`REALTIME_PILOT_ROUTER_IDS`)

- Hotspot usage metered per device from host counters (`host:<MAC>` rows);
  PPPoE from its session queue. Poller and cap sampler stand down only while
  the v2 push is fresh (< 360 s) — a router that stops pushing is collected the
  old way again, so usage is never uncounted and never double counted.
- Queue repair (orphan sweep + shadowing fix) runs as soon as a report shows a
  problem and on every queue-sync run.
- Live view: `GET /api/routers/{id}/live`, `live` block on customer usage.
  Frontend fetches on open and on Refresh only — **no timer polling**.

## Must not break (from the handoff)

- The push route calls `router_health.record_and_evaluate(..., source="push")`
  with cpu and memory present: it feeds the dashboard health card (fresh push
  < 10 min skips the RouterOS login) and CPU overload alerts (history deque 12).
- No bare `:return` in any router script (RouterOS 7.19+ rejects the whole
  script — that killed `bitwave-command-agent`).
- The endpoint's `now` is `time.monotonic()` (rate limiter) — never a DB time.

## Tools

- Install / update: `scripts/realtime_push_install.py` (dry run unless
  `APPLY=1`; refuses unencrypted tunnels; prints what it does):
  `docker exec -e ROUTER_IDS=... [-e APPLY=1] -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py`
- Rollback on a router: `/system scheduler remove [find name="bitwave-usage-push"]; /system script remove [find name="bitwave-usage-push"]`
  (the poller takes the router back within 6 min).

## Router status (2026-09-25)

| Router | Board / ROS | Push | Notes |
|---|---|---|---|
| 10 Bitwave Wangige | RB4011, 7.14 | v2 tunnel 60 s | pilot; also SNMP pilot |
| 487 OPIC #2 | RB4011, 7.21.4 | v2 tunnel 60 s | pilot; hotspot + PPPoE |
| 390 aplite Gataka | hAP lite, 6.49.6 | v2 tunnel 60 s | pilot; measured below |
| 351 HOME951, 426 LEADERS APLITE | RB951 / hAP lite | none | pilot list, unreachable — install when back |
| 141, 256, 118, 224, 163 | mixed | v1 + health, 2 min HTTPS | old "stage 1"; replace with v2 |
| 371 lee net, 195 Bilawaya | hAP lite / RB951 | — | SNMP pilot (cross-check ~1 week) |

Measured on hAP lite 390: one HTTPS request 4.9–6.8 s at 100% CPU; one tunnel
HTTP request 1.4–1.9 s; building the report 0.7–1.4 s. Average CPU at ~60 s:
51% over HTTPS, 19–23% over the tunnel (baseline ~14%).

## Held back (and why)

- 221 KARAMA, 247 Jomvu, 227 Beyond #1, 218 hEX S: multi-WAN / failover
  routing (the report's WAN figure reads `ether1` only). 227 = dual-WAN PCC
  with LB_PAID.
- 222 Ella net: CPU-optimised RB951.
- 174 Kenny #3, 258 ENNIKO: CPU spikes (47–55%).
- 184 sad #3, 308 dee.maria, 75 Kaloleni: CPU 69–86% at survey time.
- 371 lee net: 100% CPU every evening from ~17:00 EAT.
- 530 Githurai: no encrypted tunnel to Hetzner.

## Next (pending Dennis)

1. Canaries, one day each measured like 390: 224 (RB951, ROS 6), 163 (RB951,
   7.20), 521 (RB951, 7.24), 478 (hAP lite, 6 MB free).
2. Then ~10 routers/day: first the v1 routers, then those with no push.
3. Automation: add v2 to provisioning (via the backup tunnel it already
   creates) + a daily sweep that installs/updates on reachable eligible routers;
   drop the static pilot list in favour of "v2 reports are arriving".
