# Real-time usage push (v3) — rollout record and rules

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

## Which routers are on it

A router is on the real-time push when it is listed in `REALTIME_PILOT_ROUTER_IDS`
**or** has sent a v3 report in the last 15 min (`realtime_state.note_realtime_report`).
Only the installer puts v3 on a router, so installing is the opt-in and restoring
the old script is the opt-out. No redeploy per batch.

## Server behaviour for real-time routers

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

- Install / update / roll back: `scripts/realtime_push_install.py`. Dry run unless `APPLY=1`.
  - `ROLLBACK=1` restores `bitwave-usage-push-prev` (kept on the router at install), or removes the push when there was none.
  - `SKIP_RUN=1` skips the first run over the API, so the scheduler's first tick sends it.
  - It detects the WAN (active default route), refuses unencrypted tunnels and skips hAP lite/mini (see below).
  - It prints one `RESULT` JSON line per router.
  - Always take the installer from `origin/main` after a merge: a stale copy put the push on a hAP lite (439) on 2026-09-26.

  `docker exec -e ROUTER_IDS=... [-e APPLY=1|-e ROLLBACK=1] [-e SKIP_RUN=1] -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py`
- Rejected reports are logged as `[USAGE-PUSH] 422 from <identity> via <channel>: <field> <text>`.
- Measuring what we cost a router: `/tool profile duration=60` (read-only). Scripts show as `console`; API logins and fetches show as `management`; TLS shows as `ssl`/`ssld`.

## Fleet status (2026-09-26, end of rollout day)

- **On the push: 52 routers** (RB951, hEX S, RB4011, RB5009, L009, hAP ax, hAP ac lite; ROS 6.49 to 7.24; WireGuard / SSTP / L2TP+IPsec). All reporting every minute; no rejected reports since #121.
- **Cost measured with `/tool profile` (60 s):** usage push + expiry reaper = 1–3% CPU on an RB951, under 1% on RB4011/RB5009/hAP ax.
  - The big cost was `bitwave-checkin` at 10 s over HTTPS: 30–45% on RB951s. Fixed by #124 (other session): 221 went from 85% to 16% CPU, 316 from 64% to 23%.
- **Server at ~50 routers:** app ~5–17% CPU, DB ~5%, pool 0–2.
- The first reports also cleared hundreds of shadowing queues (e.g. 57 on 247, 54 on 446, 50 on 316).

## Not on the push (and why)

- **hAP lite / hAP mini (smips, 32 MB): stay on server polling — Dennis's decision, 2026-09-26.** With the push on top of our other schedulers (watchdog, check-in, command agent, reaper), 483 and 486 sat at 100% CPU with ~5 MB free and a paying customer's access was delayed ~11 min. The push was rolled back on all of them.
  - The installer skips them (`ALLOW_SMALL=1` overrides; don't use it).
  - The server answers any v3 report from one with `next_push_seconds=3600`.
- 351 HOME951: tunnel ping fails, so HTTPS; 80–90% CPU on an RB951. Rolled back.
- 131 Major1 Net: RouterOS device-mode "configuration flagged" blocks adding the scheduler. A security flag; needs the physical button.
- 365 / 367 Yetunet: the API connection drops on every script upload.
- 210 Lux, 378 TSJFIBERNET (on the push, down since 14:09 UTC): offline. 426 LEADERS: no encrypted tunnel.

## Gotchas learnt

- ROS 7 returns **empty** values for an entry that disappears between `find` and `get`. Every unquoted JSON field must be type-checked, or the whole report is rejected (#121).
- ROS 7 drivers can return empty counters (RB4011 rx-error, #109).
- `routers.last_online_at` only moves when something touches the router, so a quiet router looks offline. Check with ping + tcp/8728 from the host before calling one down.
