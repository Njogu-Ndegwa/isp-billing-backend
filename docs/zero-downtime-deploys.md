# Zero-downtime deploys for the ISP billing API (Hetzner)

Status: proposed 2026-10-03. The app, compose and workflow parts are in this PR.
The Caddy part needs Dennis's approval and is applied by hand
([ops/caddy/README.md](../ops/caddy/README.md)). Until it is applied, deploys
behave as they do today.

## What goes wrong today

Every deploy recreates `isp_billing_hetzner_app` in place. That makes API
requests fail for about 13 s. These are numbers from Caddy's journal and dockerd's
log on the box:

| Deploy | SIGTERM to old | old SIGKILLed | new uvicorn up | Caddy 502s |
|---|---|---|---|---|
| 2026-10-02 22:02 | ~22:02:13 | ~22:02:23 | ~22:02:26 | 60 (incl. the captive-portal `OPTIONS /api/hotspot/register-and-pay` at 22:02:16) |
| 2026-10-03 06:59 | 06:59:41.2 | 06:59:51.2 ("failed to exit within 10s of signal 15 - using the force") | 06:59:54.2 | 47, 06:59:41.3–06:59:54.0 |

Between 2026-09-30 and 2026-10-03 there were 15 deploys. Every one is a burst
of 34–118 upstream errors in Caddy's journal (the 10-02 14:02 crash loop was
several thousand). Outside deploys there were about 12 a day, almost all
`POST` `EOF`/`reset`.

Three facts on the box rule out the simple fixes:

1. **The gap starts at SIGTERM, not at SIGKILL.** uvicorn closes its listening
   socket as soon as it gets SIGTERM. Every second of shutdown grace is a
   second of refused requests. Graceful shutdown alone makes the gap longer.
2. **Caddy can't see a dial failure.** The app is published on
   `127.0.0.1:8000` through `docker-proxy`, which accepts the TCP connection
   even when nothing listens behind it. It then resets the connection. Caddy has
   already written the request by then, so the error is a read error, not a
   dial error. Of the 47 errors at 06:59, none were `connection refused`.
3. **Caddy 2.6.2 only retries GET after a non-dial error** (`tryAgain` in
   `reverseproxy.go` at v2.6.2). So `lb_try_duration` alone would not have
   saved the `OPTIONS` preflight or the `POST` behind it.

The steady-state errors have a separate cause. uvicorn closes an idle
keep-alive connection after 5 s (`--timeout-keep-alive 5`), and Caddy keeps
idle upstream connections for 2 min. Caddy sometimes sends a POST on a
connection uvicorn is closing.

## Options considered

**1. Caddy waits (`lb_try_duration` / `lb_try_interval`).** This is cheap but
not enough on its own, because of facts 2 and 3. It only covers dial failures,
and docker-proxy turns those into resets. `lb_retry_match` could include POST,
but then Caddy would replay payments that may have reached the app. We keep it
as a safety net (30 s, GET/HEAD/OPTIONS only), not as the fix.

**2. Blue/green.** This is the only option that closes the gap: a ready
container must be serving before the old one gets SIGTERM. Two constraints
shape it:

- *One scheduler.* APScheduler runs in-process with `RUN_SCHEDULER=true`
  (expiry removal, M-Pesa reconciliation, SMS, B2B payout). Two schedulers
  against one DB is the 2026-09-22 class of incident. No request handler
  depends on the scheduler (no `add_job` outside startup).
- *Tooling expects `isp_billing_hetzner_app`.* Skills, runbooks, the
  deploy's `docker exec` checks and the rollback all use that container
  name, and compose owns it.

**3. Graceful shutdown (`stop_grace_period`).** This is necessary but not
sufficient (fact 1). It matters once the container is out of rotation before
SIGTERM: in-flight requests and their `BackgroundTasks` finish instead of
being SIGKILLed at 10 s, as happened at 06:59.

## Chosen design: a bridge container plus a health-checked second slot

Caddy load-balances each API site block over two fixed slots,
`127.0.0.1:8000` (the compose `web` service, unchanged) and `127.0.0.1:8001`.
`lb_policy first` sends traffic to the first slot that is healthy. Caddy
probes `GET /health/ready` every 2 s. That endpoint returns 200, or 503 once the
container's drain flag `/tmp/isp-billing-draining` exists. Slot 8001 is empty
except during a deploy.

The deploy, after the existing build, smoke test and last-good tag:

1. `docker compose run -d --no-deps --name isp_billing_hetzner_app_bridge -p 127.0.0.1:8001:8000 -e RUN_SCHEDULER=false -e SCHEDULER_ENABLED=false web`
   starts the **new** image as a one-off container of the same service (same
   env file, network, read-only fs, dropped caps), with **no scheduler**. If it
   never becomes ready, the deploy stops. Nothing live was touched.
2. Wait 6 s so Caddy sees :8001 healthy. Traffic is still on :8000.
3. **Drain** the old canonical container: touch the flag, wait 6 s. Caddy
   now sends everything to the bridge.
4. `docker stop -t 30` the old container. It is out of rotation, so
   uvicorn has up to 20 s (`--timeout-graceful-shutdown`) to finish in-flight
   work, then runs the shutdown hook (scheduler stop, heartbeat retirement).
5. `docker compose up -d --no-deps --no-build web` creates the new canonical
   container on :8000, and **its scheduler starts**. The old scheduler has
   already stopped, so two never overlap. Scheduled jobs pause for up to
   ~35 s (today ~13 s). Interval jobs run on their next tick. A cron job
   (daily cleanup, B2B payout) whose fire time falls inside the pause waits
   until its next fire time. That already happens with today's gap.
6. When `/health` passes, wait 6 s. `lb_policy first` moves traffic back to :8000.
7. Drain the bridge, stop it gracefully and remove it.

If the new canonical container fails its health check, the existing rollback
runs while the bridge keeps serving customers. The bridge is retired only once
the rollback is healthy. If the rollback fails too, the bridge is left
running, because it is the only thing serving.

**Fallback.** If Caddy has no :8001 upstream (checked through the admin API,
`/reverse_proxy/upstreams`), or less than 800 MiB is available, the deploy
uses today's stop/start swap with the old 10 s stop timeout. That makes the PR
safe to merge before the Caddy change. It also means rolling Caddy back needs
no matching code change.

**Why not switch Caddy's upstream per deploy** (rewrite an import and
`caddy reload`)? It would make every deploy a production Caddy change.
With this design, Caddy is changed once, with approval, and deploys never
touch it.

**Why a bridge instead of alternating blue/green slots?** Alternating slots
would leave production as `…_blue` half the time and `…_green` the other half.
That breaks every `docker exec isp_billing_hetzner_app` in skills and
runbooks. It also needs a second compose service or project, and some form of
scheduler leader election. The bridge keeps compose and the container name
exactly as they are. The cost is two app starts per deploy (startup
migrations are idempotent "already exists, skipping" checks) and about 30 s
more deploy time.

## Constraints checked on the box (2026-10-03, read-only)

- **Memory.** 3.7 GiB total, 1.8 GiB available. The app uses 465 MiB, so two app
  containers fit. The image build (~2 GiB) finishes before the bridge starts,
  and the deploy checks `MemAvailable ≥ 800 MiB` first.
- **Postgres.** `max_connections` is 100 and 28 were in use. Each app has a
  pool of at most 30 (`DB_POOL_SIZE` 15 + 15 overflow), so two apps fit, and the
  outgoing app's pool empties as it drains. DB session discipline is unaffected:
  the bridge runs the same request code, with no new long-lived connection.
- **Network.** iptables has no per-container-IP rules for the app. Egress is
  MASQUERADE for 172.20.0.0/16 and the only INPUT rule covers the whole subnet,
  so the bridge reaches routers, RADIUS and Postgres like the app does.
- **Caddy 2.6.2 log volume.** Active health checks log every failed probe
  at INFO, and :8001 fails continuously outside deploys. Those lines go to
  `/var/lib/caddy/upstream-health.log` (5 MiB × 2) instead of the journal. The
  app filters `/health/ready` out of its access log.

## Risks and open questions

- **Schema migrations now run while the old container serves traffic.**
  Today startup `ALTER TABLE`s run during the outage, with no traffic. Under
  the bridge they run on the bridge while the old container still serves.
  Every current migration is "add if missing", but a new one that takes an
  `ACCESS EXCLUSIVE` lock on a hot table could queue behind live queries.
  New migrations should stay additive and set a `lock_timeout`.
- **Fire-and-forget `asyncio.create_task` work** (31 call sites, e.g. the
  real-time push installer) dies with whichever process started it, as it
  does today. Graceful shutdown only protects request-scoped work and
  `BackgroundTasks`. `catch_up_after_restart` already covers the push
  installer.
- **Why the old container ignored SIGTERM for 10 s is still unknown.** Its
  logs were removed along with the container. Candidates are long requests
  or `asyncio.to_thread` workers blocked on RouterOS I/O. The deploy now
  logs `isp_billing_hetzner_app stopped in Ns`, which gives the answer on the
  next deploy.
- **Requests can wait up to 30 s instead of failing** when no slot is
  healthy, for example if the app crash-loops. That is better for customers but
  holds more open connections in Caddy during a real outage or a flood. See
  `ddos-attack-response`.
- **Not tested end-to-end.** No Caddy + docker-proxy rehearsal has been run.
  The PR has unit tests and a parse check of the Caddyfile by production's own
  Caddy (`caddy adapt`). The first deploy after the Caddy change is the real
  test, so watch it: the expected result is 0 `"level":"error"` lines in
  Caddy's journal for the deploy window.
