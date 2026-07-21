# Agent Notes

This file is the handoff map for coding agents working in this repository. Keep it short and link to durable project knowledge instead of turning it into a large manual.

## First Rule

- Any backend schema change must be wired into an idempotent startup migration in `main.py` and verified as part of the server restart path. A standalone script in `migrations/` is useful for manual repair/backfill, but it is never sufficient on its own.

## Worktree Rule

- ALL agents do implementation work from a dedicated git worktree, ALWAYS — even for
  small changes and even when the task doesn't ask for it (`EnterWorktree`, or
  `git worktree add <path> origin/main`). The main checkout is for reading, queries,
  and prod-access scripts only: it permanently carries other agents' uncommitted WIP,
  and working in it has already caused collisions and a production outage
  (2026-07-21: `main.py` feedback-board wiring was pushed while the four modules it
  imports sat untracked in the main checkout; the next deploy crash-looped the app
  on ModuleNotFoundError until they were committed).
- Corollary: never commit/push wiring or imports for files that are not themselves
  committed. Before pushing anything that touches `main.py`, run `git status app/`
  and confirm no untracked module you depend on is left behind.

## Project Context

- Backend: this repository, `isp-billing`.
- Frontend sibling: `../isp-billing-admin`.
- The app controls ISP billing, customer access, MikroTik routers, M-Pesa flows, subscription billing, and RADIUS/direct-router provisioning.

## Before Making Changes

- Check `docs/agent-memory/README.md` for current operational context.
- Check `docs/agent-memory/backlog.md` for deferred architecture and reliability work.
- If working on a production incident or recurring bug, read the relevant note in `docs/agent-memory/incidents/`.
- Preserve unrelated user changes in the worktree.
- Writing code that touches the DB and also does network/router I/O? Read **Database Session Discipline** below FIRST — it is the single most common cause of outages in this app.

## Database Session Discipline

Read this before writing any endpoint, background job, or service that touches the
database and also does I/O.

This app runs as a single worker with a small connection pool (`DB_POOL_SIZE=15` +
`DB_MAX_OVERFLOW=15` = 30 max). A DB transaction left open across slow or external
I/O pins a pooled connection; enough at once drains the pool and takes the whole
app down. This has caused repeated production incidents — latest and most detailed:
`docs/agent-memory/incidents/2026-06-05-db-pool-lock-convoy.md`.

Rules:

1. Keep transactions short. Read/write, `commit()`/close the session, and only
   THEN do slow I/O — RouterOS (`api.connect()`, `send_command`), any payment
   provider (M-Pesa/Safaricom, ZenoPay, MoMo), the WG-manager, any `httpx` call,
   `asyncio.sleep`, or `asyncio.to_thread` of slow work. Never `await` the network
   with a DB session open.
2. Independent side-effects (telemetry, audit, router availability) commit in their
   OWN short session — they must not ride the caller's transaction, especially for
   writes to a hot shared row like the `routers` summary row. Otherwise one stalled
   caller wedges the row lock and fans out into a pool-draining lock convoy.
3. No fan-out with a held session. Don't loop over many routers/customers with one
   session open across per-item network I/O; commit before the fan-out, or use a
   fresh short session per item.

```python
# BAD — pooled connection pinned for the whole network call
async with async_session() as db:
    row = await db.get(Model, id)
    result = await call_router_or_provider()   # entire pool slot held here
    row.field = result
    await db.commit()

# GOOD — release the DB before I/O, persist afterward
async with async_session() as db:
    data = await read_inputs(db)
    await db.commit()
result = await call_router_or_provider()        # no DB connection held
async with async_session() as db:
    await persist(db, result)
    await db.commit()
```

Guardrails already in place (do not remove without understanding why):
`idle_in_transaction_session_timeout=60s` and `lock_timeout=5s` are set on app
connections in `app/config.py` / `app/db/database.py`, so a wedged transaction
self-aborts instead of exhausting the pool.

Diagnose pool pressure with `GET /api/admin/db-pool?include_activity=true`: a
healthy pool oscillates up and down; a leak/convoy shows `idle in transaction`
sessions plus many `Lock: tuple` waiters that only clear on restart.

## Production Reliability Guardrails

- For DB pool or app-unresponsive incidents, check background jobs first, especially MikroTik cleanup, safety-net scans, bandwidth snapshots, and provisioning retry.
- DB session/transaction discipline (short transactions, never held across I/O, telemetry in its own session): see **Database Session Discipline** above — the #1 source of pool incidents.
- Optional background work must shed load when the DB pool is busy and must back off recently-offline routers instead of retrying the same unreachable devices every scheduler tick.
- Full-fleet router jobs, especially bandwidth snapshots, must be chunked and time-budgeted; do not scan every router on every short scheduler interval.
- Avoid per-router concurrent DB rechecks after router scans; batch DB verification before fan-out or after fan-in.
- Keep customer-facing request paths and payment provisioning higher priority than cleanup, snapshots, and retry safety nets.
- Current detailed lesson: `docs/agent-memory/incidents/2026-06-05-db-pool-lock-convoy.md`.

## Server Access And Deploys

- SSH access to production (key-based, non-interactive for agents), the backend
  deploy runbook, and the one-time procedure to grant the same capability on any
  new server: [`docs/agent-memory/server-access.md`](docs/agent-memory/server-access.md).
- Claude Code skill **`accessing-production-server`** (`.claude/skills/`) packages this for
  agents: how to connect and run commands/scripts inside the prod containers safely (read-only
  first, never restart). Auto-discovered — describe a prod task and it triggers, or run
  `/accessing-production-server`.
- Never commit SSH private keys, passwords, or credentials — public keys only.

## Router Provisioning Gotchas

- Provisioning import dies with `Script Error: expected end of command` at an
  `/ip hotspot` line → the router lacks the hotspot feature. Most common: hAP
  lite/mini (smips) on RouterOS 7.20+ ship hotspot as a separate, uninstalled
  package (`/tool fetch` the exact-version npk from download.mikrotik.com, reboot,
  re-run); also caused by a device-mode lock (needs physical button press).
  Full diagnosis, field-verified fix, and manual `/complete` registration for a
  router that works but never appeared in the admin panel:
  `docs/agent-memory/incidents/2026-06-10-provision-import-parse-abort-hotspot.md`.
  The admin frontend shows this runbook in the add-router flow
  (`../isp-billing-admin/app/components/HotspotPackageTroubleshoot.tsx`).

- WAN-down means management tunnel is down. If a router has no internet (WAN not
  up on `ether1`), its WireGuard management tunnel to `10.0.0.x` is also down —
  the app and `diagnose_mikrotik.py` cannot reach it. Access locally via Winbox
  Neighbors tab (connect by MAC address from a LAN port, ether2–5, not port 1),
  or serial console. Common root causes for "ether1 connected but no internet":
  upstream is fiber ONT in bridge mode (needs PPPoE, not DHCP); WAN/LAN subnet
  conflict (upstream hands `192.168.88.x`, colliding with hotspot LAN); or
  provisioning didn't complete (ether1 still in bridge). Clients not logged into
  hotspot = no internet by design (not a fault).

- Customer router already in the system acting up (clients "connected, no internet", captive
  portal not appearing, not redirected)? Use the Claude Code skill
  **`diagnose-customer-router`** (`.claude/skills/`): pass the router id for a read-only
  diagnosis against a known-good router plus a catalog of proven fixes (7.20+ hotspot-file bug,
  DHCP subnet mismatch, leftover config) — proposed, never auto-applied. Builds on
  **`accessing-production-server`** for prod access.

- **Ex-provider (second-hand) routers** — provisioning is additive, so old-ISP config survives.
  Five confirmed instances as of 2026-07-10; all on RB951/hEX from WispMan/Simbafastnet. Check:
  (1) **foreign management tunnels** (ovpn/l2tp/pptp out-interface) + schedulers that re-arm them —
  delete scheduler FIRST, then disable tunnel; (2) **`html-directory-override`** on the hotspot
  profile — silently overrides `html-directory`; clear with `set html-directory-override=""`; 
  (3) **ether2–5 in wrong bridge** — bridgeLocal vs. bridge (additive script fails silently if port
  already in a bridge); (4) **conflicting subnet on bridge** — if the old ISP used `10.0.0.x/y`,
  the router may own `10.0.0.1`, causing `ping 10.0.0.1` to return 0ms (self-ping, not our server);
  real server RTT ~200ms. Detailed incident notes + cleanup script:
  see `project-secondhand-router-onboarding` memory and
  `.claude/skills/diagnose-customer-router/cleanup_wispman_leftovers.py`.

- **L2TP NAT collision — two routers, one public IP** — when two ROS6 routers at the same premises
  dial L2TP/IPsec to the server from behind one NAT (identical public IP), each new IKE phase-1
  handshake evicts the other's SA → both tunnels cycle every ~90–120 s indefinitely, breaking
  provisioning and payment delivery. Diagnostic: availability cliff on router A matches router B's
  `created_at` exactly; both share the same `/ip cloud` public-address; L2TP logs show
  `session closed` → redial every ~90 s. Fix: separate uplinks, or migrate one to ROS7 WireGuard
  (WireGuard multiplexes any number of peers behind one NAT). Confirm with `wan_state_probe.py`
  in `.claude/skills/diagnose-customer-router/`. Backlog: warn at registration when a new L2TP
  router's WAN IP matches an existing active router's WAN IP. hAP lite gotcha: no RTC → log
  timestamps unreliable until SNTP syncs after reboot. Server-side gotcha: stale `ppp<N>` iface
  may show `10.0.100.x` via `ip -br addr` even when router is unreachable — confirm with live ping.

- **Insurance tunnel rescue** — when a router's primary L2TP/WG path is dead, reach it via the
  new AWS server: `ssh -o BatchMode=yes dennis@35.170.199.141` (passwordless sudo granted
  2026-07-19; `dennis ALL=(ALL) NOPASSWD:ALL` in `/etc/sudoers.d/99-dennis-nopasswd`), then
  connect to `10.250.0.x` or `10.250.100.x`. NOTE: no `librouteros`/`routeros_api` on that box —
  use a raw stdlib RouterOS API client piped over ssh. Proved in anger on Router-0715 (2026-07-10).

- **Router logs are EAT (UTC+3); server/DB is UTC.** When correlating MikroTik `/log print`
  timestamps against app logs, DB records, or customer expiry fields, subtract 3 hours from the
  router timestamp (or add 3h to UTC to compare). Getting this backwards produces a ~3h ghost offset
  in incident timelines.

- **SIMSEAS #4 (router 110) has a live egress tunnel as of 2026-07-19.** A `wg-egress` WireGuard
  interface (`10.60.0.2/24` → AWS `35.170.199.141:51822`) is routing ALL customer traffic through
  AWS Virginia to test Starlink congestion bypass. Off-peak this adds ~270ms latency (10× worse).
  Failover to direct Starlink in ~3s. Production plan: move egress to Hetzner `91.98.238.12`
  (see `project-simseas-starlink-egress` memory). Don't remove this tunnel without checking with Dennis.

## Feedback Board (Ideas + Bugs)

- Shared reseller feedback board (levelsio-style): bug reports / feature ideas
  with upvote/downvote, comments, statuses, and Claude AI triage on submission
  (spam filter, severity, affected area, duplicate suggestion, critical-bug
  inbox alert to the admin). Backend: `app/api/feedback_routes.py`,
  `app/api/admin_feedback_routes.py`, `app/services/feedback_queue.py`
  (priority formula + work packets), `app/services/feedback_ai.py` (Anthropic
  calls — follows Database Session Discipline; degrades to manual triage when
  `ANTHROPIC_API_KEY` is unset). Frontend: `/feedback` board +
  `/admin/feedback` triage in `../isp-billing-admin`.
- To work the queue from Claude Code, use the **`handle-feedback`** skill
  (`.claude/skills/handle-feedback/`). Status changes notify the reporter's
  inbox — never mark a post `fixed` before the fix is deployed.
- Tests: `tests/test_feedback_routes.py`, `tests/test_admin_feedback_routes.py`,
  `tests/test_feedback_ai.py`.

## AWS Migration / Insurance Tunnel Handoff

The migration strategy is deliberately staged. The first milestone is not to move
traffic or users; it is to make every reachable, eligible router reachable from
the new AWS server through a secondary management tunnel while the old production
server remains the primary control plane. Only after this safety layer exists
should the platform/database/application cutover be attempted.

### Intended Migration Phases

1. Prepare the new AWS server with a static Elastic IP and the same required
   network services: HTTP/HTTPS routing, Docker, Apache, WireGuard, and L2TP/IPsec.
2. Deploy only the small "insurance manager" service to the new server first. It
   registers backup peers/credentials and verifies ping/API reachability over the
   backup network; it is not the full billing platform.
3. From the old production admin app, add secondary tunnels to routers remotely.
   Old operations keep using the existing `10.0.0.0/16` management path.
4. Batch the backup rollout slowly across active/trial routers only. Confirm
   backup status before expanding the batch size.
5. After enough routers have verified backup reachability, deploy the full
   platform to the new server on a separate branch/CI path and test it against a
   replicated or restored database.
6. Cut over public DNS/API/frontend traffic only after router control, payments,
   background jobs, Apache routing, and database restore/replication are proven.
   Keep the old server available for rollback until the new server is stable.

### Current Server/Tunnel Facts

- Old server remains the current production app path.
- New AWS Elastic IP is `35.170.199.141`.
- Backup management network is `10.250.0.0/16`; new server side is `10.250.0.1`.
- New server WireGuard insurance interface is `wg1`, listening on UDP `51821`,
  used by RouterOS v7 routers.
- New server also has strongSwan/xl2tpd prepared for RouterOS v6 L2TP/IPsec
  insurance tunnels.
- Do not commit manager API keys, L2TP PSKs, private keys, or router credentials.
  Keep those in server env files and GitHub secrets only.

### What Has Been Proved

- Manual proof succeeded on `Router-0244`: the primary tunnel stayed up, a
  secondary WireGuard tunnel reached `10.250.0.1`, and the new server could verify
  backup reachability.
- RouterOS v7 path: secondary WireGuard is supported.
- RouterOS v6 path: secondary L2TP/IPsec is supported, using credentials from the
  linked provisioning token where available.
- The admin frontend can show planned tunnel type and backup status/progress.

### Current Implementation

- Backend implementation lives mainly in:
  `app/api/router_management.py`, `app/services/insurance_wireguard.py`,
  `app/services/insurance_l2tp.py`, and `app/services/insurance_tunnel_batch.py`.
- Frontend admin controls live in `../isp-billing-admin/app/routers/page.tsx`
  with API/types in `../isp-billing-admin/app/lib/api.ts` and `types.ts`.
- Single-router endpoint can preview or apply the correct insurance tunnel.
  Preview uses token metadata; apply still reads RouterOS version live before
  deciding WireGuard vs L2TP.
- Batch rollout is admin-only and conservative: preview first, confirmation
  required, default UI limit `5`, default concurrency `1`, backend raw-start
  fallback limit `10`, max limit `50`, max concurrency `3`.
- Batch eligibility: admin-owned routers may be processed; reseller-owned routers
  are eligible only when owner subscription is `active` or `trial`. Suspended,
  inactive, missing-owner, recently-offline, and invalid-backup-IP routers are
  skipped before router access.
- Batch progress is in backend memory, not DB schema. It stores recent job/item
  status only, caps completed job history, and truncates large stored text/list
  values. No DB migration is needed for progress display.
- DB/session rule for this rollout: load routers/tokens/owners in a short DB
  section, release the session, then perform RouterOS/manager/ping/TCP work.
  Background router work skips when DB pool pressure is warning/critical.

### Tests And Safety Checks

- Focused tests for this area include:
  `tests/test_insurance_wireguard.py`, `tests/test_insurance_l2tp.py`, and
  `tests/test_insurance_tunnel_batch.py`.
- Before pushing migration/insurance changes, run those focused tests and a
  frontend build in `../isp-billing-admin`.

### Related Docs For Perusal

- Overall agent memory index: [`docs/agent-memory/README.md`](docs/agent-memory/README.md).
- Deferred reliability/architecture work: [`docs/agent-memory/backlog.md`](docs/agent-memory/backlog.md).
- DB pool incident that drives the short-session/no-I/O-with-DB rule:
  [`docs/agent-memory/incidents/2026-06-05-db-pool-lock-convoy.md`](docs/agent-memory/incidents/2026-06-05-db-pool-lock-convoy.md).
- Earlier DB pool incidents:
  [`docs/agent-memory/incidents/2026-05-31-db-pool-exhaustion.md`](docs/agent-memory/incidents/2026-05-31-db-pool-exhaustion.md) and
  [`docs/agent-memory/incidents/2026-06-02-db-pool-exhaustion-recurrence.md`](docs/agent-memory/incidents/2026-06-02-db-pool-exhaustion-recurrence.md).
- Router provisioning/hotspot package incident:
  [`docs/agent-memory/incidents/2026-06-10-provision-import-parse-abort-hotspot.md`](docs/agent-memory/incidents/2026-06-10-provision-import-parse-abort-hotspot.md).
- Router/VPN setup background:
  [`MIKROTIK_VPN_README.md`](MIKROTIK_VPN_README.md),
  [`WIREGUARD_SETUP.md`](WIREGUARD_SETUP.md),
  [`WIREGUARD_QUICK_START.md`](WIREGUARD_QUICK_START.md), and
  [`ROUTER_SETUP_GUIDE.md`](ROUTER_SETUP_GUIDE.md).
- Docker/server setup background:
  [`DOCKER_SETUP.md`](DOCKER_SETUP.md).
- DB pool frontend/ops monitor:
  [`DB_POOL_MONITORING_FRONTEND.md`](DB_POOL_MONITORING_FRONTEND.md).

## After Incidents

When an error teaches us something useful, add or update an incident note under:

- `docs/agent-memory/incidents/`

Use `docs/agent-memory/templates/incident-learning.md` as the format. Record symptoms, suspected cause, fix, verification, and follow-up work.

## Planned Work

Use `docs/agent-memory/backlog.md` for project-level to-do items that should survive across agent sessions.

Keep backlog items concrete. Prefer:

- problem
- why it matters
- proposed next step
- status

## Testing Notes

- Prefer focused tests for the area touched.
- If tests cannot run because dependencies are missing, say that explicitly in the final handoff.
- For router/MikroTik work, distinguish DB-only behavior from live-router behavior.
