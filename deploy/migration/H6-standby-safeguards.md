# H6 standby safeguards (2026-08-23)

This branch is based on `origin/main` at `bd71845`, then carries the four earlier
migration commits. The old `migration/hetzner-parallel` worktree was 125 commits
behind `origin/main`, so it was left untouched.

## Live check before the code change

The check at 13:24 UTC was read-only.

- Production `54.91.202.229` was healthy. `isp_billing_app` had been up for five
  days. Its container environment pointed insurance registration and pull-service
  traffic to `91.98.238.12`; `SERVER_PUBLIC_IP` was still `54.91.202.229`.
- Hetzner had 95 peers on `wg2`, 46 with a handshake in the preceding 15 minutes,
  and 16 L2TP `ppp` interfaces. Caddy was active.
- `35.170.199.141` reset SSH and HTTP management connections from this machine.
  There are no local AWS API credentials, so its EC2 state and seven-day
  zero-activity gate could not be checked. Do not stop or terminate it on the
  strength of this audit.

## Code now in this worktree

- `RUN_SCHEDULER` defaults to `true`. When set to `false`, startup still runs the
  database migrations and warms the plan cache, but it registers no APScheduler
  jobs and does not start the scheduler. Shutdown also handles a stopped scheduler.
- `docker-compose.yml` passes through `RUN_SCHEDULER`, `SERVER_PUBLIC_IP`,
  `PULL_SERVICE_URL`, and `PROVISION_LEGACY_BASE_URL`. Existing AWS defaults remain
  unchanged.
- The Hetzner override defaults to `RUN_SCHEDULER=false`,
  `SERVER_PUBLIC_IP=91.98.238.12`, and the Hetzner pull-service URL.
- FreeRADIUS accepts NAS traffic from both `10.0.0.0/16` and the parallel Hetzner
  tunnel plane at `10.251.0.0/16`.

Focused verification: 17 tests passed across app boot, the standby kill switch,
WireGuard insurance, L2TP insurance, and conservative tunnel batching. Both the
base Compose file and the combined Hetzner configuration render successfully.
Docker Desktop was not running, so `radiusd -XC` was not available for a local
FreeRADIUS process-level check.

## Still not done

No server, router, DNS record, or Git remote was changed in this phase. The
neutralized database copy, standby stack, Caddy backend hostname, parallel CI job,
sandbox payment callback, and manual cutover runbook are still pending. The old
AWS secondary also stays in place until its activity can be read and the seven-day
gate can be proved.
