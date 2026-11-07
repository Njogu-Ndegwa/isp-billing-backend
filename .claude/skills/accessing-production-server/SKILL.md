---
name: accessing-production-server
description: >
  Use when a task needs the production server or anything behind it — querying/fixing customer
  MikroTik routers (on the 10.0.0.x management-tunnel addresses), reading app logs, checking
  DB-pool pressure, inspecting Postgres, or running a one-off script against the live app.
  Covers connecting over key-based SSH and running commands/scripts safely inside the prod
  Docker containers. Production is the Hetzner box (91.98.238.12) since 2026-09-22; the old AWS
  box is a fenced standby whose app must stay stopped. Read-only first, never restart.
---

# Accessing the Production Server

## Overview
Everything runs on one Hetzner box, and customer routers are reachable **only through it**.
**Core rule: read-only by default, never restart anything, check `free -h` before heavy work.**

## Connect
- `ssh -o BatchMode=yes root@91.98.238.12` — Hetzner box (Nuremberg), hostname `egress-nbg1`.
  The hostname is historical (it began as the router-110 Starlink egress relay and became the
  primary on 2026-09-22) — it is the right server, do not go looking for another one.
- **Key-based, non-interactive** (`~/.ssh/id_ed25519`, key comment `claude-code-dennis`); no
  password prompt. Password auth is disabled on this box and must stay disabled.
- **First time / no access yet:** SSH is key-only — someone who already has access must append
  your SSH **public** key to `root`'s `~/.ssh/authorized_keys` (onboarding procedure:
  `docs/agent-memory/server-access.md`). You cannot self-serve this.
  Verify access: `ssh -o BatchMode=yes root@91.98.238.12 'echo ok'`.
- A router with WAN down has its mgmt tunnel down too ⇒ unreachable from here; fix locally.

## The box
- 3.7 GiB RAM, ~2.1 GiB available under normal load. Far roomier than the old 1 GB AWS box,
  but an image build takes ~2 GiB — run `free -h` before anything heavy and don't stack
  memory-hungry one-offs on top of a deploy.
- Docker containers:
  - **`isp_billing_hetzner_app`** — the FastAPI app (uvicorn :8000, loopback-only; Caddy fronts
    80/443). Has the app code, DB creds, the `MikroTikAPI` client, and sits on the management
    tunnels — so it can reach routers (your workstation can't). Run router/DB scripts *inside* it.
  - `isp_billing_hetzner_db` (Postgres 15) · `isp_billing_hetzner_radius` · `isp-admin` (admin
    frontend) · `insurance_wg_manager_hz` (wg2 tunnel manager) · `pull-svc`.
- Repo checkout: `/opt/isp-billing-shadow/repo` tracking `origin/main` ("shadow" in the path is
  historical; `.env.hetzner` has `SHADOW_MODE=false`, `RUN_SCHEDULER=true` — this is live).
- **Router addressing:** the DB stores every router as `10.0.X.Y` and that is the address you
  use. The host routes it natively through the Hetzner wg2 peer (`10.251.X.Y`) once
  `isp-native-router-routes.timer` (30 s, `ops/native-router-route-sync.py`) has proved TCP 8728
  through it, and otherwise falls back to `wg-aws-transit` via the AWS box (~298 ms instead of
  ~134 ms — expect slower RouterOS calls on those). Scripts never need to pick a path.

## The AWS box is a fenced standby — do not start its app
`dennis@54.91.202.229` still runs `isp_billing_postgres`, `isp_billing_radius` and
`isp_wg_manager` because its tunnels carry transit for routers without a native Hetzner path.
**`isp_billing_app` there must stay STOPPED.** Starting it on 2026-09-22 let a stale scheduler
delete 1,062 paid-client router bindings. Never `docker compose up` on that box.
- You don't need AWS to reach routers: run router scripts in `isp_billing_hetzner_app`, which
  reaches every router natively or through `wg-aws-transit`.
- If you do SSH there: no `docker compose/start/restart/run/exec`, no `.env` edits, stdlib
  `python3` only, clean `/tmp` afterwards, and one SSH connection at a time — UFW `LIMIT` on
  port 22 resets rapid reconnects. Finish with `docker ps` showing only postgres, radius and
  wg-manager. Full rules: AGENTS.md "Rules for agents on the AWS box".

## Run patterns
- **One-off command / logs:**
  ```bash
  ssh -o BatchMode=yes root@91.98.238.12 'docker logs --since 24h isp_billing_hetzner_app'
  ```
- **Run a Python script inside the app container** (best for router/DB work — reuses the app's
  client + models). Pipe it via **stdin** so you avoid quote-nesting through ssh→sh→docker;
  pass inputs with `-e`:
  ```bash
  ssh -o BatchMode=yes root@91.98.238.12 \
    "docker exec -e ROUTER_ID=201 -i isp_billing_hetzner_app python -" < your_script.py
  ```
  Do NOT hand-nest quotes inside the remote command — it gets mangled. Use the stdin pipe (a
  local file or a `<<'EOF'` heredoc) so the script arrives literal. The container is
  `read_only` with a 128 MB tmpfs on `/tmp` — write scratch output there or to stdout only.
- **Reach a router:** inside `isp_billing_hetzner_app`, read the router's creds from the DB in a
  short session, release it, then use `app.services.mikrotik_api.MikroTikAPI` against its stored
  `10.0.X.Y` IP.
- **Read-only SQL:** `docker exec -i isp_billing_hetzner_db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -qAt -f -'`
  with the SQL on stdin — the DB user/name live in `.env.hetzner`, and the container's own
  environment carries them, so never hard-code them.

## Safety rules (do not violate)
1. **Read-only by default.** `print`/`get`/logs/SELECT only. Show the user any write command and
   get explicit approval first.
2. **Never restart** a container, service, or the box. No reboots, no `/system reset`. Deploys
   go through CI (`.github/workflows/deploy.yml`) or the manual runbook in
   `docs/agent-memory/server-access.md` — never `docker compose down`.
3. **Memory:** `free -h` first; one `docker exec python` at a time; keep scripts light; dispose
   DB engines/sessions when done.
4. **DB session discipline:** read in a short session, `commit()`/close, THEN do network I/O —
   never hold a DB connection across RouterOS/HTTP/`sleep` calls (AGENTS.md). The app's API
   client UTF-8-decodes responses, so binary file contents can crash it — read **text only**,
   per-file (`/file print` caps `contents` at ~4 KB).
5. **Confirm outward/irreversible actions** (writes, deploys, deletes) before running.

## Diagnostics
- DB pool pressure: `GET /api/admin/db-pool?include_activity=true` (healthy pool oscillates;
  `idle in transaction` + many `Lock: tuple` waiters = a leak/convoy that clears only on restart).
- App logs: `docker logs --since <window> isp_billing_hetzner_app`.
- Which path a router is on: `systemctl status isp-native-router-routes.timer` and
  `ip route get 10.0.X.Y` (dev `wg2` = native, `wg-aws-transit` = fallback).
- Public health: `curl -sI https://isp.bitwavetechnologies.net/health` → `x-served-by: hetzner-api`,
  `X-ISP-Runtime-Mode: active`.

## Related
- `diagnose-customer-router` — applies this access to hotspot / captive-portal faults.
- `docs/agent-memory/server-access.md` — full SSH/deploy runbook, AWS standby facts, new-server
  key onboarding.
- AGENTS.md "Database Session Discipline" — the #1 cause of prod outages here.
