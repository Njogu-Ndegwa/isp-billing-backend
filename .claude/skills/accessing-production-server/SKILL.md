---
name: accessing-production-server
description: >
  Use when a task needs the production server or anything behind it — querying/fixing customer
  MikroTik routers (on the 10.0.0.x WireGuard tunnel), reading app logs, checking DB-pool
  pressure, inspecting Postgres, or running a one-off script against the live app. Covers
  connecting over key-based SSH and running commands/scripts safely inside the prod Docker
  containers. The box is ~1 GB RAM — read-only first, never restart.
---

# Accessing the Production Server

## Overview
Everything runs on one small AWS box, and customer routers are reachable **only through it**.
**Core rule: read-only by default, never restart anything, mind the ~1 GB RAM.**

## Connect
- `ssh -o BatchMode=yes dennis@54.91.202.229` — AWS box, hostname `ip-172-31-23-68`.
- **Key-based, non-interactive** (`~/.ssh/id_ed25519`, key comment `claude-code-dennis`); no
  password prompt. The `dennis` user runs `docker` directly (no `sudo`).
- **First time / no access yet:** SSH is key-only — someone who already has access must append
  your SSH **public** key to `dennis`'s `~/.ssh/authorized_keys` (onboarding procedure:
  `docs/agent-memory/server-access.md`). You cannot self-serve this.
  Verify access: `ssh -o BatchMode=yes dennis@54.91.202.229 'echo ok'`.
- A router with WAN down has its mgmt tunnel down too ⇒ unreachable from here; fix locally.

## The box
- ~1 GB RAM + 2 GB swap (chronically ~85% used — normal). Don't pile on memory pressure.
- Docker containers:
  - **`isp_billing_app`** — the FastAPI app (uvicorn :8000). Has the app code, DB creds, the
    `MikroTikAPI` client, and sits on the WireGuard tunnel — so it can reach `10.0.0.x` routers
    (your workstation can't). Run router/DB scripts *inside* it.
  - `isp_billing_postgres` (Postgres 15) · `isp_billing_radius` · `isp_wg_manager`.

## Run patterns
- **One-off command / logs:**
  ```bash
  ssh -o BatchMode=yes dennis@54.91.202.229 'docker logs --since 24h isp_billing_app'
  ```
- **Run a Python script inside the app container** (best for router/DB work — reuses the app's
  client + models). Pipe it via **stdin** so you avoid quote-nesting through ssh→sh→docker;
  pass inputs with `-e`:
  ```bash
  ssh -o BatchMode=yes dennis@54.91.202.229 \
    "docker exec -e ROUTER_ID=201 -i isp_billing_app python -" < your_script.py
  ```
  Do NOT hand-nest quotes inside the remote command — it gets mangled. Use the stdin pipe (a
  local file or a `<<'EOF'` heredoc) so the script arrives literal.
- **Reach a router:** inside `isp_billing_app`, read the router's creds from the DB in a short
  session, release it, then use `app.services.mikrotik_api.MikroTikAPI` against its `10.0.0.x` IP.

## Safety rules (do not violate)
1. **Read-only by default.** `print`/`get`/logs/SELECT only. Show the user any write command and
   get explicit approval first.
2. **Never restart** a container, service, or the box. No reboots, no `/system reset`.
3. **~1 GB RAM:** one short-lived `docker exec python` at a time; keep scripts light; dispose DB
   engines/sessions when done.
4. **DB session discipline:** read in a short session, `commit()`/close, THEN do network I/O —
   never hold a DB connection across RouterOS/HTTP/`sleep` calls (AGENTS.md). The app's API
   client UTF-8-decodes responses, so binary file contents can crash it — read **text only**,
   per-file (`/file print` caps `contents` at ~4 KB).
5. **Confirm outward/irreversible actions** (writes, deploys, deletes) before running.

## Diagnostics
- DB pool pressure: `GET /api/admin/db-pool?include_activity=true` (healthy pool oscillates;
  `idle in transaction` + many `Lock: tuple` waiters = a leak/convoy that clears only on restart).
- App logs: `docker logs --since <window> isp_billing_app`.
- Direct `psql` via `docker exec` was permission-blocked before — prefer logs / the API.

## Related
- `diagnose-customer-router` — applies this access to hotspot / captive-portal faults.
- `docs/agent-memory/server-access.md` — full SSH/deploy runbook + new-server key onboarding.
- AGENTS.md "Database Session Discipline" — the #1 cause of prod outages here.
