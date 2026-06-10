# Agent Notes

This file is the handoff map for coding agents working in this repository. Keep it short and link to durable project knowledge instead of turning it into a large manual.

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
