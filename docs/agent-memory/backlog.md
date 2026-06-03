# Backlog

Project-level items that should survive across agent sessions.

## Reliability And Architecture

### Router Command Outbox

- Status: planned
- Problem: direct MikroTik API calls are still spread across multiple routes/services.
- Why it matters: every router operation should have consistent timeout, retry, locking, idempotency, and audit behavior.
- Proposed next step: add a generic `router_commands` table and worker. Request handlers should write commands and return quickly when synchronous confirmation is not required.

### Central Router I/O Gateway

- Status: planned
- Problem: `MikroTikAPI` is imported in many modules.
- Why it matters: scattered imports make it easy to bypass DB-release, timeout, concurrency, and logging rules.
- Proposed next step: introduce a central service layer for router calls, then gradually route existing direct calls through it.

### DB Pool And Router I/O Observability

- Status: started
- Problem: production pool exhaustion was hard to attribute quickly.
- Why it matters: future incidents need router ID, endpoint, background job, DB pool status, and router-call duration in one trail.
- Done so far: backend exposes `GET /api/admin/db-pool` for live SQLAlchemy pool counters, observed checkout peaks, recent 5-minute peak pressure, and an optional Postgres `pg_stat_activity` summary.
- Proposed next step: add structured logs and lightweight metrics for request duration, background job duration, and MikroTik call duration by router ID.

### Expired Cleanup Job Health

- Status: planned
- Problem: expired hotspot cleanup can fall behind when RouterOS calls are slow, and APScheduler only logs `max_instances` skips.
- Why it matters: expired billing state must not depend on live router availability, and operators need an early signal before stale router access accumulates.
- Proposed next step: record cleanup job duration, skipped-run count, expired rows deactivated, router cleanup failures, and retry backlog age in a DB-backed or metrics-backed health record.

### RADIUS Expansion

- Status: planned
- Problem: direct API provisioning couples customer access lifecycle to live router availability.
- Why it matters: RADIUS is a better long-term fit for subscriber auth/accounting, while direct API should remain for router administration.
- Proposed next step: review which customer flows can safely move to RADIUS first without disrupting existing direct-api routers.

### Scheduler Isolation

- Status: planned
- Problem: APScheduler jobs run inside the web process.
- Why it matters: this is acceptable for one backend worker, but unsafe if multiple app instances/workers start the same jobs.
- Proposed next step: document deployment assumptions and consider moving scheduler work to a separate worker process before horizontal scaling.

## Operational Hygiene

### Incident Note Discipline

- Status: active
- Problem: learnings can disappear between agent sessions.
- Why it matters: repeated debugging wastes time and risks regressions.
- Proposed next step: after significant production incidents, add a note under `docs/agent-memory/incidents/` and link follow-ups here.
