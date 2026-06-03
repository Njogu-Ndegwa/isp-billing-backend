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

## Production Reliability Guardrails

- For DB pool or app-unresponsive incidents, check background jobs first, especially MikroTik cleanup, safety-net scans, bandwidth snapshots, and provisioning retry.
- Never hold DB sessions while waiting on RouterOS, payment-provider, or other slow network I/O.
- Optional background work must shed load when the DB pool is busy and must back off recently-offline routers instead of retrying the same unreachable devices every scheduler tick.
- Avoid per-router concurrent DB rechecks after router scans; batch DB verification before fan-out or after fan-in.
- Keep customer-facing request paths and payment provisioning higher priority than cleanup, snapshots, and retry safety nets.
- Current detailed lesson: `docs/agent-memory/incidents/2026-06-02-db-pool-exhaustion-recurrence.md`.

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
