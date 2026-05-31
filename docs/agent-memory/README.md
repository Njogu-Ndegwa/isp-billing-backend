# Agent Memory

This directory stores operational learnings and durable project notes for future agents.

## Why This Exists

Some failures in this project are cross-cutting: FastAPI request handlers, SQLAlchemy sessions, APScheduler jobs, MikroTik API calls, frontend polling, and production server limits can interact. A future agent should not have to rediscover those lessons from scratch.

## Files

- `backlog.md` - planned work and reliability improvements.
- `incidents/` - incident notes and postmortems.
- `templates/incident-learning.md` - format for new incident notes.

## How To Use

1. Read `AGENTS.md` first.
2. Read incident notes related to the area you are touching.
3. Add a new note after fixing a recurring production problem.
4. Move follow-up items into `backlog.md` so they can be handled one at a time.

## Current High-Value Context

- The backend talks to MikroTik routers over direct RouterOS API for many direct-api routers.
- Router calls can be slow or hang when an edge device is overloaded, offline, or reachable over a weak management path.
- DB sessions must not be held while waiting on MikroTik, payment-provider, or other slow network I/O.
- Dashboard views should prefer cached/snapshot data and avoid live router calls unless the user explicitly requests diagnostics.
- RADIUS is preferred long-term for subscriber auth/accounting where practical; direct RouterOS API remains useful for router administration and non-RADIUS routers.
