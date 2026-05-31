# 2026-05-31 DB Pool Exhaustion During MikroTik/Background Activity

## Summary

Production logs showed SQLAlchemy pool exhaustion:

```text
QueuePool limit of size 15 overflow 15 reached, connection timed out, timeout 10.00
```

The failures affected background jobs and normal API endpoints, including public portal and reconnect requests. Restarting the backend restored service temporarily.

## Symptoms

- `QueuePool` timeout errors from SQLAlchemy.
- 500 responses on DB-backed endpoints such as public portal and reconnect.
- Background jobs reported failures around M-Pesa reconciliation, subscription reconciliation, MikroTik cleanup, and router-related work.
- The issue appeared after the app had been running for hours, not immediately at boot.

## Assessment

The most likely cause was not too many users by itself. The risky pattern was request handlers and background jobs holding DB sessions while slow MikroTik/network calls were in progress.

With pool settings of `DB_POOL_SIZE=15`, `DB_MAX_OVERFLOW=15`, and `DB_POOL_TIMEOUT=10`, enough slow router/network operations could temporarily consume all available DB connections. A dashboard polling burst and scheduled jobs made the timing worse.

## Fix Applied

Two commits were pushed:

- Backend: `41347fa Release DB sessions before router I/O`
- Frontend: `45e3246 Reduce dashboard polling pressure`

Backend changes released SQLAlchemy sessions before slow RouterOS/network I/O across affected routes and services.

Frontend dashboard changes reduced polling pressure:

- health polling reduced to 60s
- top users polling reduced to 60s
- bandwidth polling reduced to 120s
- non-critical dashboard calls are staggered
- polling skips while the tab is hidden
- dashboard health calls use `preferSnapshot=true`

## Current Design Notes

- Dashboard health should prefer `BandwidthSnapshot`/cached health data.
- `BandwidthSnapshot`, `UserBandwidthUsage`, and `RouterAvailabilityCheck` are key telemetry tables.
- Live router calls are still needed for explicit diagnostics/admin operations, but should not hold DB sessions while waiting.
- Router operations should increasingly move toward an outbox/worker model.

## Verification

Code-level verification performed:

- Python compile checks were run after backend changes.
- Frontend `npm run build` passed after dashboard changes.
- Pytest could not be fully run because the local venv lacked required test dependencies.

Production verification still required:

- Watch logs for absence of `QueuePool limit` errors for 24-48 hours.
- Check Postgres connections during dashboard use and scheduled jobs.
- Confirm one slow/offline router no longer causes unrelated DB-backed endpoints to fail.

## Follow-Up Work

- Add structured logging for DB pool checkout failures and MikroTik call duration by router ID.
- Add a generic router command outbox/worker.
- Centralize direct `MikroTikAPI` usage behind a router I/O gateway.
- Expand RADIUS for subscriber auth/accounting where practical.
