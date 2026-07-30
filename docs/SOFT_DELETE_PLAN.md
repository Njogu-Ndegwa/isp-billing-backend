# System-Wide Soft Delete — Design & Rollout Plan

Status: in progress (feat/soft-delete). Owner: Claude agent, requested by Dennis 2026-07-30.

## Goal

When a user deletes anything, the row is tombstoned (`deleted_at` set), not removed.
Deleted rows vanish from every query automatically — **zero frontend changes, zero
behavior change for existing data**. A background purge job permanently removes rows
whose `deleted_at` is older than a retention window (default 90 days), replicating
today's hard-delete semantics (FK-nulling for ledger rows included) at purge time.
Recovery before purge = set `deleted_at = NULL`.

## Mechanism

1. **`SoftDeleteMixin`** in `app/db/database.py` (next to `Base`, avoiding circular
   imports): `deleted_at DateTime NULL` (naive UTC, matching `datetime.utcnow`
   convention) + `deleted_by Integer NULL` (admin/user id, no FK). Applied to **all**
   ORM models in `app/db/models.py`. The 8 model-less `radius_*` tables are NOT
   covered — FreeRADIUS reads them directly; a tombstoned `radius_check` row would
   still authenticate a customer, so RADIUS rows remain hard-deleted at
   soft-delete time (deprovisioning must take effect immediately).
2. **Global query filter** in `app/db/database.py`: `do_orm_execute` listener adding
   `with_loader_criteria(SoftDeleteMixin, deleted_at IS NULL, include_aliases=True)`
   to every ORM SELECT (excluding column/relationship refresh loads, per the
   canonical SQLAlchemy recipe). Escape hatch:
   `.execution_options(include_deleted=True)` for purge/restore/admin views.
   Bulk UPDATE/DELETE statements are NOT auto-filtered (purge and restore need them).
   `Session.get()` coverage is verified by a dedicated unit test (`tests/test_soft_delete.py`);
   if get() bypasses the filter on our SQLAlchemy version, the affected call sites
   on soft-deletable entities get explicit `deleted_at` guards.
3. **Unique constraints → partial unique indexes** (`... WHERE deleted_at IS NULL`)
   so a tombstone never blocks re-creating the same value (customer MAC, account
   number, router identity, voucher code, one-row-per-user tables). Model-side:
   `unique=True` / `UniqueConstraint` replaced with explicit
   `Index(..., unique=True, postgresql_where=..., sqlite_where=...)` so fresh DBs
   (and the SQLite test suite) natively match prod. Prod-side: idempotent startup
   migration discovers existing unique constraints/indexes from `pg_constraint` /
   `pg_indexes` and swaps them. PKs untouched. The single `ON CONFLICT` in the code
   targets a PK — unaffected.
4. **Startup migration** `run_soft_delete_migrations()` in `main.py` (First Rule):
   per modeled table `ADD COLUMN IF NOT EXISTS deleted_at/deleted_by`, a small
   partial index `WHERE deleted_at IS NOT NULL` (purge scans), then the unique swaps.
   Idempotent; Postgres-only guard; wired into the startup chain after table-creating
   migrations.

## Deleter conversions (Phase 3)

Rule: every ORM `db.delete(obj)` / `delete(Model).where(...)` in a user-facing
delete flow becomes `deleted_at = <one shared timestamp per operation>`. All raw
RADIUS deletes and router-side deprovisioning stay exactly as today.

- `DELETE /api/customers/{id}` (`customer_routes.py`) — soft-delete customer +
  child rows. **Change from today:** `CustomerPayment.customer_id` and
  `Voucher.redeemed_by` are NO LONGER nulled at delete time (rows stay live and
  linked; revenue reports unchanged since those rows were never deleted). Nulling
  moves to purge time. This kills the documented cross-tenant `customer_id IS NULL`
  leak risk and makes restore lossless.
- `DELETE /api/routers/{id}` (`router_management.py`) — soft-delete router + child
  rows; `ProvisioningLog.router_id` nulling moves to purge time; customer
  detach/status changes stay as today.
- `DELETE /api/admin/resellers/{id}` (`admin_reseller_routes.py`) — the ~40-step
  deleter becomes ~40 bulk soft-delete updates in the same order; dry-run summary
  endpoint unchanged.
- Small deletes → soft: plans, leads, ads (+ fix: also tombstone `AdImpression`,
  which today is leaked), message templates, access credentials (after router
  deprovision, as today), orphaned-customers admin sweep, `DELETE /api/profile`
  (today it FK-crashes; soft delete fixes it).
- **Stay hard-deleted (intentional):** retention prunes (`BandwidthSnapshot`,
  `RouterAvailabilityCheck`, `SmsMessage` — they exist to bound growth), RADIUS raw
  SQL, MoMo compensating rollback (`payment_gateway.py`), feedback vote toggle-off,
  portal-settings reset-and-recreate (both are state toggles, not data deletion).
- Existing `is_active`/`is_hidden`/status conventions (shop products, lead sources,
  payment methods, pairings, plans-hidden) are left as-is — they are "deactivate"
  semantics, orthogonal to deletion.

## Purge job (Phase 4)

`app/services/soft_delete_purge.py`, scheduled daily. For rows with
`deleted_at < now - SOFT_DELETE_RETENTION_DAYS` (env, default 90):
pre-steps first (NULL `CustomerPayment.customer_id`, `Voucher.redeemed_by`,
`ProvisioningLog.router_id` referencing purged parents), then hard-delete
table-by-table in bottom-up FK order (reusing the reseller deleter's order).
Each table in its own short transaction, chunked (DB Session Discipline; skip under
pool pressure like other background jobs). FK violations log + retry next run.
Cascade soft-deletes stamp one shared timestamp so parent/child purge together.

## Invariants to verify in review (Phase 5)

- No behavior change while nothing is soft-deleted (filter matches nothing).
- Aggregates/metrics (`admin_metrics.py`, `dashboard_routes.py`) unchanged for live
  data; joins from ledger rows to soft-deleted customers must not drop ledger rows
  from revenue math (check `update_reseller_financials` and payment listings).
- Raw `text()` SQL sites: enumerate, confirm each either targets radius/telemetry
  or is updated with `deleted_at IS NULL`.
- `db.get()` sites behave correctly (test-verified).
- Migration idempotent + safe to re-run; partial-index swap verified against a real
  Postgres (docker) — not just SQLite.
- Full pytest suite green; deletion tests updated to assert tombstones + invisibility.
