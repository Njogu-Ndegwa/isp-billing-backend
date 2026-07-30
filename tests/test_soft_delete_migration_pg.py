"""Rehearse run_soft_delete_migrations against a REAL Postgres schema shaped
like production BEFORE this change (full unique constraints, no deleted_at).

Skipped on SQLite — the pg_constraint/pg_index swap can only be proven on
Postgres. CI's Postgres job runs it on every push (docs/SOFT_DELETE_PLAN.md).

NOTE: CI runs xdist workers in per-worker schemas selected via search_path, so
every catalog assertion here is scoped to current_schema() — and the migration
itself resolves tables the same way.
"""

import pytest
from sqlalchemy import text

from tests.conftest import running_on_postgres

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(not running_on_postgres(), reason="Postgres-only migration rehearsal"),
]


async def _one(conn, sql, **params):
    return (await conn.execute(text(sql), params)).scalar()


async def test_migration_swaps_old_constraints_for_partial_indexes(engine, monkeypatch):
    """Simulate a pre-soft-delete production `users` table: drop the new
    columns/indexes create_all made, recreate the OLD constraint shapes, then
    run the migration and verify the swap — twice (idempotency)."""
    import main as main_module

    monkeypatch.setattr(main_module, "async_engine", engine)

    async with engine.begin() as conn:
        # Rewind `users` to its pre-migration shape.
        await conn.execute(text('DROP INDEX IF EXISTS uq_live_users_email'))
        await conn.execute(text('DROP INDEX IF EXISTS uq_live_users_user_code'))
        await conn.execute(text('DROP INDEX IF EXISTS ix_users_tombstones'))
        await conn.execute(text('ALTER TABLE users DROP COLUMN IF EXISTS deleted_at'))
        await conn.execute(text('ALTER TABLE users DROP COLUMN IF EXISTS deleted_by'))
        await conn.execute(text('ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email)'))
        await conn.execute(text('ALTER TABLE users ADD CONSTRAINT users_user_code_key UNIQUE (user_code)'))
        # And `customers` composite constraint back to its old named form.
        await conn.execute(text('DROP INDEX IF EXISTS uq_customer_mac_per_reseller'))
        await conn.execute(text('DROP INDEX IF EXISTS ix_customers_tombstones'))
        await conn.execute(text('ALTER TABLE customers DROP COLUMN IF EXISTS deleted_at'))
        await conn.execute(text('ALTER TABLE customers DROP COLUMN IF EXISTS deleted_by'))
        await conn.execute(text(
            'ALTER TABLE customers ADD CONSTRAINT uq_customer_mac_per_reseller UNIQUE (mac_address, user_id)'
        ))

    for _ in range(2):  # idempotent: second run must be a no-op, not an error
        await main_module.run_soft_delete_migrations()

    async with engine.begin() as conn:
        # Columns are back (scoped to THIS worker's schema).
        assert await _one(conn,
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'users' "
            "AND column_name IN ('deleted_at','deleted_by')") == 2

        # Old full constraints are gone.
        assert await _one(conn,
            "SELECT count(*) FROM pg_constraint "
            "WHERE connamespace = current_schema()::regnamespace "
            "AND conname IN ('users_email_key','users_user_code_key',"
            "'uq_customer_mac_per_reseller')") == 0

        # Partial unique indexes exist with the model-declared names.
        for idx in ("uq_live_users_email", "uq_live_users_user_code", "uq_customer_mac_per_reseller"):
            pred = await _one(conn,
                "SELECT pg_get_expr(x.indpred, x.indrelid) FROM pg_index x "
                "JOIN pg_class i ON i.oid = x.indexrelid "
                "WHERE i.relnamespace = current_schema()::regnamespace "
                "AND i.relname = :n AND x.indisunique",
                n=idx)
            assert pred is not None and "deleted_at IS NULL" in pred, (idx, pred)

        # Tombstone helper index exists.
        assert await _one(conn,
            "SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() "
            "AND indexname = 'ix_users_tombstones'") == 1

    # Behavior: same email may exist once live + once tombstoned...
    async with engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO users (user_code, email, password_hash, role, organization_name, subscription_status) "
            "VALUES (901, 'dup@x.io', 'h', 'RESELLER', 'o1', 'trial')"))
        await conn.execute(text(
            "INSERT INTO users (user_code, email, password_hash, role, organization_name, subscription_status, deleted_at) "
            "VALUES (902, 'dup@x.io', 'h', 'RESELLER', 'o2', 'trial', now())"))

    # ...but not twice live. Own transaction: the expected IntegrityError
    # poisons it, so it must not share a block with committing work.
    with pytest.raises(Exception):
        async with engine.begin() as conn:
            await conn.execute(text(
                "INSERT INTO users (user_code, email, password_hash, role, organization_name, subscription_status) "
                "VALUES (903, 'dup@x.io', 'h', 'RESELLER', 'o3', 'trial')"))
