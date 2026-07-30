"""Run run_soft_delete_migrations against the REAL production schema.

tests/fixtures_prod_schema.sql is a pg_dump --schema-only of the live
isp_billing_db (captured 2026-07-30). Unlike the fresh-schema rehearsal, this
exercises every quirk prod accumulated over time: hand-created duplicate
unique indexes (idx_b2b_conversation_id, idx_sub_payments_checkout,
idx_provisioning_attempts_source), legacy constraint names, the model-less
radius_* + user_payment_methods tables, etc. If the migration will surprise
us on deploy night, it should surprise us HERE first.

Postgres-only; CI runs it on every push. The dump loads into a scratch
database (per xdist worker) because it is public-schema-qualified.
"""

import os
import pathlib

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from tests.conftest import running_on_postgres

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(not running_on_postgres(), reason="Postgres-only prod-schema rehearsal"),
]

FIXTURE = pathlib.Path(__file__).parent / "fixtures_prod_schema.sql"
_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "solo")
SCRATCH_DB = f"prodshape_{_WORKER}"


def _scratch_url() -> str:
    base = os.environ["DATABASE_URL"]
    return base.rsplit("/", 1)[0] + "/" + SCRATCH_DB


async def _make_scratch_db_with_prod_schema():
    import asyncpg

    admin_dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
    admin = await asyncpg.connect(admin_dsn)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{SCRATCH_DB}" WITH (FORCE)')
        await admin.execute(f'CREATE DATABASE "{SCRATCH_DB}"')
    finally:
        await admin.close()

    scratch_dsn = admin_dsn.rsplit("/", 1)[0] + "/" + SCRATCH_DB
    # pg_dump 15.15+ wraps the file in \restrict/\unrestrict psql
    # meta-commands, which only psql understands — strip every \-line.
    ddl = "\n".join(
        line for line in FIXTURE.read_text(encoding="utf-8").splitlines()
        if not line.startswith("\\")
    )
    conn = await asyncpg.connect(scratch_dsn)
    try:
        await conn.execute(ddl)
    finally:
        await conn.close()


async def test_migration_on_real_prod_schema(monkeypatch):
    import main as main_module
    from app.db.database import Base
    import app.db.models  # noqa: F401

    await _make_scratch_db_with_prod_schema()
    engine = create_async_engine(_scratch_url(), poolclass=NullPool)
    monkeypatch.setattr(main_module, "async_engine", engine)
    try:
        for _ in range(2):  # must be idempotent on the second pass
            await main_module.run_soft_delete_migrations()
        await main_module.verify_soft_delete_schema()  # must NOT raise

        soft_tables = sorted(
            t.name for t in Base.metadata.tables.values() if "deleted_at" in t.c
        )
        async with engine.begin() as conn:
            # 1. Every modeled table got its columns.
            rows = await conn.execute(text(
                "SELECT table_name, count(*) FROM information_schema.columns "
                "WHERE table_schema = 'public' "
                "AND column_name IN ('deleted_at','deleted_by') "
                "GROUP BY table_name"
            ))
            have_cols = {r[0]: r[1] for r in rows}
            missing = [t for t in soft_tables if have_cols.get(t) != 2]
            assert not missing, f"tables missing soft-delete columns: {missing}"

            # 2. NO unique index/constraint without the deleted_at predicate
            #    survives on any soft-deletable table (PKs aside). This is the
            #    assertion that catches prod's hand-created duplicate indexes.
            rows = await conn.execute(text(
                "SELECT c.relname AS tbl, i.relname AS idx, "
                "       pg_get_expr(x.indpred, x.indrelid) AS pred "
                "FROM pg_index x "
                "JOIN pg_class i ON i.oid = x.indexrelid "
                "JOIN pg_class c ON c.oid = x.indrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND x.indisunique "
                "AND NOT x.indisprimary "
                "AND (x.indpred IS NULL OR "
                "     pg_get_expr(x.indpred, x.indrelid) NOT LIKE '%deleted_at%')"
            ))
            leftovers = [
                (r.tbl, r.idx, r.pred) for r in rows if r.tbl in set(soft_tables)
            ]
            assert not leftovers, f"unique indexes still ignoring tombstones: {leftovers}"

            # 3. radius_* and legacy model-less tables were left alone.
            rows = await conn.execute(text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema = 'public' AND column_name = 'deleted_at' "
                "AND table_name LIKE 'radius_%'"
            ))
            assert rows.scalar() == 0

        # 4. Behavior on the migrated schema: live + tombstoned duplicates OK,
        #    two live duplicates blocked.
        async with engine.begin() as conn:
            await conn.execute(text(
                "INSERT INTO users (user_code, email, password_hash, role, "
                "organization_name, subscription_status) "
                "VALUES (801, 'prod@x.io', 'h', 'RESELLER', 'o1', 'trial')"))
            await conn.execute(text(
                "INSERT INTO users (user_code, email, password_hash, role, "
                "organization_name, subscription_status, deleted_at) "
                "VALUES (802, 'prod@x.io', 'h', 'RESELLER', 'o2', 'trial', now())"))
        with pytest.raises(Exception):
            async with engine.begin() as conn:
                await conn.execute(text(
                    "INSERT INTO users (user_code, email, password_hash, role, "
                    "organization_name, subscription_status) "
                    "VALUES (803, 'prod@x.io', 'h', 'RESELLER', 'o3', 'trial')"))
    finally:
        await engine.dispose()
