"""
Pytest harness for the isp-billing project.

Sets test-only env vars BEFORE any `app.*` import (so `app.config.Settings`
doesn't fail), then exposes async fixtures that wire the entire app to one
database — shared across every connection so that service-layer code (which
opens its own sessions via `async_session()`) sees the rows the test setup
created.

Two backends are supported, chosen by DATABASE_URL:

* **Postgres** (CI, and anyone who exports a postgres DATABASE_URL) — the same
  engine and major version production runs. This is what makes the suite
  *evidence*: Postgres-only syntax in the startup migrations, enum types,
  and concurrent unique-constraint behaviour simply cannot be exercised
  anywhere else.
* **SQLite in memory** (the default, for a fast local loop) — convenient, but
  an approximation. A green SQLite run is not proof that production is fine.

Isolation differs by necessity. SQLite gets a brand-new in-memory database per
test, which is free. On Postgres that would be far too slow, so the schema is
created once and every table is truncated between tests — same guarantee (each
test starts empty, with identity counters reset), different mechanism.
"""

import os

# Must run before importing anything under `app.*`
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("MPESA_CONSUMER_KEY", "test-key")
os.environ.setdefault("MPESA_CONSUMER_SECRET", "test-secret")
os.environ.setdefault("MPESA_SHORTCODE", "600980")
os.environ.setdefault("MPESA_PASSKEY", "test-passkey")
os.environ.setdefault("MPESA_CALLBACK_URL", "https://example.com/cb")
os.environ.setdefault("MPESA_ENVIRONMENT", "sandbox")

from datetime import datetime
from typing import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Import models so Base.metadata knows every table before create_all
from app.db import database as db_module
from app.db import models as _models  # noqa: F401  (side-effect: registers tables)

DATABASE_URL = os.environ["DATABASE_URL"]
RUNNING_ON_POSTGRES = DATABASE_URL.startswith(("postgresql", "postgres://"))


def running_on_postgres() -> bool:
    """For tests that must skip when the backend can't express what they check."""
    return RUNNING_ON_POSTGRES


# One engine per pytest worker, reused for every test it runs. Building an
# engine per test meant a TCP connect and auth handshake ~670 times; the
# connection is by far the most expensive part of a test that does three
# INSERTs. Kept alive deliberately — disposing it between tests would throw
# away exactly the thing we are trying to reuse.
_PG_ENGINE = None

# Under pytest-xdist every worker needs its own tables, or one worker's TRUNCATE
# wipes the rows another is mid-way through asserting on. A schema per worker is
# far cheaper than a database per worker and needs no extra privileges.
_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "single")
_SCHEMA = f"test_{_WORKER}"


async def _postgres_engine():
    """The worker's engine, created once, pointed at that worker's own schema."""
    global _PG_ENGINE
    if _PG_ENGINE is not None:
        return _PG_ENGINE

    # CREATE SCHEMA needs its own connection outside the pooled engine, since
    # the pooled one already wants the schema in its search_path.
    admin = create_async_engine(DATABASE_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(sa_text(f'CREATE SCHEMA IF NOT EXISTS "{_SCHEMA}"'))
    await admin.dispose()

    _PG_ENGINE = create_async_engine(
        DATABASE_URL,
        future=True,
        connect_args={"server_settings": {"search_path": _SCHEMA}},
    )
    return _PG_ENGINE


async def _fresh_postgres_engine():
    """Real Postgres: reuse the worker's engine, reset its tables per test."""
    eng = await _postgres_engine()
    async with eng.begin() as conn:
        # ONE catalog query answers both questions below. The obvious
        # implementation — calling create_all(checkfirst=True) per test — issues
        # a reflection query PER TABLE instead: 65 tables x ~670 tests is about
        # 43,000 round trips, which took the suite from ~7 minutes to 18 and put
        # it within two minutes of the job timeout. SQLite hid this because
        # building an empty in-memory database costs nothing.
        existing = {
            row[0] for row in (await conn.execute(
                sa_text("SELECT tablename FROM pg_tables WHERE schemaname = :s"),
                {"s": _SCHEMA},
            )).all()
        }
        known = {t.name for t in db_module.Base.metadata.sorted_tables}

        # Build the schema only when something is actually missing — the first
        # test of a run, or after a test drops tables on purpose (the startup
        # migration test does exactly that).
        if known - existing:
            await conn.run_sync(db_module.Base.metadata.create_all)

        # Drop scratch tables that tests build themselves with raw DDL. The
        # radius_* tables have no ORM model, and two test modules create
        # radius_check with DIFFERENT columns using CREATE TABLE IF NOT EXISTS.
        # A fresh database per test hid that forever; on a persistent one,
        # whichever module runs first wins and the other fails on a missing
        # column. Dropping them restores the isolation SQLite gave us for free.
        for name in existing - known:
            await conn.execute(sa_text(f'DROP TABLE IF EXISTS "{name}" CASCADE'))

        tables = ", ".join(f'"{t.name}"' for t in db_module.Base.metadata.sorted_tables)
        if tables:
            # RESTART IDENTITY so sequence-generated ids don't leak between
            # tests; CASCADE because these tables reference each other.
            await conn.execute(
                sa_text(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE")
            )
    return eng


async def _fresh_sqlite_engine():
    """StaticPool keeps one connection alive so every session sees the same
    :memory: database."""
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with eng.begin() as conn:
        await conn.run_sync(db_module.Base.metadata.create_all)
    return eng


@pytest_asyncio.fixture
async def engine(monkeypatch):
    """A clean database per test, on whichever backend DATABASE_URL selects.

    The engine is rebound onto `app.db.database` (and onto modules that imported
    `async_session` at load time), so service code opening its own session
    routes to this same DB.
    """
    eng = (
        await _fresh_postgres_engine()
        if RUNNING_ON_POSTGRES
        else await _fresh_sqlite_engine()
    )

    factory = sessionmaker(
        bind=eng,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    # Rebind the production singletons so the app uses our test engine
    monkeypatch.setattr(db_module, "async_engine", eng)
    monkeypatch.setattr(db_module, "AsyncSessionLocal", factory)
    monkeypatch.setattr(db_module, "async_session", factory)

    # Patch modules that imported `async_session` at module load time
    import app.services.hotspot_provisioning as _hsp
    monkeypatch.setattr(_hsp, "async_session", factory)

    try:
        yield eng
    finally:
        # SQLite engines are per-test and must go. The Postgres engine is shared
        # by every test this worker runs — disposing it would discard the pooled
        # connection we are deliberately reusing.
        if not RUNNING_ON_POSTGRES:
            await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(engine):
    return sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


@pytest_asyncio.fixture
async def db(session_factory) -> AsyncIterator[AsyncSession]:
    async with session_factory() as s:
        yield s


@pytest.fixture
def now():
    return datetime.utcnow()
