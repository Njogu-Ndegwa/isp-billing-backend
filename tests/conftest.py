"""
Pytest harness for the isp-billing project.

Sets test-only env vars BEFORE any `app.*` import (so `app.config.Settings`
doesn't fail), then exposes async fixtures that wire the entire app to a
single in-memory SQLite database — shared across every connection so that
service-layer code (which opens its own sessions via `async_session()`) sees
the same rows the test setup created.
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
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Import models so Base.metadata knows every table before create_all
from app.db import database as db_module
from app.db import models as _models  # noqa: F401  (side-effect: registers tables)


@pytest_asyncio.fixture
async def engine(monkeypatch):
    """Fresh in-memory SQLite engine per test, shared across connections.

    StaticPool keeps one connection alive for the engine's lifetime so every
    session sees the same :memory: database. The engine is then rebound onto
    `app.db.database` (and onto modules that imported `async_session` at load
    time), so service code that opens its own session via `async_session()`
    routes to this same DB.
    """
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with eng.begin() as conn:
        await conn.run_sync(db_module.Base.metadata.create_all)

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
