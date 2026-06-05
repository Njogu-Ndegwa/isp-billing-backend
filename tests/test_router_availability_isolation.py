"""Regression tests for the DB-pool lock-convoy incident (2026-06-05).

Root cause: ``record_router_availability`` wrote into the *caller's* transaction
and only ``flush()``-ed. Any caller that stalled after the flush (e.g. across
RouterOS I/O) held the hot ``routers`` row lock open, producing a lock convoy
that drained the DB connection pool. The fix records availability in its own
short, immediately-committed session, decoupled from the caller.
"""

from datetime import datetime

import pytest
from sqlalchemy import select

from app.db.models import Router, RouterAvailabilityCheck
from app.services.router_availability import record_router_availability
from tests.factories import make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def test_availability_persists_even_if_caller_rolls_back(db, session_factory):
    """The write must survive a caller that never commits.

    NOTE: record is called before the caller touches the connection — under the
    test StaticPool (single shared SQLite connection) the isolated session needs
    the connection free. In production the isolated write gets its own pooled
    connection.
    """
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    async with session_factory() as caller:
        await record_router_availability(caller, router.id, True, "test_health")
        # Caller stalls/errors and its transaction is rolled back.
        await caller.rollback()

    async with session_factory() as verify:
        checks = (
            await verify.execute(
                select(RouterAvailabilityCheck).where(
                    RouterAvailabilityCheck.router_id == router.id
                )
            )
        ).scalars().all()
        assert len(checks) == 1
        assert checks[0].is_online is True

        refreshed = await verify.get(Router, router.id)
        assert refreshed.last_status is True
        assert refreshed.availability_checks == 1


async def test_missing_router_is_a_noop(db, session_factory):
    """Recording for a non-existent router must not raise."""
    async with session_factory() as caller:
        await record_router_availability(caller, 999999, False, "test_missing")

    async with session_factory() as verify:
        checks = (
            await verify.execute(select(RouterAvailabilityCheck))
        ).scalars().all()
        assert checks == []
