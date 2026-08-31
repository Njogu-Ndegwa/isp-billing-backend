"""Regression tests for the DB-pool lock-convoy incident (2026-06-05).

Root cause: ``record_router_availability`` wrote into the *caller's* transaction
and only ``flush()``-ed. Any caller that stalled after the flush (e.g. across
RouterOS I/O) held the hot ``routers`` row lock open, producing a lock convoy
that drained the DB connection pool. The fix records availability in its own
short, immediately-committed session, decoupled from the caller.
"""

from datetime import datetime, timedelta

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


async def test_failure_only_cleanup_sample_does_not_flip_router_offline(db, session_factory):
    reseller = await make_reseller(db)
    observed_at = datetime.utcnow()
    router = await make_router(
        db,
        reseller,
        last_status=True,
        last_checked_at=observed_at - timedelta(minutes=1),
        last_online_at=observed_at - timedelta(minutes=1),
        last_status_source="usage_push",
    )

    await record_router_availability(
        db, router.id, False, "expired_cleanup", checked_at=observed_at
    )

    async with session_factory() as verify:
        refreshed = await verify.get(Router, router.id)
        assert refreshed.last_status is True
        assert refreshed.last_status_source == "usage_push"
        assert refreshed.last_checked_at == observed_at - timedelta(minutes=1)

        checks = (
            await verify.execute(
                select(RouterAvailabilityCheck).where(
                    RouterAvailabilityCheck.router_id == router.id
                )
            )
        ).scalars().all()
        assert len(checks) == 1
        assert checks[0].is_online is False
        assert checks[0].source == "expired_cleanup"


async def test_one_negative_is_advisory_but_second_recent_negative_confirms_offline(
    db, session_factory
):
    reseller = await make_reseller(db)
    started_at = datetime.utcnow()
    router = await make_router(
        db,
        reseller,
        last_status=True,
        last_checked_at=started_at,
        last_online_at=started_at,
        last_status_source="usage_push",
    )

    first_failure = started_at + timedelta(minutes=1)
    await record_router_availability(
        db, router.id, False, "bandwidth_snapshot", checked_at=first_failure
    )
    async with session_factory() as verify:
        after_first = await verify.get(Router, router.id)
        assert after_first.last_status is True
        assert after_first.last_status_source == "usage_push"

    second_failure = started_at + timedelta(minutes=2)
    await record_router_availability(
        db, router.id, False, "mikrotik_health", checked_at=second_failure
    )
    async with session_factory() as verify:
        after_second = await verify.get(Router, router.id)
        assert after_second.last_status is False
        assert after_second.last_status_source == "mikrotik_health"
        assert after_second.last_checked_at == second_failure


async def test_online_sample_between_failures_resets_offline_confirmation(
    db, session_factory
):
    reseller = await make_reseller(db)
    started_at = datetime.utcnow()
    router = await make_router(
        db,
        reseller,
        last_status=True,
        last_checked_at=started_at,
        last_online_at=started_at,
        last_status_source="usage_push",
    )

    await record_router_availability(
        db,
        router.id,
        False,
        "bandwidth_snapshot",
        checked_at=started_at + timedelta(minutes=1),
    )
    await record_router_availability(
        db,
        router.id,
        True,
        "usage_push",
        checked_at=started_at + timedelta(minutes=2),
    )
    await record_router_availability(
        db,
        router.id,
        False,
        "provisioning",
        checked_at=started_at + timedelta(minutes=3),
    )

    async with session_factory() as verify:
        refreshed = await verify.get(Router, router.id)
        assert refreshed.last_status is True
        assert refreshed.last_status_source == "usage_push"


async def test_stale_negative_observation_cannot_overwrite_newer_online_summary(
    db, session_factory
):
    reseller = await make_reseller(db)
    now = datetime.utcnow()
    router = await make_router(
        db,
        reseller,
        last_status=True,
        last_checked_at=now,
        last_online_at=now,
        last_status_source="usage_push",
    )

    await record_router_availability(
        db,
        router.id,
        False,
        "mikrotik_health",
        checked_at=now - timedelta(minutes=1),
        confirm_offline=True,
    )

    async with session_factory() as verify:
        refreshed = await verify.get(Router, router.id)
        assert refreshed.last_status is True
        assert refreshed.last_status_source == "usage_push"
        assert refreshed.last_checked_at == now
