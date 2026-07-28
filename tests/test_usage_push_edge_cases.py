"""Edge cases for the usage-push channel — written by asking what the
pull-channel free-internet incident (2026-07-15) would look like here.

That incident's root cause was not a bad calculation. It was that the feature had
**no awareness of the customer lifecycle**: the pull channel was add-only, kept
serving a command after the customer's plan ended, and cleanup could never win.

Push looks safer because "it only reads". It is not, for two reasons:

* it *writes* — into the usage tables, which are what resellers bill and report on;
* it *drives FUP* — so bad data does not give free internet, it does the opposite
  and throttles or blocks someone. The mirror image of the same bug.

The router is also the least trustworthy caller in the system: it keeps queues for
customers we have deleted, it reboots and resets counters, it retries, and it can
deliver out of order over a bad link. Each test below is one of those.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    ConnectionType,
    CustomerStatus,
    CustomerUsagePeriod,
    SubscriptionStatus,
    UserBandwidthUsage,
)
from app.services import usage_push
from app.services.usage_push import UsageReport
from app.services.usage_tracking import close_open_period, open_new_period
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


async def _setup(db, *, expiry_offset_days=30, cap_mb=None,
                 mac="AA:BB:CC:11:22:33", sub_status=SubscriptionStatus.ACTIVE):
    reseller = await make_reseller(db, subscription_status=sub_status)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db, reseller, connection_type=ConnectionType.HOTSPOT, data_cap_mb=cap_mb
    )
    customer = await make_customer(
        db, reseller, plan, router,
        mac_address=mac,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=expiry_offset_days),
    )
    return reseller, router, plan, customer


# ---------------------------------------------------------------------------
# The direct analogue of the free-internet bug: no lifecycle awareness.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_customer_usage_is_not_recorded(db, session_factory):
    """A router keeps its queues until cleanup reaches it — which is exactly what
    fails during the outages this channel exists to survive. So the router WILL
    report usage for customers whose plan ended, and we must not bank it.

    The pull channel's version of ignoring this was free internet. Ours is
    billing a customer for traffic after their plan ended, and — worse — FUP
    throttling someone who no longer has a subscription at all.
    """
    _, router, _, customer = await _setup(db, expiry_offset_days=-1, mac="AA:BB:CC:EE:00:01")

    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:EE:00:01", upload_bytes=10 * MB,
                     download_bytes=90 * MB, final=True)],
        session_factory=session_factory,
    )

    assert result.accepted == 0
    assert result.rejected == 1

    async with session_factory() as s:
        periods = (await s.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == customer.id)
        )).scalars().all()
    assert periods == []


@pytest.mark.asyncio
async def test_push_does_not_reopen_a_closed_billing_period(db, session_factory):
    """``get_or_open_current_period`` clears ``closed_at`` when it finds a period
    matching the window. A late report — a retry over a bad link, or a queue the
    router only just got round to flushing — must not resurrect a period that has
    already been closed and reported on.
    """
    _, router, plan, customer = await _setup(db, mac="AA:BB:CC:EE:00:02")

    async with session_factory() as s:
        cust = await s.get(type(customer), customer.id)
        pl = await s.get(type(plan), plan.id)
        await open_new_period(s, cust, plan=pl)
        await close_open_period(s, cust.id)
        await s.commit()

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:EE:00:02", upload_bytes=MB,
                     download_bytes=MB, final=True)],
        session_factory=session_factory,
    )

    async with session_factory() as s:
        closed = (await s.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == customer.id,
                CustomerUsagePeriod.period_start
                == select(CustomerUsagePeriod.period_start)
                .where(CustomerUsagePeriod.customer_id == customer.id)
                .order_by(CustomerUsagePeriod.id).limit(1).scalar_subquery(),
            )
        )).scalars().first()

    assert closed is not None
    assert closed.closed_at is not None, "a closed period was resurrected by a late push"


@pytest.mark.asyncio
async def test_suspended_reseller_router_is_not_accepted(db, session_factory):
    """A reseller who has stopped paying still has powered-on routers in the
    field pushing at us. Recording their usage costs us work and puts numbers on
    a dashboard nobody is paying for — and it was the single biggest source of
    junk in the poll path (233 expired customers on one dead reseller's router).
    """
    _, router, _, customer = await _setup(
        db, mac="AA:BB:CC:EE:00:03", sub_status=SubscriptionStatus.SUSPENDED
    )

    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:EE:00:03", upload_bytes=MB, download_bytes=MB)],
        session_factory=session_factory,
    )

    assert result.accepted == 0


# ---------------------------------------------------------------------------
# The router is not a trustworthy narrator.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_same_mac_on_two_resellers_does_not_share_a_counter(db, session_factory):
    """MAC is unique per reseller, not globally — two resellers legitimately have
    the same device MAC (phones get randomised MACs, and they collide).

    ``user_bandwidth_usage`` is keyed by MAC alone, so both customers can land on
    one row. Their counters then interleave: each push looks like a counter reset
    to the other, and both customers accrue the other's traffic. Cross-tenant
    data corruption, and it silently bills the wrong person.
    """
    _, router_a, _, customer_a = await _setup(db, mac="AA:BB:CC:5E:5E:5E")

    reseller_b = await make_reseller(db)
    router_b = await make_router(db, reseller_b)
    plan_b = await make_plan(db, reseller_b, connection_type=ConnectionType.HOTSPOT)
    customer_b = await make_customer(
        db, reseller_b, plan_b, router_b,
        mac_address="AA:BB:CC:5E:5E:5E",  # same MAC, different reseller
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )

    # A is a heavy user; B just connected.
    for up, dn in ((0, 0), (100 * MB, 400 * MB)):
        await usage_push.ingest_usage_reports(
            router_a.id,
            [UsageReport(queue_key="AA:BB:CC:5E:5E:5E", upload_bytes=up, download_bytes=dn)],
            session_factory=session_factory,
        )
    for up, dn in ((0, 0), (1 * MB, 2 * MB)):
        await usage_push.ingest_usage_reports(
            router_b.id,
            [UsageReport(queue_key="AA:BB:CC:5E:5E:5E", upload_bytes=up, download_bytes=dn)],
            session_factory=session_factory,
        )

    async with session_factory() as s:
        period_a = (await s.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == customer_a.id)
        )).scalar_one()
        period_b = (await s.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == customer_b.id)
        )).scalar_one()
        rows = (await s.execute(select(UserBandwidthUsage))).scalars().all()

    # Each customer keeps their own counter row and their own total.
    assert len(rows) == 2, "the two resellers' customers shared one counter row"
    assert period_a.total_bytes == 500 * MB
    assert period_b.total_bytes == 3 * MB


@pytest.mark.asyncio
async def test_absurd_counter_value_is_refused(db, session_factory):
    """A corrupt read or a hostile router must not be able to write a nonsense
    total that instantly trips FUP and blocks a paying customer, or overflow the
    BIGINT column."""
    _, router, _, customer = await _setup(db, cap_mb=100, mac="AA:BB:CC:EE:00:04")

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:EE:00:04", upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )
    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:EE:00:04",
                     upload_bytes=2**62, download_bytes=2**62)],
        session_factory=session_factory,
    )

    assert result.rejected == 1
    assert result.over_cap_customer_ids == []

    async with session_factory() as s:
        period = (await s.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == customer.id)
        )).scalar_one()
    assert period.total_bytes == 0


@pytest.mark.asyncio
async def test_late_final_report_after_a_newer_sample_does_not_double_count(db, session_factory):
    """Over a flaky link a logout report can arrive *after* the next session has
    already reported. The stale, lower value looks exactly like a counter reset,
    so it would be banked a second time."""
    _, router, _, customer = await _setup(db, mac="AA:BB:CC:EE:00:05")
    key = "AA:BB:CC:EE:00:05"

    # Session 1 runs and is sampled periodically.
    await usage_push.ingest_usage_reports(
        router.id, [UsageReport(queue_key=key, upload_bytes=0, download_bytes=0)],
        session_factory=session_factory)
    await usage_push.ingest_usage_reports(
        router.id, [UsageReport(queue_key=key, upload_bytes=10 * MB, download_bytes=40 * MB)],
        session_factory=session_factory)

    # Its final report is delayed, and lands after the sample above.
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=10 * MB, download_bytes=40 * MB, final=True)],
        session_factory=session_factory)

    async with session_factory() as s:
        period = (await s.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == customer.id)
        )).scalar_one()

    # 50 MB happened. Not 100.
    assert period.total_bytes == 50 * MB


@pytest.mark.asyncio
async def test_customer_without_a_plan_is_rejected_visibly(db, session_factory):
    """Usage cannot be attributed to a period without a plan to size it. Silently
    accepting means the reseller sees zero and nobody knows why."""
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(
        db, reseller, plan, router,
        mac_address="AA:BB:CC:EE:00:06",
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    async with session_factory() as s:
        row = await s.get(type(customer), customer.id)
        row.plan_id = None
        await s.commit()

    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:EE:00:06", upload_bytes=MB, download_bytes=MB)],
        session_factory=session_factory,
    )

    assert result.accepted == 0
    assert result.rejected == 1
