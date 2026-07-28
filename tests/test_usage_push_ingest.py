"""Contract for the router-push usage channel.

These tests are written before the implementation. They pin the properties that
make the push channel safe to roll out in place of (eventually, alongside)
polling:

* pushed usage lands in the SAME tables, via the SAME helper, as polled usage —
  so the reseller dashboard keeps reading one source of truth;
* a session that opens and closes between two polls is still recorded exactly
  (the whole reason for the channel — SkyNet sells 15/30/80-minute plans against
  a ~49-minute poll rotation);
* FUP caps still trigger, because that is the thing we must not regress;
* a router can only report usage for customers that belong to it;
* replays and router reboots do not inflate usage.

Ingest is DB-only by design: it returns the ids of customers that crossed their
cap instead of enforcing inline, so no DB session is ever held across RouterOS
I/O (AGENTS.md, Database Session Discipline).
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    ConnectionType,
    CustomerStatus,
    CustomerUsagePeriod,
    UserBandwidthUsage,
)
from app.services import usage_push
from app.services.usage_push import UsageReport
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


async def _hotspot_setup(db, *, cap_mb=None, mac="AA:BB:CC:11:22:33"):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.HOTSPOT,
        data_cap_mb=cap_mb,
    )
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        mac_address=mac,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    return reseller, router, plan, customer


@pytest.mark.asyncio
async def test_push_records_usage_into_the_period(db, session_factory):
    """The baseline: a pushed cumulative counter rolls into the usage period."""
    _, router, _, customer = await _hotspot_setup(db)

    # First report establishes the baseline — no delta yet, same as polling.
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:11:22:33", upload_bytes=1 * MB, download_bytes=5 * MB)],
        session_factory=session_factory,
    )
    # Second report is +2 MB up / +10 MB down.
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:11:22:33", upload_bytes=3 * MB, download_bytes=15 * MB)],
        session_factory=session_factory,
    )

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()

    assert period.upload_bytes == 2 * MB
    assert period.download_bytes == 10 * MB
    assert period.total_bytes == 12 * MB


@pytest.mark.asyncio
async def test_short_session_is_captured_exactly_by_the_final_report(db, session_factory):
    """The case polling cannot see.

    A 15-minute customer connects and disconnects entirely between two polls.
    The router's on-logout hook sends one final report carrying the exact
    session total. Nothing was sampled beforehand, so the whole session must
    still be recorded.
    """
    _, router, _, customer = await _hotspot_setup(db, mac="AA:BB:CC:44:55:66")

    await usage_push.ingest_usage_reports(
        router.id,
        [
            UsageReport(
                queue_key="AA:BB:CC:44:55:66",
                upload_bytes=40 * MB,
                download_bytes=460 * MB,
                final=True,
            )
        ],
        session_factory=session_factory,
    )

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()

    # A first *periodic* sample only sets a baseline (we cannot know what came
    # before it). A first *final* sample is the authoritative session total, so
    # all 500 MB must land.
    assert period.total_bytes == 500 * MB


@pytest.mark.asyncio
async def test_next_session_after_logout_does_not_double_count(db, session_factory):
    """After a final report, the next session starts its counter at zero again.

    The reset-safe delta must treat that as a fresh session, not as negative
    usage and not as a re-count of the previous session.
    """
    _, router, _, customer = await _hotspot_setup(db, mac="AA:BB:CC:77:88:99")
    key = "AA:BB:CC:77:88:99"

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=10 * MB, download_bytes=90 * MB, final=True)],
        session_factory=session_factory,
    )
    # New session on the same MAC: router counter restarts from 0.
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=2 * MB, download_bytes=8 * MB, final=True)],
        session_factory=session_factory,
    )

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()

    assert period.total_bytes == 110 * MB


@pytest.mark.asyncio
async def test_replayed_report_does_not_inflate_usage(db, session_factory):
    """Flaky links mean a router may resend a batch it already delivered.

    The counters are cumulative, so re-sending the same values must be a no-op
    rather than adding the same bytes twice.
    """
    _, router, _, customer = await _hotspot_setup(db, mac="AA:BB:CC:AA:BB:CC")
    report = UsageReport(
        queue_key="AA:BB:CC:AA:BB:CC", upload_bytes=5 * MB, download_bytes=25 * MB
    )

    await usage_push.ingest_usage_reports(router.id, [report], session_factory=session_factory)
    await usage_push.ingest_usage_reports(router.id, [report], session_factory=session_factory)
    await usage_push.ingest_usage_reports(router.id, [report], session_factory=session_factory)

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()

    assert period.total_bytes == 0


@pytest.mark.asyncio
async def test_router_cannot_report_usage_for_another_routers_customer(db, session_factory):
    """Tenant isolation: this endpoint is reachable from the field.

    A report whose queue key belongs to a customer on a different router must be
    rejected outright, never attributed to that customer.
    """
    _, router_a, _, customer_a = await _hotspot_setup(db, mac="AA:BB:CC:DD:EE:01")
    reseller_b = await make_reseller(db)
    router_b = await make_router(db, reseller_b)

    result = await usage_push.ingest_usage_reports(
        router_b.id,
        [UsageReport(queue_key="AA:BB:CC:DD:EE:01", upload_bytes=9 * MB, download_bytes=9 * MB)],
        session_factory=session_factory,
    )

    assert result.accepted == 0
    assert result.rejected == 1

    async with session_factory() as s:
        periods = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer_a.id
                )
            )
        ).scalars().all()
        usage_rows = (await s.execute(select(UserBandwidthUsage))).scalars().all()

    assert periods == []
    assert usage_rows == []


@pytest.mark.asyncio
async def test_push_reports_customers_that_crossed_their_cap(db, session_factory):
    """FUP must keep working — this is the thing we cannot regress.

    Ingest itself does no router I/O; it returns the ids that crossed the cap so
    enforcement runs in its own step with no DB session held.
    """
    _, router, _, customer = await _hotspot_setup(
        db, cap_mb=100, mac="AA:BB:CC:CA:FE:01"
    )
    key = "AA:BB:CC:CA:FE:01"

    baseline = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )
    assert baseline.over_cap_customer_ids == []

    # Cross the 100 MB cap.
    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=10 * MB, download_bytes=95 * MB)],
        session_factory=session_factory,
    )

    assert result.over_cap_customer_ids == [customer.id]

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()
    assert period.total_bytes == 105 * MB


@pytest.mark.asyncio
async def test_under_cap_customer_is_not_reported_for_enforcement(db, session_factory):
    _, router, _, customer = await _hotspot_setup(
        db, cap_mb=100, mac="AA:BB:CC:CA:FE:02"
    )
    key = "AA:BB:CC:CA:FE:02"

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )
    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=1 * MB, download_bytes=20 * MB)],
        session_factory=session_factory,
    )

    assert result.over_cap_customer_ids == []


@pytest.mark.asyncio
async def test_pppoe_report_is_matched_by_username(db, session_factory):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        pppoe_username="alex",
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="pppoe:alex", upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="pppoe:alex", upload_bytes=3 * MB, download_bytes=21 * MB)],
        session_factory=session_factory,
    )

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()

    assert period.total_bytes == 24 * MB


@pytest.mark.asyncio
async def test_push_and_poll_agree_on_the_same_counters(db, session_factory):
    """One source of truth.

    The push path must reuse ``record_queue_usage_sample`` — the same helper the
    poller uses — so both produce identical rows for identical counters. If this
    ever diverges, resellers get two different usage numbers again, which is the
    bug we are fixing.
    """
    from app.services.usage_counters import record_queue_usage_sample

    _, router, plan, customer = await _hotspot_setup(db, mac="AA:BB:CC:0F:0F:0F")
    key = "AA:BB:CC:0F:0F:0F"

    # Poll path, applied directly.
    async with session_factory() as s:
        cust = await s.get(type(customer), customer.id)
        pl = await s.get(type(plan), plan.id)
        await record_queue_usage_sample(
            s, customer=cust, plan=pl, queue_key=key,
            upload_bytes=0, download_bytes=0,
        )
        await record_queue_usage_sample(
            s, customer=cust, plan=pl, queue_key=key,
            upload_bytes=4 * MB, download_bytes=16 * MB,
        )
        await s.commit()

    async with session_factory() as s:
        polled = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()
        polled_total = polled.total_bytes

    # Same counters delivered by push, on a second identical customer.
    _, router2, _, customer2 = await _hotspot_setup(db, mac="AA:BB:CC:0E:0E:0E")
    key2 = "AA:BB:CC:0E:0E:0E"
    await usage_push.ingest_usage_reports(
        router2.id,
        [UsageReport(queue_key=key2, upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )
    await usage_push.ingest_usage_reports(
        router2.id,
        [UsageReport(queue_key=key2, upload_bytes=4 * MB, download_bytes=16 * MB)],
        session_factory=session_factory,
    )

    async with session_factory() as s:
        pushed = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer2.id
                )
            )
        ).scalar_one()

    assert pushed.total_bytes == polled_total == 20 * MB


@pytest.mark.asyncio
async def test_unknown_queue_key_is_rejected_not_silently_dropped(db, session_factory):
    _, router, _, _ = await _hotspot_setup(db, mac="AA:BB:CC:12:12:12")

    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:99:99:99", upload_bytes=MB, download_bytes=MB)],
        session_factory=session_factory,
    )

    assert result.accepted == 0
    assert result.rejected == 1


@pytest.mark.asyncio
async def test_batch_partially_valid_still_records_the_valid_rows(db, session_factory):
    """A router sends one batch for everyone on it. One bad row must not discard
    the rest — that would lose real usage on every batch containing a stale MAC."""
    _, router, _, customer = await _hotspot_setup(db, mac="AA:BB:CC:33:33:33")
    key = "AA:BB:CC:33:33:33"

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )
    result = await usage_push.ingest_usage_reports(
        router.id,
        [
            UsageReport(queue_key=key, upload_bytes=MB, download_bytes=7 * MB),
            UsageReport(queue_key="AA:BB:CC:99:99:99", upload_bytes=MB, download_bytes=MB),
        ],
        session_factory=session_factory,
    )

    assert result.accepted == 1
    assert result.rejected == 1

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()
    assert period.total_bytes == 8 * MB


@pytest.mark.asyncio
async def test_push_and_poll_can_run_together_without_double_counting(db, session_factory):
    """No rollout flag needed.

    Both paths track the SAME cumulative router counter in the SAME
    user_bandwidth_usage row, so whoever reads it next simply sees the delta
    since the last reader. Interleaving them converges on the true total instead
    of adding it twice — which means a router can be switched to pushing while
    the poller still has it in rotation, with no coordination and no schema flag
    saying who owns it.
    """
    from app.services.usage_counters import record_queue_usage_sample

    _, router, plan, customer = await _hotspot_setup(db, mac="AA:BB:CC:5A:5A:5A")
    key = "AA:BB:CC:5A:5A:5A"

    async def poll(upload, download):
        async with session_factory() as s:
            cust = await s.get(type(customer), customer.id)
            pl = await s.get(type(plan), plan.id)
            await record_queue_usage_sample(
                s, customer=cust, plan=pl, queue_key=key,
                upload_bytes=upload, download_bytes=download,
            )
            await s.commit()

    async def push(upload, download, final=False):
        await usage_push.ingest_usage_reports(
            router.id,
            [UsageReport(queue_key=key, upload_bytes=upload, download_bytes=download, final=final)],
            session_factory=session_factory,
        )

    # The router's counter climbs steadily; the two readers interleave arbitrarily.
    await poll(0, 0)                 # baseline
    await push(1 * MB, 4 * MB)       # +1 / +4
    await poll(2 * MB, 9 * MB)       # +1 / +5
    await push(3 * MB, 12 * MB)      # +1 / +3
    await push(4 * MB, 16 * MB)      # +1 / +4
    await poll(5 * MB, 20 * MB)      # +1 / +4

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()

    # Exactly the counter's growth from 0 to 5/20 — counted once, not twice.
    assert period.upload_bytes == 5 * MB
    assert period.download_bytes == 20 * MB
    assert period.total_bytes == 25 * MB
