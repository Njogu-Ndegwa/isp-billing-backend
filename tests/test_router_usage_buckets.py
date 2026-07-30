"""One source of truth for dashboard usage bars.

Written before the implementation (2026-07-30), after three days of the bars
disagreeing with the per-customer pages in every direction at once:

* SkyNet router 277: bars showed 53% of real traffic,
* Ella net router 236: 2.9%,
* Ella net 222/249 and Wangige 10: 142% / 182% / 152%.

Root cause: the byte counters had THREE competing readers (push ingest, the
bandwidth poller, the cap sampler) and TWO bookkeeping systems (customer usage
periods vs snapshot bar fields fed by an in-memory bank). A reader applying a
stale router read after a fresher writer had advanced the shared baseline
tripped the "counter reset" rule and re-booked a queue's whole lifetime counter;
restarts dropped the in-memory bank; sampler slivers never reached the bars at
all.

The contract pinned here:

1. Every credited byte lands in ONE durable per-router ledger
   (``router_usage_buckets``), written by ``record_usage`` in the same
   transaction that credits the customer's period — so dashboard bars equal the
   sum of customer usage BY CONSTRUCTION, and a restart can never lose them.
2. Neither snapshot writer stamps bar bytes any more; the in-memory bank is gone.
3. A sample read from the router BEFORE the usage row's last write is discarded
   (stale-sample guard) — a genuine reboot/relogin reset still books the fresh
   counter, but a racing stale read can no longer re-book history.
4. The bandwidth-history endpoint merges the bucket ledger into its response,
   still summing legacy snapshot bars so pre-cutover history keeps displaying.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    BandwidthSnapshot,
    ConnectionType,
    CustomerStatus,
    CustomerUsagePeriod,
    RouterUsageBucket,
    UserBandwidthUsage,
)
from app.services import usage_push, usage_tracking
from app.services.usage_counters import record_queue_usage_sample
from app.services.usage_push import RouterMetrics, UsageReport
from app.services.usage_tracking import bucket_start_for, record_usage
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


async def _setup(db, *, connection_type=ConnectionType.HOTSPOT, mac="AA:BB:CC:11:22:33",
                 pppoe_username=None, phone="254700000001"):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=connection_type)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        mac_address=mac,
        phone=phone,
        pppoe_username=pppoe_username,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    return reseller, router, plan, customer


async def _buckets(session_factory, router_id):
    async with session_factory() as s:
        return (
            await s.execute(
                select(RouterUsageBucket)
                .where(RouterUsageBucket.router_id == router_id)
                .order_by(RouterUsageBucket.bucket_start)
            )
        ).scalars().all()


# ---------------------------------------------------------------------------
# The ledger itself
# ---------------------------------------------------------------------------

def test_bucket_start_floors_to_five_minutes():
    assert bucket_start_for(datetime(2026, 7, 30, 10, 3, 27)) == datetime(2026, 7, 30, 10, 0)
    assert bucket_start_for(datetime(2026, 7, 30, 10, 4, 59)) == datetime(2026, 7, 30, 10, 0)
    assert bucket_start_for(datetime(2026, 7, 30, 10, 5, 0)) == datetime(2026, 7, 30, 10, 5)


@pytest.mark.asyncio
async def test_record_usage_writes_hotspot_bucket(db, session_factory):
    _, router, plan, customer = await _setup(db)
    t = datetime(2026, 7, 30, 10, 3, 0)

    await record_usage(db, customer, 2 * MB, 10 * MB, plan=plan, now=t)
    await db.commit()

    buckets = await _buckets(session_factory, router.id)
    assert len(buckets) == 1
    b = buckets[0]
    assert b.bucket_start == datetime(2026, 7, 30, 10, 0)
    assert b.hotspot_upload_bytes == 2 * MB
    assert b.hotspot_download_bytes == 10 * MB
    assert b.pppoe_upload_bytes == 0
    assert b.pppoe_download_bytes == 0


@pytest.mark.asyncio
async def test_record_usage_writes_pppoe_bucket(db, session_factory):
    _, router, plan, customer = await _setup(
        db, connection_type=ConnectionType.PPPOE,
        mac="11:22:33:44:55:66", pppoe_username="john", phone="254700000002",
    )
    t = datetime(2026, 7, 30, 10, 3, 0)

    await record_usage(db, customer, 1 * MB, 4 * MB, plan=plan, now=t)
    await db.commit()

    b = (await _buckets(session_factory, router.id))[0]
    assert b.pppoe_upload_bytes == 1 * MB
    assert b.pppoe_download_bytes == 4 * MB
    assert b.hotspot_upload_bytes == 0


@pytest.mark.asyncio
async def test_same_window_accumulates_next_window_opens_new_row(db, session_factory):
    _, router, plan, customer = await _setup(db)

    await record_usage(db, customer, 1 * MB, 2 * MB, plan=plan, now=datetime(2026, 7, 30, 10, 1, 0))
    await record_usage(db, customer, 3 * MB, 4 * MB, plan=plan, now=datetime(2026, 7, 30, 10, 4, 0))
    await record_usage(db, customer, 5 * MB, 6 * MB, plan=plan, now=datetime(2026, 7, 30, 10, 6, 0))
    await db.commit()

    buckets = await _buckets(session_factory, router.id)
    assert [b.bucket_start for b in buckets] == [
        datetime(2026, 7, 30, 10, 0),
        datetime(2026, 7, 30, 10, 5),
    ]
    assert buckets[0].hotspot_upload_bytes == 4 * MB
    assert buckets[0].hotspot_download_bytes == 6 * MB
    assert buckets[1].hotspot_upload_bytes == 5 * MB


@pytest.mark.asyncio
async def test_zero_delta_writes_no_bucket(db, session_factory):
    _, router, plan, customer = await _setup(db)
    await record_usage(db, customer, 0, 0, plan=plan, now=datetime(2026, 7, 30, 10, 1, 0))
    await db.commit()
    assert await _buckets(session_factory, router.id) == []


# ---------------------------------------------------------------------------
# Bars == periods, by construction, through the push channel
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_push_ingest_bucket_equals_period_delta(db, session_factory):
    _, router, _, customer = await _setup(db)
    key = "AA:BB:CC:11:22:33"

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=10 * MB, download_bytes=50 * MB)],
        session_factory=session_factory,
    )
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=13 * MB, download_bytes=65 * MB)],
        session_factory=session_factory,
    )

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer.id)
            )
        ).scalar_one()
    buckets = await _buckets(session_factory, router.id)

    assert period.upload_bytes == 3 * MB
    assert period.download_bytes == 15 * MB
    assert sum(b.hotspot_upload_bytes for b in buckets) == period.upload_bytes
    assert sum(b.hotspot_download_bytes for b in buckets) == period.download_bytes


@pytest.mark.asyncio
async def test_rejected_report_writes_no_bucket(db, session_factory):
    _, router, _, _ = await _setup(db)

    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="99:99:99:99:99:99", upload_bytes=5 * MB, download_bytes=5 * MB)],
        session_factory=session_factory,
    )

    assert result.rejected == 1
    assert await _buckets(session_factory, router.id) == []


# ---------------------------------------------------------------------------
# The two-source machinery is gone
# ---------------------------------------------------------------------------

def test_in_memory_bank_is_gone():
    """The restartable in-memory bar bank was the restart-loss / two-source bug."""
    assert not hasattr(usage_push, "_bar_deltas")
    assert not hasattr(usage_push, "drain_bar_deltas")
    assert not hasattr(usage_push, "_bank_bar_delta")


@pytest.mark.asyncio
async def test_metrics_snapshot_carries_no_bar_bytes(db, session_factory):
    """A push-written snapshot records router health (interface counters,
    actives) but never bar bytes — those live only in the bucket ledger now."""
    _, router, _, _ = await _setup(db)
    key = "AA:BB:CC:11:22:33"

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=10 * MB, download_bytes=50 * MB)],
        session_factory=session_factory,
        router_metrics=RouterMetrics(iface_rx_bytes=1_000_000, iface_tx_bytes=500_000),
    )
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=13 * MB, download_bytes=65 * MB)],
        session_factory=session_factory,
        router_metrics=RouterMetrics(iface_rx_bytes=2_000_000, iface_tx_bytes=900_000),
        now=datetime.utcnow() + timedelta(seconds=usage_push.PUSH_SNAPSHOT_MIN_INTERVAL_SECONDS + 1),
    )

    async with session_factory() as s:
        snapshots = (
            await s.execute(
                select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
            )
        ).scalars().all()

    assert snapshots, "metrics push should still write health snapshots"
    for snap in snapshots:
        assert snap.hotspot_upload_bytes == 0
        assert snap.hotspot_download_bytes == 0
        assert snap.pppoe_upload_bytes == 0
        assert snap.pppoe_download_bytes == 0
    # ... while the credited bytes are all in the ledger.
    buckets = await _buckets(session_factory, router.id)
    assert sum(b.hotspot_download_bytes for b in buckets) == 15 * MB


# ---------------------------------------------------------------------------
# Stale-sample guard: the reset-race that inflated bars to 142-182%
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stale_sample_is_discarded_not_booked_as_reset(db):
    """A reader that fetched counters BEFORE the last write must be a no-op.

    This is the exact prod failure: push advanced the baseline to 110 MB, the
    poller then applied a read taken seconds earlier (108 MB < baseline), the
    old rule said "counter reset" and booked the full 108 MB again.
    """
    _, router, plan, customer = await _setup(db)
    key = "AA:BB:CC:11:22:33"
    t0 = datetime(2026, 7, 30, 10, 0, 0)

    # Baseline then a normal push delta.
    await record_queue_usage_sample(
        db, customer=customer, plan=plan, queue_key=key,
        upload_bytes=10 * MB, download_bytes=100 * MB, now=t0,
    )
    await record_queue_usage_sample(
        db, customer=customer, plan=plan, queue_key=key,
        upload_bytes=11 * MB, download_bytes=110 * MB, now=t0 + timedelta(minutes=2),
    )

    # A poller sample READ before that write but APPLIED after it.
    stale = await record_queue_usage_sample(
        db, customer=customer, plan=plan, queue_key=key,
        upload_bytes=10 * MB + 512, download_bytes=108 * MB,
        now=t0 + timedelta(minutes=3),
        sampled_at=t0 + timedelta(minutes=1, seconds=50),
    )

    assert stale.delta_upload_bytes == 0
    assert stale.delta_download_bytes == 0
    assert not stale.reset_detected
    # Baseline must NOT regress — otherwise the next push re-books the gap.
    row = (
        await db.execute(select(UserBandwidthUsage).where(UserBandwidthUsage.mac_address == key))
    ).scalar_one()
    assert row.last_upload_bytes == 11 * MB
    assert row.last_download_bytes == 110 * MB

    # The next fresh push books exactly its own delta.
    fresh = await record_queue_usage_sample(
        db, customer=customer, plan=plan, queue_key=key,
        upload_bytes=12 * MB, download_bytes=120 * MB, now=t0 + timedelta(minutes=4),
    )
    assert fresh.delta_upload_bytes == 1 * MB
    assert fresh.delta_download_bytes == 10 * MB

    period = (
        await db.execute(
            select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer.id)
        )
    ).scalar_one()
    # 10->12 up, 100->120 down since baseline. Not a byte more.
    assert period.upload_bytes == 2 * MB
    assert period.download_bytes == 20 * MB


@pytest.mark.asyncio
async def test_genuine_reset_still_books_the_fresh_counter(db):
    """Reboot/relogin: counter restarts near zero; the fresh value IS the usage."""
    _, router, plan, customer = await _setup(db)
    key = "AA:BB:CC:11:22:33"
    t0 = datetime(2026, 7, 30, 10, 0, 0)

    await record_queue_usage_sample(
        db, customer=customer, plan=plan, queue_key=key,
        upload_bytes=10 * MB, download_bytes=100 * MB, now=t0,
    )
    reset = await record_queue_usage_sample(
        db, customer=customer, plan=plan, queue_key=key,
        upload_bytes=1 * MB, download_bytes=8 * MB, now=t0 + timedelta(minutes=5),
    )

    assert reset.reset_detected
    assert reset.delta_upload_bytes == 1 * MB
    assert reset.delta_download_bytes == 8 * MB


@pytest.mark.asyncio
async def test_poller_applying_pre_push_read_cannot_rebook_history(db, session_factory):
    """End-to-end via the push channel: a stale interleaved sample changes nothing."""
    _, router, _, customer = await _setup(db)
    key = "AA:BB:CC:11:22:33"
    base = datetime.utcnow() + timedelta(minutes=5)

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=10 * MB, download_bytes=100 * MB)],
        session_factory=session_factory, now=base,
    )
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=11 * MB, download_bytes=110 * MB)],
        session_factory=session_factory, now=base + timedelta(minutes=2),
    )

    # A racing reader applies an older read directly through the shared helper.
    async with session_factory() as s:
        cust = await s.get(type(customer), customer.id)
        from app.db.models import Plan
        plan = await s.get(Plan, cust.plan_id)
        res = await record_queue_usage_sample(
            s, customer=cust, plan=plan, queue_key=key,
            upload_bytes=10 * MB + 100, download_bytes=105 * MB,
            now=base + timedelta(minutes=2, seconds=30),
            sampled_at=base + timedelta(minutes=1),
        )
        await s.commit()
    assert res.delta_download_bytes == 0

    buckets = await _buckets(session_factory, router.id)
    assert sum(b.hotspot_download_bytes for b in buckets) == 10 * MB
    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer.id)
            )
        ).scalar_one()
    assert period.download_bytes == 10 * MB


# ---------------------------------------------------------------------------
# The dashboard endpoint reads the ledger
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bandwidth_history_merges_buckets_into_snapshot_rows(db, monkeypatch):
    from app.api import mikrotik_routes

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    now = datetime.utcnow().replace(second=0, microsecond=0)

    # Two health snapshots (no bar bytes — the new writers), one legacy row
    # from before the cutover that still carries its own bars.
    db.add(BandwidthSnapshot(
        router_id=router.id, total_upload_bps=0, total_download_bps=0,
        avg_upload_bps=0, avg_download_bps=0, active_queues=1,
        active_hotspot_users=1, active_sessions=1,
        hotspot_upload_bytes=7 * MB, hotspot_download_bytes=9 * MB,
        pppoe_upload_bytes=0, pppoe_download_bytes=0,
        recorded_at=now - timedelta(minutes=60),
    ))
    db.add(BandwidthSnapshot(
        router_id=router.id, total_upload_bps=0, total_download_bps=0,
        avg_upload_bps=0, avg_download_bps=0, active_queues=1,
        active_hotspot_users=1, active_sessions=1,
        recorded_at=now - timedelta(minutes=30),
    ))
    db.add(BandwidthSnapshot(
        router_id=router.id, total_upload_bps=0, total_download_bps=0,
        avg_upload_bps=0, avg_download_bps=0, active_queues=1,
        active_hotspot_users=1, active_sessions=1,
        recorded_at=now,
    ))
    # Ledger: one bucket before the middle row, one after the last row (tail).
    db.add(RouterUsageBucket(
        router_id=router.id, bucket_start=now - timedelta(minutes=40),
        hotspot_upload_bytes=1 * MB, hotspot_download_bytes=2 * MB,
    ))
    db.add(RouterUsageBucket(
        router_id=router.id, bucket_start=now + timedelta(minutes=5),
        pppoe_upload_bytes=3 * MB, pppoe_download_bytes=4 * MB,
    ))
    await db.commit()

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(mikrotik_routes, "get_current_user", _current_user)
    response = await mikrotik_routes.get_bandwidth_history(hours=24, db=db, token="t")
    rows = response["history"]

    assert len(rows) == 3
    # Legacy row keeps its own bars.
    assert rows[0]["hotspotUploadMB"] == 7.0
    assert rows[0]["hotspotDownloadMB"] == 9.0
    # Bucket at now-40m attaches to the first row at/after it (now-30m).
    assert rows[1]["hotspotUploadMB"] == 1.0
    assert rows[1]["hotspotDownloadMB"] == 2.0
    # Tail bucket (after the last snapshot) attaches to the last row.
    assert rows[2]["pppoeUploadMB"] == 3.0
    assert rows[2]["pppoeDownloadMB"] == 4.0
    # Nothing counted twice: totals across rows equal legacy + ledger.
    assert sum(r["trackedTotalMB"] for r in rows) == 7 + 9 + 1 + 2 + 3 + 4


@pytest.mark.asyncio
async def test_bandwidth_history_synthesizes_rows_for_bucket_only_router(db, monkeypatch):
    """A router the poller cannot reach (outbound-only uplink) still shows its
    usage bars: pushes wrote buckets even though no snapshot row exists."""
    from app.api import mikrotik_routes

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    now = datetime.utcnow().replace(second=0, microsecond=0)
    db.add(RouterUsageBucket(
        router_id=router.id, bucket_start=now - timedelta(minutes=10),
        hotspot_upload_bytes=5 * MB, hotspot_download_bytes=6 * MB,
    ))
    await db.commit()

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(mikrotik_routes, "get_current_user", _current_user)
    response = await mikrotik_routes.get_bandwidth_history(hours=24, db=db, token="t")
    rows = response["history"]

    assert len(rows) == 1
    assert rows[0]["routerId"] == router.id
    assert rows[0]["hotspotUploadMB"] == 5.0
    assert rows[0]["hotspotDownloadMB"] == 6.0
    assert rows[0]["totalUploadMbps"] == 0
    assert rows[0]["activeHotspotUsers"] == 0


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bucket_ledger_is_pruned_with_snapshot_retention(db, session_factory, monkeypatch):
    from app.services import mikrotik_background

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    old = datetime.utcnow() - timedelta(days=mikrotik_background.BANDWIDTH_HISTORY_RETENTION_DAYS + 1)
    db.add(RouterUsageBucket(router_id=router.id, bucket_start=old, hotspot_upload_bytes=1))
    db.add(RouterUsageBucket(
        router_id=router.id, bucket_start=datetime.utcnow(), hotspot_upload_bytes=1
    ))
    await db.commit()

    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job: False)

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(mikrotik_background, "prune_router_availability_history", _noop)
    await mikrotik_background.collect_bandwidth_snapshot()

    buckets = await _buckets(session_factory, router.id)
    assert len(buckets) == 1
    assert buckets[0].bucket_start > old
