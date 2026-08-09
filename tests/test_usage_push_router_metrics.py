"""Contract for the push channel's optional router-metrics block.

The dashboard's router-level widgets (live bandwidth, active users, history)
read ``bandwidth_snapshots``, written only by the poller — each router's last
visit, up to ~1h stale. This extension lets a router report those numbers in the
same 2-minute push: an optional ``router`` block with interface counters and
active session counts. The server persists a snapshot row from it, throttled.

Pinned properties:

* backwards compatible — the 40 fielded scripts send no block and must be
  unaffected;
* a snapshot written from push must NOT double-count the Daily Breakdown bars —
  those sum per-queue byte deltas that only the poller computes, so push
  snapshots carry zeros there;
* throughput (avg bps) is computed against the previous snapshot regardless of
  which source wrote it;
* snapshot writes are throttled per router so 2-minute pushes do not multiply
  table growth by 15x fleet-wide;
* implausible counters are rejected (same bound as usage reports);
* a push with a router block is also a liveness proof — the router's
  availability stamps update (throttled with the snapshot write).

Incident lesson applied: fixtures include a pre-existing poller-written
snapshot (mixed-source history), not just a clean table.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    BandwidthSnapshot,
    ConnectionType,
    CustomerStatus,
    Router,
)
from app.services import usage_push
from app.services.usage_push import RouterMetrics, UsageReport
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


async def _setup(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity="Router-Test")
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(
        db, reseller, plan, router,
        mac_address="AA:BB:CC:11:22:33", status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    return router, customer


def _metrics(rx=100 * MB, tx=20 * MB, hotspot=5, pppoe=2, queues=6, version=2):
    return RouterMetrics(
        iface_rx_bytes=rx, iface_tx_bytes=tx,
        hotspot_active=hotspot, pppoe_active=pppoe, queue_count=queues,
        metrics_version=version,
    )


async def _seed_snapshot(session_factory, router_id, *, rx, tx, minutes_ago):
    async with session_factory() as s:
        s.add(BandwidthSnapshot(
            router_id=router_id,
            interface_rx_bytes=rx, interface_tx_bytes=tx,
            active_hotspot_users=1, active_sessions=0, active_queues=1,
            recorded_at=datetime.utcnow() - timedelta(minutes=minutes_ago),
        ))
        await s.commit()


@pytest.mark.asyncio
async def test_router_block_writes_a_snapshot(db, session_factory):
    router, _ = await _setup(db)

    result = await usage_push.ingest_usage_reports(
        router.id, [], router_metrics=_metrics(),
        session_factory=session_factory,
    )
    assert result.snapshot_written is True

    async with session_factory() as s:
        snap = (await s.execute(
            select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
        )).scalar_one()

    assert snap.interface_rx_bytes == 100 * MB
    assert snap.interface_tx_bytes == 20 * MB
    assert snap.active_hotspot_users == 5
    assert snap.active_sessions == 5
    # active_queues is the COMBINED count the health endpoint subtracts from.
    assert snap.active_queues == 7


@pytest.mark.asyncio
async def test_first_sample_push_snapshot_carries_zero_deltas(db, session_factory):
    """A first sample is a baseline — nothing is credited, so neither the
    snapshot bars (always zero now) nor the ledger gain any bytes."""
    router, _ = await _setup(db)

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:11:22:33", upload_bytes=MB, download_bytes=9 * MB)],
        router_metrics=_metrics(),
        session_factory=session_factory,
    )

    async with session_factory() as s:
        snap = (await s.execute(
            select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
        )).scalar_one()

    assert snap.hotspot_download_bytes == 0
    assert snap.hotspot_upload_bytes == 0
    assert snap.pppoe_download_bytes == 0
    assert snap.pppoe_upload_bytes == 0


@pytest.mark.asyncio
async def test_throughput_computed_against_previous_snapshot_any_source(db, session_factory):
    """Mixed-source history: previous snapshot came from the POLLER; the push
    snapshot's avg bps must still be derived from the counter delta."""
    router, _ = await _setup(db)
    await _seed_snapshot(session_factory, router.id, rx=40 * MB, tx=10 * MB, minutes_ago=10)

    await usage_push.ingest_usage_reports(
        router.id, [], router_metrics=_metrics(rx=100 * MB, tx=25 * MB),
        session_factory=session_factory,
    )

    async with session_factory() as s:
        snap = (await s.execute(
            select(BandwidthSnapshot)
            .where(BandwidthSnapshot.router_id == router.id)
            .order_by(BandwidthSnapshot.recorded_at.desc()).limit(1)
        )).scalars().first()

    # 60 MB down over ~600s ≈ 0.8 Mbps; assert the right order of magnitude
    # rather than exact timing.
    assert snap.avg_download_bps > 0
    assert 0.2 * 1_000_000 < snap.avg_download_bps < 3 * 1_000_000
    assert snap.avg_upload_bps > 0


@pytest.mark.asyncio
async def test_counter_reset_produces_zero_rate_not_negative(db, session_factory):
    """Router reboot resets interface counters; the delta must clamp, not go
    negative or spike."""
    router, _ = await _setup(db)
    await _seed_snapshot(session_factory, router.id, rx=500 * MB, tx=100 * MB, minutes_ago=5)

    await usage_push.ingest_usage_reports(
        router.id, [], router_metrics=_metrics(rx=3 * MB, tx=1 * MB),
        session_factory=session_factory,
    )

    async with session_factory() as s:
        snap = (await s.execute(
            select(BandwidthSnapshot)
            .where(BandwidthSnapshot.router_id == router.id)
            .order_by(BandwidthSnapshot.recorded_at.desc()).limit(1)
        )).scalars().first()

    assert snap.avg_download_bps == 0
    assert snap.avg_upload_bps == 0


@pytest.mark.asyncio
async def test_snapshot_writes_are_throttled_per_router(db, session_factory):
    """Two pushes inside the throttle window -> one snapshot. 2-minute pushes
    fleet-wide must not multiply bandwidth_snapshots growth ~15x."""
    router, _ = await _setup(db)

    r1 = await usage_push.ingest_usage_reports(
        router.id, [], router_metrics=_metrics(rx=10 * MB),
        session_factory=session_factory,
    )
    r2 = await usage_push.ingest_usage_reports(
        router.id, [], router_metrics=_metrics(rx=12 * MB),
        session_factory=session_factory,
    )

    assert r1.snapshot_written is True
    assert r2.snapshot_written is False

    async with session_factory() as s:
        count = len((await s.execute(
            select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
        )).scalars().all())
    assert count == 1


@pytest.mark.asyncio
async def test_stale_previous_snapshot_lets_the_next_write_through(db, session_factory):
    router, _ = await _setup(db)
    await _seed_snapshot(session_factory, router.id, rx=10 * MB, tx=2 * MB,
                         minutes_ago=20)

    result = await usage_push.ingest_usage_reports(
        router.id, [], router_metrics=_metrics(rx=50 * MB),
        session_factory=session_factory,
    )
    assert result.snapshot_written is True


@pytest.mark.asyncio
async def test_no_router_block_changes_nothing(db, session_factory):
    """Backwards compatibility: the 40 fielded scripts send no block."""
    router, customer = await _setup(db)

    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:11:22:33", upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )

    assert result.snapshot_written is False
    assert result.accepted == 1
    async with session_factory() as s:
        snaps = (await s.execute(
            select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
        )).scalars().all()
    assert snaps == []


@pytest.mark.asyncio
async def test_implausible_interface_counters_are_rejected(db, session_factory):
    router, _ = await _setup(db)

    result = await usage_push.ingest_usage_reports(
        router.id, [], router_metrics=_metrics(rx=2 ** 62),
        session_factory=session_factory,
    )

    assert result.snapshot_written is False
    assert "implausible_router_metrics" in result.errors

    async with session_factory() as s:
        snaps = (await s.execute(select(BandwidthSnapshot))).scalars().all()
    assert snaps == []


@pytest.mark.asyncio
async def test_metrics_push_updates_router_liveness_stamps(db, session_factory):
    """A push IS proof the router is up — the availability stamps should say so
    (updated when a snapshot is written, so the hot routers row is touched at
    the throttle cadence, not every 2 minutes)."""
    router, _ = await _setup(db)
    async with session_factory() as s:
        row = await s.get(Router, router.id)
        row.last_status = False
        row.last_checked_at = datetime.utcnow() - timedelta(hours=2)
        await s.commit()

    await usage_push.ingest_usage_reports(
        router.id, [], router_metrics=_metrics(),
        session_factory=session_factory,
    )

    async with session_factory() as s:
        row = await s.get(Router, router.id)
    assert row.last_status is True
    assert row.last_checked_at > datetime.utcnow() - timedelta(minutes=5)


# ---------------------------------------------------------------------------
# Dashboard bars: snapshots are router HEALTH only. Credited bytes land in the
# router_usage_buckets ledger inside record_usage — same transaction as the
# customer's period credit — so bars equal per-customer usage by construction.
# (The earlier in-memory bank was lost on restart and raced the poller:
# 2.9%-182% capture across the fleet, 2026-07-30.)
# ---------------------------------------------------------------------------


async def _ledger_totals(session_factory, router_id):
    from app.db.models import RouterUsageBucket

    async with session_factory() as s:
        buckets = (
            await s.execute(
                select(RouterUsageBucket).where(RouterUsageBucket.router_id == router_id)
            )
        ).scalars().all()
    return (
        sum(b.hotspot_upload_bytes for b in buckets),
        sum(b.hotspot_download_bytes for b in buckets),
        sum(b.pppoe_upload_bytes for b in buckets),
        sum(b.pppoe_download_bytes for b in buckets),
    )


@pytest.mark.asyncio
async def test_push_deltas_land_in_the_ledger_not_the_snapshot(db, session_factory):
    router, _ = await _setup(db)
    key = "AA:BB:CC:11:22:33"

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=2 * MB, download_bytes=10 * MB)],
        router_metrics=_metrics(),
        session_factory=session_factory,
    )

    async with session_factory() as s:
        snap = (await s.execute(
            select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
            .order_by(BandwidthSnapshot.recorded_at.desc()).limit(1)
        )).scalars().first()

    assert snap.hotspot_upload_bytes == 0
    assert snap.hotspot_download_bytes == 0
    assert await _ledger_totals(session_factory, router.id) == (2 * MB, 10 * MB, 0, 0)


@pytest.mark.asyncio
async def test_ledger_deltas_survive_the_snapshot_throttle(db, session_factory):
    """The snapshot throttle must never cost usage bytes: the ledger write
    rides the credit transaction, not the snapshot."""
    router, _ = await _setup(db)
    key = "AA:BB:CC:11:22:33"

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=0, download_bytes=0)],
        router_metrics=_metrics(rx=10 * MB),      # writes snapshot 1
        session_factory=session_factory,
    )
    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=key, upload_bytes=MB, download_bytes=5 * MB)],
        router_metrics=_metrics(rx=12 * MB),      # throttled — no snapshot 2
        session_factory=session_factory,
    )

    assert await _ledger_totals(session_factory, router.id) == (MB, 5 * MB, 0, 0)


@pytest.mark.asyncio
async def test_pppoe_deltas_land_in_the_pppoe_ledger_fields(db, session_factory):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity="Router-PPP")
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    await make_customer(
        db, reseller, plan, router, pppoe_username="alex",
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )

    await usage_push.ingest_usage_reports(
        router.id, [UsageReport(queue_key="pppoe:alex", upload_bytes=0, download_bytes=0)],
        session_factory=session_factory,
    )
    await usage_push.ingest_usage_reports(
        router.id, [UsageReport(queue_key="pppoe:alex", upload_bytes=MB, download_bytes=3 * MB)],
        session_factory=session_factory,
    )

    assert await _ledger_totals(session_factory, router.id) == (0, 0, MB, 3 * MB)


@pytest.mark.asyncio
async def test_hotspot_count_is_who_is_connected_not_who_holds_a_queue(db, session_factory):
    """Three paid-up customers hold queues; only one is actually on the router.

    The tile must say 1, not 3. A queue survives the customer switching their
    phone off; the hotspot host table does not.
    """
    router, _ = await _setup(db)

    reports = [
        UsageReport(queue_key="AA:BB:CC:11:22:33", upload_bytes=0, download_bytes=0),
        UsageReport(queue_key="AA:BB:CC:11:22:44", upload_bytes=0, download_bytes=0),
        UsageReport(queue_key="AA:BB:CC:11:22:55", upload_bytes=0, download_bytes=0),
    ]
    await usage_push.ingest_usage_reports(
        router.id, reports,
        router_metrics=_metrics(hotspot=1, pppoe=0, queues=3),
        session_factory=session_factory,
    )

    async with session_factory() as s:
        snap = (await s.execute(
            select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
        )).scalar_one()

    assert snap.active_hotspot_users == 1
    # Regression: this used to render as 3 phantom PPPoE users.
    assert max(0, snap.active_queues - snap.active_hotspot_users) == 0


@pytest.mark.asyncio
async def test_old_script_does_not_zero_the_hotspot_count(db, session_factory):
    """A router still on METRICS_VERSION 1 reports hotspot_active=0 because
    /ip hotspot active is empty on MAC-bypass. That 0 must not overwrite the
    poller's real figure every two minutes."""
    router, _ = await _setup(db)
    await _seed_snapshot(session_factory, router.id, rx=1 * MB, tx=1 * MB, minutes_ago=30)

    await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="AA:BB:CC:11:22:33", upload_bytes=0, download_bytes=0)],
        router_metrics=_metrics(rx=2 * MB, tx=2 * MB, hotspot=0, pppoe=0, queues=1, version=1),
        session_factory=session_factory,
    )

    async with session_factory() as s:
        snap = (await s.execute(
            select(BandwidthSnapshot)
            .where(BandwidthSnapshot.router_id == router.id)
            .order_by(BandwidthSnapshot.recorded_at.desc()).limit(1)
        )).scalars().first()

    # _seed_snapshot wrote active_hotspot_users=1; it is carried, not zeroed.
    assert snap.active_hotspot_users == 1
    assert max(0, snap.active_queues - snap.active_hotspot_users) == 0


@pytest.mark.asyncio
async def test_mixed_router_splits_hotspot_and_pppoe(db, session_factory):
    router, _ = await _setup(db)

    reports = [
        UsageReport(queue_key="AA:BB:CC:11:22:33", upload_bytes=0, download_bytes=0),
        UsageReport(queue_key="AA:BB:CC:11:22:44", upload_bytes=0, download_bytes=0),
        UsageReport(queue_key="pppoe:alex", upload_bytes=0, download_bytes=0),
    ]
    await usage_push.ingest_usage_reports(
        router.id, reports,
        router_metrics=_metrics(hotspot=2, pppoe=1, queues=3),
        session_factory=session_factory,
    )

    async with session_factory() as s:
        snap = (await s.execute(
            select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
        )).scalar_one()

    assert snap.active_hotspot_users == 2
    assert snap.active_queues == 3
    assert max(0, snap.active_queues - snap.active_hotspot_users) == 1
