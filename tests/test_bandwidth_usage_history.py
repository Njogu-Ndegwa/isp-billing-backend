from collections import deque
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    BandwidthSnapshot,
    ConnectionType,
    CustomerUsagePeriod,
    UserBandwidthUsage,
)
from app.services import mikrotik_background
from tests.factories import make_customer, make_plan, make_reseller, make_router


def test_bandwidth_snapshot_retention_covers_largest_dashboard_filter():
    assert mikrotik_background.BANDWIDTH_HISTORY_RETENTION_DAYS >= 30


def _raw_snapshot(router_id: int, *, hotspot_bytes: str, pppoe_bytes: str, rx: int, tx: int) -> dict:
    return {
        "router_id": router_id,
        "active_sessions": {"success": True, "data": []},
        "traffic": {
            "success": True,
            "data": [{"name": "ether1", "running": True, "rx_byte": rx, "tx_byte": tx}],
        },
        "speed_stats": {
            "success": True,
            "data": {
                "total_upload_bps": 0,
                "total_download_bps": 0,
                "active_queues": 0,
                "total_queues": 2,
            },
        },
        "queues": {
            "success": True,
            "data": [
                {
                    "name": "plan_AABBCCDDEEFF",
                    "comment": "MAC:AA:BB:CC:DD:EE:FF|Plan rate limit",
                    "bytes": hotspot_bytes,
                    "max-limit": "5M/5M",
                    "target": "192.168.88.10/32",
                },
                {
                    "name": "<pppoe-pppoe-test>",
                    "comment": "",
                    "bytes": pppoe_bytes,
                    "max-limit": "10M/10M",
                    "target": "10.10.10.2/32",
                },
            ],
        },
        "hotspot_hosts": {"success": True, "authorized": 1, "bypassed": 0, "total": 1},
        "arp_entries": {"success": True, "count": 0, "data": []},
        "pppoe_sessions": {"success": True, "data": [{"name": "pppoe-test"}]},
    }


@pytest.mark.asyncio
async def test_bandwidth_snapshot_records_hotspot_and_pppoe_usage_deltas(
    db,
    session_factory,
    monkeypatch,
):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    hotspot_plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    pppoe_plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    expiry = datetime.utcnow() + timedelta(days=30)
    hotspot_customer = await make_customer(
        db,
        reseller,
        hotspot_plan,
        router,
        mac_address="AA:BB:CC:DD:EE:FF",
        phone="254700000001",
        expiry=expiry,
    )
    pppoe_customer = await make_customer(
        db,
        reseller,
        pppoe_plan,
        router,
        mac_address="11:22:33:44:55:66",
        phone="254700000002",
        pppoe_username="pppoe-test",
        expiry=expiry,
    )

    payloads = deque(
        [
            _raw_snapshot(router.id, hotspot_bytes="1000/3000", pppoe_bytes="500/1500", rx=10_000, tx=5_000),
            _raw_snapshot(router.id, hotspot_bytes="2000/6000", pppoe_bytes="900/2500", rx=20_000, tx=10_000),
        ]
    )

    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job: False)
    monkeypatch.setattr(mikrotik_background, "_router_recently_offline", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(mikrotik_background, "_fetch_bandwidth_data_sync_for_router", lambda _info: payloads.popleft())

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(mikrotik_background, "record_router_availability", _noop)
    monkeypatch.setattr(mikrotik_background, "prune_router_availability_history", _noop)

    await mikrotik_background.collect_bandwidth_snapshot()
    await mikrotik_background.collect_bandwidth_snapshot()

    async with session_factory() as s:
        hotspot_period = (
            await s.execute(
                select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == hotspot_customer.id)
            )
        ).scalar_one()
        pppoe_period = (
            await s.execute(
                select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == pppoe_customer.id)
            )
        ).scalar_one()
        latest_snapshot = (
            await s.execute(
                select(BandwidthSnapshot)
                .where(BandwidthSnapshot.router_id == router.id)
                .order_by(BandwidthSnapshot.recorded_at.desc())
                .limit(1)
            )
        ).scalar_one()
        hotspot_usage = (
            await s.execute(
                select(UserBandwidthUsage).where(UserBandwidthUsage.mac_address == "AA:BB:CC:DD:EE:FF")
            )
        ).scalar_one()

    assert hotspot_period.upload_bytes == 1000
    assert hotspot_period.download_bytes == 3000
    assert hotspot_period.total_bytes == 4000
    assert pppoe_period.upload_bytes == 400
    assert pppoe_period.download_bytes == 1000
    assert pppoe_period.total_bytes == 1400
    # Snapshots carry router health only; credited bytes go to the
    # router_usage_buckets ledger via record_usage (one source of truth).
    assert latest_snapshot.hotspot_upload_bytes == 0
    assert latest_snapshot.hotspot_download_bytes == 0
    assert latest_snapshot.pppoe_upload_bytes == 0
    assert latest_snapshot.pppoe_download_bytes == 0
    async with session_factory() as s:
        from app.db.models import RouterUsageBucket

        buckets = (
            await s.execute(
                select(RouterUsageBucket).where(RouterUsageBucket.router_id == router.id)
            )
        ).scalars().all()
    assert sum(b.hotspot_upload_bytes for b in buckets) == 1000
    assert sum(b.hotspot_download_bytes for b in buckets) == 3000
    assert sum(b.pppoe_upload_bytes for b in buckets) == 400
    assert sum(b.pppoe_download_bytes for b in buckets) == 1000
    assert hotspot_usage.last_upload_bytes == 2000
    assert hotspot_usage.last_download_bytes == 6000


@pytest.mark.asyncio
async def test_bandwidth_history_returns_usage_fields_and_clamps_hours(db, monkeypatch):
    from app.api import mikrotik_routes

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    db.add(
        BandwidthSnapshot(
            router_id=router.id,
            total_upload_bps=2_000_000,
            total_download_bps=4_000_000,
            avg_upload_bps=1_000_000,
            avg_download_bps=3_000_000,
            active_queues=5,
            active_hotspot_users=2,
            active_sessions=4,
            hotspot_upload_bytes=1 * 1024 * 1024,
            hotspot_download_bytes=3 * 1024 * 1024,
            pppoe_upload_bytes=2 * 1024 * 1024,
            pppoe_download_bytes=4 * 1024 * 1024,
            recorded_at=now,
        )
    )
    await db.commit()

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(mikrotik_routes, "get_current_user", _current_user)

    response = await mikrotik_routes.get_bandwidth_history(hours=9999, db=db, token="test")
    point = response["history"][0]

    assert response["periodHours"] == 720
    assert response["periodMode"] == "rolling"
    assert point["activeHotspotUsers"] == 2
    assert point["activePppoeUsers"] == 3
    assert point["hotspotUploadMB"] == 1.0
    assert point["hotspotDownloadMB"] == 3.0
    assert point["pppoeUploadMB"] == 2.0
    assert point["pppoeDownloadMB"] == 4.0
    assert point["trackedDownloadMB"] == 7.0


# ---------------------------------------------------------------------------
# Local calendar-day filtering (00:00 EAT -> now, not a rolling 24h window)
# ---------------------------------------------------------------------------


def _snapshot(router_id: int, recorded_at: datetime, download_mb: int) -> BandwidthSnapshot:
    return BandwidthSnapshot(
        router_id=router_id,
        total_upload_bps=0,
        total_download_bps=0,
        avg_upload_bps=0,
        avg_download_bps=0,
        active_queues=0,
        active_hotspot_users=0,
        active_sessions=0,
        hotspot_upload_bytes=0,
        hotspot_download_bytes=download_mb * 1024 * 1024,
        pppoe_upload_bytes=0,
        pppoe_download_bytes=0,
        recorded_at=recorded_at,
    )


def test_today_window_starts_at_local_midnight_not_24h_ago():
    from app.core.local_time import local_midnight_utc, resolve_usage_window

    # 2026-08-07 09:00 UTC == 12:00 EAT, so "today" started at 2026-08-06 21:00 UTC.
    now = datetime(2026, 8, 7, 9, 0)
    window = resolve_usage_window(preset="today", now_utc=now)

    assert window["start"] == datetime(2026, 8, 6, 21, 0)
    assert window["end"] == datetime(2026, 8, 7, 21, 0)
    assert window["mode"] == "calendar"
    assert window["label"] == "Today"
    assert window["days"] == 1
    assert window["start"] == local_midnight_utc(now)
    # The rolling equivalent would have reached back into yesterday evening.
    assert window["start"] > now - timedelta(hours=24)


def test_calendar_days_window_covers_whole_local_days_including_today():
    from app.core.local_time import resolve_usage_window

    now = datetime(2026, 8, 7, 9, 0)
    window = resolve_usage_window(days=3, now_utc=now)

    assert window["start"] == datetime(2026, 8, 4, 21, 0)  # 00:00 EAT on the 5th
    assert window["end"] == datetime(2026, 8, 7, 21, 0)
    assert window["days"] == 3
    assert window["label"] == "Last 3 days"


def test_yesterday_and_month_windows_are_local_calendar_bounded():
    from app.core.local_time import resolve_usage_window

    now = datetime(2026, 8, 7, 9, 0)

    yesterday = resolve_usage_window(preset="yesterday", now_utc=now)
    assert yesterday["start"] == datetime(2026, 8, 5, 21, 0)
    assert yesterday["end"] == datetime(2026, 8, 6, 21, 0)

    this_month = resolve_usage_window(preset="this_month", now_utc=now)
    assert this_month["start"] == datetime(2026, 7, 31, 21, 0)  # 00:00 EAT on Aug 1
    assert this_month["end"] == datetime(2026, 8, 7, 21, 0)


def test_explicit_local_dates_are_inclusive_on_both_ends():
    from app.core.local_time import resolve_usage_window

    now = datetime(2026, 8, 7, 9, 0)
    window = resolve_usage_window(start_date="2026-08-05", end_date="2026-08-06", now_utc=now)

    assert window["start"] == datetime(2026, 8, 4, 21, 0)
    assert window["end"] == datetime(2026, 8, 6, 21, 0)
    assert window["days"] == 2


def test_calendar_window_never_reaches_past_snapshot_retention():
    from app.core.local_time import MAX_HISTORY_CALENDAR_DAYS, resolve_usage_window
    from app.services import mikrotik_background

    assert MAX_HISTORY_CALENDAR_DAYS <= mikrotik_background.BANDWIDTH_HISTORY_RETENTION_DAYS

    now = datetime(2026, 8, 7, 9, 0)
    # A 30-calendar-day window is the widest the pruner can actually serve.
    widest = resolve_usage_window(days=MAX_HISTORY_CALENDAR_DAYS, now_utc=now)
    retention_cutoff = now - timedelta(days=mikrotik_background.BANDWIDTH_HISTORY_RETENTION_DAYS)
    assert widest["start"] > retention_cutoff
    assert widest["truncated"] is False

    # An explicit range older than retention is clamped and says so.
    clamped = resolve_usage_window(start_date="2026-01-01", end_date="2026-08-07", now_utc=now)
    assert clamped["start"] == widest["start"]
    assert clamped["truncated"] is True


def test_rolling_hours_branch_is_unchanged_for_legacy_callers():
    from app.core.local_time import resolve_usage_window

    now = datetime(2026, 8, 7, 9, 0)
    window = resolve_usage_window(hours=24, now_utc=now)

    assert window["mode"] == "rolling"
    assert window["start"] == now - timedelta(hours=24)
    assert window["end"] == now
    assert window["label"] == "Last 24h"


def test_invalid_filter_values_are_rejected():
    from app.core.local_time import resolve_usage_window

    with pytest.raises(ValueError):
        resolve_usage_window(preset="last_fortnight")
    with pytest.raises(ValueError):
        resolve_usage_window(start_date="07/08/2026")
    with pytest.raises(ValueError):
        resolve_usage_window(start_date="2026-08-07", end_date="2026-08-01")


@pytest.mark.asyncio
async def test_bandwidth_history_today_excludes_yesterday_evening(db, monkeypatch):
    """The bug this fixes: a rolling 24h "today" includes last night's usage."""
    from app.api import mikrotik_routes
    from app.core.local_time import local_midnight_utc

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    today_start = local_midnight_utc()
    db.add(_snapshot(router.id, today_start - timedelta(hours=1), 500))   # 23:00 EAT yesterday
    db.add(_snapshot(router.id, today_start + timedelta(minutes=30), 7))  # 00:30 EAT today
    await db.commit()

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(mikrotik_routes, "get_current_user", _current_user)

    today = await mikrotik_routes.get_bandwidth_history(preset="today", db=db, token="test")

    assert today["periodMode"] == "calendar"
    assert today["periodLabel"] == "Today"
    assert today["periodStart"] == today_start.isoformat()
    assert today["timezoneOffsetHours"] == 3
    assert today["count"] == 1
    assert today["history"][0]["hotspotDownloadMB"] == 7.0

    # Same data, legacy rolling window: yesterday evening still counts.
    rolling = await mikrotik_routes.get_bandwidth_history(hours=24, db=db, token="test")
    assert rolling["periodMode"] == "rolling"
    assert rolling["count"] >= today["count"]


@pytest.mark.asyncio
async def test_today_window_still_includes_tail_ledger_buckets(db, monkeypatch):
    """A bucket written just after the last health snapshot must still show."""
    from app.api import mikrotik_routes
    from app.core.local_time import local_midnight_utc
    from app.db.models import RouterUsageBucket

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    # Anchored inside the local day (not to "now") so the pair can never
    # straddle local midnight while the test runs.
    last_snapshot_at = local_midnight_utc() + timedelta(hours=1)
    db.add(_snapshot(router.id, last_snapshot_at, 0))
    db.add(
        RouterUsageBucket(
            router_id=router.id,
            bucket_start=last_snapshot_at + timedelta(minutes=5),
            pppoe_upload_bytes=3 * 1024 * 1024,
            pppoe_download_bytes=4 * 1024 * 1024,
        )
    )
    await db.commit()

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(mikrotik_routes, "get_current_user", _current_user)

    response = await mikrotik_routes.get_bandwidth_history(preset="today", db=db, token="test")
    assert sum(r["trackedTotalMB"] for r in response["history"]) == 7.0


@pytest.mark.asyncio
async def test_bandwidth_history_rejects_bad_calendar_params(db, monkeypatch):
    from fastapi import HTTPException

    from app.api import mikrotik_routes

    reseller = await make_reseller(db)

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(mikrotik_routes, "get_current_user", _current_user)

    with pytest.raises(HTTPException) as exc:
        await mikrotik_routes.get_bandwidth_history(preset="nonsense", db=db, token="test")
    assert exc.value.status_code == 400
