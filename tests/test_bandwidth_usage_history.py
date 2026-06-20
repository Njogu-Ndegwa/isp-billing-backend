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
    assert latest_snapshot.hotspot_upload_bytes == 1000
    assert latest_snapshot.hotspot_download_bytes == 3000
    assert latest_snapshot.pppoe_upload_bytes == 400
    assert latest_snapshot.pppoe_download_bytes == 1000
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
    assert point["activeHotspotUsers"] == 2
    assert point["activePppoeUsers"] == 3
    assert point["hotspotUploadMB"] == 1.0
    assert point["hotspotDownloadMB"] == 3.0
    assert point["pppoeUploadMB"] == 2.0
    assert point["pppoeDownloadMB"] == 4.0
    assert point["trackedDownloadMB"] == 7.0
