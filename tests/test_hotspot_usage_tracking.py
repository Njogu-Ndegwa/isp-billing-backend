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
from app.services.usage_tracking import open_new_period
from tests.factories import make_customer, make_plan, make_reseller, make_router


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
async def test_reseller_top_usage_includes_hotspot_and_pppoe(
    db,
    monkeypatch,
):
    from app.api import usage_routes

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
        mac_address="AA:BB:CC:DD:EE:11",
        phone="254700000003",
        expiry=expiry,
    )
    pppoe_customer = await make_customer(
        db,
        reseller,
        pppoe_plan,
        router,
        mac_address="11:22:33:44:55:77",
        phone="254700000004",
        pppoe_username="pppoe-top",
        expiry=expiry,
    )
    now = datetime.utcnow()
    db.add_all(
        [
            CustomerUsagePeriod(
                customer_id=hotspot_customer.id,
                period_start=now - timedelta(days=1),
                period_end=expiry,
                upload_bytes=1 * 1024 * 1024,
                download_bytes=4 * 1024 * 1024,
                total_bytes=5 * 1024 * 1024,
            ),
            CustomerUsagePeriod(
                customer_id=pppoe_customer.id,
                period_start=now - timedelta(days=1),
                period_end=expiry,
                upload_bytes=2 * 1024 * 1024,
                download_bytes=8 * 1024 * 1024,
                total_bytes=10 * 1024 * 1024,
            ),
        ]
    )
    await db.commit()

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(usage_routes, "get_current_user", _current_user)

    rows = await usage_routes.get_top_usage_for_reseller(limit=10, db=db, token="test")
    by_type = {row.connection_type: row for row in rows}

    assert set(by_type) == {"hotspot", "pppoe"}
    assert by_type["hotspot"].identifier == "AA:BB:CC:DD:EE:11"
    assert by_type["hotspot"].total_mb == 5.0
    assert by_type["pppoe"].pppoe_username == "pppoe-top"


@pytest.mark.asyncio
async def test_open_new_period_reopens_same_billing_window_without_duplicate(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, data_cap_mb=20)
    router = await make_router(db, reseller)
    expiry = datetime.utcnow() + timedelta(days=30)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        mac_address="AA:BB:CC:DD:EE:88",
        phone="254700000088",
        expiry=expiry,
    )

    first = await open_new_period(db, customer, plan=plan, now=datetime.utcnow())
    first.upload_bytes = 1024
    first.download_bytes = 2048
    first.total_bytes = 3072
    await db.commit()

    reopened = await open_new_period(
        db,
        customer,
        plan=plan,
        now=datetime.utcnow() + timedelta(seconds=1),
    )
    await db.commit()

    periods = (
        await db.execute(
            select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer.id)
        )
    ).scalars().all()

    assert reopened.id == first.id
    assert reopened.closed_at is None
    assert reopened.period_end == expiry
    assert reopened.total_bytes == 3072
    assert len(periods) == 1
