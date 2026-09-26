"""Top users over a chosen window, from the per-customer hourly usage ledger.

The old "live" list ranked lifetime router queue counters, so a customer who
expired in March (35 GB of leftover counter) topped Bitwave Wangige's list.
Now every credit also lands in customer_usage_buckets (same transaction), and
the dashboard ranks real usage over 1h / today / 7d / 30d.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.mikrotik_routes as mr
from app.db.database import get_db
from app.db.models import ConnectionType, CustomerStatus, CustomerUsageBucket
from app.services.auth import verify_token
from app.services.usage_tracking import record_usage
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(mr.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


async def _customer(db, reseller, router, mac, name):
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    return await make_customer(db, reseller, plan, router, mac_address=mac, name=name,
                               status=CustomerStatus.ACTIVE, expiry=datetime.utcnow() + timedelta(days=5))


@pytest.mark.asyncio
async def test_record_usage_also_writes_the_hourly_customer_ledger(db, session_factory):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    customer = await _customer(db, reseller, router, "AA:BB:CC:00:00:01", "Alice")
    t = datetime(2026, 9, 26, 10, 15)
    async with session_factory() as s:
        from sqlalchemy.orm import selectinload
        c = (await s.execute(select(type(customer)).options(selectinload(type(customer).plan))
                             .where(type(customer).id == customer.id))).scalar_one()
        await record_usage(s, c, 1 * MB, 3 * MB, plan=c.plan, now=t)
        await record_usage(s, c, 1 * MB, 1 * MB, plan=c.plan, now=t + timedelta(minutes=30))   # same hour
        await record_usage(s, c, 0, 2 * MB, plan=c.plan, now=t + timedelta(hours=1))           # next hour
        await s.commit()
    async with session_factory() as s:
        rows = (await s.execute(select(CustomerUsageBucket).order_by(CustomerUsageBucket.bucket_start))).scalars().all()
    assert [(r.bucket_start, r.upload_bytes, r.download_bytes, r.router_id) for r in rows] == [
        (datetime(2026, 9, 26, 10), 2 * MB, 4 * MB, router.id),
        (datetime(2026, 9, 26, 11), 0, 2 * MB, router.id),
    ]


@pytest.mark.asyncio
async def test_top_users_ranks_real_usage_in_the_window_and_says_which_window(db, client, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    other_router = await make_router(db, reseller)
    alice = await _customer(db, reseller, router, "AA:BB:CC:00:00:01", "Alice")
    bob = await _customer(db, reseller, router, "AA:BB:CC:00:00:02", "Bob")
    ghost = await _customer(db, reseller, router, "AA:BB:CC:00:00:03", "Ghost")      # heavy, but 3 days ago
    elsewhere = await _customer(db, reseller, other_router, "AA:BB:CC:00:00:04", "Else")
    now = datetime.utcnow().replace(minute=30)
    hour = now.replace(minute=0, second=0, microsecond=0)
    db.add_all([
        CustomerUsageBucket(customer_id=alice.id, router_id=router.id, bucket_start=hour, upload_bytes=MB, download_bytes=9 * MB),
        CustomerUsageBucket(customer_id=bob.id, router_id=router.id, bucket_start=hour, upload_bytes=MB, download_bytes=40 * MB),
        CustomerUsageBucket(customer_id=ghost.id, router_id=router.id, bucket_start=hour - timedelta(days=3),
                            upload_bytes=0, download_bytes=35_000 * MB),
        CustomerUsageBucket(customer_id=elsewhere.id, router_id=other_router.id, bucket_start=hour, upload_bytes=0, download_bytes=99 * MB),
    ])
    await db.commit()

    async def as_reseller(token, db):
        return reseller
    monkeypatch.setattr(mr, "get_current_user", as_reseller)

    r = await client.get(f"/api/mikrotik/top-users?router_id={router.id}&window=1h")
    body = r.json()
    assert r.status_code == 200, body
    assert body["windowLabel"] == "Last hour" and body["window"] == "1h"
    assert [u["customerName"] for u in body["topUsers"]] == ["Bob", "Alice"]      # no ghost, no other router
    assert body["topUsers"][0]["downloadMB"] == 40.0
    assert body["totalTracked"] == 2

    r7 = (await client.get(f"/api/mikrotik/top-users?router_id={router.id}&window=7d")).json()
    assert r7["windowLabel"] == "Last 7 days"
    assert r7["topUsers"][0]["customerName"] == "Ghost"   # it WAS their usage, 3 days ago
    assert r7["windowFullyCovered"] is False              # ledger history is shorter than 7 days

    unknown = (await client.get(f"/api/mikrotik/top-users?router_id={router.id}&window=forever")).json()
    assert unknown["window"] == "today"


def test_health_tile_uses_the_reports_rate_and_ports_for_pushing_routers():
    from app.services import realtime_state

    now = datetime.utcnow()
    realtime_state.record_push(88, now=now - timedelta(seconds=60), interval_seconds=60, hosts=[], queues=[],
                               live_customers={}, metrics={"iface_rx_bytes": 0, "iface_tx_bytes": 0})
    realtime_state.record_push(88, now=now, interval_seconds=60, hosts=[], queues=[], live_customers={},
                               metrics={"iface_rx_bytes": 75_000_000, "iface_tx_bytes": 7_500_000},
                               ports=[{"name": "ether2", "running": True, "disabled": False, "rx_bytes": 5,
                                       "tx_bytes": 6, "link_downs": 0, "rx_packets": 1, "tx_packets": 2,
                                       "rx_errors": 0, "tx_errors": 0}])
    snapshot_payload = {"bandwidth": {"download_mbps": 0.5, "upload_mbps": 0.1}, "interfaces": []}
    out = mr._apply_live_push(dict(snapshot_payload), 88)
    assert out["bandwidth"] == {"download_mbps": 10.0, "upload_mbps": 1.0}     # 75 MB/60 s, not the 5-min average
    assert out["bandwidth_source"] == "push"
    assert out["interfaces"][0]["name"] == "ether2" and out["interfaces"][0]["running"] is True
    assert mr._apply_live_push(dict(snapshot_payload), 999) == snapshot_payload  # not pushing: unchanged
