"""Per-customer usage over time, from the hourly customer_usage_buckets ledger.

The customer page charts this, so every slot must be present (zero-filled),
daily slots must follow the local (EAT) calendar rather than UTC days, and a
reseller must never see another reseller's customer.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from app.api import usage_routes
from app.core.local_time import local_midnight_utc
from app.db.models import ConnectionType, CustomerUsageBucket
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


def _as(monkeypatch, user):
    async def _current_user(_token, _db):
        return user

    monkeypatch.setattr(usage_routes, "get_current_user", _current_user)


async def _timeline(db, customer_id, **kw):
    kw.setdefault("days", 7)
    kw.setdefault("granularity", None)
    return await usage_routes.get_customer_usage_timeline(
        customer_id=customer_id, db=db, token="test", **kw
    )


@pytest.mark.asyncio
async def test_daily_timeline_zero_fills_and_buckets_by_local_day(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(db, reseller, plan, router)
    other = await make_customer(db, reseller, plan, router, mac_address="AA:BB:CC:DD:EE:99")

    today = local_midnight_utc()                    # 21:00 UTC yesterday = 00:00 EAT today
    two_days_ago = local_midnight_utc(days_back=2)
    db.add_all([
        # First and last hour of today's local day both land on today.
        CustomerUsageBucket(customer_id=customer.id, router_id=router.id, bucket_start=today,
                            upload_bytes=1 * MB, download_bytes=4 * MB),
        CustomerUsageBucket(customer_id=customer.id, router_id=router.id,
                            bucket_start=today + timedelta(hours=23),
                            upload_bytes=0, download_bytes=5 * MB),
        # The hour just before local midnight belongs to yesterday, not today.
        CustomerUsageBucket(customer_id=customer.id, router_id=router.id,
                            bucket_start=today - timedelta(hours=1),
                            upload_bytes=0, download_bytes=7 * MB),
        CustomerUsageBucket(customer_id=customer.id, router_id=router.id, bucket_start=two_days_ago,
                            upload_bytes=2 * MB, download_bytes=8 * MB),
        # Outside the 7-day window: counts toward history_since, not the chart.
        CustomerUsageBucket(customer_id=customer.id, router_id=router.id,
                            bucket_start=local_midnight_utc(days_back=20),
                            upload_bytes=0, download_bytes=999 * MB),
        # Someone else's usage never leaks in.
        CustomerUsageBucket(customer_id=other.id, router_id=router.id, bucket_start=today,
                            upload_bytes=0, download_bytes=50 * MB),
    ])
    await db.commit()
    _as(monkeypatch, reseller)

    out = await _timeline(db, customer.id, days=7)

    assert out.granularity == "day"
    assert len(out.points) == 7
    assert out.points[0].start == local_midnight_utc(days_back=6)
    assert out.points[-1].start == today
    by_start = {p.start: p.total_mb for p in out.points}
    assert by_start[today] == 10.0
    assert by_start[local_midnight_utc(days_back=1)] == 7.0
    assert by_start[two_days_ago] == 10.0
    assert sum(1 for p in out.points if p.total_mb == 0) == 4
    assert (out.upload_mb, out.download_mb, out.total_mb) == (3.0, 24.0, 27.0)
    assert out.peak.total_mb == 10.0
    assert out.history_since == local_midnight_utc(days_back=20)
    assert out.timezone_offset_hours == 3


@pytest.mark.asyncio
async def test_hourly_timeline_is_rolling_and_ends_with_the_current_hour(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    customer = await make_customer(db, reseller, plan, pppoe_username="hourly-1")
    hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    db.add_all([
        CustomerUsageBucket(customer_id=customer.id, bucket_start=hour,
                            upload_bytes=MB, download_bytes=2 * MB),
        CustomerUsageBucket(customer_id=customer.id, bucket_start=hour - timedelta(hours=23),
                            upload_bytes=0, download_bytes=6 * MB),
        CustomerUsageBucket(customer_id=customer.id, bucket_start=hour - timedelta(hours=24),
                            upload_bytes=0, download_bytes=100 * MB),   # just outside 24h
    ])
    await db.commit()
    _as(monkeypatch, reseller)

    out = await _timeline(db, customer.id, days=1)

    assert out.granularity == "hour"
    assert len(out.points) == 24
    assert out.points[0].start == hour - timedelta(hours=23)
    assert out.points[-1].start == hour
    assert out.points[0].total_mb == 6.0
    assert out.points[-1].total_mb == 3.0
    assert out.total_mb == 9.0


@pytest.mark.asyncio
async def test_customer_with_no_usage_gets_an_empty_but_complete_series(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan)
    _as(monkeypatch, reseller)

    out = await _timeline(db, customer.id, days=30)

    assert len(out.points) == 30
    assert out.total_mb == 0.0
    assert out.peak is None
    assert out.history_since is None


@pytest.mark.asyncio
async def test_timeline_is_scoped_to_the_owning_reseller_but_admins_see_all(db, monkeypatch):
    owner = await make_reseller(db)
    stranger = await make_reseller(db)
    admin = await make_admin(db)
    plan = await make_plan(db, owner)
    customer = await make_customer(db, owner, plan)

    _as(monkeypatch, stranger)
    with pytest.raises(HTTPException) as exc_info:
        await _timeline(db, customer.id)
    assert exc_info.value.status_code == 404

    _as(monkeypatch, admin)
    out = await _timeline(db, customer.id)
    assert out.customer_id == customer.id
