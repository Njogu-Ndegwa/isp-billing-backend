"""A shared plan's data cap covers all its devices together, not each one.

Regression for BIG NEBS STARLINK (2026-10-02): every shared device metered into
its own period carrying a full copy of the plan cap, so a 110 GB plan on 11
devices allowed ~1.2 TB and the throttle never fired.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    ConnectionType,
    CustomerStatus,
    CustomerUsagePeriod,
    DevicePairing,
    DeviceType,
    FupAction,
)
from app.services import fup
from app.services.usage_cap_sampler import _poll_schedule_for
from app.services.usage_tracking import pooled_period_usage_bytes
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


async def _period(db, customer, start, end, total_mb, cap_mb=100, closed_at=None):
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=start,
        period_end=end,
        upload_bytes=0,
        download_bytes=total_mb * MB,
        total_bytes=total_mb * MB,
        cap_mb_snapshot=cap_mb,
        fup_action_snapshot=FupAction.THROTTLE,
        closed_at=closed_at,
    )
    db.add(period)
    await db.commit()
    await db.refresh(period)
    return period


async def _pairing(db, shared, owner, router, plan, *, active=True, expires_at=None):
    pairing = DevicePairing(
        customer_id=shared.id,
        device_mac=shared.mac_address,
        device_type=DeviceType.OTHER,
        router_id=router.id,
        plan_id=plan.id,
        subscription_owner_customer_id=owner.id,
        is_subscription_share=True,
        is_active=active,
        expires_at=expires_at or shared.expiry,
    )
    db.add(pairing)
    await db.commit()
    return pairing


async def _group(db, n_shared=2):
    """An owner plus ``n_shared`` shared devices on a 100 MB plan."""
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.HOTSPOT,
        data_cap_mb=100,
        fup_action=FupAction.THROTTLE,
        fup_throttle_profile="512K/512K",
        max_shared_users=n_shared + 1,
    )
    expiry = datetime.utcnow() + timedelta(days=5)
    owner = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=expiry
    )
    shared = []
    for _ in range(n_shared):
        device = await make_customer(
            db,
            reseller,
            plan,
            router,
            status=CustomerStatus.ACTIVE,
            expiry=expiry,
            subscription_owner_id=owner.id,
        )
        await _pairing(db, device, owner, router, plan)
        shared.append(device)
    return reseller, router, plan, owner, shared


def _window():
    now = datetime.utcnow()
    return now, now - timedelta(days=25), now + timedelta(days=5)


@pytest.fixture
def router_calls(monkeypatch):
    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    calls = []

    def fake_set_queue(router_info, mac_address, rate_limit, *, disabled="no"):
        calls.append((mac_address, rate_limit))
        return {"success": True}

    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(fup, "_set_hotspot_queue_limit_sync", fake_set_queue)
    return calls


@pytest.mark.asyncio
async def test_solo_customer_counts_only_own_usage(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, data_cap_mb=100)
    customer = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE)
    _now, start, end = _window()
    period = await _period(db, customer, start, end, 40)

    assert await pooled_period_usage_bytes(db, customer, period) == 40 * MB


@pytest.mark.asyncio
async def test_group_usage_sums_owner_and_shared_devices(db):
    _r, _router, _plan, owner, (a, b) = await _group(db)
    _now, start, end = _window()
    owner_period = await _period(db, owner, start, end, 30)
    a_period = await _period(db, a, start, end, 40)
    await _period(db, b, start, end, 50)

    # Same total whichever member is asking.
    assert await pooled_period_usage_bytes(db, owner, owner_period) == 120 * MB
    assert await pooled_period_usage_bytes(db, a, a_period) == 120 * MB


@pytest.mark.asyncio
async def test_previous_cycle_periods_do_not_count(db):
    _r, _router, _plan, owner, (a, _b) = await _group(db)
    now, start, end = _window()
    # Last cycle, closed at renewal; it overlaps the new window by a day.
    await _period(
        db, a, start - timedelta(days=30), start + timedelta(days=1), 90,
        closed_at=start,
    )
    owner_period = await _period(db, owner, start, end, 10)

    assert await pooled_period_usage_bytes(db, owner, owner_period) == 10 * MB


@pytest.mark.asyncio
async def test_removed_device_still_counts_until_its_removal(db):
    _r, router, plan, owner, (a, b) = await _group(db)
    now, start, end = _window()
    owner_period = await _period(db, owner, start, end, 10)
    await _period(db, a, start, end, 20)
    removed_period = await _period(db, b, start, end, 60)

    # Owner removes device b (disconnect_shared_pairing's end state).
    removed_at = now - timedelta(hours=1)
    b.subscription_owner_id = None
    pairing = (await db.execute(
        DevicePairing.__table__.select().where(DevicePairing.customer_id == b.id)
    )).first()
    await db.execute(
        DevicePairing.__table__.update()
        .where(DevicePairing.id == pairing.id)
        .values(is_active=False, expires_at=removed_at)
    )
    await db.commit()

    assert await pooled_period_usage_bytes(db, owner, owner_period) == 90 * MB

    # b later buys its own plan: that new period is not the group's.
    removed_period.closed_at = now
    await db.commit()
    await _period(db, b, now, now + timedelta(days=30), 500)

    assert await pooled_period_usage_bytes(db, owner, owner_period) == 90 * MB


@pytest.mark.asyncio
async def test_shared_device_under_its_own_cap_is_throttled_when_group_is_over(db, router_calls):
    _r, _router, plan, owner, (a, b) = await _group(db)
    now, start, end = _window()
    await _period(db, owner, start, end, 45)
    await _period(db, a, start, end, 45)
    b_period = await _period(db, b, start, end, 15)

    action = await fup.evaluate_and_enforce(db, b, b_period, plan=plan, now=now)

    assert action == FupAction.THROTTLE
    assert b_period.fup_triggered_at == now
    assert router_calls == [(b.mac_address, "512K/512K")]


@pytest.mark.asyncio
async def test_device_joining_an_exhausted_plan_is_throttled_immediately(db, router_calls):
    _r, router, plan, owner, (a,) = await _group(db, n_shared=1)
    now, start, end = _window()
    await _period(db, owner, start, end, 70)
    await _period(db, a, start, end, 40)

    late = await make_customer(
        db, _r, plan, router, status=CustomerStatus.ACTIVE, expiry=owner.expiry,
        subscription_owner_id=owner.id,
    )
    await _pairing(db, late, owner, router, plan)
    late_period = await _period(db, late, now, end, 0)

    action = await fup.evaluate_and_enforce(db, late, late_period, plan=plan, now=now)

    assert action == FupAction.THROTTLE
    assert router_calls == [(late.mac_address, "512K/512K")]


@pytest.mark.asyncio
async def test_group_under_cap_is_left_alone(db, router_calls):
    _r, _router, plan, owner, (a, b) = await _group(db)
    now, start, end = _window()
    await _period(db, owner, start, end, 30)
    await _period(db, a, start, end, 30)
    b_period = await _period(db, b, start, end, 30)

    action = await fup.evaluate_and_enforce(db, b, b_period, plan=plan, now=now)

    assert action is None
    assert b_period.fup_triggered_at is None
    assert router_calls == []


@pytest.mark.asyncio
async def test_throttled_group_member_is_not_released_while_group_stays_over(db, router_calls):
    _r, _router, plan, owner, (a, b) = await _group(db)
    now, start, end = _window()
    await _period(db, owner, start, end, 60)
    await _period(db, a, start, end, 50)
    b_period = await _period(db, b, start, end, 5)
    b_period.fup_triggered_at = now - timedelta(minutes=10)
    b_period.fup_action_taken = FupAction.THROTTLE
    await db.commit()

    action = await fup.evaluate_and_enforce(db, b, b_period, plan=plan, now=now)

    assert action is None
    assert b_period.fup_reverted_at is None
    assert router_calls == []


def test_poll_tier_follows_pooled_usage():
    period = CustomerUsagePeriod(total_bytes=10 * MB, cap_mb_snapshot=1000)

    assert _poll_schedule_for(period, plan=None)[1] == "normal"
    assert _poll_schedule_for(period, plan=None, used_bytes=960 * MB)[1] == "critical"
    assert _poll_schedule_for(period, plan=None, used_bytes=1000 * MB)[1] == "over_cap"
