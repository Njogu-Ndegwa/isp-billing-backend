"""Daily FUP: a plan can apply its data cap per local day instead of per paid period.

Requested by a reseller on 2026-10-24 ("a daily FUP ... currently FUPs are plan
based"). ``plan.fup_period = "daily"`` measures the cap over usage since the
last daily reset (local midnight EAT by default) and gives throttled customers
full speed back at the reset. ``"plan"`` (the default) keeps the original
per-period behaviour for every existing plan.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from app.api import plan_routes
from app.config import settings
from app.db.models import ConnectionType, CustomerStatus, CustomerUsagePeriod, FupAction
from app.services import fup, fup_daily_reset, mikrotik_background
from app.services.usage_tracking import (
    daily_fup_reset_utc,
    fup_usage_bytes,
    fup_window_start,
    get_open_period,
    record_usage,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024
NOW = datetime(2026, 10, 24, 10, 0)          # 13:00 EAT
RESET = datetime(2026, 10, 23, 21, 0)        # 00:00 EAT on the 24th
YESTERDAY = datetime(2026, 10, 23, 15, 0)    # 18:00 EAT on the 23rd

CONNECTION_TYPES = [ConnectionType.HOTSPOT, ConnectionType.PPPOE]


async def _setup(
    db,
    *,
    connection_type=ConnectionType.HOTSPOT,
    fup_period="daily",
    cap_mb=100,
    action=FupAction.THROTTLE,
    expiry=NOW + timedelta(days=20),
    **customer_overrides,
):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        connection_type=connection_type,
        speed="10M/10M",
        data_cap_mb=cap_mb,
        fup_action=action,
        fup_throttle_profile="1M/1M",
        fup_period=fup_period,
    )
    if connection_type == ConnectionType.PPPOE:
        customer_overrides.setdefault("pppoe_username", "daily_user")
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=expiry,
        **customer_overrides,
    )
    return customer, plan, router, reseller


def _patch_router(monkeypatch, *, restore_error=False):
    """Record router-side FUP calls instead of talking to a MikroTik."""
    calls = []

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    def throttle_hotspot(router_info, mac, rate, *, disabled="no"):
        calls.append(("throttle", mac, rate))
        return {"success": True}

    def restore_hotspot(router_info, mac, rate):
        calls.append(("restore", mac, rate))
        return {"error": "connect_failed"} if restore_error else {"success": True}

    def throttle_pppoe(router_info, username, profile, rate, max_devices=1):
        calls.append(("throttle", username, rate))
        return {"success": True}

    def restore_pppoe(router_info, username, bandwidth, max_devices=1):
        calls.append(("restore", username, bandwidth))
        return {"error": "connect_failed"} if restore_error else {"success": True}

    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(fup, "_set_hotspot_queue_limit_sync", throttle_hotspot)
    monkeypatch.setattr(fup, "_restore_hotspot_sync", restore_hotspot)
    monkeypatch.setattr(fup, "_set_secret_throttle_profile_sync", throttle_pppoe)
    monkeypatch.setattr(fup, "_restore_pppoe_plan_profile_sync", restore_pppoe)
    return calls


async def _use(db, customer, plan, mb, at):
    period = await record_usage(db, customer, 0, mb * MB, plan=plan, now=at)
    await db.commit()
    return period


# ------------------------------ reset boundary ------------------------------


def test_daily_reset_is_local_midnight_eat():
    assert daily_fup_reset_utc(NOW) == RESET
    # 23:59 EAT is still the same local day...
    assert daily_fup_reset_utc(datetime(2026, 10, 24, 20, 59)) == RESET
    # ...and 00:00 EAT starts the next one.
    assert daily_fup_reset_utc(datetime(2026, 10, 24, 21, 0)) == datetime(2026, 10, 24, 21, 0)


def test_daily_reset_hour_is_configurable(monkeypatch):
    monkeypatch.setattr(settings, "FUP_DAILY_RESET_HOUR", 6)
    # 13:00 EAT -> today's 06:00 EAT reset (03:00 UTC).
    assert daily_fup_reset_utc(NOW) == datetime(2026, 10, 24, 3, 0)
    # 05:00 EAT -> still yesterday's 06:00 EAT reset.
    assert daily_fup_reset_utc(datetime(2026, 10, 24, 2, 0)) == datetime(2026, 10, 23, 3, 0)


# ------------------------------ enforcement ------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("connection_type", CONNECTION_TYPES)
async def test_daily_cap_crossed_today_throttles(db, monkeypatch, connection_type):
    customer, plan, _router, _ = await _setup(db, connection_type=connection_type)
    calls = _patch_router(monkeypatch)
    period = await _use(db, customer, plan, 150, NOW - timedelta(hours=1))

    action = await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=NOW)

    assert action == FupAction.THROTTLE
    assert period.fup_triggered_at == NOW
    assert [c[0] for c in calls] == ["throttle"]


@pytest.mark.asyncio
@pytest.mark.parametrize("connection_type", CONNECTION_TYPES)
async def test_daily_cap_counts_only_usage_since_reset(db, monkeypatch, connection_type):
    customer, plan, _router, _ = await _setup(db, connection_type=connection_type)
    calls = _patch_router(monkeypatch)
    await _use(db, customer, plan, 500, YESTERDAY)        # way over, but yesterday
    period = await _use(db, customer, plan, 20, NOW - timedelta(hours=1))

    assert period.total_bytes == 520 * MB                 # the period still has it all
    assert fup_window_start(period, plan, NOW) == RESET
    assert await fup_usage_bytes(db, customer, period, plan=plan, now=NOW) == 20 * MB

    action = await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=NOW)

    assert action is None
    assert period.fup_triggered_at is None
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("connection_type", CONNECTION_TYPES)
async def test_plan_period_fup_is_unchanged(db, monkeypatch, connection_type):
    """Same usage on a "plan" plan: the whole period counts, as before."""
    customer, plan, _router, _ = await _setup(
        db, connection_type=connection_type, fup_period="plan"
    )
    calls = _patch_router(monkeypatch)
    await _use(db, customer, plan, 500, YESTERDAY)
    period = await _use(db, customer, plan, 20, NOW - timedelta(hours=1))

    assert fup_window_start(period, plan, NOW) is None
    assert await fup_usage_bytes(db, customer, period, plan=plan, now=NOW) == 520 * MB

    action = await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=NOW)
    assert action == FupAction.THROTTLE

    # And the next day nothing is lifted: a plan-period trigger only ends on renewal.
    later = await fup.evaluate_and_enforce(
        db, customer, period, plan=plan, now=NOW + timedelta(days=1)
    )
    assert later is None
    assert period.fup_triggered_at == NOW
    assert period.fup_reverted_at is None
    assert [c[0] for c in calls] == ["throttle"]


@pytest.mark.asyncio
@pytest.mark.parametrize("connection_type", CONNECTION_TYPES)
async def test_next_day_reset_restores_then_rearms(db, monkeypatch, connection_type):
    customer, plan, _router, _ = await _setup(db, connection_type=connection_type)
    calls = _patch_router(monkeypatch)

    # Yesterday: over the daily cap -> throttled.
    period = await _use(db, customer, plan, 150, YESTERDAY)
    triggered_at = YESTERDAY + timedelta(minutes=1)
    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=triggered_at) == FupAction.THROTTLE
    await db.commit()

    # Today, after the reset, with nothing used yet: full speed is restored.
    action = await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=NOW)
    await db.commit()
    assert action is None
    assert period.fup_triggered_at is None
    assert period.fup_action_taken is None
    assert period.fup_reverted_at == NOW
    assert [c[0] for c in calls] == ["throttle", "restore"]
    restored_rate = calls[-1][2]
    assert restored_rate in ("10M/10M", "10M")  # the plan's normal speed

    # Crossing the cap again today throttles again (the trigger was re-armed).
    await _use(db, customer, plan, 150, NOW + timedelta(minutes=30))
    again = await fup.evaluate_and_enforce(
        db, customer, period, plan=plan, now=NOW + timedelta(hours=1)
    )
    assert again == FupAction.THROTTLE
    assert period.fup_reverted_at is None
    assert [c[0] for c in calls] == ["throttle", "restore", "throttle"]


@pytest.mark.asyncio
async def test_notify_only_daily_rearms_without_router_calls(db, monkeypatch):
    customer, plan, _router, _ = await _setup(db, action=FupAction.NOTIFY_ONLY)
    calls = _patch_router(monkeypatch)
    period = await _use(db, customer, plan, 150, YESTERDAY)
    await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=YESTERDAY)
    assert period.fup_action_taken == FupAction.NOTIFY_ONLY

    await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=NOW)

    assert period.fup_triggered_at is None
    assert calls == []


@pytest.mark.asyncio
async def test_daily_reset_leaves_expired_customer_alone(db, monkeypatch):
    """Restoring would re-open an expired hotspot customer's binding."""
    customer, plan, _router, _ = await _setup(db, expiry=NOW - timedelta(hours=1))
    calls = _patch_router(monkeypatch)
    period = await _use(db, customer, plan, 150, YESTERDAY)
    period.fup_triggered_at = YESTERDAY
    period.fup_action_taken = FupAction.THROTTLE
    await db.commit()

    await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=NOW)

    assert calls == []
    assert period.fup_triggered_at == YESTERDAY
    assert period.fup_reverted_at is None


@pytest.mark.asyncio
async def test_daily_reset_retries_when_router_unreachable(db, monkeypatch):
    customer, plan, _router, _ = await _setup(db)
    calls = _patch_router(monkeypatch, restore_error=True)
    period = await _use(db, customer, plan, 150, YESTERDAY)
    period.fup_triggered_at = YESTERDAY
    period.fup_action_taken = FupAction.THROTTLE
    await db.commit()

    await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=NOW)

    assert [c[0] for c in calls] == ["restore"]
    # Still marked as throttled so the next evaluation tries again.
    assert period.fup_triggered_at == YESTERDAY
    assert period.fup_reverted_at is None


@pytest.mark.asyncio
async def test_renewal_today_starts_a_fresh_daily_allowance(db, monkeypatch):
    """A period that opened after the reset is the window: pre-renewal usage today doesn't count."""
    customer, plan, _router, _ = await _setup(db)
    calls = _patch_router(monkeypatch)
    # Used 200 MB this morning on the previous period...
    old = await _use(db, customer, plan, 200, NOW - timedelta(hours=4))
    old.closed_at = NOW - timedelta(hours=2)
    # ...then renewed two hours ago and used 10 MB since.
    renewed = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=NOW - timedelta(hours=2),
        period_end=NOW + timedelta(days=30),
        upload_bytes=0,
        download_bytes=0,
        total_bytes=0,
        cap_mb_snapshot=100,
        fup_action_snapshot=FupAction.THROTTLE,
    )
    db.add(renewed)
    await db.commit()
    period = await _use(db, customer, plan, 10, NOW - timedelta(hours=1))
    assert period.id == renewed.id

    assert fup_window_start(period, plan, NOW) == NOW - timedelta(hours=2)
    assert await fup_usage_bytes(db, customer, period, plan=plan, now=NOW) == 10 * MB
    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=NOW) is None
    assert calls == []


@pytest.mark.asyncio
async def test_shared_plan_daily_cap_pools_devices(db, monkeypatch):
    owner, plan, router, reseller = await _setup(db)
    shared = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=NOW + timedelta(days=20),
        subscription_owner_id=owner.id,
    )
    calls = _patch_router(monkeypatch)
    await _use(db, shared, plan, 300, YESTERDAY)          # yesterday doesn't count
    await _use(db, shared, plan, 60, NOW - timedelta(hours=2))
    period = await _use(db, owner, plan, 60, NOW - timedelta(hours=1))

    assert await fup_usage_bytes(db, owner, period, plan=plan, now=NOW) == 120 * MB
    assert await fup.evaluate_and_enforce(db, owner, period, plan=plan, now=NOW) == FupAction.THROTTLE
    assert [c[0] for c in calls] == ["throttle"]


# ------------------------------ reset sweep ------------------------------


@pytest.mark.asyncio
async def test_reset_sweep_restores_idle_daily_customers_only(db, session_factory, monkeypatch):
    monkeypatch.setattr(fup_daily_reset, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _name: False)
    monkeypatch.setattr(fup_daily_reset, "_retry_after", {})
    calls = _patch_router(monkeypatch)

    daily_customer, daily_plan, _r1, _ = await _setup(db, mac_address="AA:BB:CC:00:00:01")
    plan_customer, plan_plan, _r2, _ = await _setup(
        db, fup_period="plan", mac_address="AA:BB:CC:00:00:02"
    )
    for customer, plan in ((daily_customer, daily_plan), (plan_customer, plan_plan)):
        period = await _use(db, customer, plan, 150, YESTERDAY)
        period.fup_triggered_at = YESTERDAY
        period.fup_action_taken = FupAction.THROTTLE
    await db.commit()

    stats = await fup_daily_reset.reset_daily_fup_background(now=NOW)

    assert stats["candidates"] == 1
    assert stats["reset"] == 1
    assert calls == [("restore", "AA:BB:CC:00:00:01", calls[0][2])]
    async with session_factory() as s:
        daily_period = await get_open_period(s, daily_customer.id)
        plan_period = await get_open_period(s, plan_customer.id)
    assert daily_period.fup_triggered_at is None
    assert daily_period.fup_reverted_at == NOW
    assert plan_period.fup_triggered_at == YESTERDAY      # plan-period FUP untouched

    # Nothing left to do on the next run.
    again = await fup_daily_reset.reset_daily_fup_background(now=NOW + timedelta(minutes=2))
    assert again["candidates"] == 0


@pytest.mark.asyncio
async def test_reset_sweep_backs_off_unreachable_router(db, session_factory, monkeypatch):
    monkeypatch.setattr(fup_daily_reset, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _name: False)
    monkeypatch.setattr(fup_daily_reset, "_retry_after", {})
    calls = _patch_router(monkeypatch, restore_error=True)

    customer, plan, _router, _ = await _setup(db)
    period = await _use(db, customer, plan, 150, YESTERDAY)
    period.fup_triggered_at = YESTERDAY
    period.fup_action_taken = FupAction.THROTTLE
    await db.commit()

    first = await fup_daily_reset.reset_daily_fup_background(now=NOW)
    second = await fup_daily_reset.reset_daily_fup_background(now=NOW + timedelta(minutes=2))
    third = await fup_daily_reset.reset_daily_fup_background(now=NOW + timedelta(minutes=11))

    assert first["pending"] == 1
    assert second["candidates"] == 0                       # backing off
    assert third["candidates"] == 1                        # retried after the back-off
    assert [c[0] for c in calls] == ["restore", "restore"]


# ------------------------------ plan API ------------------------------


def _patch_plan_routes(monkeypatch, reseller):
    async def fake_current_user(_token, _db):
        return reseller

    async def fake_invalidate_plan_cache():
        return None

    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda _user: None)
    monkeypatch.setattr(plan_routes, "invalidate_plan_cache", fake_invalidate_plan_cache)


def _create_request(**overrides):
    body = dict(
        name="Daily 1GB",
        speed="10M/10M",
        price=100,
        duration_value=30,
        duration_unit="DAYS",
        connection_type="hotspot",
        data_cap_mb=1024,
        fup_action="throttle",
    )
    body.update(overrides)
    return plan_routes.PlanCreateRequest(**body)


@pytest.mark.asyncio
async def test_plan_api_defaults_to_plan_period_and_accepts_daily(db, monkeypatch):
    reseller = await make_reseller(db)
    _patch_plan_routes(monkeypatch, reseller)

    default = await plan_routes.create_plan_api(_create_request(name="Plain"), db=db, token="t")
    daily = await plan_routes.create_plan_api(
        _create_request(name="Daily", fup_period="Daily"), db=db, token="t"
    )
    assert default["fup_period"] == "plan"
    assert daily["fup_period"] == "daily"

    with pytest.raises(HTTPException) as exc:
        await plan_routes.create_plan_api(
            _create_request(name="Bad", fup_period="weekly"), db=db, token="t"
        )
    assert exc.value.status_code == 400

    # Update: switching back to "plan"; a body without the field leaves it alone.
    updated = await plan_routes.update_plan_api(
        daily["id"], plan_routes.PlanUpdateRequest(fup_period="plan"), db=db, token="t"
    )
    assert updated["fup_period"] == "plan"
    untouched = await plan_routes.update_plan_api(
        daily["id"], plan_routes.PlanUpdateRequest(price=150), db=db, token="t"
    )
    assert untouched["fup_period"] == "plan"
