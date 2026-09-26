"""A throttle must be lifted once the cap that caused it is gone.

Incident 2026-09-26 (reseller 443, router 393): a 2 GB cap on a 12 Mbps PPPoE
plan throttled every customer to 1 Mbps. The reseller then removed the cap,
but nothing lifted the throttles:

* the cap sampler stopped polling anyone without a cap, so the "uncapped:
  clear stale trigger" branch of ``evaluate_and_enforce`` never ran;
* a period that opened while the cap existed kept its 2 GB snapshot;
* the revert itself pointed PPPoE secrets at ``plan.router_profile or
  "default"``, a profile with no rate limit or address pool.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.api import plan_routes
from app.db.models import (
    ConnectionType,
    CustomerStatus,
    CustomerUsagePeriod,
    FupAction,
    RouterAuthMethod,
    UsageCapWatchState,
)
from app.services import fup, usage_cap_sampler
from app.services.mikrotik_api import parse_speed_to_mikrotik
from tests.factories import make_customer, make_plan, make_reseller, make_router

GIB = 1024 * 1024 * 1024


async def _throttled_pppoe_customer(db, *, plan_cap_mb=None, period_cap_mb=None, username="joe"):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, auth_method=RouterAuthMethod.DIRECT_API)
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.PPPOE,
        speed="12Mbps",
        data_cap_mb=plan_cap_mb,
        fup_action=FupAction.THROTTLE if plan_cap_mb else None,
    )
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        pppoe_username=username,
        expiry=datetime.utcnow() + timedelta(days=20),
    )
    now = datetime.utcnow()
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=now - timedelta(days=5),
        period_end=customer.expiry,
        total_bytes=100 * GIB,
        cap_mb_snapshot=period_cap_mb,
        fup_action_snapshot=FupAction.THROTTLE if period_cap_mb else None,
        fup_triggered_at=now - timedelta(days=4),
        fup_action_taken=FupAction.THROTTLE,
    )
    db.add(period)
    await db.commit()
    await db.refresh(period)
    return reseller, router, plan, customer, period


@pytest.mark.asyncio
async def test_uncapped_plan_revert_restores_plan_speed_profile_not_default(db, monkeypatch):
    _reseller, router, plan, customer, period = await _throttled_pppoe_customer(db)

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    calls = []

    def fake_restore(router_info, username, bandwidth_limit):
        calls.append((router_info["ip"], username, bandwidth_limit))
        return {"success": True}

    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(fup, "_restore_pppoe_plan_profile_sync", fake_restore)

    now = datetime.utcnow()
    action = await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=now)

    assert action is None
    assert period.fup_reverted_at == now
    assert calls == [(router.ip_address, "joe", "12Mbps")]


def test_restore_sync_points_secret_at_provisioning_profile(monkeypatch):
    instances = []

    class FakeMikroTik:
        def __init__(self, *args, **kwargs):
            self.commands = []
            self.ensured = []
            self.kicked = []
            instances.append(self)

        def connect(self):
            return True

        def disconnect(self):
            pass

        def _parse_speed_to_mikrotik(self, speed):
            return parse_speed_to_mikrotik(speed)

        def get_active_pppoe_profile(self):
            return {
                "found": True,
                "data": {"local_address": "192.168.89.1", "remote_address": "pppoe-pool"},
            }

        def ensure_ip_pool(self, *_args):
            return {"success": True}

        def ensure_pppoe_profile(self, name, rate_limit, **kwargs):
            self.ensured.append((name, kwargs.get("pool_name")))
            return {"success": True}

        def send_command(self, command, args=None):
            self.commands.append((command, args))
            return {"success": True}

        def disconnect_pppoe_session(self, username):
            self.kicked.append(username)
            return {"success": True}

    monkeypatch.setattr(fup, "MikroTikAPI", FakeMikroTik)

    result = fup._restore_pppoe_plan_profile_sync(
        {"ip": "10.0.0.154", "username": "admin", "password": "pw", "port": 8728},
        "joe",
        "12Mbps",
    )

    assert "error" not in result
    api = instances[0]
    assert api.ensured == [("pppoe_12M_12M", "pppoe-pool")]
    assert (
        "/ppp/secret/set",
        {"numbers": "joe", "profile": "pppoe_12M_12M", "disabled": "no"},
    ) in api.commands
    assert api.kicked == ["joe"]


@pytest.mark.asyncio
async def test_cap_sampler_keeps_polling_and_releases_throttle_after_cap_removed(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(usage_cap_sampler, "async_session", session_factory)
    monkeypatch.setattr(usage_cap_sampler, "cap_sampler_running", False)
    monkeypatch.setattr(usage_cap_sampler, "_db_pool_is_busy", lambda: False)

    _reseller, _router, _plan, customer, _period = await _throttled_pppoe_customer(db)

    monkeypatch.setattr(
        usage_cap_sampler,
        "_fetch_queue_usage_for_router_sync",
        lambda _info: {
            "success": True,
            "data": [{".id": "*1", "name": "<pppoe-joe>", "target": "<pppoe-joe>", "bytes": "0/0"}],
        },
    )
    released = []

    async def fake_evaluate(db_session, customer_obj, period, plan=None, now=None):
        released.append(customer_obj.id)
        period.fup_reverted_at = now
        return None

    monkeypatch.setattr(usage_cap_sampler, "evaluate_and_enforce", fake_evaluate)

    await usage_cap_sampler.sample_capped_usage_background()

    assert released == [customer.id]
    async with session_factory() as s:
        state = (
            await s.execute(
                select(UsageCapWatchState).where(UsageCapWatchState.customer_id == customer.id)
            )
        ).scalar_one()
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer.id)
            )
        ).scalar_one()
    assert state.poll_tier == "uncapped"
    assert period.fup_reverted_at is not None

    # Released and uncapped: no longer due, so the next run leaves it alone.
    async with session_factory() as s:
        state = (
            await s.execute(
                select(UsageCapWatchState).where(UsageCapWatchState.customer_id == customer.id)
            )
        ).scalar_one()
        state.next_poll_at = datetime.utcnow() - timedelta(seconds=1)
        await s.commit()
    await usage_cap_sampler.sample_capped_usage_background()
    assert released == [customer.id]


async def _update_cap(db, reseller, plan, monkeypatch, new_cap):
    async def fake_current_user(_token, _db):
        return reseller

    async def fake_invalidate_plan_cache():
        return None

    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda _user: None)
    monkeypatch.setattr(plan_routes, "invalidate_plan_cache", fake_invalidate_plan_cache)
    return await plan_routes.update_plan_api(
        plan.id,
        plan_routes.PlanUpdateRequest(data_cap_mb=new_cap),
        db=db,
        token="token",
    )


@pytest.mark.asyncio
async def test_removing_plan_cap_clears_open_period_snapshot(db, monkeypatch):
    reseller, _router, plan, _customer, period = await _throttled_pppoe_customer(
        db, plan_cap_mb=2048, period_cap_mb=2048
    )

    await _update_cap(db, reseller, plan, monkeypatch, None)

    await db.refresh(period)
    assert period.cap_mb_snapshot is None


@pytest.mark.asyncio
async def test_plan_cap_change_only_loosens_open_periods(db, monkeypatch):
    reseller, _router, plan, _customer, period = await _throttled_pppoe_customer(
        db, plan_cap_mb=2048, period_cap_mb=2048
    )

    await _update_cap(db, reseller, plan, monkeypatch, 1024)
    await db.refresh(period)
    assert period.cap_mb_snapshot == 2048  # lowered cap waits for the next period

    await _update_cap(db, reseller, plan, monkeypatch, 200_000)
    await db.refresh(period)
    assert period.cap_mb_snapshot == 200_000
