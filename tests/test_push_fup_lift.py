"""Lifting a FUP throttle on real-time routers, and throttling again afterwards.

Real-time membership lives in process memory unless the router is in
REALTIME_PILOT_ROUTER_IDS, so these tests start from an empty state, which is
what a process restart leaves behind.
"""

import asyncio
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api import usage_push_routes as routes
from app.config import settings
from app.db.models import (
    ConnectionType,
    CustomerStatus,
    CustomerUsagePeriod,
    DevicePairing,
    DeviceType,
    FupAction,
)
from app.services import fup, realtime_state, usage_push
from app.services.usage_push import UsageReport
from app.services.usage_push_auth import derive_router_token
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024
IDENT = "Router-0446"
MAC = "02:CC:00:00:00:01"
OTHER_MAC = "02:CC:00:00:00:02"
THROTTLE = "0.9M/0.7M"


@pytest.fixture(autouse=True)
def _restarted_process(monkeypatch):
    """Nothing in memory, and this router is not in the configured list."""
    monkeypatch.setattr(settings, "REALTIME_PILOT_ROUTER_IDS", "")
    realtime_state.reset_realtime_state()
    yield
    realtime_state.reset_realtime_state()


@pytest_asyncio.fixture
async def client(session_factory, monkeypatch):
    monkeypatch.setattr(usage_push, "async_session", session_factory, raising=False)
    monkeypatch.setattr(routes, "async_session", session_factory, raising=False)
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: False)
    routes.reset_rate_limiter()
    application = FastAPI()
    application.include_router(routes.router)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


@pytest.fixture
def enforced(monkeypatch):
    """Which customers the push route sent for enforcement."""
    calls: list[list[int]] = []

    async def capture(customer_ids):
        calls.append(list(customer_ids))

    monkeypatch.setattr(routes, "_enforce_caps", capture)
    return calls


@pytest.fixture
def router_rates(monkeypatch):
    """The speed the router would hold per MAC while throttled."""
    throttled: dict[str, str] = {}

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    def fake_throttle(_info, mac, rate, *, disabled="no"):
        throttled[mac] = rate
        return {"success": True}

    def fake_restore(_info, mac, _rate):
        throttled.pop(mac, None)
        return {"success": True}

    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(fup, "_set_hotspot_queue_limit_sync", fake_throttle)
    monkeypatch.setattr(fup, "_restore_hotspot_sync", fake_restore)
    return throttled


async def _customer(db, *, cap_mb=1000, mac=MAC, **overrides):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity=IDENT)
    plan = await make_plan(
        db, reseller, connection_type=ConnectionType.HOTSPOT, data_cap_mb=cap_mb,
        fup_action=FupAction.THROTTLE, fup_throttle_profile=THROTTLE,
    )
    customer = await make_customer(
        db, reseller, plan, router, mac_address=mac, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=5), **overrides,
    )
    return reseller, router, plan, customer


async def _open_period(db, customer, *, used_mb, cap_mb=1000, throttled=False):
    now = datetime.utcnow()
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=now - timedelta(days=1),
        period_end=customer.expiry,
        upload_bytes=0,
        download_bytes=used_mb * MB,
        total_bytes=used_mb * MB,
        cap_mb_snapshot=cap_mb,
        fup_action_snapshot=FupAction.THROTTLE,
        fup_triggered_at=(now - timedelta(hours=2)) if throttled else None,
        fup_action_taken=FupAction.THROTTLE if throttled else None,
    )
    db.add(period)
    await db.commit()
    return period


def _push(v, mac=MAC):
    return {
        "identity": IDENT,
        "v": v,
        "reports": [],
        "hosts": [{"mac": mac, "ip": "192.168.88.50", "bytes_in": 0, "bytes_out": 0,
                   "bypassed": True, "idle_time": "1s", "uptime": "1h"}],
        "router": {"iface_rx_bytes": 1000, "iface_tx_bytes": 500, "cpu_load": 7,
                   "free_memory": 900, "total_memory": 1024, "uptime": "3w", "version": "7.14",
                   "board": "RB4011iGS+"},
    }


def _auth():
    return {"Authorization": f"Bearer {derive_router_token(IDENT)}"}


# ------------------------------------------------- which routers get the lift


@pytest.mark.asyncio
async def test_first_v3_report_after_a_restart_gets_the_lift_without_the_env_list(db, client, enforced):
    _reseller, router, _plan, customer = await _customer(db)
    await _open_period(db, customer, used_mb=150, throttled=True)
    assert router.id not in realtime_state.configured_pilot_router_ids()
    assert not realtime_state.is_pilot_router(router.id)

    response = await client.post("/api/router/usage-push", json=_push(3), headers=_auth())
    await asyncio.sleep(0)  # enforcement runs as a detached task after the response

    assert response.status_code == 200
    assert response.json()["accepted"] == 1, response.json()
    assert realtime_state.is_pilot_router(router.id)
    assert enforced == [[customer.id]]


@pytest.mark.asyncio
async def test_older_script_outside_the_list_is_left_to_the_cap_sampler(db, client, enforced):
    """No push enforcement here, and the sampler still owns this router, so the
    lift comes from its own over-cap check."""
    _reseller, router, _plan, customer = await _customer(db)
    await _open_period(db, customer, used_mb=150, throttled=True)

    response = await client.post("/api/router/usage-push", json=_push(2), headers=_auth())
    await asyncio.sleep(0)

    assert response.status_code == 200
    assert not realtime_state.is_pilot_router(router.id)
    assert enforced in ([], [[]])
    assert router.id not in realtime_state.host_metered_router_ids()


@pytest.mark.asyncio
async def test_v3_router_stops_being_real_time_after_its_reports_stop(db, client, enforced, monkeypatch):
    """Once reports stop the sampler takes the router back, so nothing is stranded."""
    _reseller, router, _plan, customer = await _customer(db)
    await _open_period(db, customer, used_mb=150, throttled=True)
    await client.post("/api/router/usage-push", json=_push(3), headers=_auth())
    assert router.id in realtime_state.host_metered_router_ids()

    later = datetime.utcnow() + timedelta(seconds=realtime_state.HOST_METERING_FRESH_SECONDS + 1)

    assert router.id not in realtime_state.host_metered_router_ids(later)


@pytest.mark.asyncio
async def test_device_that_does_not_report_is_not_lifted_until_it_does(db, session_factory):
    _reseller, router, _plan, customer = await _customer(db)
    await _open_period(db, customer, used_mb=150, throttled=True)

    silent = await usage_push.ingest_usage_reports(
        router.id, [], now=datetime.utcnow(), session_factory=session_factory,
    )
    reported = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=MAC, upload_bytes=0, download_bytes=0)],
        now=datetime.utcnow(),
        session_factory=session_factory,
    )

    assert silent.release_fup_customer_ids == []
    assert reported.release_fup_customer_ids == [customer.id]


@pytest.mark.asyncio
async def test_orphaned_shared_device_is_measured_alone_once_its_owner_is_gone(db, session_factory):
    """Pins today's behaviour for a device whose owner was deleted (router 446:
    35406, 35468, 44249, 45486, 45850, 46184). With no owner the pool is just
    this device, so a throttle it got from the group lifts once it reports.
    Whether that is right is Dennis's decision; change this test when he makes it."""
    _reseller, router, plan, customer = await _customer(db)
    db.add(DevicePairing(
        customer_id=customer.id, device_mac=MAC, device_type=DeviceType.OTHER, router_id=router.id,
        plan_id=plan.id, subscription_owner_customer_id=None, is_subscription_share=True,
        is_active=True, expires_at=customer.expiry,
    ))
    await _open_period(db, customer, used_mb=150, throttled=True)

    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=MAC, upload_bytes=0, download_bytes=0)],
        now=datetime.utcnow(),
        session_factory=session_factory,
    )

    assert result.release_fup_customer_ids == [customer.id]


# ---------------------------------------------------------- throttled again


async def _reload(db, period_id):
    return (
        await db.execute(
            select(CustomerUsagePeriod)
            .where(CustomerUsagePeriod.id == period_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_lifted_device_is_throttled_again_when_it_goes_over_the_cap(db, router_rates):
    _reseller, _router, plan, customer = await _customer(db)
    period = await _open_period(db, customer, used_mb=150, throttled=True)
    router_rates[MAC] = THROTTLE

    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan) is None
    assert MAC not in router_rates
    await db.commit()

    period = await _reload(db, period.id)
    assert period.fup_reverted_at is not None
    period.download_bytes = period.total_bytes = 1200 * MB

    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan) == FupAction.THROTTLE
    assert MAC in router_rates
    await db.commit()

    period = await _reload(db, period.id)
    assert period.fup_triggered_at is not None
    assert period.fup_reverted_at is None


@pytest.mark.asyncio
async def test_lifted_device_over_the_cap_is_reported_by_the_push_again(db, session_factory, router_rates):
    _reseller, router, plan, customer = await _customer(db)
    period = await _open_period(db, customer, used_mb=150, throttled=True)
    await fup.evaluate_and_enforce(db, customer, period, plan=plan)
    await db.commit()
    period = await _reload(db, period.id)
    period.download_bytes = period.total_bytes = 1200 * MB
    await db.commit()

    result = await usage_push.ingest_usage_reports(
        router.id,
        [UsageReport(queue_key=MAC, upload_bytes=0, download_bytes=0)],
        now=datetime.utcnow(),
        session_factory=session_factory,
    )

    assert result.over_cap_customer_ids == [customer.id]


@pytest.mark.asyncio
async def test_group_going_over_after_a_lift_throttles_a_lifted_member_again(db, router_rates):
    """The case that matters for #308: a device under the pool, lifted, then the
    pool goes over because of another device's usage."""
    reseller, router, plan, owner = await _customer(db)
    shared = await make_customer(
        db, reseller, plan, router, mac_address=OTHER_MAC, status=CustomerStatus.ACTIVE,
        expiry=owner.expiry, subscription_owner_id=owner.id,
    )
    db.add(DevicePairing(
        customer_id=shared.id, device_mac=OTHER_MAC, device_type=DeviceType.OTHER, router_id=router.id,
        plan_id=plan.id, subscription_owner_customer_id=owner.id, is_subscription_share=True,
        is_active=True, expires_at=owner.expiry,
    ))
    owner_period = await _open_period(db, owner, used_mb=100, throttled=True)
    shared_period = await _open_period(db, shared, used_mb=100)
    router_rates[MAC] = THROTTLE

    assert await fup.evaluate_and_enforce(db, owner, owner_period, plan=plan) is None
    await db.commit()
    assert MAC not in router_rates

    shared_period = await _reload(db, shared_period.id)
    shared_period.download_bytes = shared_period.total_bytes = 1000 * MB
    await db.commit()

    owner_period = await _reload(db, owner_period.id)
    assert await fup.evaluate_and_enforce(db, owner, owner_period, plan=plan) == FupAction.THROTTLE
    assert MAC in router_rates


@pytest.mark.asyncio
async def test_failed_lift_keeps_the_throttle_recorded_so_it_is_retried(db, monkeypatch):
    _reseller, _router, plan, customer = await _customer(db)
    period = await _open_period(db, customer, used_mb=150, throttled=True)

    async def router_down(_db, _customer, _plan):
        return {"error": "Failed to connect to router"}

    monkeypatch.setattr(fup, "restore_normal_profile", router_down)

    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan) is None

    assert period.fup_triggered_at is not None
    assert period.fup_reverted_at is None
