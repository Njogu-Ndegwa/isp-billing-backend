"""One customer, several devices: phone reconnect adds, the dashboard manages."""

import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import select

from app.api import customer_device_routes, device_pairing, public_routes
from app.api.customer_device_routes import AddDeviceRequest, DeviceLimitRequest
from app.db.models import Customer, CustomerStatus, DevicePairing
from app.services.code_attempt_limiter import reset_code_attempt_limiter
from app.services.subscription_sharing import (
    max_devices_for_customer,
    sync_shared_subscription_devices_after_owner_renewal,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

OWNER_MAC = "AA:BB:CC:00:20:01"
TV_MAC = "AA:BB:CC:00:20:02"
LAPTOP_MAC = "AA:BB:CC:00:20:03"
PHONE = "254700002001"


@pytest.fixture(autouse=True)
def _clean_limiter():
    reset_code_attempt_limiter()
    yield
    reset_code_attempt_limiter()


@pytest.fixture
def stub_router(monkeypatch):
    """No RouterOS here: record provisioning and removals instead."""
    calls = {"provisioned": [], "removed": []}
    tasks = []

    async def fake_log(*_args, **_kwargs):
        return None

    async def fake_provision(customer_id, router_id, payload, *_args, **_kwargs):
        calls["provisioned"].append(payload.get("mac_address"))
        return {"success": True}

    async def fake_cleanup(*_args, **_kwargs):
        return {"success": True}

    def fake_remove(_router_info, mac):
        calls["removed"].append(mac)
        return {"success": True}

    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *args, **kwargs):
        task = original_create_task(coro, *args, **kwargs)
        tasks.append(task)
        return task

    monkeypatch.setattr(device_pairing, "log_provisioning_event", fake_log)
    monkeypatch.setattr(device_pairing, "provision_hotspot_customer", fake_provision)
    monkeypatch.setattr(device_pairing, "_remove_shared_device_from_direct_router_sync", fake_remove)
    monkeypatch.setattr(public_routes, "_cleanup_old_mac_with_retry", fake_cleanup)
    monkeypatch.setattr(asyncio, "create_task", tracking_create_task)

    async def drain():
        if tasks:
            await asyncio.gather(*tasks)
            tasks.clear()

    calls["drain"] = drain
    return calls


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def _owner(db, *, max_shared_users=3, override=None, expiry=None):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=max_shared_users)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=expiry or datetime.utcnow() + timedelta(days=5),
        mac_address=OWNER_MAC,
        phone=PHONE,
        max_devices_override=override,
    )
    return reseller, plan, router, owner


async def _reconnect_by_phone(db, router, mac):
    return await public_routes.reconnect_self_service(
        public_routes.ReconnectRequest(phone="0700002001", mac_address=mac, router_id=router.id),
        BackgroundTasks(),
        db,
    )


async def _active_pairings(db, owner):
    return (
        await db.execute(
            select(DevicePairing).where(
                DevicePairing.subscription_owner_customer_id == owner.id,
                DevicePairing.is_active == True,  # noqa: E712
            )
        )
    ).scalars().all()


# ---------------------------------------------------------------- phone reconnect


async def test_phone_reconnect_adds_device_when_a_slot_is_free(db, stub_router):
    _reseller, _plan, router, owner = await _owner(db, max_shared_users=3)

    result = await _reconnect_by_phone(db, router, TV_MAC)
    await stub_router["drain"]()

    assert result["outcome"] == "device_added"
    await db.refresh(owner)
    assert owner.mac_address == OWNER_MAC  # the phone keeps its slot
    pairings = await _active_pairings(db, owner)
    assert [p.device_mac for p in pairings] == [TV_MAC]
    assert stub_router["provisioned"] == [TV_MAC]


async def test_phone_reconnect_at_the_limit_lists_devices_and_moves_nothing(db, stub_router):
    _reseller, _plan, router, owner = await _owner(db, max_shared_users=2)
    await _reconnect_by_phone(db, router, TV_MAC)
    await stub_router["drain"]()

    with pytest.raises(HTTPException) as exc:
        await _reconnect_by_phone(db, router, LAPTOP_MAC)

    assert exc.value.status_code == 409
    detail = exc.value.detail
    assert detail["error"] == "device_limit_reached"
    assert [d["device_mac"] for d in detail["devices"]] == [OWNER_MAC, TV_MAC]
    await db.refresh(owner)
    assert owner.mac_address == OWNER_MAC


async def test_single_device_plan_still_moves_the_plan(db, stub_router):
    _reseller, _plan, router, owner = await _owner(db, max_shared_users=1)

    result = await _reconnect_by_phone(db, router, TV_MAC)

    assert result["success"] is True
    await db.refresh(owner)
    assert owner.mac_address == TV_MAC
    assert await _active_pairings(db, owner) == []


async def test_customer_override_lets_a_single_device_plan_add_devices(db, stub_router):
    _reseller, plan, router, owner = await _owner(db, max_shared_users=1, override=2)
    assert max_devices_for_customer(owner, plan) == 2

    result = await _reconnect_by_phone(db, router, TV_MAC)
    await stub_router["drain"]()

    assert result["outcome"] == "device_added"
    await db.refresh(owner)
    assert owner.mac_address == OWNER_MAC


# ---------------------------------------------------------------- dashboard


async def test_dashboard_lists_add_and_remove_devices(db, stub_router, monkeypatch):
    reseller, _plan, router, owner = await _owner(db, max_shared_users=3)
    hosts = {
        OWNER_MAC: {"mac-address": OWNER_MAC, "address": "192.168.88.10", "bypassed": "true", "uptime": "1h"},
    }

    async def fake_guard(_router_id, _fn, _router_info, macs, **_kwargs):
        return {"success": True, "hosts": {m: hosts[m] for m in macs if m in hosts}}

    monkeypatch.setattr(customer_device_routes, "run_with_guard", fake_guard)

    added = await customer_device_routes.add_customer_device(
        owner.id,
        AddDeviceRequest(mac_address="aa-bb-cc-00-20-02", device_name="Living room TV", device_type="tv"),
        db,
        _token(reseller),
    )
    await stub_router["drain"]()
    assert added["device_mac"] == TV_MAC

    listing = await customer_device_routes.list_customer_devices(owner.id, db, _token(reseller))
    assert listing["max_devices"] == 3
    assert listing["live_source"] == "router"
    devices = listing["devices"]
    assert [(d["device_mac"], d["is_main_device"]) for d in devices] == [(OWNER_MAC, True), (TV_MAC, False)]
    assert devices[0]["live"]["online"] is True
    assert devices[0]["live"]["ip"] == "192.168.88.10"
    assert devices[1]["live"]["online"] is False
    assert devices[1]["device_name"] == "Living room TV"

    # Opening the TV's own customer page shows the same subscription.
    tv_listing = await customer_device_routes.list_customer_devices(
        devices[1]["customer_id"], db, _token(reseller),
    )
    assert tv_listing["owner_customer_id"] == owner.id

    removed = await customer_device_routes.remove_customer_device(
        owner.id, devices[1]["pairing_id"], db, _token(reseller),
    )
    assert removed["cleanup_status"] == "removed"
    assert stub_router["removed"] == [TV_MAC]
    assert await _active_pairings(db, owner) == []


async def test_dashboard_add_refuses_when_full_or_inactive(db, stub_router):
    reseller, _plan, _router, owner = await _owner(db, max_shared_users=2)
    token, owner_id = _token(reseller), owner.id
    await customer_device_routes.add_customer_device(
        owner_id, AddDeviceRequest(mac_address=TV_MAC), db, token,
    )
    await stub_router["drain"]()

    with pytest.raises(HTTPException) as full:
        await customer_device_routes.add_customer_device(
            owner_id, AddDeviceRequest(mac_address=LAPTOP_MAC), db, token,
        )
    assert full.value.status_code == 409

    with pytest.raises(HTTPException) as bad_mac:
        await customer_device_routes.add_customer_device(
            owner_id, AddDeviceRequest(mac_address="not-a-mac"), db, token,
        )
    assert bad_mac.value.status_code == 400

    expired_reseller, _p, _r, expired = await _owner(
        db, max_shared_users=3, expiry=datetime.utcnow() - timedelta(hours=1),
    )
    await db.refresh(expired_reseller)
    expired_token = _token(expired_reseller)
    with pytest.raises(HTTPException) as inactive:
        await customer_device_routes.add_customer_device(
            expired.id, AddDeviceRequest(mac_address=LAPTOP_MAC), db, expired_token,
        )
    assert inactive.value.status_code == 400


async def test_device_limit_override_is_scoped_and_clearable(db):
    reseller, _plan, _router, owner = await _owner(db, max_shared_users=1)
    other = await make_reseller(db)

    with pytest.raises(HTTPException) as foreign:
        await customer_device_routes.set_customer_device_limit(
            owner.id, DeviceLimitRequest(max_devices=4), db, _token(other),
        )
    assert foreign.value.status_code == 404

    result = await customer_device_routes.set_customer_device_limit(
        owner.id, DeviceLimitRequest(max_devices=4), db, _token(reseller),
    )
    assert (result["max_devices"], result["plan_max_devices"]) == (4, 1)

    cleared = await customer_device_routes.set_customer_device_limit(
        owner.id, DeviceLimitRequest(max_devices=None), db, _token(reseller),
    )
    assert cleared["max_devices"] == 1
    assert cleared["max_devices_override"] is None


async def test_renewal_keeps_devices_the_override_allows(db, stub_router):
    _reseller, plan, router, owner = await _owner(db, max_shared_users=1, override=3)
    await _reconnect_by_phone(db, router, TV_MAC)
    await _reconnect_by_phone(db, router, LAPTOP_MAC)
    await stub_router["drain"]()
    assert len(await _active_pairings(db, owner)) == 2

    owner = (
        await db.execute(select(Customer).where(Customer.id == owner.id))
    ).scalar_one()
    await sync_shared_subscription_devices_after_owner_renewal(
        db, owner_customer=owner, plan=plan,
    )
    await db.commit()

    # The plan alone allows 1 device; the customer's override keeps all 3.
    assert len(await _active_pairings(db, owner)) == 2
