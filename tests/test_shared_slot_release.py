"""A full plan may free a slot held by a long-gone phone, and nothing else.

Every test but the first switches the release on; it ships switched off.
"""

import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import select

from app.api import access_code_routes, device_pairing, public_routes
from app.api.access_code_routes import redeem_code_on_device
from app.config import settings
from app.db.models import (
    Customer,
    CustomerStatus,
    CustomerUsageBucket,
    DevicePairing,
    DeviceType,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningOnlineState,
    ProvisioningState,
    ReconnectionAttempt,
)
from app.services import hotspot_provisioning, shared_slot_release
from app.services.code_attempt_limiter import reset_code_attempt_limiter
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

OWNER = "02:BB:00:00:00:01"
GONE = "02:BB:00:00:00:02"
OTHER_GONE = "02:BB:00:00:00:03"
VENDOR = "44:72:AC:00:00:04"
NEW = "02:BB:00:00:00:99"


@pytest.fixture(autouse=True)
def _clean_limiter():
    reset_code_attempt_limiter()
    yield
    reset_code_attempt_limiter()


@pytest.fixture
def world(monkeypatch):
    """Records router removals, pushes, audit events and presence checks."""

    class World:
        removed: list = []
        pushed: list = []
        events: list = []
        probes: list = []
        present = set()
        tasks: list = []

    state = World()
    state.removed, state.pushed, state.events, state.probes, state.tasks = [], [], [], [], []
    state.present = set()

    async def fake_provision(_customer_id, _router_id, hotspot_payload, *_a, **_k):
        state.pushed.append(hotspot_payload["mac_address"])
        return {"success": True}

    async def fake_log(*_a, **_k):
        return None

    def fake_remove(_router_info, mac):
        state.removed.append(mac)
        return {"success": True}

    async def fake_cleanup_old_mac(_router_info, _old_mac):
        return {"success": True}

    async def fake_present(_router_info, macs):
        state.probes.append(list(macs))
        return state.present

    async def fake_event(*args, **kwargs):
        state.events.append((args, kwargs))

    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *args, **kwargs):
        task = original_create_task(coro, *args, **kwargs)
        state.tasks.append(task)
        return task

    for module in (device_pairing, hotspot_provisioning):
        monkeypatch.setattr(module, "provision_hotspot_customer", fake_provision)
    monkeypatch.setattr(device_pairing, "log_provisioning_event", fake_log)
    monkeypatch.setattr(device_pairing, "_remove_shared_device_from_direct_router_sync", fake_remove)
    monkeypatch.setattr(public_routes, "_cleanup_old_mac_with_retry", fake_cleanup_old_mac)
    monkeypatch.setattr(shared_slot_release, "present_macs", fake_present)
    monkeypatch.setattr(access_code_routes, "record_customer_event", fake_event)
    monkeypatch.setattr(asyncio, "create_task", tracking_create_task)
    return state


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(settings, "SHARED_SLOT_IDLE_RELEASE_ENABLED", True)


def _days_ago(days, hours=0):
    return datetime.utcnow() - timedelta(days=days, hours=hours)


async def _full_plan(db, devices=((GONE, DeviceType.OTHER),), *, idle_days=30, phone="254700009001"):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=len(devices) + 1)
    router = await make_router(db, reseller)
    expiry = datetime.utcnow() + timedelta(days=5)
    owner = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=expiry,
        mac_address=OWNER, phone=phone,
    )
    for mac, device_type in devices:
        shared = await make_customer(
            db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=expiry,
            mac_address=mac, phone=phone, subscription_owner_id=owner.id,
        )
        db.add(DevicePairing(
            customer_id=shared.id, device_mac=mac, device_type=device_type, router_id=router.id,
            plan_id=plan.id, subscription_owner_customer_id=owner.id, is_subscription_share=True,
            is_active=True, expires_at=expiry, created_at=_days_ago(idle_days),
            provisioned_at=_days_ago(idle_days),
        ))
    await db.commit()
    code = (await device_pairing.get_or_create_access_code(db, owner)).code
    await db.commit()
    return reseller, router, owner, code


async def _enter(db, router, code, mac, world):
    result = await redeem_code_on_device(
        db, code=code, router_obj=router, normalized_mac=mac, background_tasks=BackgroundTasks(),
    )
    if world.tasks:
        await asyncio.gather(*world.tasks)
        world.tasks.clear()
    return result


async def _active_macs(db, owner):
    return set(
        (
            await db.execute(
                select(DevicePairing.device_mac).where(
                    DevicePairing.subscription_owner_customer_id == owner.id,
                    DevicePairing.is_active == True,  # noqa: E712
                )
            )
        ).scalars().all()
    )


async def _expect_refused(db, router, code, world):
    with pytest.raises(HTTPException) as refused:
        await _enter(db, router, code, NEW, world)
    assert refused.value.status_code == 409
    assert refused.value.detail["error"] == "device_limit_reached"
    assert world.removed == []
    assert world.events == []


async def _customer_id(db, mac):
    return (await db.execute(select(Customer.id).where(Customer.mac_address == mac))).scalar_one()


async def test_off_by_default_refuses_and_never_asks_the_router(db, world):
    assert settings.SHARED_SLOT_IDLE_RELEASE_ENABLED is False
    _reseller, router, _owner, code = await _full_plan(db)

    await _expect_refused(db, router, code, world)

    assert world.probes == []


async def test_idle_randomized_device_is_released_for_the_new_one(db, world, enabled):
    _reseller, router, owner, code = await _full_plan(db)

    result = await _enter(db, router, code, NEW, world)

    assert result["outcome"] == "device_added"
    assert world.removed == [GONE]
    assert world.pushed == [NEW]
    assert await _active_macs(db, owner) == {NEW}
    await db.refresh(owner)
    assert owner.mac_address == OWNER


async def test_each_release_is_logged(db, world, enabled, caplog):
    _reseller, router, owner, code = await _full_plan(db)

    with caplog.at_level("WARNING", logger="app.api.access_code_routes"):
        await _enter(db, router, code, NEW, world)

    assert any("Released idle device" in r.message and GONE in r.message for r in caplog.records)
    (args, kwargs), = world.events
    assert args[0] == owner.id
    assert args[1] == "shared_device_auto_released"
    assert kwargs["details"]["mac"] == GONE
    assert kwargs["details"]["cleanup_status"] == "removed"


async def test_only_one_slot_goes_and_it_is_the_longest_idle(db, world, enabled):
    _reseller, router, owner, code = await _full_plan(db, ((GONE, DeviceType.OTHER), (OTHER_GONE, DeviceType.OTHER)))
    oldest = await db.get(DevicePairing, (await _pairing_id(db, OTHER_GONE)))
    oldest.created_at = _days_ago(60)
    oldest.provisioned_at = _days_ago(60)
    await db.commit()

    await _enter(db, router, code, NEW, world)

    assert world.removed == [OTHER_GONE]
    assert await _active_macs(db, owner) == {GONE, NEW}


async def _pairing_id(db, mac):
    return (await db.execute(select(DevicePairing.id).where(DevicePairing.device_mac == mac))).scalar_one()


async def test_vendor_mac_is_never_released(db, world, enabled):
    _reseller, router, _owner, code = await _full_plan(db, ((VENDOR, DeviceType.OTHER),))

    await _expect_refused(db, router, code, world)


@pytest.mark.parametrize("device_type", [DeviceType.TV, DeviceType.CONSOLE, DeviceType.LAPTOP, DeviceType.IOT])
async def test_a_paired_device_is_never_released_even_with_a_randomized_mac(db, world, enabled, device_type):
    _reseller, router, _owner, code = await _full_plan(db, ((GONE, device_type),))

    await _expect_refused(db, router, code, world)


async def test_a_device_on_the_wifi_now_is_never_released(db, world, enabled):
    _reseller, router, _owner, code = await _full_plan(db)
    world.present = {GONE}

    await _expect_refused(db, router, code, world)

    assert world.probes == [[GONE]]


async def test_nothing_is_released_when_the_router_cannot_answer(db, world, enabled):
    _reseller, router, _owner, code = await _full_plan(db)
    world.present = None

    await _expect_refused(db, router, code, world)


async def test_a_real_time_report_counts_as_seen(db, world, enabled, monkeypatch):
    _reseller, router, _owner, code = await _full_plan(db)

    class Live:
        seen_at = _days_ago(1)
        online = False

    from app.services import realtime_state

    monkeypatch.setattr(realtime_state, "get_device_live", lambda _router, _mac: Live)

    await _expect_refused(db, router, code, world)


async def test_just_under_seven_days_is_kept(db, world, enabled):
    _reseller, router, _owner, code = await _full_plan(db, idle_days=6)

    await _expect_refused(db, router, code, world)


async def test_a_shorter_setting_cannot_go_below_seven_days(db, world, enabled, monkeypatch):
    monkeypatch.setattr(settings, "SHARED_SLOT_IDLE_RELEASE_DAYS", 1)
    _reseller, router, _owner, code = await _full_plan(db, idle_days=3)

    await _expect_refused(db, router, code, world)


async def test_recent_usage_keeps_the_device(db, world, enabled):
    _reseller, router, _owner, code = await _full_plan(db)
    customer_id = await _customer_id(db, GONE)
    db.add(CustomerUsageBucket(
        customer_id=customer_id, router_id=router.id,
        bucket_start=_days_ago(1).replace(minute=0, second=0, microsecond=0),
        upload_bytes=1, download_bytes=1, updated_at=_days_ago(1),
    ))
    await db.commit()

    await _expect_refused(db, router, code, world)


async def test_a_recent_online_sighting_keeps_the_device(db, world, enabled):
    _reseller, router, _owner, code = await _full_plan(db)
    customer_id = await _customer_id(db, GONE)
    db.add(ProvisioningAttempt(
        customer_id=customer_id, router_id=router.id, mac_address=GONE,
        source_table=ProvisioningAttemptSource.SUBSCRIPTION_SHARE, source_pk=1,
        entrypoint=ProvisioningAttemptEntrypoint.SUBSCRIPTION_SHARE,
        provisioning_state=ProvisioningState.ROUTER_UPDATED,
        online_state=ProvisioningOnlineState.ONLINE,
        created_at=_days_ago(30), updated_at=_days_ago(30), last_online_at=_days_ago(2),
    ))
    await db.commit()

    await _expect_refused(db, router, code, world)


async def test_a_recent_reconnect_keeps_the_device(db, world, enabled):
    _reseller, router, _owner, code = await _full_plan(db)
    db.add(ReconnectionAttempt(
        phone="code:voucher", mac_address=GONE, router_id=router.id, success=True,
        created_at=_days_ago(2),
    ))
    await db.commit()

    await _expect_refused(db, router, code, world)


async def test_the_main_device_is_never_a_candidate(db, world, enabled):
    """A plan with no shared devices has nothing to release, however idle its owner."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=2)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=5), mac_address=OWNER,
    )
    slots = await shared_slot_release.find_idle_slots(
        db, owner_id=owner.id, router_id=router.id, now=datetime.utcnow(),
    )

    assert slots == []


async def test_a_phone_number_reconnect_never_frees_a_slot(db, world, enabled):
    """A phone number is not proof of owning the plan, so it can't evict anyone."""
    _reseller, router, owner, _code = await _full_plan(db)

    # At the limit a phone reconnect may move the plan's own idle main device,
    # the existing rule. It must not touch the shared device.
    await public_routes.reconnect_self_service(
        public_routes.ReconnectRequest(phone="0700009001", mac_address=NEW, router_id=router.id),
        BackgroundTasks(),
        db,
    )

    assert world.removed == []
    assert world.probes == []
    assert world.events == []
    assert await _active_macs(db, owner) == {GONE}
