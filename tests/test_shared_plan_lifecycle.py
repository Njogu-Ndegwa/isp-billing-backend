"""A shared (multi-device) plan from purchase to expiry, against a fake router.

Each test walks real routes and services; only RouterOS itself is faked, by a
small stateful router (bindings + throttles) so a test can assert what a real
router would hold after every step. See docs/shared-plans.md for the feature map.

Regression source: router 446 (BIG NEBS), Oct-Nov 2026.
"""

import asyncio
from collections import Counter
from datetime import datetime, timedelta

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import select

from app.api import customer_device_routes, device_pairing, public_routes
from app.api.access_code_routes import redeem_code_on_device
from app.api.device_pairing import DevicePairVoucherRequest, pair_device_with_voucher
from app.db.models import (
    Customer,
    CustomerPayment,
    CustomerStatus,
    CustomerUsagePeriod,
    DevicePairing,
    DeviceType,
    FupAction,
    PaymentMethod,
    ProvisioningAttempt,
    ProvisioningAttemptSource,
    ProvisioningState,
    Voucher,
    VoucherStatus,
)
from app.services import (
    checkin_delivery,
    fup,
    hotspot_provisioning,
    mikrotik_background,
    voucher_service,
)
from app.services.code_attempt_limiter import reset_code_attempt_limiter
from app.services.reseller_payments import record_customer_payment
from app.services.usage_tracking import repair_stale_cap_snapshots
from tests.conftest import running_on_postgres
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

MB = 1024 * 1024
OWNER = "02:AA:00:00:00:01"
PHONE_2 = "02:AA:00:00:00:02"
PHONE_3 = "02:AA:00:00:00:03"
PHONE_4 = "02:AA:00:00:00:04"
TV = "44:72:AC:00:00:0F"
NEW_MAC = "02:AA:00:00:00:99"


class FakeHotspotRouter:
    """What a MikroTik would hold: one binding per MAC, plus throttled queues."""

    def __init__(self):
        self.bindings: dict[str, dict] = {}
        self.throttled: dict[str, str] = {}
        self.pushes: Counter = Counter()
        self._tasks: list[asyncio.Task] = []

    def macs(self) -> set[str]:
        return set(self.bindings)

    async def drain(self):
        while self._tasks:
            tasks, self._tasks = self._tasks, []
            await asyncio.gather(*tasks)


@pytest.fixture
def router_os(monkeypatch, session_factory):
    """Patch every RouterOS touchpoint of the shared-plan paths onto one fake."""
    fake = FakeHotspotRouter()

    async def fake_provision(customer_id, router_id, hotspot_payload, *_args, **_kwargs):
        payload = hotspot_payload
        mac = payload["mac_address"]
        fake.bindings[mac] = {"customer_id": customer_id, "rate": payload.get("bandwidth_limit")}
        fake.pushes[mac] += 1
        return {"success": True}

    async def fake_log(*_args, **_kwargs):
        return None

    async def fake_cleanup_old_mac(_router_info, old_mac):
        fake.bindings.pop(old_mac, None)
        return {"success": True}

    def fake_remove(_router_info, mac):
        fake.bindings.pop(mac, None)
        return {"success": True}

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    def fake_throttle(_info, mac, rate, *, disabled="no"):
        fake.throttled[mac] = rate
        return {"success": True}

    def fake_restore(_info, mac, _rate):
        fake.throttled.pop(mac, None)
        return {"success": True}

    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *args, **kwargs):
        task = original_create_task(coro, *args, **kwargs)
        fake._tasks.append(task)
        return task

    for module in (device_pairing, voucher_service, hotspot_provisioning):
        monkeypatch.setattr(module, "provision_hotspot_customer", fake_provision)
    for module in (device_pairing, voucher_service):
        monkeypatch.setattr(module, "log_provisioning_event", fake_log)
    monkeypatch.setattr(device_pairing, "_remove_shared_device_from_direct_router_sync", fake_remove)
    monkeypatch.setattr(public_routes, "_cleanup_old_mac_with_retry", fake_cleanup_old_mac)
    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(fup, "_set_hotspot_queue_limit_sync", fake_throttle)
    monkeypatch.setattr(fup, "_restore_hotspot_sync", fake_restore)
    monkeypatch.setattr(asyncio, "create_task", tracking_create_task)
    monkeypatch.setattr(checkin_delivery, "async_session", session_factory)
    return fake


@pytest.fixture(autouse=True)
def _clean_limiter():
    reset_code_attempt_limiter()
    yield
    reset_code_attempt_limiter()


async def _reseller_router(db):
    reseller = await make_reseller(db)
    return reseller, await make_router(db, reseller)


async def _group_plan(db, reseller, *, devices=3, cap_mb=None, name="Group"):
    kwargs = {}
    if cap_mb is not None:
        kwargs.update(
            data_cap_mb=cap_mb,
            fup_action=FupAction.THROTTLE,
            fup_throttle_profile="1M/1M",
        )
    return await make_plan(db, reseller, name=name, max_shared_users=devices, **kwargs)


async def _voucher(db, reseller, plan, router, code):
    voucher = Voucher(
        code=code,
        plan_id=plan.id,
        router_id=router.id,
        user_id=reseller.id,
        status=VoucherStatus.AVAILABLE,
    )
    db.add(voucher)
    await db.commit()
    return voucher


async def _enter_code(db, router, mac, code, fake):
    tasks = BackgroundTasks()
    result = await redeem_code_on_device(
        db,
        code=code,
        router_obj=router,
        normalized_mac=mac,
        background_tasks=tasks,
    )
    await tasks()
    await fake.drain()
    return result


async def _pay(db, reseller, customer_id, plan, reference="renewal"):
    await record_customer_payment(
        db=db,
        customer_id=customer_id,
        reseller_id=reseller.id,
        amount=float(plan.price),
        payment_method=PaymentMethod.CASH,
        days_paid_for=plan.duration_value,
        payment_reference=reference,
        duration_value=plan.duration_value,
        duration_unit=plan.duration_unit.value,
    )


async def _buy_group(db, fake, *, devices=3, cap_mb=None, code="11110001"):
    """A customer buys a group plan by voucher on their phone."""
    reseller, router = await _reseller_router(db)
    plan = await _group_plan(db, reseller, devices=devices, cap_mb=cap_mb)
    await _voucher(db, reseller, plan, router, code)
    result = await _enter_code(db, router, OWNER, code, fake)
    assert result["outcome"] == "plan_started"
    owner = await db.get(Customer, result["customer_id"])
    return reseller, router, plan, owner


async def _shares(db, owner) -> list[DevicePairing]:
    return (
        await db.execute(
            select(DevicePairing).where(
                DevicePairing.subscription_owner_customer_id == owner.id,
                DevicePairing.is_subscription_share == True,  # noqa: E712
                DevicePairing.is_active == True,  # noqa: E712
            ).order_by(DevicePairing.id)
        )
    ).scalars().all()


async def _members(db, owner) -> list[Customer]:
    rows = (
        await db.execute(
            select(Customer)
            .where(Customer.subscription_owner_id == owner.id)
            .order_by(Customer.id)
            .execution_options(populate_existing=True)
        )
    ).scalars().all()
    await db.refresh(owner)
    return [owner, *rows]


async def _open_period(db, customer) -> CustomerUsagePeriod:
    return (
        await db.execute(
            select(CustomerUsagePeriod)
            .where(
                CustomerUsagePeriod.customer_id == customer.id,
                CustomerUsagePeriod.closed_at.is_(None),
            )
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


# ------------------------------------------------------------- buying and adding


async def test_buying_a_group_plan_delivers_the_buyers_device(db, router_os):
    _reseller, router, plan, owner = await _buy_group(db, router_os)

    assert owner.mac_address == OWNER
    assert owner.status == CustomerStatus.ACTIVE
    assert owner.plan_id == plan.id
    assert owner.subscription_owner_id is None
    assert router_os.macs() == {OWNER}


async def test_the_code_adds_devices_up_to_the_limit(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=3)

    for mac in (PHONE_2, PHONE_3):
        result = await _enter_code(db, router, mac, "11110001", router_os)
        assert result["outcome"] == "device_added"

    assert router_os.macs() == {OWNER, PHONE_2, PHONE_3}
    members = await _members(db, owner)
    assert len(members) == 3
    assert {m.expiry for m in members} == {owner.expiry}
    assert {m.plan_id for m in members} == {owner.plan_id}


async def test_over_the_limit_is_refused_clearly_and_nobody_is_disconnected(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=2)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)

    with pytest.raises(HTTPException) as refused:
        await _enter_code(db, router, PHONE_3, "11110001", router_os)

    assert refused.value.status_code == 409
    assert refused.value.detail["error"] == "device_limit_reached"
    assert refused.value.detail["max_devices"] == 2
    # The portal shows the devices so the customer can choose one to remove.
    listed = {d["device_mac"] for d in refused.value.detail["devices"]}
    assert listed == {OWNER, PHONE_2}
    assert router_os.macs() == {OWNER, PHONE_2}
    await db.refresh(owner)
    assert owner.mac_address == OWNER


async def test_entering_the_code_again_on_a_shared_device_does_not_use_a_slot(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=2)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)

    # The plan is full, but this device is already on it: it must get back on.
    router_os.bindings.pop(PHONE_2)
    result = await _enter_code(db, router, PHONE_2, "11110001", router_os)

    assert result["outcome"] == "device_added"
    assert router_os.macs() == {OWNER, PHONE_2}
    assert len(await _shares(db, owner)) == 1
    rows = (
        await db.execute(select(Customer).where(Customer.mac_address == PHONE_2))
    ).scalars().all()
    assert len(rows) == 1


async def test_a_new_device_with_the_code_never_displaces_a_device(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=3)

    await _enter_code(db, router, NEW_MAC, "11110001", router_os)

    await db.refresh(owner)
    assert owner.mac_address == OWNER
    assert OWNER in router_os.macs()
    assert NEW_MAC in router_os.macs()


# --------------------------------------------------------------- the paired TV


async def _tv_group(db, fake, *, devices=4, cap_mb=None):
    """A TV paired by voucher on a group plan: the TV's row owns the plan."""
    reseller, router = await _reseller_router(db)
    plan = await _group_plan(db, reseller, devices=devices, cap_mb=cap_mb)
    await _voucher(db, reseller, plan, router, "22220001")
    paired = await pair_device_with_voucher(
        DevicePairVoucherRequest(
            device_mac=TV, voucher_code="22220001", router_id=router.id, device_type="tv",
        ),
        db,
    )
    await fake.drain()
    owner = await db.get(Customer, paired["customer_id"])
    return reseller, router, plan, owner


async def _age_device(db, owner, days=5):
    """Make the owner's device look switched off for ``days``."""
    await db.execute(
        ProvisioningAttempt.__table__.update()
        .where(ProvisioningAttempt.customer_id == owner.id)
        .values(
            created_at=datetime.utcnow() - timedelta(days=days),
            updated_at=datetime.utcnow() - timedelta(days=days),
            router_updated_at=None,
            access_seen_at=None,
            last_online_at=None,
        )
    )
    await db.commit()


async def test_paired_tv_keeps_its_plan_when_a_phone_enters_the_code(db, router_os):
    _reseller, router, _plan, owner = await _tv_group(db, router_os)
    await _age_device(db, owner)

    result = await _enter_code(db, router, PHONE_2, "22220001", router_os)

    assert result["outcome"] == "device_added"
    await db.refresh(owner)
    assert owner.mac_address == TV
    assert router_os.macs() == {TV, PHONE_2}


# ----------------------------------------------------------------------- removal


async def test_removing_a_device_frees_its_slot_and_takes_it_off_the_router(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=2)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    pairing = (await _shares(db, owner))[0]

    result = await device_pairing.disconnect_shared_pairing(
        db, owner=owner, router_id=router.id, pairing_id=pairing.id,
    )

    assert result["cleanup_status"] == "removed"
    assert router_os.macs() == {OWNER}
    assert await _shares(db, owner) == []

    # The freed slot can be used right away.
    added = await _enter_code(db, router, PHONE_3, "11110001", router_os)
    assert added["outcome"] == "device_added"
    assert router_os.macs() == {OWNER, PHONE_3}


async def test_dashboard_can_add_and_remove_a_device(db, router_os):
    reseller, router, _plan, owner = await _buy_group(db, router_os, devices=2)
    token = {"user_id": reseller.id, "role": reseller.role.value}

    added = await customer_device_routes.add_customer_device(
        owner.id,
        customer_device_routes.AddDeviceRequest(mac_address=TV, device_type="tv"),
        db,
        token,
    )
    await router_os.drain()
    assert router_os.macs() == {OWNER, TV}

    await customer_device_routes.remove_customer_device(owner.id, added["pairing_id"], db, token)
    assert router_os.macs() == {OWNER}
    assert await _shares(db, owner) == []


# --------------------------------------------------------- renewal and top-ups


async def test_renewal_extends_every_device_and_redelivers_it(db, router_os):
    reseller, router, plan, owner = await _buy_group(db, router_os, devices=3)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    await _enter_code(db, router, PHONE_3, "11110001", router_os)
    before = owner.expiry

    await _pay(db, reseller, owner.id, plan)

    members = await _members(db, owner)
    assert owner.expiry == before + timedelta(days=plan.duration_value)
    assert {m.expiry for m in members} == {owner.expiry}
    assert all(m.status == CustomerStatus.ACTIVE for m in members)
    for pairing in await _shares(db, owner):
        assert pairing.expires_at == owner.expiry


async def test_renewal_after_expiry_brings_every_device_back(db, router_os):
    reseller, router, plan, owner = await _buy_group(db, router_os, devices=2)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)

    # Expired and removed from the router by the expiry job.
    past = datetime.utcnow() - timedelta(days=2)
    for member in await _members(db, owner):
        member.expiry = past
        member.status = CustomerStatus.INACTIVE
    await db.commit()
    router_os.bindings.clear()

    await _pay(db, reseller, owner.id, plan)

    members = await _members(db, owner)
    assert all(m.status == CustomerStatus.ACTIVE for m in members)
    assert all(m.expiry > datetime.utcnow() for m in members)
    assert len(await _shares(db, owner)) == 1


async def test_renewal_gives_a_shared_device_a_fresh_delivery_window(db, router_os, monkeypatch, session_factory):
    """The delivery attempt is reused per pairing. A renewal a month later used
    to re-schedule the old row, and the retry job failed it as past its 4 h
    window before pushing anything."""
    reseller, router, plan, owner = await _buy_group(db, router_os, devices=2)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    pairing = (await _shares(db, owner))[0]

    old = datetime.utcnow() - timedelta(days=29)
    await db.execute(
        ProvisioningAttempt.__table__.update()
        .where(
            ProvisioningAttempt.source_table == ProvisioningAttemptSource.SUBSCRIPTION_SHARE,
            ProvisioningAttempt.source_pk == pairing.id,
        )
        .values(
            created_at=old,
            provisioning_state=ProvisioningState.ROUTER_UPDATED,
            attempt_count=3,
        )
    )
    await db.commit()

    await _pay(db, reseller, owner.id, plan)

    pushed = []

    async def capture_groups(router_groups):
        pushed.extend(item for items in router_groups.values() for item in items)

    monkeypatch.setattr(hotspot_provisioning, "async_session", session_factory)
    monkeypatch.setattr(hotspot_provisioning, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(hotspot_provisioning, "_process_hotspot_retry_router_groups", capture_groups)
    await hotspot_provisioning.retry_pending_hotspot_provisioning_background()

    attempt = (
        await db.execute(
            select(ProvisioningAttempt)
            .where(
                ProvisioningAttempt.source_table == ProvisioningAttemptSource.SUBSCRIPTION_SHARE,
                ProvisioningAttempt.source_pk == pairing.id,
            )
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert attempt.provisioning_state == ProvisioningState.SCHEDULED
    assert attempt.attempt_count == 0
    assert attempt.created_at > old + timedelta(days=28)
    assert pushed, "the retry job should push the renewed shared device"


async def test_same_voucher_plan_on_the_owner_stacks_and_keeps_devices(db, router_os):
    reseller, router, plan, owner = await _buy_group(db, router_os, devices=3)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    before = owner.expiry
    await _voucher(db, reseller, plan, router, "11110002")

    result = await _enter_code(db, router, OWNER, "11110002", router_os)

    assert result["outcome"] == "plan_started"
    members = await _members(db, owner)
    assert owner.expiry == before + timedelta(days=plan.duration_value)
    assert {m.expiry for m in members} == {owner.expiry}
    assert len(await _shares(db, owner)) == 1


async def test_voucher_for_a_bigger_plan_applies_its_cap_not_the_old_one(db, router_os):
    """Router 446, Oct 2026: 200 GB plan bought on top of a 2 GB one kept the
    2 GB cap in the new usage period, so its owner was throttled for 17 days
    with 120 GB of the group's 200 GB used."""
    reseller, router = await _reseller_router(db)
    small = await _group_plan(db, reseller, devices=1, cap_mb=2048, name="TV bundle")
    big = await _group_plan(db, reseller, devices=10, cap_mb=204800, name="200 GB")
    await _voucher(db, reseller, small, router, "33330001")
    await _voucher(db, reseller, big, router, "33330002")

    first = await _enter_code(db, router, TV, "33330001", router_os)
    owner = await db.get(Customer, first["customer_id"])
    assert (await _open_period(db, owner)).cap_mb_snapshot == 2048

    await _enter_code(db, router, TV, "33330002", router_os)

    await db.refresh(owner)
    assert owner.plan_id == big.id
    assert (await _open_period(db, owner)).cap_mb_snapshot == 204800

    added = await _enter_code(db, router, PHONE_2, "33330002", router_os)
    assert added["outcome"] == "device_added"
    shared = await db.get(Customer, added["customer_id"])
    assert (await _open_period(db, shared)).cap_mb_snapshot == 204800


async def test_pair_voucher_for_a_bigger_plan_applies_its_cap_not_the_old_one(db, router_os):
    """Same bug, through the device-pairing voucher path."""
    reseller, router = await _reseller_router(db)
    small = await _group_plan(db, reseller, devices=1, cap_mb=2048, name="TV bundle")
    big = await _group_plan(db, reseller, devices=10, cap_mb=204800, name="200 GB")
    await _voucher(db, reseller, small, router, "33330003")
    await _voucher(db, reseller, big, router, "33330004")

    for code in ("33330003", "33330004"):
        paired = await pair_device_with_voucher(
            DevicePairVoucherRequest(
                device_mac=TV, voucher_code=code, router_id=router.id, device_type="tv",
            ),
            db,
        )
        await router_os.drain()

    owner = await db.get(Customer, paired["customer_id"])
    await db.refresh(owner)
    assert owner.plan_id == big.id
    assert (await _open_period(db, owner)).cap_mb_snapshot == 204800


async def _swapped_group(db, fake):
    """Router 446, customer 50758: a TV owns a group plan with phones on it, and
    a 1-device voucher swapped the plan. Vouchers are refused now, so the rows
    are set directly: groups swapped before the refusal shipped still exist."""
    reseller, router, group, owner = await _tv_group(db, fake, devices=4, cap_mb=245760)
    await _enter_code(db, router, PHONE_2, "22220001", fake)
    await _enter_code(db, router, PHONE_3, "22220001", fake)
    single = await _group_plan(db, reseller, devices=1, cap_mb=2048, name="TV bundle")
    for member in await _members(db, owner):
        member.plan_id = single.id
    await db.commit()
    await db.refresh(owner, ["plan"])
    return reseller, router, group, single, owner


async def _refused_voucher_state(db, voucher_code):
    voucher = (
        await db.execute(
            select(Voucher)
            .where(Voucher.code == voucher_code)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    payments = (
        await db.execute(
            select(CustomerPayment).where(CustomerPayment.payment_reference == f"VOUCHER-{voucher_code}")
        )
    ).scalars().all()
    return voucher, payments


async def test_smaller_voucher_on_a_live_group_is_refused_with_a_clear_message(db, router_os):
    """The customer sees why, the voucher stays usable, and nothing moves."""
    reseller, router, group, owner = await _tv_group(db, router_os, devices=4, cap_mb=245760)
    await _enter_code(db, router, PHONE_2, "22220001", router_os)
    single = await _group_plan(db, reseller, devices=1, cap_mb=2048, name="TV bundle")
    await _voucher(db, reseller, single, router, "22220002")
    before = owner.expiry
    pushes = sum(router_os.pushes.values())

    with pytest.raises(HTTPException) as refused:
        await pair_device_with_voucher(
            DevicePairVoucherRequest(
                device_mac=TV, voucher_code="22220002", router_id=router.id, device_type="tv",
            ),
            db,
        )
    await router_os.drain()

    assert refused.value.status_code == 400
    assert refused.value.detail == (
        "This voucher is for a smaller plan than the Group plan on this device, so we did "
        "not use it. It is still valid. Use it after this plan ends, or on another device."
    )
    voucher, payments = await _refused_voucher_state(db, "22220002")
    assert voucher.status == VoucherStatus.AVAILABLE
    assert voucher.redeemed_by is None
    assert payments == []
    await db.refresh(owner)
    assert owner.plan_id == group.id
    assert owner.expiry == before
    assert (await _open_period(db, owner)).cap_mb_snapshot == group.data_cap_mb
    assert len(await _shares(db, owner)) == 1
    assert sum(router_os.pushes.values()) == pushes


async def test_portal_code_path_returns_the_same_refusal(db, router_os):
    reseller, router, group, owner = await _buy_group(db, router_os, devices=3, cap_mb=1000)
    small = await _group_plan(db, reseller, devices=3, cap_mb=100, name="Small")
    await _voucher(db, reseller, small, router, "11110009")

    with pytest.raises(HTTPException) as refused:
        await _enter_code(db, router, OWNER, "11110009", router_os)

    assert refused.value.status_code == 400
    assert "smaller plan than the Group plan" in refused.value.detail
    assert "still valid" in refused.value.detail
    voucher, payments = await _refused_voucher_state(db, "11110009")
    assert voucher.status == VoucherStatus.AVAILABLE
    assert payments == []
    await db.refresh(owner)
    assert owner.plan_id == group.id


async def test_public_voucher_route_returns_the_same_refusal(db, router_os):
    reseller, router, group, owner = await _buy_group(db, router_os, devices=3)
    single = await _group_plan(db, reseller, devices=1, name="One device")
    await _voucher(db, reseller, single, router, "11110010")

    with pytest.raises(HTTPException) as refused:
        await public_routes.redeem_voucher_public(
            {"code": "11110010", "mac_address": OWNER, "router_id": router.id}, db,
        )

    assert refused.value.status_code == 400
    assert "still valid" in refused.value.detail
    await db.refresh(owner)
    assert owner.plan_id == group.id


async def test_same_or_bigger_voucher_on_a_live_group_still_works(db, router_os):
    reseller, router, _group, owner = await _buy_group(db, router_os, devices=3, cap_mb=1000)
    bigger = await _group_plan(db, reseller, devices=5, cap_mb=2000, name="Bigger")
    await _voucher(db, reseller, bigger, router, "11110011")

    result = await _enter_code(db, router, OWNER, "11110011", router_os)

    assert result["outcome"] == "plan_started"
    await db.refresh(owner)
    assert owner.plan_id == bigger.id


async def test_smaller_voucher_is_allowed_once_the_plan_has_ended(db, router_os):
    reseller, router, _group, owner = await _buy_group(db, router_os, devices=3, cap_mb=1000)
    single = await _group_plan(db, reseller, devices=1, cap_mb=100, name="One device")
    await _voucher(db, reseller, single, router, "11110012")
    owner.expiry = datetime.utcnow() - timedelta(minutes=1)
    await db.commit()

    result = await _enter_code(db, router, OWNER, "11110012", router_os)

    assert result["outcome"] == "plan_started"
    await db.refresh(owner)
    assert owner.plan_id == single.id


async def test_single_device_top_up_with_a_capped_plan_is_not_refused(db, router_os):
    """An unlimited hour followed by a capped week is the ordinary top-up."""
    reseller, router, _plan, owner = await _buy_group(db, router_os, devices=1)
    week = await _group_plan(db, reseller, devices=1, cap_mb=20480, name="Week")
    await _voucher(db, reseller, week, router, "11110013")

    result = await _enter_code(db, router, OWNER, "11110013", router_os)

    assert result["outcome"] == "plan_started"
    await db.refresh(owner)
    assert owner.plan_id == week.id


async def test_customer_override_keeps_their_device_limit(db, router_os):
    """The reseller's per-customer limit wins over either plan, so a plan with a
    lower allowance takes no devices away."""
    reseller, router, _group, owner = await _buy_group(db, router_os, devices=4)
    owner.max_devices_override = 4
    await db.commit()
    smaller = await _group_plan(db, reseller, devices=2, name="Two devices")
    await _voucher(db, reseller, smaller, router, "11110014")

    result = await _enter_code(db, router, OWNER, "11110014", router_os)

    assert result["outcome"] == "plan_started"


async def test_group_already_swapped_to_one_device_refuses_the_same_voucher_again(db, router_os):
    """Another TV bundle on a swapped group would release all its devices."""
    reseller, router, _group, single, owner = await _swapped_group(db, router_os)
    await _voucher(db, reseller, single, router, "22220003")

    with pytest.raises(HTTPException) as refused:
        await pair_device_with_voucher(
            DevicePairVoucherRequest(
                device_mac=TV, voucher_code="22220003", router_id=router.id, device_type="tv",
            ),
            db,
        )

    assert refused.value.status_code == 400
    assert len(await _shares(db, owner)) == 2
    voucher, _payments = await _refused_voucher_state(db, "22220003")
    assert voucher.status == VoucherStatus.AVAILABLE


async def test_swapped_group_refuses_a_new_device_and_keeps_the_tv(db, router_os):
    """The 446 incident, replayed. Before #300 the code moved the plan off the TV."""
    _reseller, router, _group, _single, owner = await _swapped_group(db, router_os)
    await _age_device(db, owner)

    with pytest.raises(HTTPException) as refused:
        await _enter_code(db, router, PHONE_4, "22220001", router_os)

    assert refused.value.status_code == 409
    assert refused.value.detail["error"] == "device_limit_reached"
    await db.refresh(owner)
    assert owner.mac_address == TV
    assert router_os.macs() == {TV, PHONE_2, PHONE_3}


async def test_attached_device_gets_back_on_a_swapped_group_with_the_code(db, router_os):
    """Found on router 563: on a healthy group a device already attached gets
    re-delivered, on a swapped group it was refused as if it were new."""
    _reseller, router, _group, _single, owner = await _swapped_group(db, router_os)
    await _age_device(db, owner)
    router_os.bindings.pop(PHONE_2)

    result = await _enter_code(db, router, PHONE_2, "22220001", router_os)

    assert result["outcome"] == "device_added"
    assert router_os.macs() == {TV, PHONE_2, PHONE_3}
    assert len(await _shares(db, owner)) == 2
    await db.refresh(owner)
    assert owner.mac_address == TV
    rows = (await db.execute(select(Customer).where(Customer.mac_address == PHONE_2))).scalars().all()
    assert len(rows) == 1


async def test_attached_device_gets_back_on_a_group_over_its_limit(db, router_os):
    """A reseller lowered the plan's limit below the devices attached: the plan
    still allows sharing, and the device already holds a slot."""
    _reseller, router, plan, owner = await _buy_group(db, router_os, devices=3)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    await _enter_code(db, router, PHONE_3, "11110001", router_os)
    plan.max_shared_users = 2
    await db.commit()
    await db.refresh(owner, ["plan"])
    router_os.bindings.pop(PHONE_3)

    result = await _enter_code(db, router, PHONE_3, "11110001", router_os)

    assert result["outcome"] == "device_added"
    assert router_os.macs() == {OWNER, PHONE_2, PHONE_3}
    assert len(await _shares(db, owner)) == 2


async def test_attached_device_gets_back_on_a_swapped_group_by_phone(db, router_os):
    _reseller, router, _group, _single, owner = await _swapped_group(db, router_os)
    owner.phone = "254700007001"
    await db.commit()
    await _age_device(db, owner)
    router_os.bindings.pop(PHONE_2)
    tasks = BackgroundTasks()

    result = await public_routes.reconnect_self_service(
        public_routes.ReconnectRequest(phone="0700007001", mac_address=PHONE_2, router_id=router.id),
        tasks,
        db,
    )
    await tasks()
    await router_os.drain()

    assert result["outcome"] == "device_added"
    assert router_os.macs() == {TV, PHONE_2, PHONE_3}
    await db.refresh(owner)
    assert owner.mac_address == TV
    assert len(await _shares(db, owner)) == 2


async def test_a_shared_tv_entering_the_code_again_stays_a_tv(db, router_os):
    """The portal sends "other". A TV must not lose what it was paired as, or the
    rules protecting paired devices stop applying to it."""
    reseller, router, _plan, owner = await _buy_group(db, router_os, devices=3)
    token = {"user_id": reseller.id, "role": reseller.role.value}
    await customer_device_routes.add_customer_device(
        owner.id,
        customer_device_routes.AddDeviceRequest(mac_address=TV, device_type="tv"),
        db,
        token,
    )
    await router_os.drain()

    await _enter_code(db, router, TV, "11110001", router_os)

    pairing = (await _shares(db, owner))[0]
    await db.refresh(pairing)
    assert pairing.device_type == DeviceType.TV


async def test_a_released_device_on_a_swapped_group_is_still_refused(db, router_os):
    """Holding a slot is what counts, not having held one."""
    _reseller, router, _group, _single, owner = await _swapped_group(db, router_os)
    pairing = next(p for p in await _shares(db, owner) if p.device_mac == PHONE_2)
    await device_pairing.disconnect_shared_pairing(
        db, owner=owner, router_id=router.id, pairing_id=pairing.id,
    )
    await _age_device(db, owner)

    with pytest.raises(HTTPException) as refused:
        await _enter_code(db, router, PHONE_2, "22220001", router_os)

    assert refused.value.status_code == 409
    assert refused.value.detail["error"] == "device_limit_reached"
    assert router_os.macs() == {TV, PHONE_3}


async def test_a_new_device_is_still_refused_on_a_group_over_its_limit(db, router_os):
    _reseller, router, plan, owner = await _buy_group(db, router_os, devices=3)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    await _enter_code(db, router, PHONE_3, "11110001", router_os)
    plan.max_shared_users = 2
    await db.commit()
    await db.refresh(owner, ["plan"])

    with pytest.raises(HTTPException) as refused:
        await _enter_code(db, router, PHONE_4, "11110001", router_os)

    assert refused.value.status_code == 409
    assert router_os.macs() == {OWNER, PHONE_2, PHONE_3}


async def test_paired_tv_on_a_single_device_plan_is_never_moved(db, router_os):
    _reseller, router, _plan, owner = await _tv_group(db, router_os, devices=1)
    await _age_device(db, owner)

    with pytest.raises(HTTPException) as refused:
        await _enter_code(db, router, PHONE_2, "22220001", router_os)

    assert refused.value.status_code == 409
    await db.refresh(owner)
    assert owner.mac_address == TV
    assert router_os.macs() == {TV}


# ------------------------------------------------------------- data cap and FUP


async def _pay_after_switching(db, reseller, owner, plan):
    owner.plan_id = plan.id
    await db.commit()
    await db.refresh(owner, ["plan"])
    await _pay(db, reseller, owner.id, plan, reference="switch")


async def _meter(db, customer, mb):
    period = await _open_period(db, customer)
    period.download_bytes = mb * MB
    period.total_bytes = mb * MB
    await db.commit()
    return period


async def test_pooled_cap_throttles_every_device_and_renewal_lifts_it(db, router_os):
    reseller, router, plan, owner = await _buy_group(db, router_os, devices=3, cap_mb=100)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    await _enter_code(db, router, PHONE_3, "11110001", router_os)
    members = await _members(db, owner)

    # 40 + 40 + 40 MB: no single device is over 100 MB, the plan is.
    for member in members:
        await _meter(db, member, 40)
    for member in members:
        await db.refresh(member, ["plan"])
        period = await _open_period(db, member)
        applied = await fup.evaluate_and_enforce(db, member, period, plan=plan)
        await db.commit()
        assert applied == FupAction.THROTTLE

    assert set(router_os.throttled) == {OWNER, PHONE_2, PHONE_3}

    await _pay(db, reseller, owner.id, plan)

    assert router_os.throttled == {}
    for member in await _members(db, owner):
        period = await _open_period(db, member)
        assert period.total_bytes == 0
        assert period.fup_triggered_at is None


async def test_under_the_pooled_cap_nobody_is_throttled(db, router_os):
    _reseller, router, plan, owner = await _buy_group(db, router_os, devices=2, cap_mb=100)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)

    for member in await _members(db, owner):
        await _meter(db, member, 40)
    for member in await _members(db, owner):
        period = await _open_period(db, member)
        assert await fup.evaluate_and_enforce(db, member, period, plan=plan) is None

    assert router_os.throttled == {}


async def test_a_removed_devices_usage_still_counts_toward_the_cap(db, router_os):
    _reseller, router, plan, owner = await _buy_group(db, router_os, devices=2, cap_mb=100)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    pairing = (await _shares(db, owner))[0]
    shared = await db.get(Customer, pairing.customer_id)
    await _meter(db, shared, 80)

    # Removing and re-adding a device must not reset the allowance.
    await device_pairing.disconnect_shared_pairing(
        db, owner=owner, router_id=router.id, pairing_id=pairing.id,
    )
    period = await _meter(db, owner, 30)

    assert await fup.evaluate_and_enforce(db, owner, period, plan=plan) == FupAction.THROTTLE
    assert OWNER in router_os.throttled


# ------------------------------------------------------------------------ expiry


async def test_expiry_removes_every_device_from_the_router(db, router_os, monkeypatch, session_factory):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=3)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    await _enter_code(db, router, PHONE_3, "11110001", router_os)
    assert router_os.macs() == {OWNER, PHONE_2, PHONE_3}

    past = datetime.utcnow() - timedelta(hours=1)
    for member in await _members(db, owner):
        member.expiry = past
    await db.commit()

    def remove_from_fake(_router_info, customers):
        for customer in customers:
            router_os.bindings.pop(customer["mac_address"], None)
        return {"removed": [{"id": c["id"]} for c in customers], "failed": [], "connected": True}

    async def zero(*_a, **_k):
        return 0

    async def none(*_a, **_k):
        return None

    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability", none)
    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_hotspot_sync", remove_from_fake)

    await mikrotik_background.cleanup_expired_users_background()

    assert router_os.macs() == set()
    for member in await _members(db, owner):
        assert member.status == CustomerStatus.INACTIVE
    # The slots stay reserved: renewal brings the same devices back.
    assert len(await _shares(db, owner)) == 2


async def test_expired_plan_code_is_refused(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=3)
    owner.expiry = datetime.utcnow() - timedelta(minutes=1)
    await db.commit()

    with pytest.raises(HTTPException) as refused:
        await _enter_code(db, router, PHONE_2, "11110001", router_os)

    assert refused.value.status_code == 410
    assert PHONE_2 not in router_os.macs()


# ----------------------------------------------------------------- MAC rotation


async def test_owner_phone_with_a_rotated_mac_gets_a_slot_and_the_old_one_stays(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=3)

    # A randomized MAC looks like a new device, so it takes a free slot.
    result = await _enter_code(db, router, NEW_MAC, "11110001", router_os)

    assert result["outcome"] == "device_added"
    await db.refresh(owner)
    assert owner.mac_address == OWNER


async def test_rotated_mac_on_a_full_plan_can_release_the_main_device(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=2)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)

    with pytest.raises(HTTPException) as refused:
        await _enter_code(db, router, NEW_MAC, "11110001", router_os)
    assert refused.value.detail["error"] == "device_limit_reached"
    assert router_os.macs() == {OWNER, PHONE_2}

    # The customer removes the old main device from the portal's list.
    released = await device_pairing.release_main_device(db, owner=owner)
    assert released["cleanup_status"] == "removed"
    result = await _enter_code(db, router, NEW_MAC, "11110001", router_os)

    assert result["outcome"] == "main_device"
    await db.refresh(owner)
    assert owner.mac_address == NEW_MAC
    assert router_os.macs() == {PHONE_2, NEW_MAC}


# --------------------------------------------------- reboot / check-in re-delivery


async def test_checkin_offers_every_device_after_the_router_lost_them(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=3)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    await _enter_code(db, router, PHONE_3, "11110001", router_os)

    # Router rebooted with a clean table and reports nothing.
    router_os.bindings.clear()
    state = await checkin_delivery.load_checkin_state(router.id, datetime.utcnow())
    missing, _unknown = checkin_delivery.compute_diff(state.desired, set())

    assert {entry.mac for entry in missing} == {OWNER, PHONE_2, PHONE_3}
    epochs = {entry.expiry_epoch for entry in missing}
    assert len(epochs) == 1  # one plan, one deadline on every binding


async def test_checkin_stops_offering_a_removed_device(db, router_os):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=2)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    pairing = (await _shares(db, owner))[0]

    await device_pairing.disconnect_shared_pairing(
        db, owner=owner, router_id=router.id, pairing_id=pairing.id,
    )

    state = await checkin_delivery.load_checkin_state(router.id, datetime.utcnow())
    assert {entry.mac for entry in state.desired} == {OWNER}


# ------------------------------------------------------- owner edits and chains


async def test_reseller_editing_owner_expiry_moves_every_device(db, router_os):
    reseller, router, _plan, owner = await _buy_group(db, router_os, devices=2)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    new_expiry = owner.expiry + timedelta(days=10)

    from app.api import customer_routes

    request = customer_routes.CustomerEditRequest(expiry=new_expiry)
    token = {"user_id": reseller.id, "role": reseller.role.value}
    await customer_routes.edit_customer(owner.id, request, db, token)

    members = await _members(db, owner)
    assert {m.expiry for m in members} == {new_expiry}
    assert (await _shares(db, owner))[0].expires_at == new_expiry


async def test_expired_owner_added_to_another_plan_lets_go_of_its_own_devices(db, router_os):
    """An expired owner reused as someone else's shared device used to stay the
    owner of its own devices: an owner -> shared -> shared chain that renewals
    never walk, so the last link drifted out of sync (seen on 2 groups)."""
    reseller, router, plan, owner = await _buy_group(db, router_os, devices=3)
    await _enter_code(db, router, PHONE_2, "11110001", router_os)
    owner.expiry = datetime.utcnow() - timedelta(days=1)
    owner.status = CustomerStatus.INACTIVE
    await db.commit()
    child = (await _shares(db, owner))[0]
    child_customer = await db.get(Customer, child.customer_id)

    other_plan = await _group_plan(db, reseller, devices=3, name="Other")
    await _voucher(db, reseller, other_plan, router, "55550001")
    other = await _enter_code(db, router, PHONE_3, "55550001", router_os)

    await _enter_code(db, router, OWNER, "55550001", router_os)

    await db.refresh(owner)
    assert owner.subscription_owner_id == other["customer_id"]
    assert await _shares(db, owner) == []
    await db.refresh(child_customer)
    assert child_customer.subscription_owner_id is None


# ---------------------------------------------------------------- stale cap repair


async def _stale_group(db, fake, *, big_cap=204800):
    """What the old bug left behind: a 2 GB cap on a 200 GB purchase."""
    reseller, router = await _reseller_router(db)
    small = await _group_plan(db, reseller, devices=1, cap_mb=2048, name="TV bundle")
    big = await _group_plan(db, reseller, devices=10, cap_mb=big_cap, name="200 GB")
    await _voucher(db, reseller, small, router, "66660001")
    await _voucher(db, reseller, big, router, "66660002")
    first = await _enter_code(db, router, TV, "66660001", fake)
    owner = await db.get(Customer, first["customer_id"])
    await _enter_code(db, router, TV, "66660002", fake)
    await _enter_code(db, router, PHONE_2, "66660002", fake)
    shared = (await _members(db, owner))[1]

    for member in (owner, shared):
        period = await _open_period(db, member)
        period.cap_mb_snapshot = 2048
    await db.commit()
    return reseller, router, big, owner, shared


async def test_repair_gives_owner_and_devices_the_cap_they_paid_for(db, router_os):
    _reseller, _router, big, owner, shared = await _stale_group(db, router_os)

    repaired = await repair_stale_cap_snapshots(db)
    await db.commit()

    assert [r["customer_id"] for r in repaired] == [owner.id]
    assert repaired[0]["from_cap_mb"] == 2048
    assert repaired[0]["to_cap_mb"] == big.data_cap_mb
    for member in (owner, shared):
        assert (await _open_period(db, member)).cap_mb_snapshot == big.data_cap_mb

    # Idempotent: the same rows do not match again.
    assert await repair_stale_cap_snapshots(db) == []


async def test_repair_lifts_a_wrong_throttle_but_not_a_right_one(db, router_os):
    _reseller, _router, big, owner, _shared = await _stale_group(db, router_os)
    period = await _meter(db, owner, 3000)
    assert await fup.evaluate_and_enforce(db, owner, period, plan=big) == FupAction.THROTTLE
    assert OWNER not in router_os.throttled and TV in router_os.throttled
    await db.commit()

    await repair_stale_cap_snapshots(db)
    await db.commit()

    period = await _open_period(db, owner)
    assert await fup.evaluate_and_enforce(db, owner, period, plan=big) is None
    assert TV not in router_os.throttled


async def test_repair_leaves_a_resellers_later_cap_edit_alone(db, router_os):
    """A plan whose cap was raised and not carried over is not this bug: the
    snapshot does not match the previous purchase's plan."""
    reseller, router, plan, owner = await _buy_group(db, router_os, devices=2, cap_mb=100)
    other = await _group_plan(db, reseller, devices=2, cap_mb=200, name="Other")
    await _pay(db, reseller, owner.id, plan, reference="first")
    owner.plan_id = other.id
    await db.commit()
    await _pay(db, reseller, owner.id, other, reference="second")

    period = await _open_period(db, owner)
    period.cap_mb_snapshot = 150
    await db.commit()

    assert await repair_stale_cap_snapshots(db) == []
    assert (await _open_period(db, owner)).cap_mb_snapshot == 150


async def test_repair_never_tightens(db, router_os):
    """TV bundle bought on a 240 GB plan: the stale cap is bigger than the plan
    paid for. Taking it away is a product decision, so it stays."""
    reseller, router = await _reseller_router(db)
    big = await _group_plan(db, reseller, devices=10, cap_mb=245760, name="240 GB")
    small = await _group_plan(db, reseller, devices=1, cap_mb=2048, name="TV bundle")
    await _voucher(db, reseller, big, router, "77770001")
    await _voucher(db, reseller, small, router, "77770002")
    first = await _enter_code(db, router, TV, "77770001", router_os)
    owner = await db.get(Customer, first["customer_id"])
    # Written directly: vouchers can no longer produce this, but rows from before can.
    await _pay_after_switching(db, reseller, owner, small)
    period = await _open_period(db, owner)
    period.cap_mb_snapshot = 245760
    await db.commit()

    assert await repair_stale_cap_snapshots(db) == []
    assert (await _open_period(db, owner)).cap_mb_snapshot == 245760


# ------------------------------------------------------------------------- races


@pytest.mark.skipif(not running_on_postgres(), reason="row locks need real Postgres")
async def test_concurrent_codes_never_exceed_the_device_limit(db, router_os, session_factory):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=2)
    router_id = router.id

    async def attempt(mac):
        async with session_factory() as session:
            router_row = await session.get(type(router), router_id)
            try:
                return await redeem_code_on_device(
                    session,
                    code="11110001",
                    router_obj=router_row,
                    normalized_mac=mac,
                    background_tasks=BackgroundTasks(),
                )
            except HTTPException as exc:
                return exc

    results = await asyncio.gather(*(attempt(mac) for mac in (PHONE_2, PHONE_3, PHONE_4, NEW_MAC)))
    await router_os.drain()

    added = [r for r in results if isinstance(r, dict)]
    refused = [r for r in results if isinstance(r, HTTPException)]
    assert len(added) == 1
    assert {r.status_code for r in refused} == {409}
    assert len(await _shares(db, owner)) == 1


@pytest.mark.skipif(not running_on_postgres(), reason="row locks need real Postgres")
async def test_double_tap_of_the_same_device_provisions_one_row(db, router_os, session_factory):
    _reseller, router, _plan, owner = await _buy_group(db, router_os, devices=3)
    router_id = router.id

    async def attempt():
        async with session_factory() as session:
            router_row = await session.get(type(router), router_id)
            return await redeem_code_on_device(
                session,
                code="11110001",
                router_obj=router_row,
                normalized_mac=PHONE_2,
                background_tasks=BackgroundTasks(),
            )

    await asyncio.gather(attempt(), attempt())
    await router_os.drain()

    assert len(await _shares(db, owner)) == 1
    rows = (
        await db.execute(select(Customer).where(Customer.mac_address == PHONE_2))
    ).scalars().all()
    assert len(rows) == 1
