"""One code per purchase, valid on every device the plan covers."""

import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import select

from app.api import access_code_routes, device_pairing, payment_routes, public_routes
from app.api.access_code_routes import (
    AccessCodeDevicesRequest,
    AccessCodeDisconnectRequest,
    AccessCodeRedeemRequest,
)
from app.db.models import (
    Customer,
    CustomerStatus,
    DevicePairing,
    DeviceType,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    Voucher,
    VoucherStatus,
)
from app.services import voucher_service
from app.services.code_attempt_limiter import MAX_FAILURES_PER_DEVICE, reset_code_attempt_limiter
from app.services.reseller_payments import record_customer_payment
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

OWNER_MAC = "AA:BB:CC:00:00:01"
PHONE_2 = "AA:BB:CC:00:00:02"
PHONE_3 = "AA:BB:CC:00:00:03"


@pytest.fixture(autouse=True)
def _clean_limiter():
    reset_code_attempt_limiter()
    yield
    reset_code_attempt_limiter()


@pytest.fixture
def stub_provisioning(monkeypatch):
    """Router delivery is out of scope here; record calls instead."""
    calls = []
    tasks = []

    async def fake_log(*_args, **_kwargs):
        return None

    async def fake_provision(*args, **kwargs):
        calls.append((args, kwargs))
        return {"success": True}

    async def fake_old_mac_cleanup(*_args, **_kwargs):
        return {"success": True}

    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *args, **kwargs):
        task = original_create_task(coro, *args, **kwargs)
        tasks.append(task)
        return task

    for module in (device_pairing, voucher_service):
        monkeypatch.setattr(module, "log_provisioning_event", fake_log)
        monkeypatch.setattr(module, "provision_hotspot_customer", fake_provision)
    monkeypatch.setattr(public_routes, "_cleanup_old_mac_with_retry", fake_old_mac_cleanup)
    monkeypatch.setattr(asyncio, "create_task", tracking_create_task)

    class Stub:
        async def drain(self):
            if tasks:
                await asyncio.gather(*tasks)
                tasks.clear()

    stub = Stub()
    stub.calls = calls
    return stub


async def _setup(db, *, max_shared_users=2):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=max_shared_users)
    router = await make_router(db, reseller)
    return reseller, plan, router


async def _voucher(db, reseller, plan, router, code="48392910"):
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


async def _redeem(db, router, code, mac, **extra):
    return await access_code_routes.redeem_access_code(
        AccessCodeRedeemRequest(code=code, router_id=router.id, mac_address=mac, **extra),
        BackgroundTasks(),
        db,
    )


async def _active_owner(db, reseller, plan, router, **overrides):
    defaults = dict(
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=2),
        mac_address=OWNER_MAC,
        phone="254700000900",
    )
    defaults.update(overrides)
    return await make_customer(db, reseller, plan, router, **defaults)


async def test_same_voucher_starts_plan_then_adds_second_device(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    voucher = await _voucher(db, reseller, plan, router)

    first = await _redeem(db, router, "4839-2910", OWNER_MAC)
    await stub_provisioning.drain()
    assert first["outcome"] == "plan_started"
    assert first["access_code"] == "48392910"
    assert first["max_devices"] == 2
    await db.refresh(voucher)
    assert voucher.status == VoucherStatus.REDEEMED
    owner_id = voucher.redeemed_by

    second = await _redeem(db, router, "48392910", PHONE_2, device_name="Tablet")
    await stub_provisioning.drain()
    assert second["outcome"] == "device_added"
    assert second["owner_customer_id"] == owner_id

    shared = (await db.execute(select(Customer).where(Customer.mac_address == PHONE_2))).scalar_one()
    owner = await db.get(Customer, owner_id)
    assert shared.subscription_owner_id == owner_id
    assert shared.expiry == owner.expiry


async def test_code_at_device_limit_refuses_and_lists_devices(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    await _voucher(db, reseller, plan, router)
    await _redeem(db, router, "48392910", OWNER_MAC)
    await _redeem(db, router, "48392910", PHONE_2)
    await stub_provisioning.drain()

    with pytest.raises(HTTPException) as exc:
        await _redeem(db, router, "48392910", PHONE_3)
    assert exc.value.status_code == 409
    detail = exc.value.detail
    assert detail["error"] == "device_limit_reached"
    assert detail["max_devices"] == 2
    assert [d["device_mac"] for d in detail["devices"]] == [OWNER_MAC, PHONE_2]
    assert detail["devices"][0]["is_main_device"] is True

    # Nobody was kicked to make room.
    pairing = (await db.execute(select(DevicePairing).where(DevicePairing.device_mac == PHONE_2))).scalar_one()
    assert pairing.is_active is True
    assert (await db.execute(select(Customer).where(Customer.mac_address == PHONE_3))).scalar_one_or_none() is None


async def test_reentering_code_on_a_connected_device_uses_no_slot(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    await _voucher(db, reseller, plan, router)
    await _redeem(db, router, "48392910", OWNER_MAC)
    await _redeem(db, router, "48392910", PHONE_2)
    await stub_provisioning.drain()

    again_main = await _redeem(db, router, "48392910", OWNER_MAC)
    again_shared = await _redeem(db, router, "48392910", PHONE_2)
    await stub_provisioning.drain()

    assert again_main["outcome"] == "main_device"
    assert again_shared["outcome"] == "device_added"
    pairings = (await db.execute(select(DevicePairing))).scalars().all()
    assert len(pairings) == 1


async def test_single_device_plan_moves_to_the_new_device(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=1)
    await _voucher(db, reseller, plan, router)
    first = await _redeem(db, router, "48392910", OWNER_MAC)
    await stub_provisioning.drain()

    moved = await _redeem(db, router, "48392910", PHONE_2)
    assert moved["outcome"] == "main_device"
    assert moved["mac_changed"] is True
    owner = await db.get(Customer, first["customer_id"])
    await db.refresh(owner)
    assert owner.mac_address == PHONE_2
    assert (await db.execute(select(DevicePairing))).scalars().all() == []


async def test_access_code_from_payment_status_needs_the_paying_device(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=3)
    owner = await _active_owner(db, reseller, plan, router)

    no_mac = await payment_routes.get_payment_status(owner.id, BackgroundTasks(), None, db)
    wrong_mac = await payment_routes.get_payment_status(owner.id, BackgroundTasks(), PHONE_2, db)
    assert no_mac["access_code"] is None
    assert wrong_mac["access_code"] is None

    status = await payment_routes.get_payment_status(owner.id, BackgroundTasks(), OWNER_MAC.lower(), db)
    assert status["max_devices"] == 3
    code = status["access_code"]
    assert code and len(code.replace("-", "")) == 6

    again = await payment_routes.get_payment_status(owner.id, BackgroundTasks(), OWNER_MAC, db)
    assert again["access_code"] == code

    added = await _redeem(db, router, code.lower(), PHONE_2)
    await stub_provisioning.drain()
    assert added["outcome"] == "device_added"
    assert added["owner_customer_id"] == owner.id


async def test_single_device_plan_gets_no_access_code(db):
    reseller, plan, router = await _setup(db, max_shared_users=1)
    owner = await _active_owner(db, reseller, plan, router)
    status = await payment_routes.get_payment_status(owner.id, BackgroundTasks(), OWNER_MAC, db)
    assert status["access_code"] is None


async def test_mpesa_receipt_works_as_a_code(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    owner = await _active_owner(db, reseller, plan, router)
    db.add(MpesaTransaction(
        checkout_request_id="ws_CO_1",
        phone_number=owner.phone,
        amount=plan.price,
        reference="ref",
        customer_id=owner.id,
        status=MpesaTransactionStatus.completed,
        mpesa_receipt_number="SIG7X2ABCD",
    ))
    await db.commit()

    added = await _redeem(db, router, "sig7x2abcd", PHONE_2)
    await stub_provisioning.drain()
    assert added["outcome"] == "device_added"
    assert added["owner_customer_id"] == owner.id

    # The receipt proves ownership, but the code to hand out is the access code.
    listing = await access_code_routes.list_access_code_devices(
        AccessCodeDevicesRequest(code="SIG7X2ABCD", router_id=router.id), db
    )
    assert listing["share_code"] != "SIG7X2ABCD"
    assert len(listing["share_code"].replace("-", "")) == 6


async def test_pending_receipt_is_not_a_code(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    owner = await _active_owner(db, reseller, plan, router)
    db.add(MpesaTransaction(
        checkout_request_id="ws_CO_2",
        phone_number=owner.phone,
        amount=plan.price,
        reference="ref",
        customer_id=owner.id,
        status=MpesaTransactionStatus.failed,
        mpesa_receipt_number="SIG7X2WXYZ",
    ))
    await db.commit()
    with pytest.raises(HTTPException) as exc:
        await _redeem(db, router, "SIG7X2WXYZ", PHONE_2)
    assert exc.value.status_code == 404


async def test_expired_plan_code_is_refused(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    owner = await _active_owner(db, reseller, plan, router)
    code = (await device_pairing.get_or_create_access_code(db, owner)).code
    owner.expiry = datetime.utcnow() - timedelta(minutes=1)
    await db.commit()

    with pytest.raises(HTTPException) as exc:
        await _redeem(db, router, code, PHONE_2)
    assert exc.value.status_code == 410


async def test_code_from_another_router_is_refused(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    other_router = await make_router(db, reseller)
    await _voucher(db, reseller, plan, router)
    await _redeem(db, router, "48392910", OWNER_MAC)
    await stub_provisioning.drain()

    with pytest.raises(HTTPException) as exc:
        await _redeem(db, other_router, "48392910", PHONE_2)
    assert exc.value.status_code == 400


async def test_wrong_codes_are_throttled(db):
    reseller, plan, router = await _setup(db)
    for _ in range(MAX_FAILURES_PER_DEVICE):
        with pytest.raises(HTTPException) as exc:
            await _redeem(db, router, "NOPE99", PHONE_2)
        assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await _redeem(db, router, "NOPE99", PHONE_2)
    assert exc.value.status_code == 429


async def test_placeholder_mac_is_refused(db, stub_provisioning):
    reseller, plan, router = await _setup(db)
    voucher = await _voucher(db, reseller, plan, router)
    with pytest.raises(HTTPException) as exc:
        await _redeem(db, router, "48392910", "AA:BB:CC:DD:EE:FF")
    assert exc.value.status_code == 400
    await db.refresh(voucher)
    assert voucher.status == VoucherStatus.AVAILABLE


async def test_remove_a_device_then_connect_another(db, stub_provisioning, monkeypatch):
    monkeypatch.setattr(
        device_pairing,
        "_remove_shared_device_from_direct_router_sync",
        lambda router_info, mac: {"success": True},
    )
    reseller, plan, router = await _setup(db, max_shared_users=2)
    await _voucher(db, reseller, plan, router)
    await _redeem(db, router, "48392910", OWNER_MAC)
    await _redeem(db, router, "48392910", PHONE_2)
    await stub_provisioning.drain()

    listing = await access_code_routes.list_access_code_devices(
        AccessCodeDevicesRequest(code="48392910", router_id=router.id, mac_address=PHONE_3), db
    )
    assert listing["share_code"] == "48392910"
    assert listing["available_devices"] == 0
    shared = next(d for d in listing["devices"] if not d["is_main_device"])

    removed = await access_code_routes.disconnect_access_code_device(
        AccessCodeDisconnectRequest(code="48392910", router_id=router.id, pairing_id=shared["pairing_id"]),
        db,
    )
    assert removed["cleanup_status"] == "removed"

    added = await _redeem(db, router, "48392910", PHONE_3)
    await stub_provisioning.drain()
    assert added["outcome"] == "device_added"


async def test_replacing_the_main_device(db, stub_provisioning, monkeypatch):
    cleaned = []
    monkeypatch.setattr(
        device_pairing,
        "_remove_shared_device_from_direct_router_sync",
        lambda router_info, mac: cleaned.append(mac) or {"success": True},
    )
    reseller, plan, router = await _setup(db, max_shared_users=2)
    await _voucher(db, reseller, plan, router)
    first = await _redeem(db, router, "48392910", OWNER_MAC)
    await _redeem(db, router, "48392910", PHONE_2)
    await stub_provisioning.drain()

    # The owner's phone came back with a new random MAC: every slot is taken.
    with pytest.raises(HTTPException):
        await _redeem(db, router, "48392910", PHONE_3)

    await access_code_routes.disconnect_access_code_device(
        AccessCodeDisconnectRequest(code="48392910", router_id=router.id, main_device=True),
        db,
    )
    assert cleaned == [OWNER_MAC]

    result = await _redeem(db, router, "48392910", PHONE_3)
    assert result["outcome"] == "main_device"
    owner = await db.get(Customer, first["customer_id"])
    await db.refresh(owner)
    assert owner.mac_address == PHONE_3


async def test_managing_devices_needs_a_valid_code(db):
    reseller, plan, router = await _setup(db)
    await _active_owner(db, reseller, plan, router)
    await _voucher(db, reseller, plan, router)  # never redeemed

    for code in ("", "WRONG1", "48392910"):
        with pytest.raises(HTTPException) as exc:
            await access_code_routes.list_access_code_devices(
                AccessCodeDevicesRequest(code=code, router_id=router.id), db
            )
        assert exc.value.status_code == 401


async def test_phone_reconnect_never_takes_over_a_shared_device(db, stub_provisioning, monkeypatch):
    async def cleanup_ok(*_args, **_kwargs):
        return {"success": True}

    monkeypatch.setattr(public_routes, "_cleanup_old_mac_with_retry", cleanup_ok)
    reseller, plan, router = await _setup(db, max_shared_users=2)
    owner = await _active_owner(db, reseller, plan, router)
    shared = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=owner.expiry + timedelta(seconds=1),  # would sort first before the fix
        mac_address=PHONE_2,
        phone=owner.phone,
        subscription_owner_id=owner.id,
    )

    result = await public_routes.reconnect_self_service(
        public_routes.ReconnectRequest(phone="0700000900", mac_address=PHONE_3, router_id=router.id),
        BackgroundTasks(),
        db,
    )
    assert result["success"] is True
    await db.refresh(owner)
    await db.refresh(shared)
    assert owner.mac_address == PHONE_3
    assert shared.mac_address == PHONE_2


async def test_voucher_reconnect_adds_device_instead_of_moving_plan(db, stub_provisioning):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    await _voucher(db, reseller, plan, router)
    first = await _redeem(db, router, "48392910", OWNER_MAC)
    await stub_provisioning.drain()

    result = await public_routes.reconnect_self_service(
        public_routes.ReconnectRequest(voucher_code="48392910", mac_address=PHONE_2, router_id=router.id),
        BackgroundTasks(),
        db,
    )
    await stub_provisioning.drain()
    assert result["outcome"] == "device_added"
    owner = await db.get(Customer, first["customer_id"])
    await db.refresh(owner)
    assert owner.mac_address == OWNER_MAC


async def _shared_device(db, reseller, plan, router, owner, mac, created_at):
    shared = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=owner.expiry,
        mac_address=mac,
        phone=owner.phone,
        subscription_owner_id=owner.id,
    )
    pairing = DevicePairing(
        customer_id=shared.id,
        device_mac=mac,
        device_type=DeviceType.OTHER,
        router_id=router.id,
        plan_id=plan.id,
        subscription_owner_customer_id=owner.id,
        is_subscription_share=True,
        is_active=True,
        expires_at=owner.expiry,
        created_at=created_at,
    )
    db.add(pairing)
    await db.commit()
    return shared, pairing


async def test_renewal_onto_smaller_plan_keeps_only_newest_devices(db):
    reseller, big_plan, router = await _setup(db, max_shared_users=3)
    small_plan = await make_plan(db, reseller, max_shared_users=2)
    owner = await _active_owner(db, reseller, big_plan, router)
    now = datetime.utcnow()
    old_shared, old_pairing = await _shared_device(db, reseller, big_plan, router, owner, PHONE_2, now - timedelta(hours=2))
    new_shared, new_pairing = await _shared_device(db, reseller, big_plan, router, owner, PHONE_3, now - timedelta(hours=1))

    owner.plan_id = small_plan.id
    await db.commit()
    await record_customer_payment(
        db=db,
        customer_id=owner.id,
        reseller_id=reseller.id,
        amount=float(small_plan.price),
        payment_method=PaymentMethod.CASH,
        days_paid_for=small_plan.duration_value,
        payment_reference="downgrade",
        duration_value=small_plan.duration_value,
        duration_unit=small_plan.duration_unit.value,
    )

    await db.refresh(old_pairing)
    await db.refresh(new_pairing)
    await db.refresh(old_shared)
    assert new_pairing.is_active is True
    assert old_pairing.is_active is False
    assert old_shared.subscription_owner_id is None


async def test_shared_device_buying_its_own_plan_is_detached(db):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    owner = await _active_owner(db, reseller, plan, router)
    shared, pairing = await _shared_device(db, reseller, plan, router, owner, PHONE_2, datetime.utcnow())

    await record_customer_payment(
        db=db,
        customer_id=shared.id,
        reseller_id=reseller.id,
        amount=float(plan.price),
        payment_method=PaymentMethod.CASH,
        days_paid_for=plan.duration_value,
        payment_reference="own-plan",
        duration_value=plan.duration_value,
        duration_unit=plan.duration_unit.value,
    )
    await db.refresh(shared)
    await db.refresh(pairing)
    own_expiry = shared.expiry
    assert shared.subscription_owner_id is None
    assert pairing.is_active is False

    # The former owner renewing must not touch it any more.
    await record_customer_payment(
        db=db,
        customer_id=owner.id,
        reseller_id=reseller.id,
        amount=float(plan.price),
        payment_method=PaymentMethod.CASH,
        days_paid_for=1,
        payment_reference="owner-renewal",
        duration_value=1,
        duration_unit=plan.duration_unit.value,
    )
    await db.refresh(shared)
    assert shared.expiry == own_expiry


async def test_unpair_requires_matching_phone_and_skips_shared_devices(db):
    reseller, plan, router = await _setup(db, max_shared_users=2)
    owner = await _active_owner(db, reseller, plan, router)
    _shared, shared_pairing = await _shared_device(db, reseller, plan, router, owner, PHONE_2, datetime.utcnow())

    with pytest.raises(HTTPException) as exc:
        await device_pairing.unpair_device(shared_pairing.id, db=db)
    assert exc.value.status_code == 400

    with pytest.raises(HTTPException) as exc:
        await device_pairing.unpair_device(shared_pairing.id, router_id=router.id, owner_phone="0799999999", db=db)
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await device_pairing.unpair_device(shared_pairing.id, router_id=router.id, owner_phone=owner.phone, db=db)
    assert exc.value.status_code == 400
    await db.refresh(shared_pairing)
    assert shared_pairing.is_active is True


async def test_failures_without_a_device_do_not_share_a_bucket(db):
    from app.services import code_attempt_limiter as limiter

    for _ in range(MAX_FAILURES_PER_DEVICE + 2):
        limiter.record_code_failure(1, None)
    limiter.check_code_attempts(1, None)
    limiter.check_code_attempts(1, PHONE_2)

    for _ in range(limiter.MAX_FAILURES_PER_ROUTER):
        limiter.record_code_failure(1, None)
    with pytest.raises(HTTPException) as exc:
        limiter.check_code_attempts(1, PHONE_2)
    assert exc.value.status_code == 429
    limiter.check_code_attempts(2, PHONE_2)


async def test_legacy_voucher_endpoints_are_throttled(db):
    reseller, plan, router = await _setup(db)

    for _ in range(MAX_FAILURES_PER_DEVICE):
        with pytest.raises(HTTPException) as exc:
            await public_routes.redeem_voucher_public(
                {"code": "11112222", "mac_address": PHONE_2, "router_id": router.id}, db
            )
        assert exc.value.status_code == 400
    with pytest.raises(HTTPException) as exc:
        await public_routes.redeem_voucher_public(
            {"code": "11112222", "mac_address": PHONE_2, "router_id": router.id}, db
        )
    assert exc.value.status_code == 429

    for _ in range(MAX_FAILURES_PER_DEVICE):
        with pytest.raises(HTTPException) as exc:
            await device_pairing.pair_device_with_voucher(
                device_pairing.DevicePairVoucherRequest(
                    device_mac=PHONE_3, voucher_code="11112222", router_id=router.id
                ),
                db,
            )
        assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc:
        await device_pairing.pair_device_with_voucher(
            device_pairing.DevicePairVoucherRequest(
                device_mac=PHONE_3, voucher_code="11112222", router_id=router.id
            ),
            db,
        )
    assert exc.value.status_code == 429


async def test_legacy_voucher_verify_is_throttled(db):
    from app.services import code_attempt_limiter as limiter

    for _ in range(limiter.MAX_FAILURES_PER_ROUTER):
        with pytest.raises(HTTPException) as exc:
            await public_routes.verify_voucher_public("11112222", 0, db)
        assert exc.value.status_code == 400
    with pytest.raises(HTTPException) as exc:
        await public_routes.verify_voucher_public("11112222", 0, db)
    assert exc.value.status_code == 429


async def test_legacy_voucher_redeem_still_works(db, stub_provisioning):
    reseller, plan, router = await _setup(db)
    await _voucher(db, reseller, plan, router)
    result = await public_routes.redeem_voucher_public(
        {"code": "48392910", "mac_address": OWNER_MAC, "router_id": router.id}, db
    )
    await stub_provisioning.drain()
    assert result["success"] is True
