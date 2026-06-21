from datetime import datetime, timedelta
import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import device_pairing
from app.api.device_pairing import (
    ShareSubscriptionCodeCreateRequest,
    ShareSubscriptionCodeRedeemRequest,
    ShareSubscriptionRequest,
)
from app.db.models import (
    Customer,
    CustomerStatus,
    CustomerUsagePeriod,
    DevicePairing,
    DeviceType,
    PaymentMethod,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    SubscriptionShareCode,
)
from app.services.reseller_payments import record_customer_payment
from tests.factories import make_customer, make_plan, make_reseller, make_router


def _enum_value(value):
    return value.value if hasattr(value, "value") else value


@pytest.mark.asyncio
async def test_share_subscription_creates_shared_customer_and_direct_attempt_with_phone_variant(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=3)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=2),
        mac_address="AA:BB:CC:DD:EE:01",
        phone="254700000001",
    )

    provision_calls = []
    tasks = []

    async def fake_log(*_args, **_kwargs):
        return None

    async def fake_provision(*args, **kwargs):
        provision_calls.append((args, kwargs))
        return {"success": True}

    def fake_create_task(coro):
        task = asyncio.get_running_loop().create_task(coro)
        tasks.append(task)
        return task

    monkeypatch.setattr(device_pairing, "log_provisioning_event", fake_log)
    monkeypatch.setattr(device_pairing, "provision_hotspot_customer", fake_provision)
    monkeypatch.setattr(device_pairing.asyncio, "create_task", fake_create_task)

    response = await device_pairing.share_subscription_with_device(
        ShareSubscriptionRequest(
            owner_phone="0700000001",
            owner_mac=owner.mac_address,
            router_id=router.id,
            device_mac="AA:BB:CC:DD:EE:02",
            device_name="Living Room TV",
            device_type="tv",
        ),
        db,
    )
    if tasks:
        await asyncio.gather(*tasks)

    assert response["success"] is True
    assert response["owner_customer_id"] == owner.id
    assert response["max_shared_users"] == 3
    assert response["active_shared_devices"] == 1
    assert response["auth_method"] == "DIRECT_API"

    shared_customer = (
        await db.execute(
            select(Customer).where(Customer.mac_address == "AA:BB:CC:DD:EE:02")
        )
    ).scalar_one()
    assert shared_customer.subscription_owner_id == owner.id
    assert shared_customer.status == CustomerStatus.ACTIVE
    assert shared_customer.expiry == owner.expiry
    assert shared_customer.plan_id == plan.id
    assert shared_customer.phone == "0700000001"

    pairing = (
        await db.execute(
            select(DevicePairing).where(DevicePairing.device_mac == shared_customer.mac_address)
        )
    ).scalar_one()
    assert pairing.is_subscription_share is True
    assert pairing.subscription_owner_customer_id == owner.id
    assert pairing.expires_at == owner.expiry

    attempt = (
        await db.execute(
            select(ProvisioningAttempt).where(ProvisioningAttempt.customer_id == shared_customer.id)
        )
    ).scalar_one()
    assert _enum_value(attempt.source_table) == ProvisioningAttemptSource.SUBSCRIPTION_SHARE.value
    assert _enum_value(attempt.entrypoint) == ProvisioningAttemptEntrypoint.SUBSCRIPTION_SHARE.value
    assert attempt.source_pk == pairing.id
    assert provision_calls


@pytest.mark.asyncio
async def test_share_subscription_allows_second_shared_device_without_owner_mac(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=2)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=2),
        mac_address="AA:BB:CC:DD:EE:A1",
        phone="254700000101",
    )

    tasks = []

    async def fake_log(*_args, **_kwargs):
        return None

    async def fake_provision(*_args, **_kwargs):
        return {"success": True}

    def fake_create_task(coro):
        task = asyncio.get_running_loop().create_task(coro)
        tasks.append(task)
        return task

    monkeypatch.setattr(device_pairing, "log_provisioning_event", fake_log)
    monkeypatch.setattr(device_pairing, "provision_hotspot_customer", fake_provision)
    monkeypatch.setattr(device_pairing.asyncio, "create_task", fake_create_task)

    first = await device_pairing.share_subscription_with_device(
        ShareSubscriptionRequest(
            owner_phone="0700000101",
            router_id=router.id,
            device_mac="AA:BB:CC:DD:EE:A2",
            device_name="Tablet",
            device_type="other",
        ),
        db,
    )
    second = await device_pairing.share_subscription_with_device(
        ShareSubscriptionRequest(
            owner_phone="0700000101",
            router_id=router.id,
            device_mac="AA:BB:CC:DD:EE:A3",
            device_name="Laptop",
            device_type="laptop",
        ),
        db,
    )
    if tasks:
        await asyncio.gather(*tasks)

    assert first["owner_customer_id"] == owner.id
    assert first["active_shared_devices"] == 1
    assert second["owner_customer_id"] == owner.id
    assert second["max_shared_users"] == 2
    assert second["active_shared_devices"] == 2
    assert second["delivery"]["delivery_status"] == "activating"

    pairings = (
        await db.execute(
            select(DevicePairing).where(
                DevicePairing.subscription_owner_customer_id == owner.id,
                DevicePairing.is_subscription_share == True,  # noqa: E712
                DevicePairing.is_active == True,  # noqa: E712
            )
        )
    ).scalars().all()
    assert {p.device_mac for p in pairings} == {
        "AA:BB:CC:DD:EE:A2",
        "AA:BB:CC:DD:EE:A3",
    }


@pytest.mark.asyncio
async def test_share_code_redeems_detected_device_and_marks_code_used(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=2)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=2),
        mac_address="AA:BB:CC:DD:EE:D1",
        phone="254700000401",
    )

    tasks = []

    async def fake_log(*_args, **_kwargs):
        return None

    async def fake_provision(*_args, **_kwargs):
        return {"success": True}

    def fake_create_task(coro):
        task = asyncio.get_running_loop().create_task(coro)
        tasks.append(task)
        return task

    monkeypatch.setattr(device_pairing, "log_provisioning_event", fake_log)
    monkeypatch.setattr(device_pairing, "provision_hotspot_customer", fake_provision)
    monkeypatch.setattr(device_pairing.asyncio, "create_task", fake_create_task)

    code_response = await device_pairing.create_share_subscription_code(
        ShareSubscriptionCodeCreateRequest(
            owner_phone="0700000401",
            router_id=router.id,
        ),
        db,
    )

    assert code_response["success"] is True
    assert len(code_response["raw_code"]) == 6
    assert code_response["available_shared_devices"] == 2
    second_code_response = await device_pairing.create_share_subscription_code(
        ShareSubscriptionCodeCreateRequest(
            owner_phone="0700000401",
            router_id=router.id,
        ),
        db,
    )
    assert second_code_response["raw_code"] == code_response["raw_code"]

    response = await device_pairing.redeem_share_subscription_code(
        ShareSubscriptionCodeRedeemRequest(
            code=code_response["code"].lower(),
            router_id=router.id,
            device_mac="AA:BB:CC:DD:EE:D2",
            device_name="Friend phone",
            device_type="laptop",
        ),
        db,
    )
    if tasks:
        await asyncio.gather(*tasks)

    assert response["success"] is True
    assert response["owner_customer_id"] == owner.id
    assert response["device_mac"] == "AA:BB:CC:DD:EE:D2"
    assert response["active_shared_devices"] == 1

    share_code = (
        await db.execute(
            select(SubscriptionShareCode).where(SubscriptionShareCode.code == code_response["raw_code"])
        )
    ).scalar_one()
    assert share_code.status == "redeemed"
    assert share_code.redeemed_customer_id == response["customer_id"]
    assert share_code.redeemed_pairing_id == response["pairing_id"]
    assert share_code.redeemed_at is not None

    with pytest.raises(HTTPException) as exc:
        await device_pairing.redeem_share_subscription_code(
            ShareSubscriptionCodeRedeemRequest(
                code=code_response["raw_code"],
                router_id=router.id,
                device_mac="AA:BB:CC:DD:EE:D3",
            ),
            db,
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_expired_share_code_cannot_be_redeemed(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=2)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=2),
        mac_address="AA:BB:CC:DD:EE:E1",
        phone="254700000501",
    )
    share_code = SubscriptionShareCode(
        code="ABC123",
        router_id=router.id,
        owner_customer_id=owner.id,
        status="active",
        expires_at=datetime.utcnow() - timedelta(minutes=1),
    )
    db.add(share_code)
    await db.commit()

    with pytest.raises(HTTPException) as exc:
        await device_pairing.redeem_share_subscription_code(
            ShareSubscriptionCodeRedeemRequest(
                code="ABC-123",
                router_id=router.id,
                device_mac="AA:BB:CC:DD:EE:E2",
            ),
            db,
        )

    assert exc.value.status_code == 400
    await db.refresh(share_code)
    assert share_code.status == "expired"


@pytest.mark.asyncio
async def test_share_subscription_without_owner_mac_prefers_shareable_owner(db, monkeypatch):
    reseller = await make_reseller(db)
    private_plan = await make_plan(db, reseller, max_shared_users=1)
    share_plan = await make_plan(db, reseller, max_shared_users=3)
    router = await make_router(db, reseller)
    phone = "254700000201"
    await make_customer(
        db,
        reseller,
        private_plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=5),
        mac_address="AA:BB:CC:DD:EE:B1",
        phone=phone,
    )
    share_owner = await make_customer(
        db,
        reseller,
        share_plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1),
        mac_address="AA:BB:CC:DD:EE:B2",
        phone=phone,
    )

    async def fake_log(*_args, **_kwargs):
        return None

    async def fake_provision(*_args, **_kwargs):
        return {"success": True}

    monkeypatch.setattr(device_pairing, "log_provisioning_event", fake_log)
    monkeypatch.setattr(device_pairing, "provision_hotspot_customer", fake_provision)
    monkeypatch.setattr(device_pairing.asyncio, "create_task", lambda coro: asyncio.get_running_loop().create_task(coro))

    response = await device_pairing.share_subscription_with_device(
        ShareSubscriptionRequest(
            owner_phone="0700000201",
            router_id=router.id,
            device_mac="AA:BB:CC:DD:EE:B3",
            device_name="Phone",
            device_type="other",
        ),
        db,
    )

    assert response["owner_customer_id"] == share_owner.id


@pytest.mark.asyncio
async def test_share_owner_status_lists_existing_shared_devices_by_phone_variant(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=2)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=2),
        mac_address="AA:BB:CC:DD:EE:C1",
        phone="254700000301",
    )
    shared = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=owner.expiry,
        mac_address="AA:BB:CC:DD:EE:C2",
        phone=owner.phone,
        subscription_owner_id=owner.id,
    )
    pairing = DevicePairing(
        customer_id=shared.id,
        device_mac=shared.mac_address,
        device_name="Kitchen TV",
        device_type=DeviceType.TV,
        router_id=router.id,
        plan_id=plan.id,
        subscription_owner_customer_id=owner.id,
        is_subscription_share=True,
        is_active=True,
        expires_at=shared.expiry,
    )
    db.add(pairing)
    await db.commit()

    response = await device_pairing.get_share_subscription_owner_status(
        router.id,
        "0700000301",
        db,
    )

    assert response["has_active_subscription"] is True
    assert response["sharing_enabled"] is True
    assert response["owner_customer_id"] == owner.id
    assert response["owner_device_mac"] == owner.mac_address
    assert response["max_shared_users"] == 2
    assert response["max_companion_devices"] == 2
    assert response["active_shared_devices"] == 1
    assert response["available_shared_devices"] == 1
    assert response["message"] == "Subscription can share another device."
    assert response["devices"][0]["device_mac"] == shared.mac_address
    assert response["devices"][0]["customer"]["id"] == shared.id


@pytest.mark.asyncio
async def test_share_owner_status_returns_no_active_subscription(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    response = await device_pairing.get_share_subscription_owner_status(
        router.id,
        "0700000401",
        db,
    )

    assert response["has_active_subscription"] is False
    assert response["sharing_enabled"] is False
    assert response["devices"] == []
    assert response["count"] == 0


@pytest.mark.asyncio
async def test_share_subscription_rejects_plan_with_no_sharing(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=1)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=2),
        mac_address="AA:BB:CC:DD:EE:11",
        phone="254700000011",
    )

    with pytest.raises(HTTPException) as exc:
        await device_pairing.share_subscription_with_device(
            ShareSubscriptionRequest(
                owner_phone=owner.phone,
                owner_mac=owner.mac_address,
                router_id=router.id,
                device_mac="AA:BB:CC:DD:EE:12",
            ),
            db,
        )

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_share_subscription_enforces_plan_device_limit(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=2)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=2),
        mac_address="AA:BB:CC:DD:EE:21",
        phone="254700000021",
    )
    first_shared = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=owner.expiry,
        mac_address="AA:BB:CC:DD:EE:22",
        phone=owner.phone,
        subscription_owner_id=owner.id,
    )
    second_shared = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=owner.expiry,
        mac_address="AA:BB:CC:DD:EE:23",
        phone=owner.phone,
        subscription_owner_id=owner.id,
    )
    db.add_all([
        DevicePairing(
            customer_id=first_shared.id,
            device_mac=first_shared.mac_address,
            device_name="TV",
            device_type=DeviceType.TV,
            router_id=router.id,
            plan_id=plan.id,
            subscription_owner_customer_id=owner.id,
            is_subscription_share=True,
            is_active=True,
            expires_at=owner.expiry,
        ),
        DevicePairing(
            customer_id=second_shared.id,
            device_mac=second_shared.mac_address,
            device_name="Laptop",
            device_type=DeviceType.LAPTOP,
            router_id=router.id,
            plan_id=plan.id,
            subscription_owner_customer_id=owner.id,
            is_subscription_share=True,
            is_active=True,
            expires_at=owner.expiry,
        ),
    ])
    await db.commit()

    with pytest.raises(HTTPException) as exc:
        await device_pairing.share_subscription_with_device(
            ShareSubscriptionRequest(
                owner_phone=owner.phone,
                owner_mac=owner.mac_address,
                router_id=router.id,
                device_mac="AA:BB:CC:DD:EE:24",
            ),
            db,
        )

    assert exc.value.status_code == 409
    assert "maximum 2 shared device" in exc.value.detail


@pytest.mark.asyncio
async def test_owner_renewal_extends_shared_devices_and_schedules_delivery(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=3, data_cap_mb=20)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1),
        mac_address="AA:BB:CC:DD:EE:31",
        phone="254700000031",
    )
    shared = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=owner.expiry,
        mac_address="AA:BB:CC:DD:EE:32",
        phone=owner.phone,
        subscription_owner_id=owner.id,
    )
    pairing = DevicePairing(
        customer_id=shared.id,
        device_mac=shared.mac_address,
        device_name="Console",
        device_type=DeviceType.CONSOLE,
        router_id=router.id,
        plan_id=plan.id,
        subscription_owner_customer_id=owner.id,
        is_subscription_share=True,
        is_active=True,
        expires_at=shared.expiry,
    )
    db.add(pairing)
    await db.commit()
    await db.refresh(pairing)

    await record_customer_payment(
        db=db,
        customer_id=owner.id,
        reseller_id=reseller.id,
        amount=float(plan.price),
        payment_method=PaymentMethod.CASH,
        days_paid_for=plan.duration_value,
        payment_reference="renewal-share-test",
        duration_value=plan.duration_value,
        duration_unit=plan.duration_unit.value,
    )

    await db.refresh(owner)
    await db.refresh(shared)
    await db.refresh(pairing)

    assert shared.status == CustomerStatus.ACTIVE
    assert shared.expiry == owner.expiry
    assert pairing.expires_at == owner.expiry
    shared_period = (
        await db.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == shared.id,
                CustomerUsagePeriod.closed_at.is_(None),
            )
        )
    ).scalar_one()
    assert shared_period.period_end == shared.expiry
    assert shared_period.cap_mb_snapshot == 20

    attempt = (
        await db.execute(
            select(ProvisioningAttempt).where(
                ProvisioningAttempt.source_table == ProvisioningAttemptSource.SUBSCRIPTION_SHARE,
                ProvisioningAttempt.source_pk == pairing.id,
            )
        )
    ).scalar_one()
    assert attempt.customer_id == shared.id
    assert _enum_value(attempt.entrypoint) == ProvisioningAttemptEntrypoint.SUBSCRIPTION_SHARE.value
