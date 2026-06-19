from datetime import datetime, timedelta
import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import device_pairing
from app.api.device_pairing import ShareSubscriptionRequest
from app.db.models import (
    Customer,
    CustomerStatus,
    DevicePairing,
    DeviceType,
    PaymentMethod,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
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
    db.add(
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
        )
    )
    await db.commit()

    with pytest.raises(HTTPException) as exc:
        await device_pairing.share_subscription_with_device(
            ShareSubscriptionRequest(
                owner_phone=owner.phone,
                owner_mac=owner.mac_address,
                router_id=router.id,
                device_mac="AA:BB:CC:DD:EE:23",
            ),
            db,
        )

    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_owner_renewal_extends_shared_devices_and_schedules_delivery(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=3)
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
