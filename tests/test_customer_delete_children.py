"""Deleting a customer must clear every row that would block it.

2026-10-10: a reseller could not delete a customer because
``customer_usage_buckets`` (added 2026-09-26) still referenced it and
``delete_customer`` did not know about the new table. The guard below fails
the build for the next table that is added the same way.
"""

import inspect
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select, text

from app.api import customer_routes
from app.api import device_pairing
from app.db.models import (
    Base,
    Customer,
    CustomerPayment,
    CustomerStatus,
    CustomerUsageBucket,
    DevicePairing,
    DeviceType,
    PaymentMethod,
    SmsMessage,
    SmsMessageKind,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


def _blocking_customer_fks():
    """(model class name, column) for every FK to customers.id with no ON DELETE."""
    classes = {m.local_table.name: m.class_.__name__ for m in Base.registry.mappers}
    out = []
    for table in Base.metadata.sorted_tables:
        for fk in table.foreign_keys:
            if fk.column.table.name == "customers" and fk.ondelete is None:
                out.append((classes.get(table.name, table.name), fk.parent.name))
    return out


def test_delete_customer_handles_every_blocking_foreign_key():
    src = inspect.getsource(customer_routes._delete_customer_row)
    missing = [
        f"{model}.{column}" for model, column in _blocking_customer_fks()
        if f"{model}.{column} == customer_id" not in src
    ]
    assert not missing, (
        "delete_customer does not delete or NULL these rows, so deleting a "
        f"customer that has one fails with a foreign-key error: {missing}"
    )


@pytest.mark.asyncio
async def test_delete_customer_clears_usage_buckets_and_keeps_sms_history(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router, expiry=datetime.utcnow() + timedelta(days=1),
        mac_address="62:39:3A:F0:4D:5F",
    )
    db.add(CustomerUsageBucket(
        customer_id=customer.id, router_id=router.id,
        bucket_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0),
        upload_bytes=10, download_bytes=20,
    ))
    sms = SmsMessage(
        user_id=reseller.id, customer_id=customer.id, recipient_phone="254712345678",
        body="hello", segments=1, credits_charged=1, kind=list(SmsMessageKind)[0],
    )
    db.add(sms)
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_check (customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_reply (customer_id INTEGER)"))
    await db.commit()

    response = await customer_routes.delete_customer(
        customer.id, db, {"user_id": reseller.id, "role": reseller.role.value})

    assert response["success"] is True
    assert (await db.execute(select(Customer).where(Customer.id == customer.id))).scalar_one_or_none() is None
    buckets = await db.execute(
        select(func.count()).select_from(CustomerUsageBucket).where(CustomerUsageBucket.customer_id == customer.id))
    assert buckets.scalar_one() == 0
    kept = (await db.execute(select(SmsMessage).where(SmsMessage.id == sms.id))).scalar_one()
    assert kept.customer_id is None


async def _group(db, *, n_shared=2, router_overrides=None):
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_check (customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_reply (customer_id INTEGER)"))
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=n_shared + 1)
    router = await make_router(db, reseller, **(router_overrides or {}))
    expiry = datetime.utcnow() + timedelta(days=5)
    owner = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=expiry,
        mac_address="02:AA:00:00:01:00",
    )
    shared = []
    for index in range(n_shared):
        device = await make_customer(
            db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=expiry,
            mac_address=f"02:AA:00:00:01:{index + 1:02X}", subscription_owner_id=owner.id,
        )
        db.add(DevicePairing(
            customer_id=device.id, device_mac=device.mac_address, device_type=DeviceType.OTHER,
            router_id=router.id, plan_id=plan.id, subscription_owner_customer_id=owner.id,
            is_subscription_share=True, is_active=True, expires_at=expiry,
        ))
        shared.append(device)
    await db.commit()
    return reseller, plan, router, owner, shared


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def _customer_ids(db):
    return set((await db.execute(select(Customer.id))).scalars().all())


@pytest.fixture
def router_removals(monkeypatch):
    calls = []

    def fake_remove(router_info, mac):
        calls.append((router_info["port"], mac))
        return {"success": True}

    monkeypatch.setattr(device_pairing, "_remove_shared_device_from_direct_router_sync", fake_remove)
    return calls


@pytest.mark.asyncio
async def test_deleting_an_owner_removes_its_shared_devices(db, router_removals):
    reseller, _plan, router, owner, shared = await _group(db)

    response = await customer_routes.delete_customer(owner.id, db, _token(reseller))

    assert response["success"] is True
    assert response["shared_devices_removed"] == 2
    assert response["shared_devices_router_pending"] == []
    assert await _customer_ids(db) == set()
    pairings = (await db.execute(select(func.count(DevicePairing.id)))).scalar_one()
    assert pairings == 0
    assert sorted(mac for _port, mac in router_removals) == sorted(d.mac_address for d in shared)
    assert {port for port, _mac in router_removals} == {router.port}


@pytest.mark.asyncio
async def test_deleting_an_owner_keeps_the_shared_devices_payment_history(db, router_removals):
    reseller, plan, router, owner, shared = await _group(db, n_shared=1)
    db.add(CustomerPayment(
        customer_id=shared[0].id, reseller_id=reseller.id, amount=100.0,
        payment_method=PaymentMethod.CASH, days_paid_for=1, plan_id=plan.id, router_id=router.id,
    ))
    await db.commit()

    await customer_routes.delete_customer(owner.id, db, _token(reseller))

    payment = (await db.execute(select(CustomerPayment))).scalar_one()
    assert payment.customer_id is None
    assert payment.amount == 100.0
    assert payment.customer_name == shared[0].name


@pytest.mark.asyncio
async def test_deleting_a_shared_device_leaves_its_owner_and_the_others(db, router_removals):
    reseller, _plan, _router, owner, shared = await _group(db)

    response = await customer_routes.delete_customer(shared[0].id, db, _token(reseller))

    assert response["shared_devices_removed"] == 0
    assert await _customer_ids(db) == {owner.id, shared[1].id}
    assert router_removals == []


@pytest.mark.asyncio
async def test_a_customer_with_no_shared_devices_deletes_as_before(db, router_removals):
    reseller, _plan, _router, owner, _shared = await _group(db, n_shared=0)

    response = await customer_routes.delete_customer(owner.id, db, _token(reseller))

    assert response["shared_devices_removed"] == 0
    assert await _customer_ids(db) == set()
    assert router_removals == []


@pytest.mark.asyncio
async def test_unreachable_router_still_deletes_and_reports_what_is_pending(db, monkeypatch):
    reseller, _plan, _router, owner, shared = await _group(db, n_shared=3)
    attempts = []

    def dead_router(_router_info, mac):
        attempts.append(mac)
        return {"success": False, "error": "Failed to connect to router"}

    monkeypatch.setattr(device_pairing, "_remove_shared_device_from_direct_router_sync", dead_router)

    response = await customer_routes.delete_customer(owner.id, db, _token(reseller))

    assert response["shared_devices_removed"] == 3
    assert sorted(response["shared_devices_router_pending"]) == sorted(d.mac_address for d in shared)
    assert await _customer_ids(db) == set()
    assert len(attempts) == 1  # a dead router is tried once, not once per device


@pytest.mark.asyncio
async def test_another_resellers_customer_is_not_deleted_and_nothing_is_removed(db, router_removals):
    _reseller, _plan, _router, owner, _shared = await _group(db)
    stranger = await make_reseller(db)

    with pytest.raises(HTTPException) as refused:
        await customer_routes.delete_customer(owner.id, db, _token(stranger))

    assert refused.value.status_code == 404
    assert len(await _customer_ids(db)) == 3
    assert router_removals == []


@pytest.mark.asyncio
async def test_owner_that_fails_to_delete_keeps_its_shared_devices(db, router_removals, monkeypatch):
    reseller, _plan, _router, owner, _shared = await _group(db)
    real = customer_routes._delete_customer_row

    async def fail_for_owner(customer_id, session, user):
        if customer_id == owner.id:
            raise HTTPException(status_code=502, detail="router said no")
        return await real(customer_id, session, user)

    monkeypatch.setattr(customer_routes, "_delete_customer_row", fail_for_owner)

    with pytest.raises(HTTPException):
        await customer_routes.delete_customer(owner.id, db, _token(reseller))

    assert len(await _customer_ids(db)) == 3
    assert router_removals == []
