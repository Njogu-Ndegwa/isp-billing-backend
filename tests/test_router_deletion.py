from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select, text

from app.api import router_management
from app.db.models import (
    AccessCredential,
    BandwidthSnapshot,
    Customer,
    CustomerPayment,
    CustomerRating,
    CustomerStatus,
    DevicePairing,
    MpesaTransaction,
    MtnMomoTransaction,
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningLog,
    ProvisioningToken,
    ProvisioningTokenStatus,
    ReconnectionAttempt,
    Router,
    RouterAvailabilityCheck,
    RouterLogEntry,
    UserBandwidthUsage,
    Voucher,
    VoucherStatus,
    ZenoPayTransaction,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def _count(db, model) -> int:
    return await db.scalar(select(func.count()).select_from(model))


async def _fake_current_user(user):
    async def _inner(_token, _db):
        return user

    return _inner


class _FakeMikroTikAPI:
    removed = []

    def __init__(self, *_args, **_kwargs):
        self.connected = True

    def remove_hotspot_user(self, username):
        self.removed.append(("user", username))

    def remove_ip_binding(self, mac_address):
        self.removed.append(("binding", mac_address))

    def remove_simple_queue(self, mac_address):
        self.removed.append(("queue", mac_address))

    def disconnect(self):
        return None


async def test_delete_router_requires_force_when_customers_exist(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    await make_customer(db, reseller, plan, router, status=CustomerStatus.INACTIVE)

    monkeypatch.setattr(router_management, "get_current_user", await _fake_current_user(reseller))

    with pytest.raises(HTTPException) as exc:
        await router_management.delete_router(router.id, False, db, _token(reseller))

    assert exc.value.status_code == 400
    assert await _count(db, Router) == 1
    assert await _count(db, Customer) == 1


async def test_force_delete_router_preserves_customer_money_history_and_cleans_dependents(db, monkeypatch):
    await db.execute(text("PRAGMA foreign_keys=ON"))
    await db.execute(text("""
        CREATE TABLE radius_nas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nasname VARCHAR(128) NOT NULL,
            secret VARCHAR(60) NOT NULL,
            router_id INTEGER NOT NULL REFERENCES routers(id) ON DELETE RESTRICT
        )
    """))
    await db.commit()

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=3),
        mac_address="AA:BB:CC:00:00:01",
        phone="254700000001",
    )

    attempt = ProvisioningAttempt(
        customer_id=customer.id,
        router_id=router.id,
        mac_address=customer.mac_address,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
        source_pk=101,
        entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT,
    )
    db.add(attempt)
    await db.commit()
    await db.refresh(attempt)

    available_voucher = Voucher(
        code="12345670",
        plan_id=plan.id,
        router_id=router.id,
        user_id=reseller.id,
        status=VoucherStatus.AVAILABLE,
    )
    redeemed_voucher = Voucher(
        code="12345688",
        plan_id=plan.id,
        router_id=router.id,
        user_id=reseller.id,
        status=VoucherStatus.REDEEMED,
        redeemed_by=customer.id,
        redeemed_at=datetime.utcnow(),
    )

    db.add_all([
        attempt,
        ProvisioningLog(
            customer_id=customer.id,
            router_id=router.id,
            attempt_id=attempt.id,
            mac_address=customer.mac_address,
            action="provision",
            status="failed",
        ),
        BandwidthSnapshot(router_id=router.id, total_upload_bps=10, total_download_bps=20),
        ProvisioningToken(
            user_id=reseller.id,
            token="token-router-delete",
            router_name=router.name,
            identity="router-delete-test",
            vpn_type="wireguard",
            wireguard_ip="10.0.10.10",
            ssid="Test WiFi",
            router_admin_password="admin",
            server_public_ip="198.51.100.1",
            status=ProvisioningTokenStatus.PROVISIONED,
            router_id=router.id,
        ),
        available_voucher,
        redeemed_voucher,
        DevicePairing(
            customer_id=customer.id,
            device_mac="AA:BB:CC:00:00:02",
            router_id=router.id,
            plan_id=plan.id,
        ),
        ReconnectionAttempt(
            phone=customer.phone,
            mac_address=customer.mac_address,
            router_id=router.id,
            customer_id=customer.id,
        ),
        AccessCredential(
            user_id=reseller.id,
            router_id=router.id,
            username="guest",
            password="secret",
        ),
        RouterLogEntry(router_id=router.id, topic="hotspot", message="test log"),
        RouterAvailabilityCheck(router_id=router.id, is_online=True, source="test"),
        Payment(customer_id=customer.id, amount=100, days_paid_for=1),
        CustomerPayment(
            customer_id=customer.id,
            reseller_id=reseller.id,
            amount=100,
            payment_method=PaymentMethod.CASH,
            days_paid_for=1,
            status=PaymentStatus.COMPLETED,
            customer_name=customer.name,
        ),
        MpesaTransaction(
            checkout_request_id="checkout-router-delete",
            phone_number=customer.phone,
            amount=100,
            reference="router-delete",
            customer_id=customer.id,
        ),
        ZenoPayTransaction(
            order_id="zeno-router-delete",
            reseller_id=reseller.id,
            customer_id=customer.id,
            amount=100,
            buyer_phone=customer.phone,
        ),
        MtnMomoTransaction(
            reference_id="momo-router-delete",
            reseller_id=reseller.id,
            customer_id=customer.id,
            amount=100,
            currency="UGX",
            phone=customer.phone,
            target_environment="sandbox",
        ),
        CustomerRating(customer_id=customer.id, phone=customer.phone, rating=5),
        UserBandwidthUsage(customer_id=customer.id, mac_address=customer.mac_address),
    ])
    await db.execute(
        text("INSERT INTO radius_nas (nasname, secret, router_id) VALUES ('nas', 'secret', :router_id)"),
        {"router_id": router.id},
    )
    await db.commit()

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    import app.services.mikrotik_api as mikrotik_api

    _FakeMikroTikAPI.removed = []
    monkeypatch.setattr(mikrotik_api, "MikroTikAPI", _FakeMikroTikAPI)
    monkeypatch.setattr(router_management.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(router_management, "get_current_user", await _fake_current_user(reseller))

    response = await router_management.delete_router(router.id, True, db, _token(reseller))

    assert response["success"] is True
    assert response["customers_deactivated"] == 1
    assert response["mikrotik_cleaned"] == 1
    assert ("user", "AABBCC000001") in _FakeMikroTikAPI.removed

    assert await db.get(Router, router.id) is None

    await db.refresh(customer)
    assert customer.router_id is None
    assert customer.status == CustomerStatus.INACTIVE

    assert await _count(db, Customer) == 1
    assert await _count(db, Payment) == 1
    assert await _count(db, CustomerPayment) == 1
    assert await _count(db, MpesaTransaction) == 1
    assert await _count(db, ZenoPayTransaction) == 1
    assert await _count(db, MtnMomoTransaction) == 1
    assert await _count(db, CustomerRating) == 1
    assert await _count(db, UserBandwidthUsage) == 1

    preserved_log = (await db.execute(select(ProvisioningLog))).scalar_one()
    assert preserved_log.customer_id == customer.id
    assert preserved_log.router_id is None
    assert preserved_log.attempt_id is None

    available_after = await db.get(Voucher, available_voucher.id)
    redeemed_after = await db.get(Voucher, redeemed_voucher.id)
    assert available_after.router_id is None
    assert available_after.status == VoucherStatus.DISABLED
    assert redeemed_after.router_id is None
    assert redeemed_after.status == VoucherStatus.REDEEMED
    assert redeemed_after.redeemed_by == customer.id

    assert await _count(db, ProvisioningAttempt) == 0
    assert await _count(db, BandwidthSnapshot) == 0
    assert await _count(db, ProvisioningToken) == 0
    assert await _count(db, DevicePairing) == 0
    assert await _count(db, ReconnectionAttempt) == 0
    assert await _count(db, AccessCredential) == 0
    assert await _count(db, RouterLogEntry) == 0
    assert await _count(db, RouterAvailabilityCheck) == 0
    assert await db.scalar(text("SELECT COUNT(*) FROM radius_nas")) == 0
