from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from app.api import payment_method_routes as pm_routes
from app.api.fapshi_routes import get_fapshi_status, kick_pending_fapshi_check
from app.api.public_routes import get_portal_data
from app.api.router_management import get_router_by_identity
from app.api.payment_method_routes import router as payment_method_router
from app.db.database import get_db
from app.db.models import (
    CollectionMode,
    Customer,
    CustomerPayment,
    CustomerStatus,
    FapshiTransaction,
    FapshiTransactionStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    RouterAuthMethod,
)
from app.services.auth import verify_token
from app.services.payment_gateway import encrypt_credential, initiate_customer_payment
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def payment_method_app(session_factory):
    application = FastAPI()
    application.include_router(payment_method_router)

    async def _override_get_db():
        async with session_factory() as session:
            yield session

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "test-token"
    return application


@pytest_asyncio.fixture
async def payment_method_client(payment_method_app):
    async with AsyncClient(
        transport=ASGITransport(app=payment_method_app), base_url="http://test"
    ) as client:
        yield client


async def test_reseller_can_create_and_read_masked_fapshi_method(
    db, payment_method_client, monkeypatch
):
    reseller = await make_reseller(db)

    async def _current_user(token, session):
        return reseller

    monkeypatch.setattr(pm_routes, "get_current_user", _current_user)
    response = await payment_method_client.post(
        "/api/payment-methods",
        json={
            "method_type": "fapshi",
            "label": "Cameroon Mobile Money",
            "fapshi_api_user": "api-user-123",
            "fapshi_api_key": "super-secret-provider-key",
            "fapshi_environment": "live",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["method_type"] == "fapshi"
    assert body["fapshi_api_user"] == "api-user-123"
    assert body["fapshi_environment"] == "live"
    assert body["fapshi_api_key"].endswith("-key")
    assert "super-secret-provider-key" not in response.text

    stored = (
        await db.execute(
            select(ResellerPaymentMethod).where(
                ResellerPaymentMethod.id == body["id"]
            )
        )
    ).scalar_one()
    assert stored.fapshi_api_key_encrypted != "super-secret-provider-key"


async def test_fapshi_method_rejects_unknown_environment(
    db, payment_method_client, monkeypatch
):
    reseller = await make_reseller(db)

    async def _current_user(token, session):
        return reseller

    monkeypatch.setattr(pm_routes, "get_current_user", _current_user)
    response = await payment_method_client.post(
        "/api/payment-methods",
        json={
            "method_type": "fapshi",
            "label": "Bad environment",
            "fapshi_api_user": "user",
            "fapshi_api_key": "key",
            "fapshi_environment": "production",
        },
    )
    assert response.status_code == 400
    assert "sandbox" in response.json()["detail"]


async def test_router_assignment_dispatches_to_fapshi_and_persists_transaction(
    db, monkeypatch
):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=500)
    customer = await make_customer(
        db, reseller, plan, router, phone="+237 670 000 000"
    )
    method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.FAPSHI,
        label="Fapshi Live",
        is_active=True,
        fapshi_api_user="api-user",
        fapshi_api_key_encrypted=encrypt_credential("api-key"),
        fapshi_environment="live",
    )
    db.add(method)
    await db.commit()
    await db.refresh(method)

    from app.services import fapshi as fapshi_service

    direct_pay = AsyncMock(
        return_value={"message": "accepted", "transId": "FAPSHI-TX-1"}
    )
    monkeypatch.setattr(fapshi_service, "initiate_direct_payment", direct_pay)

    result = await initiate_customer_payment(
        db=db,
        payment_method=method,
        customer=customer,
        router=router,
        phone=customer.phone,
        amount=500,
        reference="HOTSPOT-1-TEST",
        plan_name=plan.name,
    )

    assert result["gateway"] == "fapshi"
    assert result["trans_id"] == "FAPSHI-TX-1"
    assert result["collection_mode"] == CollectionMode.DIRECT
    assert direct_pay.await_args.kwargs["phone"] == "670000000"
    assert direct_pay.await_args.kwargs["environment"] == "live"

    txn = (
        await db.execute(
            select(FapshiTransaction).where(
                FapshiTransaction.trans_id == "FAPSHI-TX-1"
            )
        )
    ).scalar_one()
    assert txn.customer_id == customer.id
    assert txn.payment_method_id == method.id
    assert txn.status == FapshiTransactionStatus.PENDING


async def test_captive_portal_contract_identifies_assigned_fapshi_gateway(db):
    reseller = await make_reseller(db)
    method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.FAPSHI,
        label="Fapshi",
        is_active=True,
        fapshi_api_user="user",
        fapshi_api_key_encrypted=encrypt_credential("key"),
        fapshi_environment="sandbox",
    )
    db.add(method)
    await db.flush()
    router = await make_router(
        db,
        reseller,
        identity="Cameroon-Router",
        payment_method_id=method.id,
    )
    await make_plan(db, reseller, price=500)

    payload = await get_portal_data(identity=router.identity, db=db)
    fallback_payload = await get_router_by_identity(identity=router.identity, db=db)

    assert payload["router"]["payment_provider"] == "fapshi"
    assert "mpesa" in payload["router"]["payment_methods"]
    assert fallback_payload["payment_provider"] == "fapshi"


async def test_status_poll_records_and_provisions_a_success_only_once(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=500)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        phone="670000000",
        mac_address="",  # keep this unit test away from RouterOS background I/O
        status=CustomerStatus.PENDING,
    )
    method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.FAPSHI,
        label="Fapshi Sandbox",
        is_active=True,
        fapshi_api_user="api-user",
        fapshi_api_key_encrypted=encrypt_credential("api-key"),
        fapshi_environment="sandbox",
    )
    db.add(method)
    await db.flush()
    txn = FapshiTransaction(
        trans_id="FAPSHI-SUCCESS-1",
        external_id="BW-external-1",
        reseller_id=reseller.id,
        customer_id=customer.id,
        payment_method_id=method.id,
        amount=500,
        phone="670000000",
        status=FapshiTransactionStatus.PENDING,
        environment="sandbox",
    )
    db.add(txn)
    await db.commit()

    from app.services import fapshi as fapshi_service

    remote_status = AsyncMock(return_value={
        "transId": "FAPSHI-SUCCESS-1",
        "externalId": "BW-external-1",
        "status": "SUCCESSFUL",
        "transType": "Collection",
        "amount": 500,
        "medium": "mobile money",
        "financialTransId": "MTN-CM-123",
        "dateConfirmed": "2026-08-31T10:00:00Z",
    })
    monkeypatch.setattr(fapshi_service, "get_payment_status", remote_status)

    first = await get_fapshi_status("FAPSHI-SUCCESS-1", db)
    second = await get_fapshi_status("FAPSHI-SUCCESS-1", db)

    assert first["status"] == "successful"
    assert second["status"] == "successful"
    assert first["customer_status"] == "active"
    assert remote_status.await_count == 1

    payment_count = (
        await db.execute(
            select(func.count(CustomerPayment.id)).where(
                CustomerPayment.customer_id == customer.id
            )
        )
    ).scalar_one()
    assert payment_count == 1

    payment = (
        await db.execute(
            select(CustomerPayment).where(CustomerPayment.customer_id == customer.id)
        )
    ).scalar_one()
    assert payment.collection_mode == CollectionMode.DIRECT
    assert payment.payment_reference == "FAPSHI-MTN-CM-123"

    refreshed_customer = await db.get(Customer, customer.id)
    assert refreshed_customer.status == CustomerStatus.ACTIVE
    assert refreshed_customer.expiry is not None


async def test_provider_agnostic_portal_poll_reconciles_fapshi(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, price=500)
    customer = await make_customer(
        db,
        reseller,
        plan,
        phone="670000002",
        mac_address="",
        status=CustomerStatus.PENDING,
    )
    method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.FAPSHI,
        label="Fapshi",
        is_active=True,
        fapshi_api_user="user",
        fapshi_api_key_encrypted=encrypt_credential("key"),
        fapshi_environment="sandbox",
    )
    db.add(method)
    await db.flush()
    db.add(FapshiTransaction(
        trans_id="PORTAL-POLL-1",
        external_id="BW-portal-poll",
        reseller_id=reseller.id,
        customer_id=customer.id,
        payment_method_id=method.id,
        amount=500,
        phone="670000002",
        status=FapshiTransactionStatus.PENDING,
        environment="sandbox",
        updated_at=datetime.utcnow() - timedelta(seconds=15),
    ))
    await db.commit()

    from app.services import fapshi as fapshi_service

    monkeypatch.setattr(fapshi_service, "get_payment_status", AsyncMock(return_value={
        "transId": "PORTAL-POLL-1",
        "externalId": "BW-portal-poll",
        "status": "SUCCESSFUL",
        "transType": "Collection",
        "amount": 500,
        "medium": "orange money",
        "financialTransId": "OM-CM-1",
    }))

    await kick_pending_fapshi_check(customer.id)

    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE
    assert (
        await db.execute(
            select(func.count(CustomerPayment.id)).where(
                CustomerPayment.customer_id == customer.id
            )
        )
    ).scalar_one() == 1


async def test_fapshi_success_provisions_radius_captive_portal_credentials(
    db, monkeypatch
):
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        auth_method=RouterAuthMethod.RADIUS,
    )
    plan = await make_plan(db, reseller, price=500)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        phone="654874452",
        mac_address="AA:BB:CC:DD:EE:99",
        status=CustomerStatus.PENDING,
    )
    method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.FAPSHI,
        label="Fapshi RADIUS",
        is_active=True,
        fapshi_api_user="user",
        fapshi_api_key_encrypted=encrypt_credential("key"),
        fapshi_environment="sandbox",
    )
    db.add(method)
    await db.flush()
    db.add(FapshiTransaction(
        trans_id="RADIUS-FAPSHI-1",
        external_id="BW-radius-fapshi",
        reseller_id=reseller.id,
        customer_id=customer.id,
        payment_method_id=method.id,
        amount=500,
        phone="654874452",
        status=FapshiTransactionStatus.PENDING,
        environment="sandbox",
    ))
    await db.commit()

    from app.services import fapshi as fapshi_service
    from app.services.radius_provisioning import RadiusProvisioning

    monkeypatch.setattr(fapshi_service, "get_payment_status", AsyncMock(return_value={
        "transId": "RADIUS-FAPSHI-1",
        "externalId": "BW-radius-fapshi",
        "status": "SUCCESSFUL",
        "transType": "Collection",
        "amount": 500,
        "medium": "mtn mobile money",
        "financialTransId": "RADIUS-CM-1",
    }))
    provision = AsyncMock(return_value={
        "success": True,
        "username": "AABBCCDDEE99",
        "password": "radius-secret",
        "expiry": "2026-09-01T10:00:00",
    })
    monkeypatch.setattr(RadiusProvisioning, "provision_hotspot_user", provision)

    response = await get_fapshi_status("RADIUS-FAPSHI-1", db)

    assert response["status"] == "successful"
    await db.refresh(customer)
    credentials = json.loads(customer.pending_update_data)
    assert credentials["auth_method"] == "RADIUS"
    assert credentials["radius_username"] == "AABBCCDDEE99"
    assert credentials["radius_password"] == "radius-secret"
    assert provision.await_args.kwargs["fixed_expiry"] == customer.expiry


async def test_fapshi_client_normalizes_cameroon_number_and_sends_no_medium(monkeypatch):
    from app.services import fapshi

    captured = {}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, *, headers, json):
            captured.update(url=url, headers=headers, json=json)
            request = httpx.Request("POST", url)
            return httpx.Response(
                200,
                request=request,
                json={"message": "accepted", "transId": "TX-1"},
            )

    monkeypatch.setattr(fapshi.httpx, "AsyncClient", FakeClient)
    result = await fapshi.initiate_direct_payment(
        api_user="user",
        api_key="key",
        environment="sandbox",
        amount=100,
        phone="+237 654-874-452",
        name="Test",
        user_id="customer-1",
        external_id="BW-1",
    )

    assert result["transId"] == "TX-1"
    assert captured["url"] == "https://sandbox.fapshi.com/direct-pay"
    assert captured["json"]["phone"] == "654874452"
    assert "medium" not in captured["json"]
    assert captured["headers"]["apiuser"] == "user"


@pytest.mark.parametrize("amount", [99, 100.5])
async def test_fapshi_client_rejects_invalid_xaf_amounts(amount):
    from app.services.fapshi import normalize_xaf_amount

    with pytest.raises(ValueError):
        normalize_xaf_amount(amount)
