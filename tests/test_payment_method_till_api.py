"""M-Pesa Till as a first-class payment method over HTTP (added 2026-08-14).

The Buy Goods payout path (BusinessBuyGoods, receiver type 2) has existed
since 2026-07-21, but the admin frontend never offered `mpesa_till`, so nobody
could reach it. These tests pin the API contract the new UI depends on:

  - a till number is validated the same way on create AND on update — a phone
    number in this field silently kills every future payout;
  - the serialized method carries `mpesa_till_number` so the settings page and
    the admin reseller view can render the destination.
"""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api import payment_method_routes as pmr
from app.api.payment_method_routes import router as payment_method_router
from app.db.database import get_db
from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType
from app.services.auth import verify_token
from tests.factories import make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(payment_method_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    return application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(pmr, "get_current_user", _fake)


@pytest.mark.asyncio
async def test_create_till_returns_till_number(db, client, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/payment-methods", json={
        "method_type": "mpesa_till",
        "label": "Shop Till",
        "mpesa_till_number": " 5678901 ",
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["method_type"] == "mpesa_till"
    assert body["mpesa_till_number"] == "5678901"  # whitespace stripped


@pytest.mark.asyncio
async def test_create_rejects_phone_number_as_till(db, client, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/payment-methods", json={
        "method_type": "mpesa_till",
        "label": "Not a till",
        "mpesa_till_number": "0722123456",
    })

    assert resp.status_code == 400
    assert "till" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_update_rejects_phone_number_as_till(db, client, monkeypatch):
    """A valid till must not be editable into an unpayable phone number."""
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)

    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Shop Till",
        is_active=True,
        mpesa_till_number="5678901",
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)

    resp = await client.put(f"/api/payment-methods/{pm.id}", json={
        "mpesa_till_number": "0722123456",
    })

    assert resp.status_code == 400
    await db.refresh(pm)
    assert pm.mpesa_till_number == "5678901"  # unchanged


@pytest.mark.asyncio
async def test_update_accepts_a_real_till(db, client, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)

    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Shop Till",
        is_active=True,
        mpesa_till_number="5678901",
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)

    resp = await client.put(f"/api/payment-methods/{pm.id}", json={
        "mpesa_till_number": "998877",
    })

    assert resp.status_code == 200, resp.text
    await db.refresh(pm)
    assert pm.mpesa_till_number == "998877"


def test_admin_serializer_exposes_till_number():
    """The admin reseller view reads the destination from this serializer."""
    from app.api.admin_reseller_routes import _serialize_payment_method_for_admin

    pm = ResellerPaymentMethod(
        id=7,
        user_id=1,
        method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Shop Till",
        is_active=True,
        mpesa_till_number="5678901",
    )

    result = _serialize_payment_method_for_admin(pm)
    assert result["mpesa_till_number"] == "5678901"
