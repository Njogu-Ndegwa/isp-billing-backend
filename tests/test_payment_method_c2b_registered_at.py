"""`c2b_registered_at` on the reseller payment-method API (added 2026-10-23).

The column is stamped by POST /api/payment-methods/{id}/register-c2b, but the
serializer never returned it, so the admin Settings -> Payment methods
"C2B Active" badge never showed and the frontend could not pick a reseller's
own C2B-registered paybill. These tests pin the field on every endpoint that
serializes a method (list, get, create, update), null and set, and confirm the
list still only returns the caller's own methods.
"""

from datetime import datetime

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

REGISTERED_AT = datetime(2026, 10, 20, 9, 30, 0)


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


async def _paybill(db, user, *, label, registered_at=None, shortcode="600111"):
    pm = ResellerPaymentMethod(
        user_id=user.id,
        method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        label=label,
        is_active=True,
        mpesa_shortcode=shortcode,
        c2b_registered_at=registered_at,
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    return pm


def test_serializer_returns_null_when_not_registered():
    pm = ResellerPaymentMethod(
        id=1,
        user_id=1,
        method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Shop Till",
        is_active=True,
        mpesa_till_number="5678901",
    )
    result = pmr._serialize_payment_method(pm)
    assert "c2b_registered_at" in result
    assert result["c2b_registered_at"] is None


def test_serializer_returns_iso_timestamp_when_registered():
    pm = ResellerPaymentMethod(
        id=2,
        user_id=1,
        method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        label="Own Paybill",
        is_active=True,
        mpesa_shortcode="600111",
        c2b_registered_at=REGISTERED_AT,
    )
    result = pmr._serialize_payment_method(pm)
    assert result["c2b_registered_at"] == REGISTERED_AT.isoformat()


@pytest.mark.asyncio
async def test_list_returns_field_and_only_own_methods(db, client, monkeypatch):
    owner = await make_reseller(db)
    other = await make_reseller(db)
    registered = await _paybill(db, owner, label="Registered", registered_at=REGISTERED_AT)
    unregistered = await _paybill(db, owner, label="Unregistered", shortcode="600222")
    foreign = await _paybill(db, other, label="Other reseller", registered_at=REGISTERED_AT,
                             shortcode="600333")
    _auth_as(monkeypatch, owner)

    resp = await client.get("/api/payment-methods")

    assert resp.status_code == 200, resp.text
    by_id = {m["id"]: m for m in resp.json()}
    assert set(by_id) == {registered.id, unregistered.id}
    assert foreign.id not in by_id
    assert by_id[registered.id]["c2b_registered_at"] == REGISTERED_AT.isoformat()
    assert by_id[unregistered.id]["c2b_registered_at"] is None


@pytest.mark.asyncio
async def test_get_returns_field(db, client, monkeypatch):
    owner = await make_reseller(db)
    pm = await _paybill(db, owner, label="Registered", registered_at=REGISTERED_AT)
    _auth_as(monkeypatch, owner)

    resp = await client.get(f"/api/payment-methods/{pm.id}")

    assert resp.status_code == 200, resp.text
    assert resp.json()["c2b_registered_at"] == REGISTERED_AT.isoformat()


@pytest.mark.asyncio
async def test_get_other_resellers_method_still_404(db, client, monkeypatch):
    owner = await make_reseller(db)
    other = await make_reseller(db)
    foreign = await _paybill(db, other, label="Other", registered_at=REGISTERED_AT)
    _auth_as(monkeypatch, owner)

    resp = await client.get(f"/api/payment-methods/{foreign.id}")

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_returns_null_field(db, client, monkeypatch):
    owner = await make_reseller(db)
    _auth_as(monkeypatch, owner)

    resp = await client.post("/api/payment-methods", json={
        "method_type": "mpesa_till",
        "label": "Shop Till",
        "mpesa_till_number": "5678901",
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "c2b_registered_at" in body
    assert body["c2b_registered_at"] is None


@pytest.mark.asyncio
async def test_update_keeps_registered_timestamp(db, client, monkeypatch):
    owner = await make_reseller(db)
    pm = await _paybill(db, owner, label="Registered", registered_at=REGISTERED_AT)
    _auth_as(monkeypatch, owner)

    resp = await client.put(f"/api/payment-methods/{pm.id}", json={"label": "Renamed"})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["label"] == "Renamed"
    assert body["c2b_registered_at"] == REGISTERED_AT.isoformat()
