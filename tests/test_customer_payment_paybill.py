"""`payment_paybill` on the customer list and detail endpoints.

The admin customer page shows "Paybill / Account Number" so a reseller can
tell PPPoE customers where to pay. The paybill comes from the same resolver
the expiry reminders and the M-Pesa prompt use
(customer_expiry_notifications.resolve_paybills), so the page can never name
a different paybill from the one the payment actually lands in:

- reseller's own C2B-registered paybill on the router -> that shortcode
- platform-collected (no method / platform settlement) -> platform paybill
  (settings.MPESA_SHORTCODE, never hard-coded in the UI)
- direct settlement with no paybill we can match -> None
"""

from datetime import datetime

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.customer_routes as cr
from app.api.customer_routes import router as customer_router
from app.config import settings
from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(customer_router)

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
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(cr, "get_current_user", _fake)


async def _pppoe_customer(db, reseller, router):
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    return await make_customer(
        db, reseller, plan, router,
        pppoe_username=f"pppoe{router.id}", account_number=f"1000{router.id}",
    )


async def _add_method(db, reseller, method_type, **fields):
    method = ResellerPaymentMethod(
        user_id=reseller.id, method_type=method_type, label="Own", is_active=True, **fields,
    )
    db.add(method)
    await db.commit()
    await db.refresh(method)
    return method


@pytest.mark.asyncio
async def test_platform_collected_customer_gets_the_platform_paybill(db, client, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="platform")
    router = await make_router(db, reseller)
    customer = await _pppoe_customer(db, reseller, router)
    _auth_as(monkeypatch, reseller)

    detail = (await client.get(f"/api/customers/{customer.id}")).json()
    listed = (await client.get("/api/customers")).json()

    assert detail["payment_paybill"] == settings.MPESA_SHORTCODE
    assert listed[0]["payment_paybill"] == settings.MPESA_SHORTCODE


@pytest.mark.asyncio
async def test_own_c2b_paybill_is_shown_instead_of_the_platform_one(db, client, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    method = await _add_method(
        db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        mpesa_shortcode=" 555111 ", c2b_registered_at=datetime.utcnow(),
    )
    router.payment_method_id = method.id
    await db.commit()
    customer = await _pppoe_customer(db, reseller, router)
    _auth_as(monkeypatch, reseller)

    detail = (await client.get(f"/api/customers/{customer.id}")).json()
    listed = (await client.get("/api/customers")).json()

    assert detail["payment_paybill"] == "555111"
    assert listed[0]["payment_paybill"] == "555111"


@pytest.mark.asyncio
async def test_paybill_is_per_router(db, client, monkeypatch):
    """Two routers of one reseller can collect into different paybills."""
    reseller = await make_reseller(db, settlement_mode="platform")
    own_router = await make_router(db, reseller)
    legacy_router = await make_router(db, reseller)
    method = await _add_method(
        db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        mpesa_shortcode="555111", c2b_registered_at=datetime.utcnow(),
    )
    own_router.payment_method_id = method.id
    await db.commit()
    own = await _pppoe_customer(db, reseller, own_router)
    legacy = await _pppoe_customer(db, reseller, legacy_router)
    _auth_as(monkeypatch, reseller)

    listed = {c["id"]: c for c in (await client.get("/api/customers")).json()}

    assert listed[own.id]["payment_paybill"] == "555111"
    assert listed[legacy.id]["payment_paybill"] == settings.MPESA_SHORTCODE


@pytest.mark.asyncio
async def test_unregistered_own_paybill_is_never_the_platform_paybill(db, client, monkeypatch):
    """Without C2B we can't match the account number, and the money is not
    ours, so no paybill is offered (the 2026-10-11 reminder bug)."""
    reseller = await make_reseller(db, settlement_mode="direct")
    router = await make_router(db, reseller)
    method = await _add_method(
        db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        mpesa_shortcode="4699342", c2b_registered_at=None,
    )
    router.payment_method_id = method.id
    await db.commit()
    customer = await _pppoe_customer(db, reseller, router)
    _auth_as(monkeypatch, reseller)

    detail = (await client.get(f"/api/customers/{customer.id}")).json()

    assert detail["payment_paybill"] is None


@pytest.mark.asyncio
async def test_resolver_failure_does_not_break_the_customer_list(db, client, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    await _pppoe_customer(db, reseller, router)
    _auth_as(monkeypatch, reseller)

    async def _boom(*args, **kwargs):
        raise RuntimeError("resolver down")
    import app.services.customer_expiry_notifications as cen
    monkeypatch.setattr(cen, "resolve_paybills", _boom)

    resp = await client.get("/api/customers")

    assert resp.status_code == 200
    assert resp.json()[0]["payment_paybill"] is None
