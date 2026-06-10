"""A second pay attempt while one is pending must NOT fire a second STK push.

Production failure mode: a Safaricom callback goes missing, the customer sees
the portal spinner stall, taps "Pay" again, and gets charged twice. The guard
in POST /api/hotspot/register-and-pay must refuse to initiate a new STK push
while the customer already has a PENDING MpesaTransaction younger than 3
minutes, answering 409 {"status": "payment_in_progress", ...} so the portal
resumes polling the existing payment instead.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.payment_routes import router as payment_router
from app.db.database import get_db
from app.db.models import MpesaTransaction, MpesaTransactionStatus
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def app(session_factory):
    app = FastAPI()
    app.include_router(payment_router)

    async def _get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _get_db
    return app


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


MAC = "AA:BB:CC:DD:EE:01"


def _pay_body(plan, router, mac=MAC):
    return {
        "phone": "0712345678",
        "mac_address": mac,
        "plan_id": plan.id,
        "router_id": router.id,
        "payment_method": "mobile_money",
    }


class _FakeStk:
    checkout_request_id = "ws_CO_FAKE_1"
    merchant_request_id = "mr_1"


async def _seed(db):
    """Reseller (default TRIAL subscription passes the 503 gate) + hotspot
    plan + router + existing customer matched by MAC + user_id."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)  # defaults: HOTSPOT, owned by reseller
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, mac_address=MAC)
    return reseller, plan, router, customer


async def _seed_pending_txn(db, customer, *, age: timedelta, checkout_id: str):
    txn = MpesaTransaction(
        checkout_request_id=checkout_id,
        phone_number=customer.phone,
        amount=500,
        reference=f"HOTSPOT-{customer.id}-SEEDED",
        customer_id=customer.id,
        status=MpesaTransactionStatus.pending,
        created_at=datetime.utcnow() - age,
    )
    db.add(txn)
    await db.commit()
    return txn


def _patch_payment_path(stk_mock):
    """Force the legacy initiate_stk_push path: no configured gateway on the
    router. Both names are imported inside the route body, so patching the
    source modules takes effect at request time."""
    return (
        patch(
            "app.services.payment_gateway.resolve_router_payment_method",
            new=AsyncMock(return_value=None),
        ),
        patch("app.services.mpesa.initiate_stk_push", new=stk_mock),
    )


async def test_second_payment_within_window_returns_409(engine, db, client):
    _, plan, router, customer = await _seed(db)
    await _seed_pending_txn(
        db, customer, age=timedelta(seconds=30), checkout_id="ws_CO_EXISTING_30S"
    )

    stk = AsyncMock(return_value=_FakeStk())
    gw_patch, stk_patch = _patch_payment_path(stk)
    with gw_patch, stk_patch:
        resp = await client.post("/api/hotspot/register-and-pay", json=_pay_body(plan, router))

    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["status"] == "payment_in_progress"
    assert detail["customer_id"] == customer.id
    assert "message" in detail
    # The whole point: no second charge was initiated.
    assert stk.await_count == 0


async def test_payment_allowed_when_no_pending_txn(engine, db, client):
    """Happy-path guarantee: the guard must not block a customer with no
    in-flight payment — proves the 409 above comes from the guard, not from
    some earlier validation failing."""
    _, plan, router, customer = await _seed(db)

    stk = AsyncMock(return_value=_FakeStk())
    gw_patch, stk_patch = _patch_payment_path(stk)
    with gw_patch, stk_patch:
        resp = await client.post("/api/hotspot/register-and-pay", json=_pay_body(plan, router))

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == customer.id
    assert body["status"] == "pending"
    assert stk.await_count == 1


async def test_payment_allowed_when_pending_txn_is_stale(engine, db, client):
    """A pending txn older than the 3-minute window is presumed dead (lost
    callback the reconciler will expire) — the customer may retry."""
    _, plan, router, customer = await _seed(db)
    await _seed_pending_txn(
        db, customer, age=timedelta(minutes=10), checkout_id="ws_CO_EXISTING_10M"
    )

    stk = AsyncMock(return_value=_FakeStk())
    gw_patch, stk_patch = _patch_payment_path(stk)
    with gw_patch, stk_patch:
        resp = await client.post("/api/hotspot/register-and-pay", json=_pay_body(plan, router))

    assert resp.status_code == 200, resp.text
    assert resp.json()["id"] == customer.id
    assert stk.await_count == 1
