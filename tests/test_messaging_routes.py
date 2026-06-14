import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.messaging_routes as mr
from app.api.messaging_routes import router as messaging_router
from app.db.database import get_db
from app.services.auth import verify_token
from app.db.models import SmsCreditOrder, SmsCreditOrderStatus, UserRole
from app.services import sms_credits
from tests.factories import make_reseller, make_plan, make_customer, make_sms_account


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(messaging_router)

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
    monkeypatch.setattr(mr, "get_current_user", _fake)


@pytest.mark.asyncio
async def test_purchase_creates_order_and_calls_stk(db, client, monkeypatch):
    r = await make_reseller(db)
    _auth_as(monkeypatch, r)

    class _Stk:
        checkout_request_id = "ws_CO_1"
        merchant_request_id = "mr_1"

    async def _fake_stk(**kwargs):
        assert kwargs["amount"] == 50      # 50 credits * default price 1.0
        return _Stk()
    monkeypatch.setattr(mr, "initiate_stk_push_direct", _fake_stk)

    resp = await client.post("/api/messaging/credits/purchase",
                             json={"quantity": 50, "phone_number": "0712345678"})
    assert resp.status_code == 200
    assert resp.json()["checkout_request_id"] == "ws_CO_1"


@pytest.mark.asyncio
async def test_callback_grants_credits(db, client, monkeypatch):
    r = await make_reseller(db)
    _auth_as(monkeypatch, r)
    db.add(SmsCreditOrder(user_id=r.id, quantity=50, unit_price=1, amount=50,
                          phone_number="254712345678",
                          status=SmsCreditOrderStatus.PENDING,
                          mpesa_checkout_request_id="ws_CO_2"))
    await db.commit()

    resp = await client.post("/api/messaging/credits/mpesa/callback", json={
        "Body": {"stkCallback": {"CheckoutRequestID": "ws_CO_2", "ResultCode": 0,
                 "CallbackMetadata": {"Item": [
                     {"Name": "MpesaReceiptNumber", "Value": "QABC123"}]}}}})
    assert resp.status_code == 200
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 50


@pytest.mark.asyncio
async def test_send_rejects_when_insufficient_credits(db, client, monkeypatch):
    r = await make_reseller(db)
    p = await make_plan(db, r)
    await make_customer(db, r, p, phone="254700000001")
    await make_sms_account(db, r, balance=0)
    _auth_as(monkeypatch, r)
    resp = await client.post("/api/messaging/send",
                             json={"body": "Hi", "filter": "all"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_template_create_then_list(db, client, monkeypatch):
    r = await make_reseller(db)
    _auth_as(monkeypatch, r)
    create = await client.post("/api/messaging/templates",
                               json={"name": "Welcome", "body": "Hi there"})
    assert create.status_code == 200
    listed = await client.get("/api/messaging/templates")
    names = [t["name"] for t in listed.json()["templates"]]
    assert "Welcome" in names


@pytest.mark.asyncio
async def test_recipients_count_scoped(db, client, monkeypatch):
    r = await make_reseller(db)
    p = await make_plan(db, r)
    await make_customer(db, r, p, phone="254700000001")
    await make_customer(db, r, p, phone="254700000002")
    _auth_as(monkeypatch, r)
    resp = await client.get("/api/messaging/recipients?filter=all")
    assert resp.json()["count"] == 2


@pytest.mark.asyncio
async def test_callback_failed_result_does_not_grant(db, client, monkeypatch):
    r = await make_reseller(db)
    _auth_as(monkeypatch, r)
    db.add(SmsCreditOrder(user_id=r.id, quantity=50, unit_price=1, amount=50,
                          phone_number="254712345678",
                          status=SmsCreditOrderStatus.PENDING,
                          mpesa_checkout_request_id="ws_CO_FAIL"))
    await db.commit()

    resp = await client.post("/api/messaging/credits/mpesa/callback", json={
        "Body": {"stkCallback": {"CheckoutRequestID": "ws_CO_FAIL",
                                 "ResultCode": 1032, "ResultDesc": "Cancelled"}}})
    assert resp.status_code == 200
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 0   # no grant on non-zero ResultCode


@pytest.mark.asyncio
async def test_callback_is_idempotent_on_duplicate(db, client, monkeypatch):
    r = await make_reseller(db)
    _auth_as(monkeypatch, r)
    db.add(SmsCreditOrder(user_id=r.id, quantity=20, unit_price=1, amount=20,
                          phone_number="254712345678",
                          status=SmsCreditOrderStatus.PENDING,
                          mpesa_checkout_request_id="ws_CO_DUP"))
    await db.commit()
    payload = {"Body": {"stkCallback": {"CheckoutRequestID": "ws_CO_DUP",
               "ResultCode": 0, "CallbackMetadata": {"Item": [
                   {"Name": "MpesaReceiptNumber", "Value": "QDUP1"}]}}}}

    first = await client.post("/api/messaging/credits/mpesa/callback", json=payload)
    second = await client.post("/api/messaging/credits/mpesa/callback", json=payload)
    assert first.status_code == 200 and second.status_code == 200
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 20   # granted once, not twice


@pytest.mark.asyncio
async def test_admin_is_rejected_from_reseller_endpoint(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    _auth_as(monkeypatch, admin)
    resp = await client.get("/api/messaging/credits")
    assert resp.status_code == 403
