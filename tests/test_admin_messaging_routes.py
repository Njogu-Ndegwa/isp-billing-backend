import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.admin_messaging_routes as amr
from app.api.admin_messaging_routes import router as admin_messaging_router
from app.db.database import get_db
from app.services.auth import verify_token
from app.db.models import MessagingSettings, ResellerInboxMessage, UserRole
from app.services import sms_credits
from tests.factories import make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(admin_messaging_router)

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
    monkeypatch.setattr(amr, "get_current_user", _fake)


@pytest.mark.asyncio
async def test_admin_updates_price(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    db.add(MessagingSettings(id=1))
    await db.commit()
    _auth_as(monkeypatch, admin)
    resp = await client.put("/api/admin/messaging/settings",
                            json={"price_per_sms_kes": 0.8})
    assert resp.status_code == 200
    s = await db.get(MessagingSettings, 1)
    assert float(s.price_per_sms_kes) == 0.8


@pytest.mark.asyncio
async def test_admin_adjust_grants_credits(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, admin)
    resp = await client.post(
        f"/api/admin/messaging/resellers/{reseller.id}/credits/adjust",
        json={"delta": 25, "note": "promo"})
    assert resp.status_code == 200
    acct = await sms_credits.get_or_create_account(db, reseller.id)
    assert acct.balance == 25


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,payload", [
    ("GET", "/api/admin/messaging/settings", None),
    ("PUT", "/api/admin/messaging/settings", {"price_per_sms_kes": 1.0}),
    ("GET", "/api/admin/messaging/credits/orders", None),
    ("POST", "/api/admin/messaging/resellers/999/credits/adjust", {"delta": 1}),
    ("POST", "/api/admin/messaging/inbox", {"recipient": "all", "body": "hi"}),
])
async def test_reseller_is_rejected_from_all_admin_endpoints(
        db, client, monkeypatch, method, path, payload):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)
    fn = getattr(client, method.lower())
    resp = await (fn(path, json=payload) if payload is not None else fn(path))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_inbox_send_to_one_reseller_creates_row(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, admin)
    resp = await client.post("/api/admin/messaging/inbox", json={
        "recipient": str(reseller.id), "subject": "Notice",
        "body": "Please update your details", "also_sms": False})
    assert resp.status_code == 200
    assert resp.json()["recipients"] == 1
    from sqlalchemy import select
    rows = (await db.execute(select(ResellerInboxMessage).where(
        ResellerInboxMessage.recipient_user_id == reseller.id))).scalars().all()
    assert len(rows) == 1
    assert rows[0].body == "Please update your details"
