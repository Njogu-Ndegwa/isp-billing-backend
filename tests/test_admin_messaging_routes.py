import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.admin_messaging_routes as amr
from app.api.admin_messaging_routes import router as admin_messaging_router
from app.db.database import get_db
from app.services.auth import verify_token
from app.db.models import (
    MessagingSettings, ResellerInboxMessage, SmsMessage, SmsMessageKind,
    SmsMessageStatus, UserRole,
)
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
async def test_admin_settings_default_price_is_half_shilling(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    _auth_as(monkeypatch, admin)
    resp = await client.get("/api/admin/messaging/settings")
    assert resp.status_code == 200
    assert resp.json()["price_per_sms_kes"] == 0.5


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
    ("GET", "/api/admin/messaging/sms", None),
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


@pytest.mark.asyncio
async def test_inbox_send_with_sms_creates_status_rows(
        db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    reseller_with_phone = await make_reseller(
        db, support_phone="254700000001", organization_name="Phone ISP")
    reseller_without_phone = await make_reseller(db, support_phone=None)
    db.add(MessagingSettings(id=1, sender_id="BRAND"))
    await db.commit()
    _auth_as(monkeypatch, admin)

    dispatched = []

    async def _fake_dispatch(message_ids, sender_id):
        dispatched.append((message_ids, sender_id))

    monkeypatch.setattr(amr.sms_dispatch, "dispatch_admin_sms_messages",
                        _fake_dispatch)

    resp = await client.post("/api/admin/messaging/inbox", json={
        "recipient": "all", "subject": "Notice",
        "body": "Please update your details", "also_sms": True})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["recipients"] == 2
    assert payload["sms_queued"] == 1
    assert payload["sms_skipped_no_phone"] == 1

    rows = (await db.execute(
        select(SmsMessage).where(SmsMessage.kind == SmsMessageKind.ADMIN_TO_RESELLER)
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == reseller_with_phone.id
    assert rows[0].recipient_phone == "254700000001"
    assert rows[0].status == SmsMessageStatus.QUEUED
    assert rows[0].credits_charged == 1
    assert dispatched == [([rows[0].id], "TALKSASA")]


@pytest.mark.asyncio
async def test_admin_sms_history_shows_sent_and_failed_counts(
        db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    r1 = await make_reseller(db, organization_name="Alpha ISP")
    r2 = await make_reseller(db, organization_name="Beta ISP")
    db.add_all([
        SmsMessage(user_id=r1.id, recipient_phone="254700000001", body="Hi",
                   segments=1, credits_charged=1,
                   kind=SmsMessageKind.ADMIN_TO_RESELLER,
                   status=SmsMessageStatus.SENT, provider="fake",
                   provider_message_id="M1"),
        SmsMessage(user_id=r2.id, recipient_phone="254700000002", body="Hi",
                   segments=1, credits_charged=1,
                   kind=SmsMessageKind.ADMIN_TO_RESELLER,
                   status=SmsMessageStatus.FAILED, provider="fake",
                   error="Rejected"),
    ])
    await db.commit()
    _auth_as(monkeypatch, admin)

    resp = await client.get("/api/admin/messaging/sms")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["summary"]["sent"] == 1
    assert payload["summary"]["failed"] == 1
    assert payload["summary"]["queued"] == 0
    names = {m["reseller_name"] for m in payload["messages"]}
    assert names == {"Alpha ISP", "Beta ISP"}


@pytest.mark.asyncio
async def test_settings_returns_welcome_defaults(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    _auth_as(monkeypatch, admin)
    resp = await client.get("/api/admin/messaging/settings")
    body = resp.json()
    assert body["welcome_enabled"] is True
    assert body["welcome_subject"]
    assert body["welcome_message_body"]
    assert "welcome_support_phone" in body


@pytest.mark.asyncio
async def test_settings_update_welcome_fields(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    db.add(MessagingSettings(id=1))
    await db.commit()
    _auth_as(monkeypatch, admin)
    resp = await client.put("/api/admin/messaging/settings", json={
        "welcome_enabled": False,
        "welcome_message_body": "Custom welcome for {org}",
        "welcome_support_phone": "254700999888"})
    assert resp.status_code == 200
    s = await db.get(MessagingSettings, 1)
    assert s.welcome_enabled is False
    assert s.welcome_message_body == "Custom welcome for {org}"
    assert s.welcome_support_phone == "254700999888"


@pytest.mark.asyncio
async def test_admin_sms_history_filters_by_category(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    r1 = await make_reseller(db, organization_name="Welcome ISP")
    r2 = await make_reseller(db, organization_name="Promo ISP")
    db.add_all([
        SmsMessage(user_id=r1.id, recipient_phone="254700000001", body="Welcome",
                   segments=1, credits_charged=1,
                   kind=SmsMessageKind.ADMIN_TO_RESELLER,
                   status=SmsMessageStatus.SENT, category="reseller_welcome"),
        SmsMessage(user_id=r2.id, recipient_phone="254700000002", body="Promo",
                   segments=1, credits_charged=1,
                   kind=SmsMessageKind.ADMIN_TO_RESELLER,
                   status=SmsMessageStatus.SENT, category=None),
    ])
    await db.commit()
    _auth_as(monkeypatch, admin)
    resp = await client.get("/api/admin/messaging/sms?category=reseller_welcome")
    msgs = resp.json()["messages"]
    assert len(msgs) == 1
    assert msgs[0]["category"] == "reseller_welcome"
    assert msgs[0]["reseller_name"] == "Welcome ISP"
