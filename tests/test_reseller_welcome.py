import pytest
from sqlalchemy import select

from app.db.models import (
    MessagingSettings, ResellerInboxMessage, SmsMessage, SmsMessageKind,
    SmsMessageStatus, UserRole,
)
from app.services.reseller_welcome import (
    queue_reseller_welcome, render_welcome_body, effective_welcome_settings,
    WELCOME_CATEGORY, DEFAULT_WELCOME_BODY,
)
from tests.factories import make_reseller


@pytest.mark.asyncio
async def test_new_columns_exist_and_default(db):
    db.add(MessagingSettings(id=1))
    await db.commit()
    s = await db.get(MessagingSettings, 1)
    assert s.welcome_enabled is True
    assert s.welcome_subject is None
    assert s.welcome_message_body is None
    assert s.welcome_support_phone is None

    row = SmsMessage(user_id=1, recipient_phone="254700000000", body="hi",
                     segments=1, credits_charged=1,
                     kind=SmsMessageKind.ADMIN_TO_RESELLER,
                     status=SmsMessageStatus.QUEUED, category="reseller_welcome")
    db.add(row)
    await db.commit()
    got = (await db.execute(select(SmsMessage))).scalars().one()
    assert got.category == "reseller_welcome"


@pytest.mark.asyncio
async def test_queue_creates_inbox_and_sms_when_enabled_with_phone(db):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db, support_phone="254700111222",
                                   organization_name="Acme Net")
    db.add(MessagingSettings(id=1, welcome_support_phone="254799000000"))
    await db.commit()

    sms_ids = await queue_reseller_welcome(db, reseller)
    await db.commit()

    inbox = (await db.execute(select(ResellerInboxMessage).where(
        ResellerInboxMessage.recipient_user_id == reseller.id))).scalars().all()
    assert len(inbox) == 1
    assert inbox[0].sender_user_id == admin.id
    assert inbox[0].sent_sms is True

    sms = (await db.execute(select(SmsMessage).where(
        SmsMessage.user_id == reseller.id))).scalars().all()
    assert len(sms) == 1
    assert sms[0].kind == SmsMessageKind.ADMIN_TO_RESELLER
    assert sms[0].category == WELCOME_CATEGORY
    assert sms[0].status == SmsMessageStatus.QUEUED
    assert sms[0].recipient_phone == "254700111222"
    assert "254799000000" in sms[0].body
    assert "Acme Net" in sms[0].body
    assert sms_ids == [sms[0].id]


@pytest.mark.asyncio
async def test_queue_no_phone_creates_inbox_only(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db, support_phone=None)
    db.add(MessagingSettings(id=1))
    await db.commit()

    sms_ids = await queue_reseller_welcome(db, reseller)
    await db.commit()

    assert sms_ids == []
    inbox = (await db.execute(select(ResellerInboxMessage).where(
        ResellerInboxMessage.recipient_user_id == reseller.id))).scalars().all()
    assert len(inbox) == 1
    assert inbox[0].sent_sms is False
    assert (await db.execute(select(SmsMessage))).scalars().all() == []


@pytest.mark.asyncio
async def test_queue_disabled_creates_nothing(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db, support_phone="254700111222")
    db.add(MessagingSettings(id=1, welcome_enabled=False))
    await db.commit()

    sms_ids = await queue_reseller_welcome(db, reseller)
    await db.commit()

    assert sms_ids == []
    assert (await db.execute(select(ResellerInboxMessage))).scalars().all() == []
    assert (await db.execute(select(SmsMessage))).scalars().all() == []


@pytest.mark.asyncio
async def test_queue_messaging_globally_disabled_skips_sms(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db, support_phone="254700111222")
    db.add(MessagingSettings(id=1, enabled=False))
    await db.commit()

    sms_ids = await queue_reseller_welcome(db, reseller)
    await db.commit()

    assert sms_ids == []
    inbox = (await db.execute(select(ResellerInboxMessage).where(
        ResellerInboxMessage.recipient_user_id == reseller.id))).scalars().all()
    assert len(inbox) == 1
    assert inbox[0].sent_sms is False
    assert (await db.execute(select(SmsMessage))).scalars().all() == []


def test_render_welcome_body_substitutes_placeholders():
    out = render_welcome_body("Hi {org}, call {support_phone}.",
                              org="Acme", support_phone="0712")
    assert out == "Hi Acme, call 0712."


def test_render_welcome_body_handles_missing_phone():
    out = render_welcome_body("Call {support_phone} now.", org="Acme",
                              support_phone=None)
    assert "{support_phone}" not in out
    assert "our support line" in out


def test_effective_welcome_settings_defaults_when_null():
    cfg = effective_welcome_settings(None)
    assert cfg["enabled"] is True
    assert cfg["body"] == DEFAULT_WELCOME_BODY
    assert cfg["support_phone"] is None


@pytest.mark.asyncio
async def test_registration_triggers_welcome(db, session_factory, monkeypatch):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from app.api.auth_routes import router as auth_router
    from app.db.database import get_db

    await make_reseller(db, role=UserRole.ADMIN)
    db.add(MessagingSettings(id=1, welcome_support_phone="254799000000"))
    await db.commit()

    application = FastAPI()
    application.include_router(auth_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise
    application.dependency_overrides[get_db] = _override_get_db

    dispatched = []

    async def _fake_dispatch(message_ids, sender_id):
        dispatched.append((message_ids, sender_id))
    monkeypatch.setattr(
        "app.services.sms_dispatch.dispatch_admin_sms_messages", _fake_dispatch)

    async with AsyncClient(transport=ASGITransport(app=application),
                           base_url="http://test") as client:
        resp = await client.post("/api/users/register", json={
            "email": "newreseller@example.com", "password": "secret123",
            "role": "reseller", "organization_name": "Newbie ISP",
            "support_phone": "254700111222"})
    assert resp.status_code == 200

    sms = (await db.execute(select(SmsMessage).where(
        SmsMessage.category == WELCOME_CATEGORY))).scalars().all()
    assert len(sms) == 1
    assert dispatched and dispatched[0][0] == [sms[0].id]


@pytest.mark.asyncio
async def test_registration_survives_welcome_failure(db, session_factory, monkeypatch):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from app.api.auth_routes import router as auth_router
    from app.db.database import get_db
    from app.db.models import User

    application = FastAPI()
    application.include_router(auth_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise
    application.dependency_overrides[get_db] = _override_get_db

    async def _boom(db, reseller):
        raise RuntimeError("boom")
    monkeypatch.setattr(
        "app.services.reseller_welcome.queue_reseller_welcome", _boom)

    async with AsyncClient(transport=ASGITransport(app=application),
                           base_url="http://test") as client:
        resp = await client.post("/api/users/register", json={
            "email": "survivor@example.com", "password": "secret123",
            "role": "reseller", "organization_name": "Survivor ISP",
            "support_phone": "254700111222"})
    assert resp.status_code == 200
    user = (await db.execute(select(User).where(
        User.email == "survivor@example.com"))).scalar_one_or_none()
    assert user is not None
