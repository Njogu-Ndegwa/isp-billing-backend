"""Self-service password reset: forgot-password + reset-password endpoints."""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.auth_routes as ar
from app.api.auth_routes import router as auth_router, _hash_reset_token
from app.db.database import get_db
from app.db.models import PasswordResetToken
from app.services import email_service
from app.services.auth import pwd_context
from tests.factories import make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
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
    return application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def clear_throttle():
    ar._reset_request_log.clear()
    yield
    ar._reset_request_log.clear()


@pytest.fixture
def sent_emails(monkeypatch):
    """Capture reset emails instead of hitting the provider."""
    sent = []

    async def _fake(to, reset_url):
        sent.append((to, reset_url))
        return True

    monkeypatch.setattr(email_service, "send_password_reset_email", _fake)
    return sent


def _token_from_url(url: str) -> str:
    return url.split("token=", 1)[1]


async def _request_reset(client, email):
    resp = await client.post("/api/auth/forgot-password", json={"email": email})
    assert resp.status_code == 200
    return resp.json()


@pytest.mark.asyncio
async def test_forgot_password_creates_token_and_sends_email(db, client, sent_emails):
    user = await make_reseller(db, email="dennis@example.com")

    body = await _request_reset(client, "dennis@example.com")
    assert "reset link" in body["message"]

    rows = (await db.execute(select(PasswordResetToken))).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == user.id
    assert rows[0].used_at is None
    assert rows[0].expires_at > datetime.utcnow()

    assert len(sent_emails) == 1
    to, url = sent_emails[0]
    assert to == "dennis@example.com"
    assert "/reset-password?token=" in url
    # The raw token is only in the email; DB stores its hash
    raw = _token_from_url(url)
    assert rows[0].token_hash == _hash_reset_token(raw)
    assert raw not in rows[0].token_hash


@pytest.mark.asyncio
async def test_forgot_password_unknown_email_is_generic_and_silent(db, client, sent_emails):
    body = await _request_reset(client, "nobody@example.com")
    assert "reset link" in body["message"]
    rows = (await db.execute(select(PasswordResetToken))).scalars().all()
    assert rows == []
    assert sent_emails == []


@pytest.mark.asyncio
async def test_forgot_password_email_is_case_insensitive(db, client, sent_emails):
    await make_reseller(db, email="dennis@example.com")
    await _request_reset(client, "  DENNIS@Example.COM ")
    assert len(sent_emails) == 1


@pytest.mark.asyncio
async def test_new_request_invalidates_previous_token(db, client, sent_emails):
    await make_reseller(db, email="dennis@example.com")
    await _request_reset(client, "dennis@example.com")
    await _request_reset(client, "dennis@example.com")

    first_raw = _token_from_url(sent_emails[0][1])
    resp = await client.post("/api/auth/reset-password", json={
        "token": first_raw, "new_password": "newpass123",
    })
    assert resp.status_code == 400

    second_raw = _token_from_url(sent_emails[1][1])
    resp = await client.post("/api/auth/reset-password", json={
        "token": second_raw, "new_password": "newpass123",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_throttle_caps_requests_per_email(db, client, sent_emails):
    await make_reseller(db, email="dennis@example.com")
    for _ in range(5):
        body = await _request_reset(client, "dennis@example.com")
        assert "reset link" in body["message"]  # always generic, even throttled
    assert len(sent_emails) == 3  # RESET_REQUESTS_PER_WINDOW


@pytest.mark.asyncio
async def test_reset_password_happy_path(db, client, sent_emails):
    user = await make_reseller(db, email="dennis@example.com")
    await _request_reset(client, "dennis@example.com")
    raw = _token_from_url(sent_emails[0][1])

    resp = await client.post("/api/auth/reset-password", json={
        "token": raw, "new_password": "brand-new-pass",
    })
    assert resp.status_code == 200

    await db.refresh(user)
    assert pwd_context.verify("brand-new-pass", user.password_hash)

    token_row = (await db.execute(select(PasswordResetToken))).scalar_one()
    assert token_row.used_at is not None

    # Token is single-use
    resp = await client.post("/api/auth/reset-password", json={
        "token": raw, "new_password": "another-pass",
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_reset_password_rejects_expired_token(db, client, sent_emails):
    await make_reseller(db, email="dennis@example.com")
    await _request_reset(client, "dennis@example.com")
    raw = _token_from_url(sent_emails[0][1])

    token_row = (await db.execute(select(PasswordResetToken))).scalar_one()
    token_row.expires_at = datetime.utcnow() - timedelta(minutes=1)
    await db.commit()

    resp = await client.post("/api/auth/reset-password", json={
        "token": raw, "new_password": "newpass123",
    })
    assert resp.status_code == 400
    assert "expired" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reset_password_rejects_bogus_token_and_short_password(db, client):
    resp = await client.post("/api/auth/reset-password", json={
        "token": "not-a-real-token", "new_password": "newpass123",
    })
    assert resp.status_code == 400

    resp = await client.post("/api/auth/reset-password", json={
        "token": "whatever", "new_password": "short",
    })
    assert resp.status_code == 400
    assert "6 characters" in resp.json()["detail"]
