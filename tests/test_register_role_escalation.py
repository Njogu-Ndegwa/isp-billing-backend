"""Public signup must not be a way to mint admins.

`POST /api/users/register` is unauthenticated because resellers sign
themselves up from the marketing site. It used to take `role` straight from
the request body, so anyone could POST `{"role": "admin"}` and get a full
admin: resellers, payouts, password resets, impersonation, all of it.

The signup page only ever sends `role: "reseller"`. An admin account can
still be created through this endpoint, but only by a caller who is already
an admin and proves it with their bearer token.
"""

from datetime import timedelta
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import router as auth_router
from app.db.database import get_db
from app.db.models import User, UserRole
from app.services.auth import create_access_token
from tests.factories import make_admin, make_reseller

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def no_welcome_sms(monkeypatch):
    import app.services.sms_dispatch as sms_dispatch
    monkeypatch.setattr(sms_dispatch, "dispatch_admin_sms_messages", AsyncMock())


@pytest_asyncio.fixture
async def client(session_factory):
    app = FastAPI()
    app.include_router(auth_router)

    async def _get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def _payload(email, role):
    return {
        "email": email,
        "password": "hunter2hunter2",
        "role": role,
        "organization_name": "Soko WiFi",
        "support_phone": "+254712345678",
    }


def _bearer_for(user) -> dict:
    token = create_access_token({
        "sub": str(user.id),
        "user_code": user.user_code,
        "user_id": user.id,
        "role": user.role.value,
        "organization_name": user.organization_name,
    }, timedelta(minutes=30))
    return {"Authorization": f"Bearer {token}"}


async def _find(db, email):
    return (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()


@pytest.mark.parametrize("role", ["admin", "ADMIN", "Admin"])
async def test_unauthenticated_admin_signup_is_rejected(client, db, role):
    response = await client.post("/api/users/register", json=_payload("evil@example.com", role))

    assert response.status_code == 403, response.text
    assert await _find(db, "evil@example.com") is None


async def test_reseller_token_cannot_create_an_admin(client, db):
    reseller = await make_reseller(db)

    response = await client.post(
        "/api/users/register",
        json=_payload("evil@example.com", "admin"),
        headers=_bearer_for(reseller),
    )

    assert response.status_code == 403, response.text
    assert await _find(db, "evil@example.com") is None


async def test_forged_token_cannot_create_an_admin(client, db):
    response = await client.post(
        "/api/users/register",
        json=_payload("evil@example.com", "admin"),
        headers={"Authorization": "Bearer not-a-real-jwt"},
    )

    assert response.status_code in (401, 403), response.text
    assert await _find(db, "evil@example.com") is None


async def test_public_reseller_signup_still_works(client, db):
    response = await client.post("/api/users/register", json=_payload("shop@example.com", "reseller"))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["role"] == "reseller"
    assert set(body) == {
        "id", "email", "user_code", "role", "organization_name", "business_name",
        "support_phone", "mpesa_shortcode", "acquisition_source", "created_at",
    }
    user = await _find(db, "shop@example.com")
    assert user.role == UserRole.RESELLER


async def test_existing_admin_can_still_create_an_admin(client, db):
    admin = await make_admin(db)

    response = await client.post(
        "/api/users/register",
        json=_payload("second-admin@example.com", "admin"),
        headers=_bearer_for(admin),
    )

    assert response.status_code == 200, response.text
    user = await _find(db, "second-admin@example.com")
    assert user.role == UserRole.ADMIN
    # Leaves a trail: who made this admin.
    assert user.created_by == admin.id
