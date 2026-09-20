"""Reseller self-service gateways, tenant isolation, and default-path safety."""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.messaging_provider_routes as mpr
from app.api.messaging_provider_routes import router as provider_router
from app.config import settings
from app.db.database import get_db
from app.db.models import MessagingProviderAccount, MessagingSettings
from app.services.auth import verify_token
from app.services.messaging import accounts, registry, resolve_sender_id
from tests.factories import make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(provider_router)

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
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user

    monkeypatch.setattr(mpr, "get_current_user", _fake)


def _creds(**over):
    config = {"userid": "dukestop", "password": "d0vEaW5n"}
    config.update(over)
    return accounts.encrypt_config(registry.get_spec("hostpinnacle"), config)


async def _own_account(db, user, **over):
    defaults = dict(
        user_id=user.id, provider="hostpinnacle", label="My gateway",
        sender_id="DUKESTOP", credentials=_creds(),
        is_default=True, is_active=True,
    )
    defaults.update(over)
    account = MessagingProviderAccount(**defaults)
    db.add(account)
    await db.flush()
    return account


# ---------------------------------------------------------------------------
# The default path must be untouched
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("sms_sender_id,configured", [
    ("", None),
    ("", "DBBRAND"),
    ("GLOBAL", None),
    ("GLOBAL", "DBBRAND"),
])
async def test_sender_id_identical_to_the_old_helper_when_no_accounts_exist(
    db, monkeypatch, sms_sender_id, configured
):
    """With nothing configured, tenant-aware resolution == the old function.

    This is the guarantee that shipping per-tenant gateways changed nothing
    for an existing deployment. If it ever fails, the default path moved.
    """
    monkeypatch.setattr(settings, "SMS_SENDER_ID", sms_sender_id)
    monkeypatch.setattr(settings, "SMS_PROVIDER", "talksasa")
    monkeypatch.setattr(settings, "TALKSASA_SENDER_ID", "TALKSASA")

    user = await make_reseller(db)
    assert (
        await accounts.resolve_sender_id_for(db, user.id, configured)
        == resolve_sender_id(configured)
    )


@pytest.mark.asyncio
async def test_provider_identical_to_the_old_factory_when_no_accounts_exist(
    db, monkeypatch
):
    monkeypatch.setattr(settings, "SMS_PROVIDER", "talksasa")
    monkeypatch.setattr(settings, "TALKSASA_API_TOKEN", "env-token")
    user = await make_reseller(db)

    resolved = await accounts.resolve(db, user.id)
    assert resolved.source == "env"
    assert resolved.provider.name == "talksasa"
    assert resolved.provider.api_token == "env-token"


@pytest.mark.asyncio
async def test_self_service_is_off_until_an_admin_turns_it_on(db):
    db.add(MessagingSettings(id=1))
    await db.flush()
    row = await db.get(MessagingSettings, 1)
    assert row.allow_reseller_gateways is False


# ---------------------------------------------------------------------------
# Self-service gating
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reseller_cannot_add_a_gateway_while_self_service_is_off(client, db, monkeypatch):
    db.add(MessagingSettings(id=1, allow_reseller_gateways=False))
    user = await make_reseller(db)
    await db.commit()
    _auth_as(monkeypatch, user)

    resp = await client.post(
        "/api/messaging/provider-accounts",
        json={"provider": "hostpinnacle", "label": "Mine",
              "credentials": {"userid": "u", "password": "p"}},
    )
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reseller_can_add_and_use_a_gateway_once_enabled(client, db, monkeypatch):
    db.add(MessagingSettings(id=1, allow_reseller_gateways=True))
    user = await make_reseller(db)
    await db.commit()
    _auth_as(monkeypatch, user)

    resp = await client.post(
        "/api/messaging/provider-accounts",
        json={"provider": "hostpinnacle", "label": "Mine",
              "sender_id": "DUKESTOP",
              "credentials": {"userid": "dukestop", "password": "d0vEaW5n"}},
    )
    assert resp.status_code == 200, resp.text
    account = resp.json()["account"]
    assert account["user_id"] == user.id
    assert account["scope"] == "reseller"
    # The secret never comes back in plaintext.
    assert account["credentials"]["password"] != "d0vEaW5n"
    assert "d0vEaW5n" not in resp.text

    listed = await client.get("/api/messaging/provider-accounts")
    body = listed.json()
    assert [a["id"] for a in body["accounts"]] == [account["id"]]
    assert body["effective"]["source"] == "reseller"
    assert body["effective"]["provider"] == "hostpinnacle"
    assert body["effective"]["sender_id"] == "DUKESTOP"


@pytest.mark.asyncio
async def test_reseller_may_read_a_gateway_an_admin_set_up_while_off(client, db, monkeypatch):
    """Self-service off still lets a reseller see what they are sending on."""
    db.add(MessagingSettings(id=1, allow_reseller_gateways=False))
    user = await make_reseller(db)
    await _own_account(db, user)
    await db.commit()
    _auth_as(monkeypatch, user)

    resp = await client.get("/api/messaging/provider-accounts")
    assert resp.status_code == 200
    body = resp.json()
    assert body["self_service_enabled"] is False
    assert len(body["accounts"]) == 1
    assert body["effective"]["source"] == "reseller"


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_reseller_never_sees_another_tenants_gateway(client, db, monkeypatch):
    db.add(MessagingSettings(id=1, allow_reseller_gateways=True))
    mine = await make_reseller(db)
    theirs = await make_reseller(db)
    await _own_account(db, theirs, label="Their gateway")
    db.add(MessagingProviderAccount(
        user_id=None, provider="talksasa", label="Platform",
        credentials=accounts.encrypt_config(
            registry.get_spec("talksasa"), {"api_token": "t"}
        ),
        is_default=True, is_active=True,
    ))
    await db.commit()
    _auth_as(monkeypatch, mine)

    resp = await client.get("/api/messaging/provider-accounts")
    assert resp.json()["accounts"] == []


@pytest.mark.asyncio
async def test_a_reseller_cannot_edit_another_tenants_gateway(client, db, monkeypatch):
    db.add(MessagingSettings(id=1, allow_reseller_gateways=True))
    mine = await make_reseller(db)
    theirs = await make_reseller(db)
    other = await _own_account(db, theirs)
    await db.commit()
    _auth_as(monkeypatch, mine)

    for call in (
        client.put(f"/api/messaging/provider-accounts/{other.id}",
                   json={"label": "hijacked"}, ),
        client.delete(f"/api/messaging/provider-accounts/{other.id}",
                      ),
        client.post(f"/api/messaging/provider-accounts/{other.id}/test",
                    json={"phone": "254712345678"}, ),
    ):
        resp = await call
        # 404, not 403 — a reseller must not learn that the id exists.
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_a_reseller_cannot_touch_the_platform_gateway(client, db, monkeypatch):
    db.add(MessagingSettings(id=1, allow_reseller_gateways=True))
    user = await make_reseller(db)
    platform = MessagingProviderAccount(
        user_id=None, provider="talksasa", label="Platform",
        credentials=accounts.encrypt_config(
            registry.get_spec("talksasa"), {"api_token": "t"}
        ),
        is_default=True, is_active=True,
    )
    db.add(platform)
    await db.flush()
    await db.commit()
    _auth_as(monkeypatch, user)

    resp = await client.put(f"/api/messaging/provider-accounts/{platform.id}",
                            json={"label": "hijacked"})
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_deactivating_own_gateway_falls_back_to_the_platform(client, db, monkeypatch):
    db.add(MessagingSettings(id=1, allow_reseller_gateways=True))
    user = await make_reseller(db)
    mine = await _own_account(db, user)
    db.add(MessagingProviderAccount(
        user_id=None, provider="talksasa", label="Platform",
        sender_id="PLATFORMSMS",
        credentials=accounts.encrypt_config(
            registry.get_spec("talksasa"), {"api_token": "t"}
        ),
        is_default=True, is_active=True,
    ))
    await db.commit()
    _auth_as(monkeypatch, user)

    resp = await client.delete(f"/api/messaging/provider-accounts/{mine.id}")
    assert resp.status_code == 200

    listed = await client.get("/api/messaging/provider-accounts")
    assert listed.json()["effective"]["source"] == "platform"
