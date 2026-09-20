"""Portal credits are not charged for sends that go out on a reseller's own gateway."""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.messaging_routes as mr
from app.api.messaging_routes import router as messaging_router
from app.db.database import get_db
from app.services.auth import verify_token
from app.db.models import (
    MessagingProviderAccount,
    MessagingSettings,
    SmsCampaign,
    SmsMessage,
)
from app.services import sms_credits
from app.services.messaging import accounts, registry
from tests.factories import (
    make_customer, make_plan, make_reseller, make_sms_account,
)


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
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user

    monkeypatch.setattr(mr, "get_current_user", _fake)


async def _own_gateway(db, user):
    account = MessagingProviderAccount(
        user_id=user.id,
        provider="hostpinnacle",
        label="Own gateway",
        sender_id="DUKESTOP",
        credentials=accounts.encrypt_config(
            registry.get_spec("hostpinnacle"),
            {"userid": "dukestop", "password": "secret"},
        ),
        is_default=True,
        is_active=True,
    )
    db.add(account)
    await db.flush()
    return account


# ---------------------------------------------------------------------------
# The decision itself
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_platform_gateway_still_bills_credits(db):
    user = await make_reseller(db)
    assert await accounts.bills_platform_credits(db, user.id) is True


@pytest.mark.asyncio
async def test_own_gateway_does_not_bill_credits(db):
    user = await make_reseller(db)
    await _own_gateway(db, user)
    assert await accounts.bills_platform_credits(db, user.id) is False


@pytest.mark.asyncio
async def test_deactivating_own_gateway_restores_billing(db):
    """Switching back to the platform gateway resumes portal charging."""
    user = await make_reseller(db)
    account = await _own_gateway(db, user)
    assert await accounts.bills_platform_credits(db, user.id) is False

    account.is_active = False
    await db.flush()
    assert await accounts.bills_platform_credits(db, user.id) is True


@pytest.mark.asyncio
async def test_a_reseller_gateway_does_not_affect_another_reseller(db):
    mine = await make_reseller(db)
    theirs = await make_reseller(db)
    await _own_gateway(db, theirs)
    assert await accounts.bills_platform_credits(db, mine.id) is True
    assert await accounts.bills_platform_credits(db, theirs.id) is False


@pytest.mark.asyncio
async def test_platform_account_alone_still_bills_resellers(db):
    """The platform's own gateway row must not zero-rate everyone."""
    user = await make_reseller(db)
    db.add(MessagingProviderAccount(
        user_id=None, provider="talksasa", label="Platform",
        credentials=accounts.encrypt_config(
            registry.get_spec("talksasa"), {"api_token": "t"}
        ),
        is_default=True, is_active=True,
    ))
    await db.flush()
    assert await accounts.bills_platform_credits(db, user.id) is True


# ---------------------------------------------------------------------------
# What the credits screen is told
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gateway_summary_reports_the_platform(db):
    user = await make_reseller(db)
    summary = await accounts.gateway_summary(db, user.id)
    assert summary["source"] == "platform"
    assert summary["bills_platform_credits"] is True


@pytest.mark.asyncio
async def test_gateway_summary_reports_the_resellers_own(db):
    user = await make_reseller(db)
    account = await _own_gateway(db, user)
    summary = await accounts.gateway_summary(db, user.id)
    assert summary["source"] == "reseller"
    assert summary["provider"] == "hostpinnacle"
    assert summary["provider_label"] == "HostPinnacle Kenya"
    assert summary["sender_id"] == "DUKESTOP"
    assert summary["account_id"] == account.id
    assert summary["bills_platform_credits"] is False


@pytest.mark.asyncio
async def test_gateway_summary_survives_an_uninstalled_provider(db):
    """A stale provider name must not break the credits endpoint."""
    user = await make_reseller(db)
    db.add(MessagingProviderAccount(
        user_id=user.id, provider="gone-away", label="Stale",
        credentials={}, is_default=True, is_active=True,
    ))
    await db.flush()
    summary = await accounts.gateway_summary(db, user.id)
    assert summary["source"] == "reseller"
    assert summary["provider_label"] == "gone-away"


# ---------------------------------------------------------------------------
# End to end through the campaign send path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_own_gateway_send_costs_no_credits_and_ignores_balance(
    db, client, monkeypatch
):
    """The whole point: zero balance, own gateway, the send still goes out."""
    user = await make_reseller(db)
    _auth_as(monkeypatch, user)
    plan = await make_plan(db, user)
    await make_customer(db, user, plan, phone="254700000301")
    await make_sms_account(db, user, balance=0)
    await _own_gateway(db, user)
    db.add(MessagingSettings(id=1))
    await db.commit()

    async def _fake_dispatch(cid):
        return None

    monkeypatch.setattr(mr.sms_dispatch, "dispatch_campaign", _fake_dispatch)
    resp = await client.post("/api/messaging/send",
                             json={"body": "Hi", "filter": "all"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["credits_reserved"] == 0

    acct = await sms_credits.get_or_create_account(db, user.id)
    assert acct.balance == 0
    assert acct.total_spent == 0

    camp = await db.get(SmsCampaign, resp.json()["campaign_id"])
    assert camp.total_credits == 0
    rows = (await db.execute(
        select(SmsMessage).where(SmsMessage.campaign_id == camp.id)
    )).scalars().all()
    assert rows
    assert all(r.credits_charged == 0 for r in rows)
    # Segments stay factual even when they cost nothing.
    assert all(r.segments >= 1 for r in rows)


@pytest.mark.asyncio
async def test_platform_gateway_send_still_charges(db, client, monkeypatch):
    user = await make_reseller(db)
    _auth_as(monkeypatch, user)
    plan = await make_plan(db, user)
    await make_customer(db, user, plan, phone="254700000302")
    await make_sms_account(db, user, balance=10)
    db.add(MessagingSettings(id=1))
    await db.commit()

    async def _fake_dispatch(cid):
        return None

    monkeypatch.setattr(mr.sms_dispatch, "dispatch_campaign", _fake_dispatch)
    resp = await client.post("/api/messaging/send",
                             json={"body": "Hi", "filter": "all"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["credits_reserved"] == 1
    acct = await sms_credits.get_or_create_account(db, user.id)
    assert acct.balance == 9


@pytest.mark.asyncio
async def test_platform_gateway_send_still_gated_by_balance(db, client, monkeypatch):
    user = await make_reseller(db)
    _auth_as(monkeypatch, user)
    plan = await make_plan(db, user)
    await make_customer(db, user, plan, phone="254700000303")
    await make_sms_account(db, user, balance=0)
    db.add(MessagingSettings(id=1))
    await db.commit()

    resp = await client.post("/api/messaging/send",
                             json={"body": "Hi", "filter": "all"})
    assert resp.status_code == 400
    assert "Insufficient" in str(resp.json()["detail"])


@pytest.mark.asyncio
async def test_credits_endpoint_says_which_gateway_is_in_use(db, client, monkeypatch):
    user = await make_reseller(db)
    _auth_as(monkeypatch, user)
    await make_sms_account(db, user, balance=5)
    db.add(MessagingSettings(id=1))
    await db.commit()

    body = (await client.get("/api/messaging/credits")).json()
    assert body["bills_platform_credits"] is True
    assert body["gateway"]["source"] == "platform"

    await _own_gateway(db, user)
    await db.commit()

    body = (await client.get("/api/messaging/credits")).json()
    assert body["bills_platform_credits"] is False
    assert body["gateway"]["source"] == "reseller"
    assert body["gateway"]["provider_label"] == "HostPinnacle Kenya"
