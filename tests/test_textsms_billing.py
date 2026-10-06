"""Portal credits on a real campaign sent through TextSMS, queue to settlement.

Covers both billing cases end to end through `/api/messaging/send` and
`dispatch_campaign`, with real account resolution and only the HTTP call
faked:

* a reseller on their own TextSMS account pays no portal credits, even with a
  zero balance, and a failed recipient is not "refunded" credits it never paid
* a reseller on the platform gateway (which is TextSMS) is charged, and the
  failed recipient's credit comes back
"""

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.messaging_routes as mr
from app.api.messaging_routes import router as messaging_router
from app.db.database import get_db
from app.db.models import (
    MessagingProviderAccount,
    MessagingSettings,
    SmsCampaign,
    SmsMessage,
    SmsMessageStatus,
)
from app.services import sms_credits, sms_dispatch
from app.services.auth import verify_token
from app.services.messaging import accounts, registry
from tests.factories import make_customer, make_plan, make_reseller, make_sms_account

OK_PHONE = "254700000401"
LOW_CREDIT_PHONE = "254700000402"


@pytest_asyncio.fixture
async def client(session_factory):
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
    async with AsyncClient(transport=ASGITransport(app=application),
                           base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user

    monkeypatch.setattr(mr, "get_current_user", _fake)


def _fake_textsms(monkeypatch):
    """TextSMS accepts OK_PHONE and rejects LOW_CREDIT_PHONE with code 1004."""
    calls = []

    class _Resp:
        status_code = 200

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            calls.append({"url": url, "json": json})
            rows = []
            for m in json["smslist"]:
                if m["mobile"] == OK_PHONE:
                    rows.append({"respose-code": 200, "response-description": "Success",
                                 "mobile": m["mobile"], "messageid": 555,
                                 "clientsmsid": m["clientsmsid"]})
                else:
                    rows.append({"respose-code": 1004,
                                 "response-description": "Low bulk credits",
                                 "mobile": m["mobile"], "clientsmsid": m["clientsmsid"]})
            return _Resp({"responses": rows})

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    return calls


async def _textsms_account(db, user_id, sender_id):
    account = MessagingProviderAccount(
        user_id=user_id,
        provider="textsms",
        label="TextSMS",
        sender_id=sender_id,
        credentials=accounts.encrypt_config(
            registry.get_spec("textsms"),
            {"api_key": f"key-{sender_id}", "partner_id": "77"},
        ),
        is_default=True,
        is_active=True,
    )
    db.add(account)
    await db.flush()
    return account


async def _send_campaign(db, client, session_factory, monkeypatch, user):
    plan = await make_plan(db, user)
    await make_customer(db, user, plan, phone=OK_PHONE)
    await make_customer(db, user, plan, phone=LOW_CREDIT_PHONE)
    db.add(MessagingSettings(id=1))
    await db.commit()

    # Queue through the API, but run the dispatcher ourselves so the test can
    # await it (it is a background task in the route).
    real_dispatch = sms_dispatch.dispatch_campaign
    queued = []

    async def _capture(campaign_id):
        queued.append(campaign_id)

    monkeypatch.setattr(sms_dispatch, "dispatch_campaign", _capture)
    resp = await client.post("/api/messaging/send",
                             json={"body": "Your plan expires soon", "filter": "all"})
    assert resp.status_code == 200, resp.text
    assert len(queued) == 1

    # The real dispatcher, with real account resolution.
    monkeypatch.setattr(sms_dispatch, "async_session", session_factory)
    await real_dispatch(queued[0])
    return resp.json(), queued[0]


async def _rows(session_factory, campaign_id):
    async with session_factory() as s:
        camp = await s.get(SmsCampaign, campaign_id)
        rows = (await s.execute(
            select(SmsMessage).where(SmsMessage.campaign_id == campaign_id)
        )).scalars().all()
        return camp, {r.recipient_phone: r for r in rows}


@pytest.mark.asyncio
async def test_own_textsms_gateway_costs_no_credits_end_to_end(
    db, client, session_factory, monkeypatch
):
    user = await make_reseller(db)
    _auth_as(monkeypatch, user)
    await make_sms_account(db, user, balance=0)
    account = await _textsms_account(db, user.id, "DEMOISP")
    calls = _fake_textsms(monkeypatch)

    body, campaign_id = await _send_campaign(db, client, session_factory, monkeypatch, user)
    assert body["credits_reserved"] == 0

    # It went out on the reseller's own TextSMS account and sender ID.
    assert len(calls) == 1
    sent = calls[0]["json"]["smslist"]
    assert {m["shortcode"] for m in sent} == {"DEMOISP"}
    assert {m["apikey"] for m in sent} == {"key-DEMOISP"}

    camp, rows = await _rows(session_factory, campaign_id)
    assert rows[OK_PHONE].status == SmsMessageStatus.SENT
    assert rows[LOW_CREDIT_PHONE].status == SmsMessageStatus.FAILED
    assert rows[LOW_CREDIT_PHONE].error == "Low bulk credits"
    assert all(r.provider == "textsms" for r in rows.values())
    assert all(r.provider_account_id == account.id for r in rows.values())
    assert all(r.credits_charged == 0 for r in rows.values())

    # Nothing charged, so nothing to refund: the balance never moves.
    assert camp.total_credits == 0
    assert camp.refunded_credits == 0
    async with session_factory() as s:
        acct = await sms_credits.get_or_create_account(s, user.id)
        assert acct.balance == 0
        assert acct.total_spent == 0


@pytest.mark.asyncio
async def test_platform_textsms_gateway_charges_and_refunds_failures(
    db, client, session_factory, monkeypatch
):
    user = await make_reseller(db)
    _auth_as(monkeypatch, user)
    await make_sms_account(db, user, balance=10)
    platform = await _textsms_account(db, None, "BITWAVE")
    calls = _fake_textsms(monkeypatch)

    body, campaign_id = await _send_campaign(db, client, session_factory, monkeypatch, user)
    assert body["credits_reserved"] == 2

    sent = calls[0]["json"]["smslist"]
    assert {m["shortcode"] for m in sent} == {"BITWAVE"}

    camp, rows = await _rows(session_factory, campaign_id)
    assert rows[OK_PHONE].status == SmsMessageStatus.SENT
    assert rows[LOW_CREDIT_PHONE].status == SmsMessageStatus.FAILED
    assert all(r.provider_account_id == platform.id for r in rows.values())

    # Two reserved, the failed one refunded: 10 - 2 + 1.
    assert camp.total_credits == 2
    assert camp.refunded_credits == 1
    async with session_factory() as s:
        acct = await sms_credits.get_or_create_account(s, user.id)
        assert acct.balance == 9
