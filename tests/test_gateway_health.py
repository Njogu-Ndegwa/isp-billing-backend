"""SMS gateway status: failure reasons, live balance, health state, alerts.

The scenario these guard is real: on 2026-10-08 a reseller's TextSMS key
stopped working, every message failed with "Invalid credentials" for two
days, and the reseller only saw "0 portal credits" with no reason.
"""

from datetime import datetime, timedelta

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
    ResellerInboxMessage,
    SmsCampaign,
    SmsCampaignStatus,
    SmsMessage,
    SmsMessageKind,
    SmsMessageStatus,
)
from app.services.auth import verify_token
from app.services.messaging import accounts, gateway_health, registry
from app.services.messaging.base import BalanceResult, parse_amount
from app.services.messaging.failure_reasons import classify, describe
from app.services.messaging.textsms import TextSmsProvider
from app.services.messaging.africas_talking import AfricasTalkingProvider
from tests.factories import make_admin, make_reseller


@pytest.fixture(autouse=True)
def _clear_balance_cache():
    gateway_health._balance_cache.clear()
    yield
    gateway_health._balance_cache.clear()


# ---------------------------------------------------------------------------
# Failure reasons — every string below was seen in production sms_messages
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("error,code,severity", [
    ("Invalid credentials", "invalid_credentials", "blocking"),
    ("You have exceeded your sending limit.", "sending_limit", "blocking"),
    ("Pricing configuration is required. Please configure pricing with sending "
     "server in your account", "account_setup", "blocking"),
    ("fwrite(): write of 138 bytes failed with errno=28 No space left on device",
     "provider_error", "temporary"),
    ("Service Unavailable", "provider_error", "temporary"),
    ("An unexpected error occurred. Please try again.", "provider_error", "temporary"),
    ("254254797842377 is a invalid phone number", "invalid_recipient", "per_message"),
    ("missing_api_token", "config_incomplete", "blocking"),
    ("missing_sender_id", "sender_id", "blocking"),
    ("no_response", "no_response", "temporary"),
    ("network_error: ConnectTimeout", "network", "temporary"),
    ("The supplied authentication is invalid", "invalid_credentials", "blocking"),
    ("low_credits", "low_balance", "blocking"),
    (None, "no_response", "temporary"),
    ("something nobody has seen", "unknown", "temporary"),
])
def test_classify_production_errors(error, code, severity):
    reason = classify(error)
    assert reason.code == code
    assert reason.severity == severity


def test_describe_names_own_provider_and_keeps_raw_error():
    out = describe("Invalid credentials", own_gateway=True, provider_label="TextSMS Kenya")
    assert out["code"] == "invalid_credentials"
    assert out["explanation"].startswith("TextSMS Kenya refused")
    assert "TextSMS Kenya dashboard" in out["action"]
    assert out["raw_error"] == "Invalid credentials"


def test_describe_platform_failure_points_to_support_not_the_reseller():
    out = describe("Invalid credentials", own_gateway=False)
    assert out["code"] == "invalid_credentials"  # still grouped by cause
    assert out["title"] == "Platform SMS gateway problem"
    assert "on our side" in out["action"]
    assert "API key" not in out["action"]
    assert "login" not in out["explanation"]
    # A bad phone number is still the reseller's to fix on any gateway.
    phone = describe("0712 is a invalid phone number", own_gateway=False)
    assert phone["code"] == "invalid_recipient"
    assert "Correct the customer's phone number" in phone["action"]


@pytest.mark.parametrize("value,amount,unit", [
    ("800.00", 800.0, None),
    (800, 800.0, None),
    ("1,234.5", 1234.5, None),
    ("KES 1785.50", 1785.5, "KES"),
    ("$9,999", 9999.0, "$"),
    ("-5", -5.0, None),
    ("n/a", None, None),
    (None, None, None),
])
def test_parse_amount(value, amount, unit):
    assert parse_amount(value) == (amount, unit)


# ---------------------------------------------------------------------------
# Provider balance calls
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, status_code, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else str(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def _fake_client(response, captured):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            captured.append({"url": url, "json": json})
            if isinstance(response, Exception):
                raise response
            return response

        async def get(self, url, params=None, headers=None):
            captured.append({"url": url, "params": params, "headers": headers})
            if isinstance(response, Exception):
                raise response
            return response

    return _Client


@pytest.mark.asyncio
async def test_textsms_balance_success(monkeypatch):
    captured = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(
        _Resp(200, {"response-code": 200, "credit": "800.00", "partner-id": "77"}), captured))
    result = await TextSmsProvider("key", "77", "https://sms.example/").get_balance()
    assert result.ok and result.balance == 800.0
    assert captured[0]["url"] == "https://sms.example/api/services/getbalance/"
    assert captured[0]["json"] == {"apikey": "key", "partnerID": "77"}


@pytest.mark.asyncio
async def test_textsms_balance_invalid_credentials(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(
        _Resp(200, {"response-code": 1006, "response-description": "Invalid credentials"}), []))
    result = await TextSmsProvider("old-key", "77").get_balance()
    assert not result.ok
    assert result.error == "Invalid credentials"
    assert classify(result.error).code == "invalid_credentials"


@pytest.mark.asyncio
async def test_textsms_balance_network_failure(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(httpx.ConnectTimeout("slow"), []))
    result = await TextSmsProvider("key", "77").get_balance()
    assert not result.ok and result.error.startswith("network_error")


@pytest.mark.asyncio
async def test_textsms_balance_missing_config_makes_no_call(monkeypatch):
    captured = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(_Resp(200, {}), captured))
    result = await TextSmsProvider("", "77").get_balance()
    assert result.error == "missing_api_key" and captured == []


@pytest.mark.asyncio
async def test_africastalking_balance(monkeypatch):
    captured = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(
        _Resp(200, {"UserData": {"balance": "KES 1785.50"}}), captured))
    result = await AfricasTalkingProvider("acme", "k", "https://api.example").get_balance()
    assert result.ok and result.balance == 1785.5 and result.unit == "KES"
    assert captured[0]["params"] == {"username": "acme"}


@pytest.mark.asyncio
async def test_africastalking_balance_bad_key(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(
        _Resp(401, None, text="The supplied authentication is invalid"), []))
    result = await AfricasTalkingProvider("acme", "bad", "https://api.example").get_balance()
    assert not result.ok
    assert classify(result.error).code == "invalid_credentials"


def test_balance_support_is_declared():
    registry.reset_cache()
    assert TextSmsProvider.supports_balance
    assert AfricasTalkingProvider.supports_balance
    assert not registry.get_spec("hostpinnacle").factory.supports_balance


# ---------------------------------------------------------------------------
# Health from message history
# ---------------------------------------------------------------------------

async def _textsms_account(db, user, *, updated_at=None, api_key="k"):
    account = MessagingProviderAccount(
        user_id=user.id, provider="textsms", label="TextSMS Kenya gateway",
        sender_id="Techmid",
        credentials=accounts.encrypt_config(
            registry.get_spec("textsms"), {"api_key": api_key, "partner_id": "77"}),
        is_default=True, is_active=True,
    )
    db.add(account)
    await db.flush()
    stamp = updated_at or (datetime.utcnow() - timedelta(days=5))
    account.created_at = stamp
    account.updated_at = stamp
    await db.commit()
    return account


async def _msg(db, user, *, ago, ok, error=None, account=None,
               kind=SmsMessageKind.RESELLER_TO_CUSTOMER, category=None,
               campaign_id=None):
    row = SmsMessage(
        user_id=user.id, recipient_phone="254700000001", body="hi",
        segments=1, credits_charged=0, kind=kind, category=category,
        campaign_id=campaign_id,
        status=SmsMessageStatus.SENT if ok else SmsMessageStatus.FAILED,
        error=None if ok else error,
        provider="textsms" if account else "talksasa",
        provider_account_id=account.id if account else None,
        created_at=datetime.utcnow() - ago,
    )
    db.add(row)
    await db.commit()
    return row


@pytest.mark.asyncio
async def test_idle_when_nothing_sent(db):
    user = await make_reseller(db)
    report, provider, _ = await gateway_health.collect(db, user.id)
    assert report["health"]["state"] == "idle"
    assert report["gateway"]["source"] == "platform"
    assert report["balance"] == {"available": False, "unavailable_reason": "platform_gateway"}
    assert provider is None


@pytest.mark.asyncio
async def test_own_gateway_failing_with_invalid_credentials(db):
    """The Techmid case: worked for two days, then every send rejected."""
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    for hours in (60, 50, 40):
        await _msg(db, user, ago=timedelta(hours=hours), ok=True, account=account)
    for hours in (30, 20, 2):
        await _msg(db, user, ago=timedelta(hours=hours), ok=False,
                   error="Invalid credentials", account=account)

    report, provider, cache_key = await gateway_health.collect(db, user.id)
    health = report["health"]
    assert health["state"] == "failing"
    assert health["consecutive_failures"] == 3
    assert health["reason"]["code"] == "invalid_credentials"
    assert "TextSMS Kenya" in health["reason"]["action"]
    assert health["message"].startswith("Your last 3 messages have failed.")

    windows = report["metrics"]["windows"]
    assert windows["24h"] == {"sent": 0, "failed": 2, "total": 2, "success_rate": 0.0}
    assert windows["7d"]["sent"] == 3 and windows["7d"]["failed"] == 3
    assert report["failure_reasons"][0]["code"] == "invalid_credentials"
    assert report["failure_reasons"][0]["count"] == 3
    assert isinstance(provider, TextSmsProvider) and cache_key[0] == account.id


@pytest.mark.asyncio
async def test_settings_changed_after_failures_is_unverified(db):
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    await _msg(db, user, ago=timedelta(hours=3), ok=False,
               error="Invalid credentials", account=account)
    account.updated_at = datetime.utcnow() - timedelta(minutes=5)
    await db.commit()

    report, _, _ = await gateway_health.collect(db, user.id)
    assert report["health"]["state"] == "unverified"


@pytest.mark.asyncio
async def test_successful_test_send_clears_failing(db):
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    await _msg(db, user, ago=timedelta(hours=3), ok=False,
               error="Invalid credentials", account=account)
    account.last_test_at = datetime.utcnow() - timedelta(minutes=1)
    account.last_test_ok = True
    account.updated_at = account.last_test_at
    await db.commit()

    report, _, _ = await gateway_health.collect(db, user.id)
    # The failure is still in the last 24 h, but the newest evidence works.
    assert report["health"]["state"] == "degraded"


@pytest.mark.asyncio
async def test_bad_phone_numbers_do_not_mark_gateway_failing(db):
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    await _msg(db, user, ago=timedelta(hours=5), ok=True, account=account)
    for minutes in (30, 20, 10):
        await _msg(db, user, ago=timedelta(minutes=minutes), ok=False,
                   error="254254700 is a invalid phone number", account=account)
    report, _, _ = await gateway_health.collect(db, user.id)
    assert report["health"]["state"] == "ok"
    assert report["failure_reasons"][0]["code"] == "invalid_recipient"


@pytest.mark.asyncio
async def test_temporary_errors_need_a_run_before_failing(db):
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    await _msg(db, user, ago=timedelta(hours=5), ok=True, account=account)
    for minutes in (30, 20):
        await _msg(db, user, ago=timedelta(minutes=minutes), ok=False,
                   error="Service Unavailable", account=account)
    report, _, _ = await gateway_health.collect(db, user.id)
    assert report["health"]["state"] == "degraded"

    await _msg(db, user, ago=timedelta(minutes=5), ok=False,
               error="Service Unavailable", account=account)
    report, _, _ = await gateway_health.collect(db, user.id)
    assert report["health"]["state"] == "failing"
    assert report["health"]["reason"]["code"] == "provider_error"


@pytest.mark.asyncio
async def test_platform_gateway_failures_point_to_support(db):
    user = await make_reseller(db)
    await _msg(db, user, ago=timedelta(minutes=5), ok=False,
               error="Pricing configuration is required.")
    report, provider, _ = await gateway_health.collect(db, user.id)
    assert report["health"]["state"] == "failing"
    assert "on our side" in report["health"]["reason"]["action"]
    assert provider is None


@pytest.mark.asyncio
async def test_other_resellers_and_platform_sends_are_excluded(db):
    user = await make_reseller(db)
    other = await make_reseller(db)
    await _msg(db, other, ago=timedelta(minutes=5), ok=False, error="Invalid credentials")
    await _msg(db, user, ago=timedelta(minutes=5), ok=False, error="Invalid credentials",
               kind=SmsMessageKind.ADMIN_TO_RESELLER, category="reseller_welcome")
    report, _, _ = await gateway_health.collect(db, user.id)
    assert report["health"]["state"] == "idle"
    # Router alerts are billed to the reseller, so they do count.
    await _msg(db, user, ago=timedelta(minutes=1), ok=True,
               kind=SmsMessageKind.ADMIN_TO_RESELLER, category="router_status_alert")
    report, _, _ = await gateway_health.collect(db, user.id)
    assert report["metrics"]["windows"]["24h"]["sent"] == 1


# ---------------------------------------------------------------------------
# Live balance folded into health
# ---------------------------------------------------------------------------

def _stub_balance(monkeypatch, result, calls=None):
    async def _fake(self):
        if calls is not None:
            calls.append(1)
        return result
    monkeypatch.setattr(TextSmsProvider, "get_balance", _fake)


@pytest.mark.asyncio
async def test_status_reports_balance_and_caches_it(db, monkeypatch):
    user = await make_reseller(db)
    await _textsms_account(db, user)
    calls = []
    _stub_balance(monkeypatch, BalanceResult(ok=True, balance=412.0), calls)

    report = await gateway_health.status(db, user.id)
    assert report["balance"]["available"] and report["balance"]["balance"] == 412.0
    await gateway_health.status(db, user.id)
    assert len(calls) == 1  # cached
    await gateway_health.status(db, user.id, force_balance=True)
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_balance_check_rejection_marks_failing_before_any_send(db, monkeypatch):
    user = await make_reseller(db)
    await _textsms_account(db, user)
    _stub_balance(monkeypatch, BalanceResult(ok=False, error="Invalid credentials"))
    report = await gateway_health.status(db, user.id)
    assert report["health"]["state"] == "failing"
    assert report["health"]["reason"]["code"] == "invalid_credentials"
    assert report["balance"]["failure"]["code"] == "invalid_credentials"


@pytest.mark.asyncio
async def test_zero_balance_marks_failing(db, monkeypatch):
    user = await make_reseller(db)
    await _textsms_account(db, user)
    _stub_balance(monkeypatch, BalanceResult(ok=True, balance=0.0))
    report = await gateway_health.status(db, user.id)
    assert report["health"]["state"] == "failing"
    assert report["health"]["reason"]["code"] == "low_balance"


@pytest.mark.asyncio
async def test_working_key_downgrades_old_credential_failures(db, monkeypatch):
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    await _msg(db, user, ago=timedelta(hours=1), ok=False,
               error="Invalid credentials", account=account)
    _stub_balance(monkeypatch, BalanceResult(ok=True, balance=90.0))
    report = await gateway_health.status(db, user.id)
    assert report["health"]["state"] == "unverified"


@pytest.mark.asyncio
async def test_network_error_on_balance_does_not_change_state(db, monkeypatch):
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    await _msg(db, user, ago=timedelta(hours=1), ok=True, account=account)
    _stub_balance(monkeypatch, BalanceResult(ok=False, error="network_error: timeout"))
    report = await gateway_health.status(db, user.id)
    assert report["health"]["state"] == "ok"
    assert report["balance"]["ok"] is False


# ---------------------------------------------------------------------------
# Inbox alert, once per outage
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_alert_once_per_failure_episode(db):
    await make_admin(db)
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    await _msg(db, user, ago=timedelta(hours=2), ok=False,
               error="Invalid credentials", account=account)

    assert await gateway_health.alert_if_failing(user.id) is True
    assert await gateway_health.alert_if_failing(user.id) is False  # same outage

    rows = (await db.execute(select(ResellerInboxMessage).where(
        ResellerInboxMessage.recipient_user_id == user.id))).scalars().all()
    assert len(rows) == 1
    assert rows[0].subject == "SMS not sending: Gateway rejected your login"
    assert "Fix: Copy the current API key" in rows[0].body

    # It recovers, then breaks again: a new outage, a new alert.
    await _msg(db, user, ago=timedelta(minutes=30), ok=True, account=account)
    await _msg(db, user, ago=timedelta(minutes=10), ok=False,
               error="Invalid credentials", account=account)
    assert await gateway_health.alert_if_failing(user.id) is True


@pytest.mark.asyncio
async def test_no_alert_on_platform_gateway(db):
    await make_admin(db)
    user = await make_reseller(db)
    await _msg(db, user, ago=timedelta(minutes=5), ok=False, error="Invalid credentials")
    assert await gateway_health.alert_if_failing(user.id) is False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

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


@pytest.mark.asyncio
async def test_gateway_status_route(client, db, monkeypatch):
    user = await make_reseller(db)
    account = await _textsms_account(db, user, api_key="SUPERSECRET-API-KEY-9f3")
    await _msg(db, user, ago=timedelta(hours=1), ok=False,
               error="Invalid credentials", account=account)
    _stub_balance(monkeypatch, BalanceResult(ok=False, error="Invalid credentials"))
    _auth_as(monkeypatch, user)

    resp = await client.get("/api/messaging/gateway/status")
    assert "SUPERSECRET" not in resp.text
    assert resp.status_code == 200
    body = resp.json()
    assert body["health"]["state"] == "failing"
    assert body["gateway"]["provider"] == "textsms"
    assert body["gateway"]["sender_id"] == "Techmid"
    assert "credentials" not in body["gateway"]


@pytest.mark.asyncio
async def test_campaign_detail_explains_each_failure(client, db, monkeypatch):
    user = await make_reseller(db)
    account = await _textsms_account(db, user)
    camp = SmsCampaign(user_id=user.id, body="hi", recipient_count=2,
                       segments_per_message=1, total_credits=0,
                       status=SmsCampaignStatus.PARTIAL)
    db.add(camp)
    await db.commit()
    await _msg(db, user, ago=timedelta(minutes=2), ok=True, account=account,
               campaign_id=camp.id)
    await _msg(db, user, ago=timedelta(minutes=1), ok=False, error="Invalid credentials",
               account=account, campaign_id=camp.id)
    _auth_as(monkeypatch, user)

    resp = await client.get(f"/api/messaging/campaigns/{camp.id}")
    assert resp.status_code == 200
    body = resp.json()
    failed = [m for m in body["messages"] if m["status"] == "failed"]
    assert failed[0]["reason"]["code"] == "invalid_credentials"
    assert "TextSMS Kenya" in failed[0]["reason"]["action"]
    sent = [m for m in body["messages"] if m["status"] == "sent"]
    assert sent[0]["reason"] is None
    assert body["failure_reasons"] == [{
        "code": "invalid_credentials", "title": "Gateway rejected your login",
        "explanation": failed[0]["reason"]["explanation"],
        "action": failed[0]["reason"]["action"], "severity": "blocking", "count": 1,
    }]
