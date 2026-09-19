"""Automatic verification of card subscription payments with Paystack.

Money path. Pins that a card payment activates a reseller ONLY when Paystack
(queried with the account's secret key) reports success for the exact amount
and currency, that it activates at most once whichever trigger fires
(return-from-checkout, webhook, background job), and that nothing changes
when no key is configured (admin confirmation keeps working).
"""

import hashlib
import hmac
import json
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.subscription_routes as sr
import app.services.paystack as paystack
from app.config import settings
from app.db.database import get_db
from app.db.models import (
    InvoiceStatus,
    SubscriptionInvoice,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
    SubscriptionStatus,
    User,
)
from app.services.auth import verify_token
from app.services.card_payments import reconcile_card_payment, reconcile_pending_card_payments
from tests.factories import make_reseller

KEY = "sk_test_local_only"


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setattr(settings, "PAYSTACK_SECRET_KEY", KEY)


def _paystack_answers(monkeypatch, answers: dict):
    """answers: reference -> Paystack transaction data (or None = unknown)."""
    calls = []

    async def _verify(reference):
        calls.append(reference)
        return answers.get(reference)

    monkeypatch.setattr(paystack, "verify_transaction", _verify)
    return calls


async def _reseller_with_card_payment(db, *, amount=10.0, currency="USD", created_at=None,
                                      provider_ref="PAF-ABC123", our_ref="SUBCARD-1-deadbeef"):
    expires = datetime.utcnow() + timedelta(days=3)
    reseller = await make_reseller(db, market_code="CM", subscription_status=SubscriptionStatus.TRIAL,
                                   subscription_expires_at=expires)
    invoice = SubscriptionInvoice(
        user_id=reseller.id, period_start=datetime.utcnow() - timedelta(days=26),
        period_end=datetime.utcnow(), final_charge=amount, gross_charge=amount,
        currency=currency, status=InvoiceStatus.PENDING, due_date=expires,
    )
    db.add(invoice)
    await db.flush()
    payment = SubscriptionPayment(
        invoice_id=invoice.id, user_id=reseller.id, amount=amount, currency=currency,
        payment_method="card", status=SubscriptionPaymentStatus.PENDING,
        provider_reference=provider_ref, payment_reference=our_ref,
        created_at=created_at or datetime.utcnow() - timedelta(minutes=5),
    )
    db.add(payment)
    await db.commit()
    return reseller, invoice, payment, expires


def _success(ref="PAF-ABC123", amount_minor=1000, currency="USD"):
    return {"status": "success", "reference": ref, "amount": amount_minor, "currency": currency, "id": 42}


async def _state(session_factory, reseller_id, invoice_id, payment_id):
    async with session_factory() as s:
        user = await s.get(User, reseller_id)
        inv = await s.get(SubscriptionInvoice, invoice_id)
        pay = await s.get(SubscriptionPayment, payment_id)
        return user, inv, pay


@pytest.mark.asyncio
async def test_without_key_nothing_changes(db, monkeypatch, session_factory):
    monkeypatch.setattr(settings, "PAYSTACK_SECRET_KEY", "")
    reseller, invoice, payment, _ = await _reseller_with_card_payment(db)
    calls = _paystack_answers(monkeypatch, {"PAF-ABC123": _success()})

    assert await reconcile_card_payment(payment.id) == "not_configured"
    assert (await reconcile_pending_card_payments()) == {"skipped": True}
    assert calls == []
    _, _, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.PENDING


@pytest.mark.asyncio
async def test_paystack_success_activates_once(db, key, monkeypatch, session_factory):
    reseller, invoice, payment, expires = await _reseller_with_card_payment(db)
    _paystack_answers(monkeypatch, {"PAF-ABC123": _success()})

    assert await reconcile_card_payment(payment.id) == "completed"
    user, inv, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.COMPLETED
    assert pay.payment_reference == "PAYSTACK-PAF-ABC123"
    assert inv.status == InvoiceStatus.PAID
    assert user.subscription_status == SubscriptionStatus.ACTIVE
    first_expiry = user.subscription_expires_at
    assert first_expiry > expires

    # Every later trigger is a no-op: no second month.
    assert await reconcile_card_payment(payment.id) == "already_completed"
    await reconcile_pending_card_payments()
    user, _, _ = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert user.subscription_expires_at == first_expiry


@pytest.mark.asyncio
@pytest.mark.parametrize("amount_minor,currency", [(500, "USD"), (1000, "KES"), (100, "USD")])
async def test_wrong_amount_or_currency_never_activates(db, key, monkeypatch, session_factory,
                                                        amount_minor, currency):
    reseller, invoice, payment, _ = await _reseller_with_card_payment(db)
    _paystack_answers(monkeypatch, {"PAF-ABC123": _success(amount_minor=amount_minor, currency=currency)})

    assert await reconcile_card_payment(payment.id) == "mismatch"
    user, inv, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.PENDING
    assert inv.status == InvoiceStatus.PENDING
    assert user.subscription_status == SubscriptionStatus.TRIAL


@pytest.mark.asyncio
async def test_falls_back_to_our_reference(db, key, monkeypatch, session_factory):
    reseller, invoice, payment, _ = await _reseller_with_card_payment(db)
    calls = _paystack_answers(monkeypatch, {"PAF-ABC123": None,
                                            "SUBCARD-1-deadbeef": _success(ref="SUBCARD-1-deadbeef")})

    assert await reconcile_card_payment(payment.id) == "completed"
    assert calls == ["PAF-ABC123", "SUBCARD-1-deadbeef"]


@pytest.mark.asyncio
async def test_failed_and_abandoned(db, key, monkeypatch, session_factory):
    _, _, failed_payment, _ = await _reseller_with_card_payment(db, provider_ref="PAF-F", our_ref="SUBCARD-F")
    _, _, abandoned, _ = await _reseller_with_card_payment(db, provider_ref="PAF-A", our_ref="SUBCARD-A")
    _paystack_answers(monkeypatch, {
        "PAF-F": {"status": "failed", "reference": "PAF-F", "amount": 1000, "currency": "USD"},
        "PAF-A": {"status": "abandoned", "reference": "PAF-A", "amount": 1000, "currency": "USD"},
    })

    assert await reconcile_card_payment(failed_payment.id) == "failed"
    assert await reconcile_card_payment(abandoned.id) == "pending"


@pytest.mark.asyncio
async def test_unpaid_checkout_expires_after_48h(db, key, monkeypatch, session_factory):
    reseller, invoice, payment, _ = await _reseller_with_card_payment(
        db, created_at=datetime.utcnow() - timedelta(hours=49))
    _paystack_answers(monkeypatch, {})

    assert await reconcile_card_payment(payment.id) == "expired"
    _, inv, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.FAILED
    assert inv.status == InvoiceStatus.PENDING  # still payable with a new checkout


@pytest.mark.asyncio
async def test_background_job_completes_pending(db, key, monkeypatch, session_factory):
    reseller, invoice, payment, _ = await _reseller_with_card_payment(db)
    _paystack_answers(monkeypatch, {"PAF-ABC123": _success()})

    result = await reconcile_pending_card_payments()
    assert result["results"] == {"completed": 1}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(sr.router)

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
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(sr, "get_current_user", _fake)


@pytest.mark.asyncio
async def test_return_from_checkout_activates(db, key, client, monkeypatch, session_factory):
    reseller, invoice, payment, _ = await _reseller_with_card_payment(db)
    _paystack_answers(monkeypatch, {"PAF-ABC123": _success()})
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/subscription/pay-card/verify")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["auto_verify"] is True and body["activated"] is True
    assert body["subscription_status"] == "active"


@pytest.mark.asyncio
async def test_return_without_key_reports_manual(db, client, monkeypatch):
    monkeypatch.setattr(settings, "PAYSTACK_SECRET_KEY", "")
    reseller, _, _, _ = await _reseller_with_card_payment(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/subscription/pay-card/verify")

    assert resp.json() == {"auto_verify": False, "results": {}, "activated": False}


def _sign(body: bytes) -> str:
    return hmac.new(KEY.encode(), body, hashlib.sha512).hexdigest()


@pytest.mark.asyncio
async def test_webhook_rejects_bad_signature(db, key, client, monkeypatch, session_factory):
    reseller, invoice, payment, _ = await _reseller_with_card_payment(db)
    calls = _paystack_answers(monkeypatch, {"PAF-ABC123": _success()})
    body = json.dumps({"event": "charge.success", "data": {"reference": "PAF-ABC123"}}).encode()

    resp = await client.post("/api/paystack/webhook", content=body,
                             headers={"x-paystack-signature": "forged"})

    assert resp.status_code == 401
    assert calls == []
    _, _, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.PENDING


@pytest.mark.asyncio
async def test_signed_webhook_reverifies_then_activates(db, key, client, monkeypatch, session_factory):
    reseller, invoice, payment, _ = await _reseller_with_card_payment(db)
    calls = _paystack_answers(monkeypatch, {"PAF-ABC123": _success()})
    body = json.dumps({"event": "charge.success", "data": {"reference": "PAF-ABC123"}}).encode()

    resp = await client.post("/api/paystack/webhook", content=body,
                             headers={"x-paystack-signature": _sign(body)})

    assert resp.status_code == 200
    assert calls == ["PAF-ABC123"]  # the event is re-verified via the API
    user, _, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.COMPLETED
    assert user.subscription_status == SubscriptionStatus.ACTIVE


# ---------------------------------------------------------------------------
# Paystack HTTP client
# ---------------------------------------------------------------------------

def _mock_paystack_http(monkeypatch, handler):
    import httpx
    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(paystack.httpx, "AsyncClient", _factory)


@pytest.mark.asyncio
async def test_verify_transaction_sends_key_and_parses(key, monkeypatch):
    import httpx
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"status": True, "data": {"status": "success", "amount": 1000}})

    _mock_paystack_http(monkeypatch, handler)
    data = await paystack.verify_transaction("PAF-XYZ")
    assert data == {"status": "success", "amount": 1000}
    assert seen["url"] == "https://api.paystack.co/transaction/verify/PAF-XYZ"
    assert seen["auth"] == f"Bearer {KEY}"


@pytest.mark.asyncio
async def test_verify_transaction_unknown_reference_is_none(key, monkeypatch):
    import httpx
    _mock_paystack_http(monkeypatch, lambda r: httpx.Response(
        400, json={"status": False, "message": "Transaction reference not found"}))
    assert await paystack.verify_transaction("nope") is None


@pytest.mark.asyncio
async def test_verify_transaction_server_error_raises(key, monkeypatch):
    import httpx
    _mock_paystack_http(monkeypatch, lambda r: httpx.Response(500, json={}))
    with pytest.raises(paystack.PaystackError):
        await paystack.verify_transaction("PAF-XYZ")


def test_minor_units():
    assert paystack.to_minor_units(10) == 1000
    assert paystack.to_minor_units(10.5) == 1050
    assert paystack.to_minor_units("8.36") == 836
