"""PayAfrica's payment webhook (money path).

A card payment activates a reseller only when the call carries the token we
derived for that payment AND the payload reports success for the right amount
and currency. Everything else is refused or ignored, and a replay never gives
a second month.
"""

import json
import secrets
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.subscription_routes as sr
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
from app.services.payafrica_webhook import (
    amount_matches, extract_outcome, webhook_token, webhook_url_for,
)
from tests.factories import make_reseller


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


async def _pending_card_payment(db, *, amount=10.0, currency="USD"):
    expires = datetime.utcnow() + timedelta(days=3)
    reseller = await make_reseller(db, market_code="CM", subscription_status=SubscriptionStatus.TRIAL,
                                   subscription_expires_at=expires)
    invoice = SubscriptionInvoice(
        user_id=reseller.id, period_start=datetime.utcnow() - timedelta(days=26),
        period_end=datetime.utcnow(), gross_charge=amount, final_charge=amount,
        currency=currency, status=InvoiceStatus.PENDING, due_date=expires,
    )
    db.add(invoice)
    await db.flush()
    payment = SubscriptionPayment(
        invoice_id=invoice.id, user_id=reseller.id, amount=amount, currency=currency,
        payment_method="card", status=SubscriptionPaymentStatus.PENDING,
        provider_reference=f"PAF-{secrets.token_hex(4)}", payment_reference=f"SUBCARD-{secrets.token_hex(4)}",
    )
    db.add(payment)
    await db.commit()
    return reseller, invoice, payment


def _body(status="success", amount=10, currency="USD"):
    return json.dumps({"event": "payment.completed",
                       "data": {"status": status, "amount": amount, "currency": currency,
                                "reference": "PAF-ABC"}}).encode()


async def _state(session_factory, reseller_id, invoice_id, payment_id):
    async with session_factory() as s:
        return (await s.get(User, reseller_id), await s.get(SubscriptionInvoice, invoice_id),
                await s.get(SubscriptionPayment, payment_id))


# ---------------------------------------------------------------------------
# Parsing helpers (the payload format is not documented yet)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload,expected", [
    ({"status": "success"}, "success"),
    ({"event": "payment.completed"}, "success"),
    ({"data": {"status": "successful"}}, "success"),
    ({"status": "failed"}, "failed"),
    ({"event": "payment.failed"}, "failed"),
    ({"status": "pending"}, "unknown"),
    ({}, "unknown"),
])
def test_extract_outcome(payload, expected):
    assert extract_outcome(payload) == expected


@pytest.mark.parametrize("payload,ok", [
    ({"amount": 10, "currency": "USD"}, True),
    ({"amount": 1000, "currency": "USD"}, True),      # minor units
    ({"data": {"amount": "10.00", "currency": "usd"}}, True),
    ({"amount": 10}, True),                            # currency omitted
    ({"amount": 9, "currency": "USD"}, False),
    ({"amount": 10, "currency": "KES"}, False),
    ({"status": "success"}, False),                    # no amount at all
])
def test_amount_matches(payload, ok):
    assert amount_matches(payload, 10.0, "USD") is ok


def test_webhook_url_and_token(monkeypatch):
    url = webhook_url_for(42)
    assert url.endswith(f"/api/payafrica/webhook/42/{webhook_token(42)}")
    assert webhook_token(42) != webhook_token(43)
    from app.config import settings
    monkeypatch.setattr(settings, "PAYAFRICA_WEBHOOK_BASE_URL", "")
    assert webhook_url_for(42) is None


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_valid_webhook_activates(db, client, session_factory):
    reseller, invoice, payment = await _pending_card_payment(db)
    expires_before = reseller.subscription_expires_at

    resp = await client.post(f"/api/payafrica/webhook/{payment.id}/{webhook_token(payment.id)}",
                             content=_body())

    assert resp.status_code == 200 and resp.json()["status"] == "completed"
    user, inv, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.COMPLETED
    assert inv.status == InvoiceStatus.PAID
    assert user.subscription_status == SubscriptionStatus.ACTIVE
    assert user.subscription_expires_at > expires_before

    # A replay must not add a second month.
    again = await client.post(f"/api/payafrica/webhook/{payment.id}/{webhook_token(payment.id)}",
                              content=_body())
    assert again.json()["status"] == "completed"  # already completed, reported as-is
    user2, _, _ = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert user2.subscription_expires_at == user.subscription_expires_at


@pytest.mark.asyncio
async def test_forged_token_is_refused(db, client, session_factory):
    reseller, invoice, payment = await _pending_card_payment(db)

    resp = await client.post(f"/api/payafrica/webhook/{payment.id}/deadbeef", content=_body())

    assert resp.status_code == 401
    user, _, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.PENDING
    assert user.subscription_status == SubscriptionStatus.TRIAL


@pytest.mark.asyncio
async def test_token_of_another_payment_is_refused(db, client):
    _, _, payment = await _pending_card_payment(db)
    _, _, other = await _pending_card_payment(db)

    resp = await client.post(f"/api/payafrica/webhook/{payment.id}/{webhook_token(other.id)}",
                             content=_body())

    assert resp.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("body,expected", [
    (_body(amount=5), "mismatch"),
    (_body(currency="KES"), "mismatch"),
    (_body(status="failed"), "failed"),
    (_body(status="pending"), "unknown"),
])
async def test_bad_payloads_never_activate(db, client, session_factory, body, expected):
    reseller, invoice, payment = await _pending_card_payment(db)

    resp = await client.post(f"/api/payafrica/webhook/{payment.id}/{webhook_token(payment.id)}",
                             content=body)

    assert resp.status_code == 200 and resp.json()["status"] == expected
    user, inv, pay = await _state(session_factory, reseller.id, invoice.id, payment.id)
    assert pay.status == SubscriptionPaymentStatus.PENDING
    assert inv.status == InvoiceStatus.PENDING
    assert user.subscription_status == SubscriptionStatus.TRIAL


@pytest.mark.asyncio
async def test_unknown_payment_is_404(client):
    resp = await client.post(f"/api/payafrica/webhook/999999/{webhook_token(999999)}", content=_body())
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_probe_checks_reachability(db, client):
    _, _, payment = await _pending_card_payment(db)

    ok = await client.get(f"/api/payafrica/webhook/{payment.id}/{webhook_token(payment.id)}")
    bad = await client.get(f"/api/payafrica/webhook/{payment.id}/nope")

    assert ok.status_code == 200 and ok.json()["expects"] == "POST"
    assert bad.status_code == 401
