"""Country markets and multi-currency reseller subscriptions.

Pins:
  * the market registry is internally consistent (every market can convert
    its revenue into its invoice currency, every market has a way to pay)
  * Kenya's usage formula is unchanged; international markets pay the same
    formula in USD (3% of hotspot revenue converted at the market's fixed
    rate + USD 0.20 per PPPoE user, minimum USD 10)
  * the per-reseller price override
  * repricing an invoice issued under the wrong market (prod invoice #597:
    XAF revenue billed as KES 4,774.20)
  * M-Pesa refuses non-KES invoices; card checkout keeps DB and provider I/O
    apart and never activates without an admin confirmation
  * card money (settled at PayAfrica) never counts as shortcode money that
    the B2B "send to bank" job can forward
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.subscription_routes as sr
from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    CustomerPayment,
    CustomerStatus,
    InvoiceStatus,
    PaymentMethod,
    PaymentStatus,
    SubscriptionInvoice,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
    SubscriptionStatus,
    User,
)
from app.services.auth import verify_token
from app.services.markets import (
    MARKETS, PAY_CARD, PRICING_USAGE, get_market, reseller_pricing,
)
from app.services.subscription import (
    MINIMUM_CHARGE,
    calculate_reseller_charges,
    reprice_unpaid_invoice,
)
from tests.factories import make_admin, make_customer, make_plan, make_reseller

PERIOD_START = datetime(2026, 8, 23)
PERIOD_END = datetime(2026, 9, 18)
IN_PERIOD = datetime(2026, 9, 1, 12, 0, 0)


async def _hotspot_revenue(db, reseller, amount):
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(db, reseller, plan)
    db.add(CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=1,
        status=PaymentStatus.COMPLETED,
        created_at=IN_PERIOD,
    ))
    await db.commit()


async def _invoice(db, reseller, *, final_charge, currency="KES"):
    invoice = SubscriptionInvoice(
        user_id=reseller.id,
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        gross_charge=final_charge,
        final_charge=final_charge,
        currency=currency,
        status=InvoiceStatus.PENDING,
        due_date=PERIOD_END + timedelta(days=5),
    )
    db.add(invoice)
    await db.commit()
    await db.refresh(invoice)
    return invoice


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_every_market_is_consistent():
    for code, market in MARKETS.items():
        assert market.code == code
        assert market.default_language in market.languages
        assert market.subscription_payment_methods, code
        if market.pricing.kind == PRICING_USAGE:
            # Revenue is summed in the market currency and must be convertible.
            assert market.fx_rate_to(market.pricing.currency) > 0, code


def test_unknown_market_falls_back_to_kenya():
    assert get_market(None).code == "KE"
    assert get_market("zz").code == "KE"


# ---------------------------------------------------------------------------
# Charges
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kenya_reseller_keeps_usage_formula(db):
    reseller = await make_reseller(db)
    await _hotspot_revenue(db, reseller, 100_000)

    charges = await calculate_reseller_charges(db, reseller.id, PERIOD_START, PERIOD_END)

    assert charges["currency"] == "KES"
    assert charges["hotspot_charge"] == 3000.0
    assert charges["final_charge"] == 3000.0
    assert charges["pricing_rule"]["kind"] == "usage"


@pytest.mark.asyncio
async def test_cameroon_reseller_below_threshold_pays_usd_minimum(db):
    reseller = await make_reseller(db, market_code="CM")
    await _hotspot_revenue(db, reseller, 159_140)  # XAF, as on prod invoice #597

    charges = await calculate_reseller_charges(db, reseller.id, PERIOD_START, PERIOD_END)

    rate = MARKETS["CM"].usd_rate
    assert charges["currency"] == "USD"
    assert charges["hotspot_revenue"] == round(159_140 / rate, 2)
    assert charges["hotspot_charge"] == round(charges["hotspot_revenue"] * 0.03, 2)
    assert charges["hotspot_charge"] < 10.0
    assert charges["final_charge"] == 10.0
    assert charges["pricing_rule"]["hotspot_revenue_local"] == 159_140
    assert charges["pricing_rule"]["revenue_currency"] == "XAF"
    assert charges["pricing_rule"]["fx_rate"] == rate


@pytest.mark.asyncio
async def test_cameroon_reseller_above_threshold_pays_three_percent_in_usd(db):
    reseller = await make_reseller(db, market_code="CM")
    rate = MARKETS["CM"].usd_rate
    await _hotspot_revenue(db, reseller, 500 * rate)  # USD 500 of XAF revenue

    charges = await calculate_reseller_charges(db, reseller.id, PERIOD_START, PERIOD_END)

    assert charges["hotspot_revenue"] == 500.0
    assert charges["hotspot_charge"] == 15.0
    assert charges["final_charge"] == 15.0


@pytest.mark.asyncio
async def test_international_pppoe_users_cost_twenty_cents(db):
    reseller = await make_reseller(db, market_code="UG")
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    for _ in range(60):
        await make_customer(
            db, reseller, plan, status=CustomerStatus.ACTIVE,
            expiry=PERIOD_END + timedelta(days=10),
        )
    rate = MARKETS["UG"].usd_rate
    await _hotspot_revenue(db, reseller, 100 * rate)  # USD 100 -> USD 3

    charges = await calculate_reseller_charges(db, reseller.id, PERIOD_START, PERIOD_END)

    assert charges["pppoe_user_count"] == 60
    assert charges["pppoe_charge"] == 12.0
    assert charges["gross_charge"] == 15.0
    assert charges["final_charge"] == 15.0


@pytest.mark.asyncio
async def test_price_override_replaces_the_minimum_charge(db):
    intl = await make_reseller(db, market_code="UG", subscription_price_override=15.0)  # minimum $15
    kenyan = await make_reseller(db, subscription_price_override=300.0)

    assert (await calculate_reseller_charges(db, intl.id, PERIOD_START, PERIOD_END))["final_charge"] == 15.0
    assert reseller_pricing(kenyan).minimum == 300.0
    assert (await calculate_reseller_charges(db, kenyan.id, PERIOD_START, PERIOD_END))["final_charge"] == 300.0
    assert reseller_pricing(await make_reseller(db)).minimum == MINIMUM_CHARGE


@pytest.mark.asyncio
async def test_reprice_fixes_invoice_issued_under_wrong_market(db):
    reseller = await make_reseller(db, market_code="CM")
    invoice = await _invoice(db, reseller, final_charge=4774.2)

    await reprice_unpaid_invoice(db, invoice)
    await db.commit()

    assert invoice.final_charge == 10.0
    assert invoice.currency == "USD"
    assert invoice.pricing_rule["minimum"] == 10.0


@pytest.mark.asyncio
async def test_reprice_refuses_once_a_payment_completed(db):
    reseller = await make_reseller(db, market_code="CM")
    invoice = await _invoice(db, reseller, final_charge=500.0)
    db.add(SubscriptionPayment(
        invoice_id=invoice.id, user_id=reseller.id, amount=100.0,
        status=SubscriptionPaymentStatus.COMPLETED,
    ))
    await db.commit()

    with pytest.raises(ValueError):
        await reprice_unpaid_invoice(db, invoice)


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
async def test_mpesa_refuses_usd_invoice(db, client, monkeypatch):
    reseller = await make_reseller(db, market_code="CM")
    invoice = await _invoice(db, reseller, final_charge=10.0, currency="USD")
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/subscription/pay", json={
        "invoice_id": invoice.id, "phone_number": "0712345678",
    })

    assert resp.status_code == 400
    assert "card" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_card_checkout_then_admin_confirmation_activates(db, client, monkeypatch, session_factory):
    reseller = await make_reseller(
        db, market_code="CM", subscription_status=SubscriptionStatus.TRIAL,
        subscription_expires_at=datetime.utcnow() + timedelta(days=2),
    )
    invoice = await _invoice(db, reseller, final_charge=10.0, currency="USD")
    calls = []

    async def _fake_checkout(**kwargs):
        calls.append(kwargs)
        return {
            "status": "pending",
            "payment_url": "https://checkout.paystack.com/abc123",
            "reference": "PAF-TEST123",
            "external_reference": kwargs["reference"],
        }

    import app.services.payafrica as payafrica
    monkeypatch.setattr(payafrica, "initialize_card_checkout", _fake_checkout)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/subscription/pay-card", json={"invoice_id": invoice.id})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["payment_url"] == "https://checkout.paystack.com/abc123"
    assert calls[0]["amount"] == 10.0 and calls[0]["currency"] == "USD"
    assert calls[0]["customer_email"] == reseller.email

    async with session_factory() as s:
        payment = await s.get(SubscriptionPayment, body["payment_id"])
        assert payment.status == SubscriptionPaymentStatus.PENDING
        assert payment.payment_method == PAY_CARD
        assert payment.currency == "USD"
        assert payment.provider_reference == "PAF-TEST123"
        refreshed = await s.get(User, reseller.id)
        assert refreshed.subscription_status == SubscriptionStatus.TRIAL  # not yet

    admin = await make_admin(db)
    _auth_as(monkeypatch, admin)
    resp = await client.post(
        f"/api/admin/subscriptions/payments/{body['payment_id']}/confirm-card",
        json={"receipt": "T123456789"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["subscription_status"] == "active"

    async with session_factory() as s:
        inv = await s.get(SubscriptionInvoice, invoice.id)
        assert inv.status == InvoiceStatus.PAID
        payment = await s.get(SubscriptionPayment, body["payment_id"])
        assert payment.payment_reference == "T123456789"

    # A second confirmation is refused rather than extending twice.
    resp = await client.post(
        f"/api/admin/subscriptions/payments/{body['payment_id']}/confirm-card", json={},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_failed_checkout_marks_payment_failed(db, client, monkeypatch, session_factory):
    reseller = await make_reseller(db, market_code="CM")
    invoice = await _invoice(db, reseller, final_charge=10.0, currency="USD")

    import app.services.payafrica as payafrica

    async def _boom(**kwargs):
        raise payafrica.PayAfricaAPIError("upstream down", status_code=503)

    monkeypatch.setattr(payafrica, "initialize_card_checkout", _boom)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/subscription/pay-card", json={"invoice_id": invoice.id})

    assert resp.status_code == 502
    async with session_factory() as s:
        rows = (await s.execute(select(SubscriptionPayment))).scalars().all()
        assert [r.status for r in rows] == [SubscriptionPaymentStatus.FAILED]


@pytest.mark.asyncio
async def test_card_money_is_never_forwardable_by_b2b(db):
    kenyan = await make_reseller(db)
    intl = await make_reseller(db, market_code="CM")
    db.add_all([
        SubscriptionPayment(user_id=kenyan.id, amount=500.0, payment_method="mpesa",
                            status=SubscriptionPaymentStatus.COMPLETED),
        SubscriptionPayment(user_id=intl.id, amount=10.0, currency="USD", payment_method=PAY_CARD,
                            status=SubscriptionPaymentStatus.COMPLETED),
    ])
    await db.commit()

    summary = await sr._subscription_collection_summary(db)
    allocations = await sr._subscription_payment_send_allocations(db)

    assert summary["total_collected"] == 500.0
    assert len(allocations) == 1


@pytest.mark.asyncio
async def test_admin_sets_market_and_reprices(db, client, monkeypatch):
    reseller = await make_reseller(db)
    invoice = await _invoice(db, reseller, final_charge=4774.2)
    _auth_as(monkeypatch, await make_admin(db))

    resp = await client.patch(f"/api/admin/subscriptions/{reseller.id}", json={"market_code": "cm"})
    assert resp.status_code == 200, resp.text
    market = resp.json()["market"]
    assert market["code"] == "CM"
    assert market["currency"] == "XAF"
    assert market["subscription_currency"] == "USD"
    assert market["subscription_payment_methods"] == ["card"]

    resp = await client.post(f"/api/admin/subscriptions/{reseller.id}/reprice/{invoice.id}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["before"] == {"final_charge": 4774.2, "currency": "KES"}
    assert resp.json()["invoice"]["final_charge"] == 10.0
    assert resp.json()["invoice"]["currency"] == "USD"
    # The UI shows the local revenue and FX rate from the invoice's pricing rule.
    assert resp.json()["invoice"]["pricing_rule"]["minimum"] == 10.0
    assert resp.json()["invoice"]["pricing_rule"]["revenue_currency"] == "XAF"

    bad = await client.patch(f"/api/admin/subscriptions/{reseller.id}", json={"market_code": "XX"})
    assert bad.status_code == 400
