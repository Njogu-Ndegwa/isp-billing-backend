"""Admin money totals across markets are reported in KES.

A Cameroon reseller's revenue is in XAF and an international reseller's
subscription is paid in USD. Platform-wide admin totals used to add those
numbers up as if they were KES (XAF 5,710 counted as KES 5,710 instead of about
KES 1,295; a USD 10 card payment counted as KES 10). Pins:

  * cross-reseller totals and rankings convert to KES at the fixed market rates;
  * per-reseller rows keep the reseller's own currency and say which it is;
  * Kenya-only data produces exactly the raw sums it always did.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.admin_reseller_routes as arr
import app.api.dashboard_routes as dr
import app.api.subscription_routes as sr
from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
    SubscriptionStatus,
)
from app.services.admin_metrics import (
    compute_mrr,
    compute_revenue_concentration,
    compute_subscription_revenue_history,
)
from app.services.auth import verify_token
from app.services.markets import PAY_CARD
from tests.factories import make_admin, make_customer, make_plan, make_reseller

XAF_TO_KES = 129.5 / 571.0
USD_TO_KES = 129.5

# Every scenario places payments inside the current month so far.
_NOW = datetime.utcnow()
pytestmark = pytest.mark.skipif(
    _NOW - datetime(_NOW.year, _NOW.month, 1) < timedelta(hours=2),
    reason="needs a few hours elapsed in the current month to place test events",
)


def _recently() -> datetime:
    return datetime.utcnow() - timedelta(minutes=5)


async def _customer_payment(db, reseller, amount):
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(db, reseller, plan)
    db.add(CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=1,
        status=PaymentStatus.COMPLETED,
        created_at=_recently(),
    ))
    await db.commit()


async def _subscription_payment(db, reseller, amount, *, currency="KES", method="mpesa"):
    db.add(SubscriptionPayment(
        user_id=reseller.id,
        amount=amount,
        currency=currency,
        payment_method=method,
        status=SubscriptionPaymentStatus.COMPLETED,
        created_at=_recently(),
    ))
    await db.commit()


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(sr.router)
    application.include_router(arr.router)
    application.include_router(dr.router)

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
    monkeypatch.setattr(arr, "get_current_user", _fake)
    monkeypatch.setattr(dr, "get_current_user", _fake)


# ---------------------------------------------------------------------------
# Customer revenue (reseller market currency)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revenue_total_converts_xaf_to_kes(db):
    kenyan = await make_reseller(db, organization_name="Nairobi ISP")
    cameroon = await make_reseller(db, organization_name="Douala ISP", market_code="CM")
    await _customer_payment(db, kenyan, 1000.0)
    await _customer_payment(db, cameroon, 5710.0)

    result = await compute_revenue_concentration(db)

    assert result["currency"] == "KES"
    assert result["total_revenue"] == pytest.approx(1000 + 5710 * XAF_TO_KES, abs=0.01)
    by_id = {c["id"]: c["revenue"] for c in result["top_contributors"]}
    assert by_id[kenyan.id] == 1000.0
    assert by_id[cameroon.id] == pytest.approx(1295.0, abs=0.01)


@pytest.mark.asyncio
async def test_top_resellers_are_ranked_by_kes_value(db, client, monkeypatch):
    admin = await make_admin(db)
    kenyan = await make_reseller(db, organization_name="Nairobi ISP")
    cameroon = await make_reseller(db, organization_name="Douala ISP", market_code="CM")
    # Raw numbers would put Cameroon first (5,710 > 1,500); in KES it is 1,295.
    await _customer_payment(db, kenyan, 1500.0)
    await _customer_payment(db, cameroon, 5710.0)
    _auth_as(monkeypatch, admin)

    resp = await client.get("/api/admin/dashboard")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["currency"] == "KES"
    assert body["revenue"]["this_month"] == pytest.approx(1500 + 5710 * XAF_TO_KES, abs=0.01)
    assert body["revenue"]["all_time_mpesa"] == pytest.approx(1500 + 5710 * XAF_TO_KES, abs=0.01)
    top = body["top_resellers_this_month"]
    assert [t["id"] for t in top] == [kenyan.id, cameroon.id]
    assert top[1]["month_revenue"] == pytest.approx(1295.0, abs=0.01)


@pytest.mark.asyncio
async def test_reseller_list_rows_keep_local_currency(db, client, monkeypatch):
    admin = await make_admin(db)
    kenyan = await make_reseller(db)
    cameroon = await make_reseller(db, market_code="CM")
    await _customer_payment(db, kenyan, 1500.0)
    await _customer_payment(db, cameroon, 5710.0)
    _auth_as(monkeypatch, admin)

    resp = await client.get("/api/admin/resellers", params={"sort_by": "revenue"})

    assert resp.status_code == 200, resp.text
    rows = resp.json()["resellers"]
    assert [r["id"] for r in rows] == [kenyan.id, cameroon.id]
    by_id = {r["id"]: r for r in rows}
    assert by_id[kenyan.id]["currency"] == "KES"
    assert by_id[kenyan.id]["total_revenue"] == 1500.0
    assert by_id[cameroon.id]["currency"] == "XAF"
    assert by_id[cameroon.id]["total_revenue"] == 5710.0

    detail = await client.get(f"/api/admin/resellers/{cameroon.id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["currency"] == "XAF"
    assert detail.json()["revenue"]["all_time"] == 5710.0

    payments = await client.get(f"/api/admin/resellers/{cameroon.id}/payments")
    assert payments.json()["currency"] == "XAF"
    assert payments.json()["summary"]["total_amount"] == 5710.0


# ---------------------------------------------------------------------------
# Subscription revenue (per-payment currency)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subscription_revenue_sums_usd_card_payment_in_kes(db, client, monkeypatch):
    admin = await make_admin(db)
    kenyan = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    cameroon = await make_reseller(
        db, market_code="CM", subscription_status=SubscriptionStatus.ACTIVE,
    )
    await _subscription_payment(db, kenyan, 500.0)
    await _subscription_payment(db, cameroon, 10.0, currency="USD", method=PAY_CARD)
    _auth_as(monkeypatch, admin)

    resp = await client.get("/api/admin/subscriptions/revenue")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["currency"] == "KES"
    assert body["total_collected"] == pytest.approx(500 + 1295, abs=0.01)
    assert body["this_month_collected"] == pytest.approx(500 + 1295, abs=0.01)
    assert body["paystack"] == {
        "fee_rate": 0.03,
        "fee_assumed": True,
        "currency": "KES",
        "payment_count": 1,
        "gross_collected": 1295.0,
        "processing_fees": 38.85,
        "net_settlement": 1256.15,
        "this_month": {
            "fee_rate": 0.03,
            "fee_assumed": True,
            "currency": "KES",
            "payment_count": 1,
            "gross_collected": 1295.0,
            "processing_fees": 38.85,
            "net_settlement": 1256.15,
        },
    }

    mrr = await compute_mrr(db)
    assert mrr["current_mrr"] == pytest.approx(500 + 1256.15, abs=0.01)
    assert mrr["basis"] == "net_subscription_revenue"
    assert mrr["card_processing_fee_rate"] == 0.03

    history = await compute_subscription_revenue_history(db, period="30d")
    assert history["total_revenue"] == pytest.approx(500 + 1256.15, abs=0.01)


@pytest.mark.asyncio
async def test_admin_subscription_list_labels_each_row(db, client, monkeypatch):
    admin = await make_admin(db)
    kenyan = await make_reseller(db)
    cameroon = await make_reseller(db, market_code="CM")
    await _subscription_payment(db, kenyan, 500.0)
    await _subscription_payment(db, cameroon, 10.0, currency="USD", method=PAY_CARD)
    _auth_as(monkeypatch, admin)

    resp = await client.get("/api/admin/subscriptions", params={"sort_by": "revenue"})

    assert resp.status_code == 200, resp.text
    rows = {r["id"]: r for r in resp.json()["subscriptions"]}
    assert rows[kenyan.id]["currency"] == "KES"
    assert rows[kenyan.id]["total_paid"] == 500.0
    assert rows[cameroon.id]["currency"] == "USD"
    assert rows[cameroon.id]["total_paid"] == 10.0
    # USD 10 is KES 1,295, so it outranks KES 500 when sorted by revenue.
    ordered = [r["id"] for r in resp.json()["subscriptions"]]
    assert ordered.index(cameroon.id) < ordered.index(kenyan.id)


# ---------------------------------------------------------------------------
# Kenya-only data is unchanged
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kenya_only_totals_equal_raw_sums(db, client, monkeypatch):
    admin = await make_admin(db)
    a = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    b = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    customer_amounts = {a.id: [120.0, 35.5], b.id: [999.99]}
    for reseller in (a, b):
        for amount in customer_amounts[reseller.id]:
            await _customer_payment(db, reseller, amount)
    await _subscription_payment(db, a, 500.0)
    await _subscription_payment(db, b, 733.25)
    _auth_as(monkeypatch, admin)

    raw_customer = sum(sum(v) for v in customer_amounts.values())
    raw_subscription = 500.0 + 733.25

    concentration = await compute_revenue_concentration(db)
    assert concentration["total_revenue"] == round(raw_customer, 2)

    mrr = await compute_mrr(db)
    assert mrr["current_mrr"] == round(raw_subscription, 2)

    dashboard = (await client.get("/api/admin/dashboard")).json()
    assert dashboard["revenue"]["this_month"] == raw_customer
    assert dashboard["revenue"]["all_time"] == raw_customer

    revenue = (await client.get("/api/admin/subscriptions/revenue")).json()
    assert revenue["total_collected"] == raw_subscription

    subs = {r["id"]: r for r in (await client.get("/api/admin/subscriptions")).json()["subscriptions"]}
    assert subs[a.id]["total_paid"] == 500.0
    assert subs[b.id]["total_paid"] == 733.25
    assert {r["currency"] for r in subs.values()} == {"KES"}


# ---------------------------------------------------------------------------
# Individual USD payments and the USD-view metadata
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_usd_card_payment_listed_with_kes_value(db, client, monkeypatch):
    admin = await make_admin(db)
    cameroon = await make_reseller(db, market_code="CM")
    await _subscription_payment(db, cameroon, 10.0, currency="USD", method=PAY_CARD)
    _auth_as(monkeypatch, admin)

    resp = await client.get("/api/admin/subscriptions/payments")

    assert resp.status_code == 200, resp.text
    [row] = resp.json()["payments"]
    assert row["amount"] == 10
    assert row["currency"] == "USD"
    assert row["amount_kes"] == 1295.0

    detail = (await client.get(f"/api/admin/subscriptions/{cameroon.id}")).json()
    assert detail["payments"][0]["amount_kes"] == 1295.0


@pytest.mark.asyncio
async def test_admin_totals_carry_reporting_currency_and_usd_rate(db, client, monkeypatch):
    admin = await make_admin(db)
    _auth_as(monkeypatch, admin)

    revenue = (await client.get("/api/admin/subscriptions/revenue")).json()
    dashboard = (await client.get("/api/admin/dashboard")).json()
    mrr = await compute_mrr(db)

    for body in (revenue, dashboard, mrr):
        assert body["reporting_currency"] == "KES"
        assert body["usd_rate"] == USD_TO_KES


# ---------------------------------------------------------------------------
# Shared dashboard charts: admins see every reseller, so they convert to KES
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_daily_transactions_and_revenue_series_are_in_kes(db, client, monkeypatch):
    ke = await make_reseller(db)
    cm = await make_reseller(db, market_code="CM")
    await _customer_payment(db, ke, 1_000)
    await _customer_payment(db, cm, 5_710)
    expected = round(1_000 + 5_710 * XAF_TO_KES, 2)

    _auth_as(monkeypatch, await make_admin(db))
    daily = (await client.get("/api/dashboard/transactions-daily?period=7d")).json()
    assert daily["currency"] == "KES"
    assert daily["totals"]["revenue"] == pytest.approx(expected, abs=0.02)

    series = (await client.get("/api/dashboard/revenue-over-time?period=7d")).json()
    assert series["currency"] == "KES"
    assert sum(p.get("revenue", 0) for p in series["data"]) == pytest.approx(expected, abs=0.05)


@pytest.mark.asyncio
async def test_reseller_daily_transactions_stay_in_their_currency(db, client, monkeypatch):
    cm = await make_reseller(db, market_code="CM")
    await _customer_payment(db, cm, 5_710)

    _auth_as(monkeypatch, cm)
    daily = (await client.get("/api/dashboard/transactions-daily?period=7d")).json()
    assert daily["currency"] == "XAF"
    assert daily["totals"]["revenue"] == 5_710
