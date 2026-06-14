"""
TDD tests: compensation vouchers must NOT add to amount/revenue totals but
MUST be counted in transaction counts and appear in lists.

Part 4 of the compensation voucher fix:
- Test 1: transactions summary excludes comp from money, counts it
- Test 2: reseller dashboard total_revenue excludes comp
"""

from types import SimpleNamespace

import pytest

from app.db.models import (
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    UserRole,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _add_payment(
    db,
    customer,
    reseller,
    *,
    amount: float,
    payment_method: PaymentMethod = PaymentMethod.CASH,
    counts_as_revenue: bool = True,
    status: PaymentStatus = PaymentStatus.COMPLETED,
    payment_reference: str = None,
):
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=payment_method,
        payment_reference=payment_reference or f"REF-{customer.id}-{amount}",
        days_paid_for=1,
        status=status,
        counts_as_revenue=counts_as_revenue,
    )
    db.add(payment)
    await db.commit()
    await db.refresh(payment)
    return payment


# ---------------------------------------------------------------------------
# Test 1: transactions summary excludes comp from money but counts it
# ---------------------------------------------------------------------------

async def test_transactions_summary_excludes_comp_from_money_keeps_count(db, monkeypatch):
    """
    Seed one SALE payment (amount 100, counts_as_revenue=True) and one
    COMPENSATION payment (amount 50, counts_as_revenue=False) for the same
    reseller.

    Expected:
      total_amount == 100          (comp excluded from money)
      total_transactions == 2      (both counted)
      compensation_total == 50     (reported separately for transparency)
    """
    from app.api import payment_routes

    reseller = await make_reseller(db, email="summary-reseller@example.com")
    plan = await make_plan(db, reseller, price=100)
    router = await make_router(db, reseller, ip_address="10.0.1.1")
    customer = await make_customer(
        db, reseller, plan, router,
        phone="254700000010",
        mac_address="AA:BB:CC:DD:00:01",
    )

    # Normal sale payment
    await _add_payment(
        db, customer, reseller,
        amount=100.0,
        payment_method=PaymentMethod.CASH,
        counts_as_revenue=True,
    )

    # Compensation payment (free voucher — no revenue)
    await _add_payment(
        db, customer, reseller,
        amount=50.0,
        payment_method=PaymentMethod.CASH,
        counts_as_revenue=False,
    )

    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", fake_current_user)

    result = await payment_routes.get_mpesa_transactions_summary(
        router_id=None,
        payment_method=None,
        date=None,
        start_date=None,
        end_date=None,
        db=db,
        token="test-token",
    )

    assert result["total_transactions"] == 2, (
        f"Expected 2 transactions (comp counted), got {result['total_transactions']}"
    )
    assert result["total_amount"] == 100.0, (
        f"Expected total_amount==100 (comp excluded), got {result['total_amount']}"
    )
    assert "compensation_total" in result, (
        "Response must include 'compensation_total' key"
    )
    assert result["compensation_total"] == 50.0, (
        f"Expected compensation_total==50, got {result.get('compensation_total')}"
    )


# ---------------------------------------------------------------------------
# Test 2: reseller dashboard total_revenue excludes comp
# ---------------------------------------------------------------------------

async def test_reseller_dashboard_total_revenue_excludes_comp(db, monkeypatch):
    """
    Seed a sale payment (amount=200) and a comp payment (amount=100) for a
    reseller; call get_dashboard_overview and assert the all_time revenue
    equals only the sale amount.
    """
    from app.api import dashboard_routes

    reseller = await make_reseller(db, email="dash-reseller@example.com")
    plan = await make_plan(db, reseller, price=200)
    router = await make_router(db, reseller, ip_address="10.0.2.1")
    customer = await make_customer(
        db, reseller, plan, router,
        phone="254700000020",
        mac_address="AA:BB:CC:DD:00:02",
    )

    # Normal sale
    await _add_payment(
        db, customer, reseller,
        amount=200.0,
        payment_method=PaymentMethod.CASH,
        counts_as_revenue=True,
    )

    # Compensation (should NOT count toward revenue)
    await _add_payment(
        db, customer, reseller,
        amount=100.0,
        payment_method=PaymentMethod.CASH,
        counts_as_revenue=False,
    )

    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)

    result = await dashboard_routes.get_dashboard_overview(
        router_id=None,
        db=db,
        token="test-token",
    )

    all_time = result["revenue"]["all_time"]
    assert all_time == 200.0, (
        f"Expected all_time revenue==200 (comp excluded), got {all_time}"
    )


# ---------------------------------------------------------------------------
# Test 3: revenue-over-time chart excludes comp from money, counts it
# ---------------------------------------------------------------------------

async def test_revenue_over_time_excludes_comp_keeps_transaction_count(db, monkeypatch):
    """
    Seed one SALE payment (amount 300, counts_as_revenue=True) and one
    COMPENSATION payment (amount 80, counts_as_revenue=False) for the same
    reseller on the current day, then call get_revenue_over_time.

    Expected (the comp must NOT inflate money, but MUST be counted):
      totals.revenue       == 300    (comp excluded from money)
      totals.transactions  == 2      (both counted)
      today's bucket revenue       == 300
      today's bucket transactions  == 2
    """
    from datetime import datetime

    from app.api import dashboard_routes

    reseller = await make_reseller(db, email="rot-reseller@example.com")
    plan = await make_plan(db, reseller, price=300)
    router = await make_router(db, reseller, ip_address="10.0.3.1")
    customer = await make_customer(
        db, reseller, plan, router,
        phone="254700000030",
        mac_address="AA:BB:CC:DD:00:03",
    )

    # Normal sale (counts as revenue)
    await _add_payment(
        db, customer, reseller,
        amount=300.0,
        payment_method=PaymentMethod.CASH,
        counts_as_revenue=True,
    )

    # Compensation voucher (free — must NOT count toward revenue, but IS a txn)
    await _add_payment(
        db, customer, reseller,
        amount=80.0,
        payment_method=PaymentMethod.CASH,
        counts_as_revenue=False,
    )

    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)

    result = await dashboard_routes.get_revenue_over_time(
        period="30d",
        start_date=None,
        end_date=None,
        router_id=None,
        db=db,
        token="test-token",
    )

    # Totals: revenue excludes comp, transactions count both
    assert result["totals"]["revenue"] == 300.0, (
        f"Expected totals.revenue==300 (comp excluded), got {result['totals']['revenue']}"
    )
    assert result["totals"]["transactions"] == 2, (
        f"Expected totals.transactions==2 (comp counted), got {result['totals']['transactions']}"
    )

    # The day bucket for "today" must show the same: revenue 300, 2 transactions
    today_key = datetime.utcnow().strftime("%Y-%m-%d")
    today_bucket = next(
        (p for p in result["data"] if p["date"] == today_key), None
    )
    assert today_bucket is not None, (
        f"Expected a data bucket for today ({today_key}); got dates "
        f"{[p['date'] for p in result['data']]}"
    )
    assert today_bucket["revenue"] == 300.0, (
        f"Expected today's bucket revenue==300 (comp excluded), got {today_bucket['revenue']}"
    )
    assert today_bucket["transactions"] == 2, (
        f"Expected today's bucket transactions==2 (comp counted), got {today_bucket['transactions']}"
    )


# ---------------------------------------------------------------------------
# Test 4: per-router analytics endpoint excludes comp from revenue, counts it
# ---------------------------------------------------------------------------

async def test_dashboard_analytics_excludes_comp_from_revenue_keeps_count(db, monkeypatch):
    """
    /api/dashboard/analytics (get_dashboard_analytics) accumulates revenue in
    Python per payment across many figures (summary.totalRevenue, today.revenue,
    planPerformance, topSpenders, hourly/daily revenue). A compensation voucher
    must NOT inflate any of them, but MUST still be counted/listed.

    Seed one SALE (amount 5, counts_as_revenue=True) and one COMPENSATION
    (amount 1, counts_as_revenue=False) today on the same plan.

    Expected:
      summary.totalRevenue      == 5   (comp excluded)
      summary.totalTransactions == 2   (both counted)
      today.revenue == 5, today.transactions == 2
      planPerformance[0]: revenue == 5, count == 2
    """
    from app.api import dashboard_routes

    reseller = await make_reseller(db, email="analytics-reseller@example.com")
    plan = await make_plan(db, reseller, price=5)
    router = await make_router(db, reseller, ip_address="10.0.4.1")
    customer = await make_customer(
        db, reseller, plan, router,
        phone="254700000040",
        mac_address="AA:BB:CC:DD:00:04",
    )

    await _add_payment(
        db, customer, reseller,
        amount=5.0, payment_method=PaymentMethod.CASH, counts_as_revenue=True,
    )
    await _add_payment(
        db, customer, reseller,
        amount=1.0, payment_method=PaymentMethod.CASH, counts_as_revenue=False,
    )

    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)

    result = await dashboard_routes.get_dashboard_analytics(
        router_id=None,
        days=None,
        start_date=None,
        end_date=None,
        preset="today",
        db=db,
        token="test-token",
    )

    assert result["summary"]["totalTransactions"] == 2, (
        f"Expected 2 transactions (comp counted), got {result['summary']['totalTransactions']}"
    )
    assert result["summary"]["totalRevenue"] == 5.0, (
        f"Expected totalRevenue==5 (comp excluded), got {result['summary']['totalRevenue']}"
    )
    assert result["today"]["revenue"] == 5.0, (
        f"Expected today.revenue==5 (comp excluded), got {result['today']['revenue']}"
    )
    assert result["today"]["transactions"] == 2, (
        f"Expected today.transactions==2 (comp counted), got {result['today']['transactions']}"
    )
    pp = result["planPerformance"][0]
    assert pp["count"] == 2, f"Expected plan count==2 (comp counted), got {pp['count']}"
    assert pp["revenue"] == 5.0, f"Expected plan revenue==5 (comp excluded), got {pp['revenue']}"
