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
