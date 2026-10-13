"""
Plan reports must credit each payment to the plan it bought, not the
customer's current plan.

Bug: /api/dashboard/analytics (planPerformance), /api/dashboard/overview
(revenue_by_plan, recent_transactions) and /api/plans/performance joined Plan
via Customer.plan_id, which is overwritten on every purchase. A customer who
bought a cheap plan twice and then switched had all three payments credited
to the new plan. /api/plans/performance also dropped plans with no sales in
the requested period.

Fix: group by CustomerPayment.plan_id (the snapshot). Legacy payments from
before the snapshot existed fall back to the customer's current plan; a NULL
snapshot after that means the plan was deleted, so it is not credited to the
customer's current plan.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from app.db.models import (
    CustomerPayment,
    CustomerStatus,
    PaymentMethod,
    PaymentStatus,
    UserRole,
)
from app.services.payment_plan import PLAN_SNAPSHOT_SINCE
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def _pay(db, customer, reseller, *, amount, plan_id, created_at=None):
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.CASH,
        payment_reference=f"REF-{amount}-{plan_id}-{created_at}",
        days_paid_for=1,
        status=PaymentStatus.COMPLETED,
        plan_id=plan_id,
    )
    if created_at is not None:
        payment.created_at = created_at
    db.add(payment)
    await db.commit()
    return payment


async def _setup(db, monkeypatch):
    """Customer bought 'Daily' twice, then switched to 'Weekly' and bought it once."""
    from app.api import dashboard_routes, plan_routes

    reseller = await make_reseller(db)
    daily = await make_plan(db, reseller, price=20, duration_value=1, name="Daily")
    weekly = await make_plan(db, reseller, price=100, duration_value=7, name="Weekly")
    unsold = await make_plan(db, reseller, price=50, duration_value=3, name="Unsold")
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, weekly, router, mac_address="AA:BB:CC:DD:EE:31",
        status=CustomerStatus.ACTIVE,
    )

    await _pay(db, customer, reseller, amount=20.0, plan_id=daily.id)
    await _pay(db, customer, reseller, amount=20.0, plan_id=daily.id)
    await _pay(db, customer, reseller, amount=100.0, plan_id=weekly.id)

    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    return reseller, daily, weekly, unsold, customer


async def _analytics(db):
    from app.api import dashboard_routes

    return await dashboard_routes.get_dashboard_analytics(
        router_id=None, days=None, start_date=None, end_date=None,
        preset="all_time", db=db, token="test-token",
    )


async def _plan_performance(db, **kwargs):
    from app.api import plan_routes

    result = await plan_routes.get_plan_performance(
        start_date=kwargs.get("start_date"), end_date=kwargs.get("end_date"),
        db=db, token="test-token",
    )
    return {p["plan_name"]: p for p in result["plans"]}


async def test_analytics_plan_performance_uses_purchased_plan(db, monkeypatch):
    await _setup(db, monkeypatch)

    result = await _analytics(db)
    by_name = {p["name"]: p for p in result["planPerformance"]}

    assert by_name["Daily"] == {"name": "Daily", "count": 2, "revenue": 40.0}
    assert by_name["Weekly"] == {"name": "Weekly", "count": 1, "revenue": 100.0}


async def test_overview_revenue_by_plan_and_recent_use_purchased_plan(db, monkeypatch):
    from app.api import dashboard_routes

    _, daily, weekly, _, _ = await _setup(db, monkeypatch)

    result = await dashboard_routes.get_dashboard_overview(
        router_id=None, db=db, token="test-token",
    )
    by_id = {p["plan_id"]: p for p in result["revenue_by_plan"]}

    assert by_id[daily.id]["sales_count"] == 2
    assert by_id[daily.id]["revenue"] == 40.0
    assert by_id[weekly.id]["sales_count"] == 1
    assert by_id[weekly.id]["revenue"] == 100.0
    assert sorted(t["plan_name"] for t in result["recent_transactions"]) == [
        "Daily", "Daily", "Weekly",
    ]


async def test_plans_performance_uses_purchased_plan(db, monkeypatch):
    await _setup(db, monkeypatch)

    plans = await _plan_performance(db)

    assert plans["Daily"]["total_sales"] == 2
    assert plans["Daily"]["total_revenue"] == 40.0
    assert plans["Daily"]["total_customers"] == 1
    assert plans["Daily"]["average_revenue_per_sale"] == 20.0
    assert plans["Weekly"]["total_sales"] == 1
    assert plans["Weekly"]["total_revenue"] == 100.0
    # Active customers is current state: the customer is on Weekly now.
    assert plans["Daily"]["active_customers"] == 0
    assert plans["Weekly"]["active_customers"] == 1


async def test_plans_performance_keeps_plans_without_sales_in_period(db, monkeypatch):
    await _setup(db, monkeypatch)

    today = datetime.utcnow().strftime("%Y-%m-%d")
    plans = await _plan_performance(db, start_date=today, end_date=today)

    assert set(plans) == {"Daily", "Weekly", "Unsold"}
    assert plans["Unsold"]["total_sales"] == 0
    assert plans["Unsold"]["total_revenue"] == 0.0
    assert plans["Daily"]["total_sales"] == 2

    long_ago = "2020-01-01"
    plans = await _plan_performance(db, start_date=long_ago, end_date=long_ago)
    assert set(plans) == {"Daily", "Weekly", "Unsold"}
    assert all(p["total_sales"] == 0 for p in plans.values())


async def test_legacy_payment_without_snapshot_falls_back_to_customer_plan(db, monkeypatch):
    reseller, daily, weekly, unsold, customer = await _setup(db, monkeypatch)

    # Before the snapshot column existed: best guess is the current plan.
    await _pay(
        db, customer, reseller, amount=100.0, plan_id=None,
        created_at=PLAN_SNAPSHOT_SINCE - timedelta(days=30),
    )

    plans = await _plan_performance(db)
    assert plans["Weekly"]["total_sales"] == 2
    assert plans["Weekly"]["total_revenue"] == 200.0

    by_name = {p["name"]: p for p in (await _analytics(db))["planPerformance"]}
    assert by_name["Weekly"]["count"] == 2


async def test_deleted_plan_payment_is_not_credited_to_current_plan(db, monkeypatch):
    reseller, daily, weekly, unsold, customer = await _setup(db, monkeypatch)

    # After the snapshot existed, NULL means the plan was deleted (FK SET NULL).
    await _pay(db, customer, reseller, amount=50.0, plan_id=None)

    plans = await _plan_performance(db)
    assert plans["Weekly"]["total_sales"] == 1
    assert plans["Weekly"]["total_revenue"] == 100.0

    by_name = {p["name"]: p for p in (await _analytics(db))["planPerformance"]}
    assert by_name["Weekly"]["count"] == 1
    assert by_name["Unknown"] == {"name": "Unknown", "count": 1, "revenue": 50.0}
