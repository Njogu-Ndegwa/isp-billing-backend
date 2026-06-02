from datetime import datetime
from types import SimpleNamespace

import pytest

from app.api import dashboard_routes
from app.db.models import CustomerPayment, PaymentMethod, PaymentStatus, UserRole
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


async def _add_payment(db, customer, reseller, *, amount, created_at):
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        payment_reference=f"TEST-{customer.id}-{amount}",
        days_paid_for=1,
        status=PaymentStatus.COMPLETED,
        created_at=created_at,
        payment_date=created_at,
    )
    db.add(payment)
    await db.commit()
    return payment


async def _seed_two_reseller_payments(db):
    reseller_a = await make_reseller(db, email="reseller-a@example.com")
    reseller_b = await make_reseller(db, email="reseller-b@example.com")

    plan_a = await make_plan(db, reseller_a, price=100)
    plan_b = await make_plan(db, reseller_b, price=200)
    router_a = await make_router(db, reseller_a, ip_address="10.0.0.10")
    router_b = await make_router(db, reseller_b, ip_address="10.0.0.11")
    customer_a = await make_customer(
        db,
        reseller_a,
        plan_a,
        router_a,
        phone="254700000001",
        mac_address="AA:00:00:00:00:01",
    )
    customer_b = await make_customer(
        db,
        reseller_b,
        plan_b,
        router_b,
        phone="254700000002",
        mac_address="AA:00:00:00:00:02",
    )

    day = datetime(2026, 6, 2, 8, 0, 0)
    await _add_payment(db, customer_a, reseller_a, amount=100.0, created_at=day)
    await _add_payment(db, customer_b, reseller_b, amount=200.0, created_at=day)
    return reseller_a, reseller_b


async def test_transactions_daily_admin_sees_all_reseller_payments(db, monkeypatch):
    await _seed_two_reseller_payments(db)
    admin = SimpleNamespace(id=1, role=UserRole.ADMIN)

    async def fake_current_user(token, db):
        return admin

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)

    result = await dashboard_routes.get_daily_transaction_counts(
        start_date="2026-06-02",
        end_date="2026-06-02",
        status="completed",
        db=db,
        token="test-token",
    )

    assert result["totals"]["transactions"] == 2
    assert result["totals"]["revenue"] == 300.0
    assert result["data"][0]["transactions"] == 2
    assert result["data"][0]["revenue"] == 300.0


async def test_transactions_daily_reseller_sees_only_own_payments(db, monkeypatch):
    reseller_a, _reseller_b = await _seed_two_reseller_payments(db)

    async def fake_current_user(token, db):
        return reseller_a

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)

    result = await dashboard_routes.get_daily_transaction_counts(
        start_date="2026-06-02",
        end_date="2026-06-02",
        status="completed",
        db=db,
        token="test-token",
    )

    assert result["totals"]["transactions"] == 1
    assert result["totals"]["revenue"] == 100.0
    assert result["data"][0]["transactions"] == 1
    assert result["data"][0]["revenue"] == 100.0


async def test_revenue_over_time_admin_sees_all_reseller_payments(db, monkeypatch):
    await _seed_two_reseller_payments(db)
    admin = SimpleNamespace(id=1, role=UserRole.ADMIN)

    async def fake_current_user(token, db):
        return admin

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)

    result = await dashboard_routes.get_revenue_over_time(
        start_date="2026-06-02",
        end_date="2026-06-02",
        db=db,
        token="test-token",
    )

    assert result["totals"]["transactions"] == 2
    assert result["totals"]["revenue"] == 300.0
    assert result["data"][0]["transactions"] == 2
    assert result["data"][0]["revenue"] == 300.0
