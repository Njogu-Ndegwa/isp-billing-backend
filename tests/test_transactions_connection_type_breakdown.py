"""
TDD test: the transactions summary must report a connection_type_breakdown
(hotspot vs pppoe) covering only completed, revenue-counting transactions.
static_ip / null plans are excluded from the split but still in the totals.
"""
from types import SimpleNamespace

import pytest

from app.db.models import (
    ConnectionType,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    UserRole,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def _add_payment(db, customer, reseller, *, amount,
                       counts_as_revenue=True, status=PaymentStatus.COMPLETED):
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.CASH,
        payment_reference=f"REF-{customer.id}-{amount}-{status.value}",
        days_paid_for=1,
        status=status,
        counts_as_revenue=counts_as_revenue,
    )
    db.add(payment)
    await db.commit()
    await db.refresh(payment)
    return payment


async def test_summary_reports_connection_type_breakdown(db, monkeypatch):
    from app.api import payment_routes

    reseller = await make_reseller(db, email="ct-reseller@example.com")
    router = await make_router(db, reseller, ip_address="10.0.9.1")

    hotspot_plan = await make_plan(db, reseller, price=100, connection_type=ConnectionType.HOTSPOT)
    pppoe_plan = await make_plan(db, reseller, price=300, connection_type=ConnectionType.PPPOE)
    static_plan = await make_plan(db, reseller, price=500, connection_type=ConnectionType.STATIC_IP)

    hotspot_customer = await make_customer(
        db, reseller, hotspot_plan, router,
        phone="254700000091", mac_address="AA:BB:CC:DD:09:01")
    pppoe_customer = await make_customer(
        db, reseller, pppoe_plan, router,
        phone="254700000092", mac_address="AA:BB:CC:DD:09:02")
    static_customer = await make_customer(
        db, reseller, static_plan, router,
        phone="254700000093", mac_address="AA:BB:CC:DD:09:03")

    # Hotspot: two completed sales 100 + 100 = 200
    await _add_payment(db, hotspot_customer, reseller, amount=100.0)
    await _add_payment(db, hotspot_customer, reseller, amount=100.0)
    # PPPoE: one completed sale 300
    await _add_payment(db, pppoe_customer, reseller, amount=300.0)
    # Static IP: one completed sale 500 (in totals, excluded from split)
    await _add_payment(db, static_customer, reseller, amount=500.0)
    # Hotspot pending (not completed -> excluded from split)
    await _add_payment(db, hotspot_customer, reseller, amount=999.0, status=PaymentStatus.PENDING)
    # Hotspot compensation (not revenue -> excluded from split)
    await _add_payment(db, hotspot_customer, reseller, amount=50.0, counts_as_revenue=False)

    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", fake_current_user)

    result = await payment_routes.get_mpesa_transactions_summary(
        router_id=None, payment_method=None, date=None,
        start_date=None, end_date=None, db=db, token="test-token",
    )

    ctb = result["connection_type_breakdown"]
    assert ctb["hotspot"] == {"count": 2, "amount": 200.0}, ctb
    assert ctb["pppoe"] == {"count": 1, "amount": 300.0}, ctb
    assert "static_ip" not in ctb, "static_ip must be excluded from the split"

    # static_ip revenue is still part of the overall completed total (200 + 300 + 500).
    # count is 5: the four sales plus the completed-but-non-revenue compensation row.
    completed = result["status_breakdown"]["completed"]
    assert completed["count"] == 5, completed
    assert completed["amount"] == 1000.0, completed
