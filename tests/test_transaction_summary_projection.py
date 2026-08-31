from types import SimpleNamespace

import pytest
from sqlalchemy import event

from app.api import payment_routes
from app.db.models import (
    CustomerPayment,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
    UserRole,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


async def test_transaction_summary_selects_only_columns_used_by_response(
    db,
    engine,
    monkeypatch,
):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    db.add_all(
        [
            MpesaTransaction(
                checkout_request_id="summary-projection-mpesa",
                phone_number=customer.phone,
                amount=100,
                reference="summary-projection-mpesa",
                customer_id=customer.id,
                plan_id=plan.id,
                status=MpesaTransactionStatus.completed,
            ),
            CustomerPayment(
                customer_id=customer.id,
                reseller_id=reseller.id,
                amount=50,
                payment_method=PaymentMethod.CASH,
                payment_reference="summary-projection-cash",
                days_paid_for=1,
                plan_id=plan.id,
                status=PaymentStatus.COMPLETED,
            ),
        ]
    )
    await db.commit()

    async def _current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", _current_user)
    source_selects = {}

    def _capture_sql(_conn, _cursor, statement, _parameters, _context, _executemany):
        normalized = " ".join(statement.lower().split())
        if " from mpesa_transactions " in normalized:
            source_selects["mpesa"] = normalized.split(" from ", 1)[0]
        elif " from customer_payments " in normalized:
            source_selects["customer_payments"] = normalized.split(" from ", 1)[0]

    event.listen(engine.sync_engine, "before_cursor_execute", _capture_sql)
    try:
        result = await payment_routes.get_mpesa_transactions_summary(
            router_id=None,
            payment_method=None,
            date=None,
            start_date=None,
            end_date=None,
            db=db,
            token="test-token",
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _capture_sql)

    assert result["total_transactions"] == 2
    assert result["total_amount"] == 150
    assert result["method_breakdown"]["mobile_money"]["count"] == 1
    assert result["method_breakdown"]["cash"]["count"] == 1

    assert set(source_selects) == {"mpesa", "customer_payments"}
    assert "mpesa_transactions.amount" in source_selects["mpesa"]
    assert "mpesa_transactions.checkout_request_id" not in source_selects["mpesa"]
    assert "customer_payments.amount" in source_selects["customer_payments"]
    assert "customer_payments.notes" not in source_selects["customer_payments"]
    for projection in source_selects.values():
        assert "customers.name" not in projection
        assert "routers.password" not in projection
        assert "plans.name" not in projection
