from datetime import datetime, timedelta

import pytest
from sqlalchemy import event

from app.api import payment_routes
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CustomerPayment,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


async def test_transaction_sources_are_bounded_before_global_pagination(
    db,
    engine,
    monkeypatch,
):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    base = datetime(2026, 1, 1, 12, 0, 0)

    for index in range(6):
        db.add(
            MpesaTransaction(
                checkout_request_id=f"bounded-mpesa-{index}",
                phone_number=customer.phone,
                amount=10,
                reference=f"mpesa-{index}",
                customer_id=customer.id,
                plan_id=plan.id,
                status=MpesaTransactionStatus.completed,
                created_at=base + timedelta(minutes=index * 3),
            )
        )
        db.add(
            CustomerPayment(
                customer_id=customer.id,
                reseller_id=reseller.id,
                amount=20,
                payment_method=PaymentMethod.CASH,
                payment_reference=f"cash-{index}",
                days_paid_for=1,
                plan_id=plan.id,
                status=PaymentStatus.COMPLETED,
                created_at=base + timedelta(minutes=index * 3 + 1),
            )
        )
        db.add(
            C2BTransaction(
                trans_id=f"bounded-c2b-{index}",
                bill_ref_number=f"c2b-{index}",
                trans_amount=30,
                status=C2BTransactionStatus.PROCESSED,
                matched_customer_id=customer.id,
                matched_reseller_id=reseller.id,
                received_at=base + timedelta(minutes=index * 3 + 2),
            )
        )
    await db.commit()

    async def _current_user(_token, _db):
        return reseller

    delivery_source_sizes = []

    async def _delivery_attempts(_db, *, mpesa_ids, customer_payment_ids):
        delivery_source_sizes.append((len(mpesa_ids), len(customer_payment_ids)))
        return {}

    monkeypatch.setattr(payment_routes, "get_current_user", _current_user)
    monkeypatch.setattr(
        payment_routes,
        "load_delivery_attempts_by_source",
        _delivery_attempts,
    )

    source_selects = []

    def _capture_sql(_conn, _cursor, statement, _parameters, context, _executemany):
        normalized = " ".join(statement.lower().split())
        if any(
            f"from {table}" in normalized
            for table in ("mpesa_transactions", "customer_payments", "c2b_transactions")
        ):
            limit_clause = context.compiled.statement._limit_clause
            source_selects.append((normalized, limit_clause.value))

    event.listen(engine.sync_engine, "before_cursor_execute", _capture_sql)
    try:
        rows = await payment_routes.get_mpesa_transactions(
            router_id=None,
            payment_method=None,
            date=None,
            start_date=None,
            end_date=None,
            status=None,
            limit=3,
            offset=1,
            db=db,
            token="test-token",
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _capture_sql)

    assert [row["reference"] for row in rows] == [
        "cash-5",
        "mpesa-5",
        "c2b-4",
    ]
    assert len(source_selects) == 3
    assert all(" order by " in statement for statement, _ in source_selects)
    assert all(" limit " in statement for statement, _ in source_selects)
    assert all(limit_value == 4 for _, limit_value in source_selects)
    assert delivery_source_sizes == [(4, 4)]
