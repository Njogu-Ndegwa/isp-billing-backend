from types import SimpleNamespace

import pytest

from app.api import payment_routes
from app.db.models import MpesaTransaction, MpesaTransactionStatus, UserRole
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


async def test_mpesa_list_and_summary_exclude_unowned_transactions(db, monkeypatch):
    reseller = await make_reseller(db)
    other_reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    other_plan = await make_plan(db, other_reseller)
    router = await make_router(db, reseller)
    other_router = await make_router(db, other_reseller)
    customer = await make_customer(db, reseller, plan, router)
    other_customer = await make_customer(db, other_reseller, other_plan, other_router)

    db.add_all([
        MpesaTransaction(
            checkout_request_id="owned-transaction",
            phone_number=customer.phone,
            amount=100,
            reference="owned-transaction",
            customer_id=customer.id,
            status=MpesaTransactionStatus.completed,
        ),
        MpesaTransaction(
            checkout_request_id="other-reseller-transaction",
            phone_number=other_customer.phone,
            amount=200,
            reference="other-reseller-transaction",
            customer_id=other_customer.id,
            status=MpesaTransactionStatus.completed,
        ),
        MpesaTransaction(
            checkout_request_id="unowned-transaction",
            phone_number="254700000000",
            amount=300,
            reference="unowned-transaction",
            customer_id=None,
            status=MpesaTransactionStatus.completed,
        ),
    ])
    await db.commit()

    async def _current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", _current_user)

    rows = await payment_routes.get_mpesa_transactions(
        router_id=None,
        payment_method="mobile_money",
        date=None,
        start_date=None,
        end_date=None,
        status=None,
        limit=200,
        offset=0,
        db=db,
        token="test-token",
    )
    summary = await payment_routes.get_mpesa_transactions_summary(
        router_id=None,
        payment_method="mobile_money",
        date=None,
        start_date=None,
        end_date=None,
        db=db,
        token="test-token",
    )

    assert [row["checkout_request_id"] for row in rows] == ["owned-transaction"]
    assert summary["total_transactions"] == 1
    assert summary["total_amount"] == 100
