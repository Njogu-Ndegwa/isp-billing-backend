"""The period summary counts what the reseller made: completed payments only.

A failed, expired or pending M-Pesa prompt is an attempt, not a sale. Counting
it made "How much did I make this month?" read KES 21,908 from 1,741
transactions when only KES 17,070 had come in (2026-11-25)."""
from types import SimpleNamespace

import pytest

from app.api import payment_routes
from app.db.models import MpesaTransaction, MpesaTransactionStatus, UserRole
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


async def test_failed_expired_and_pending_prompts_stay_out_of_the_totals(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    for i, (amount, status) in enumerate([
        (100, MpesaTransactionStatus.completed),
        (50, MpesaTransactionStatus.completed),
        (30, MpesaTransactionStatus.failed),
        (20, MpesaTransactionStatus.expired),
        (10, MpesaTransactionStatus.pending),
    ]):
        db.add(MpesaTransaction(
            checkout_request_id=f"completed-only-{i}", phone_number=customer.phone, amount=amount,
            reference=f"completed-only-{i}", customer_id=customer.id, plan_id=plan.id, status=status,
        ))
    await db.commit()

    async def _current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", _current_user)
    result = await payment_routes.get_mpesa_transactions_summary(
        router_id=None, payment_method=None, date=None, start_date=None, end_date=None,
        db=db, token="test-token",
    )

    assert result["total_transactions"] == 2
    assert result["total_amount"] == 150
    assert result["not_completed"] == {"count": 3, "amount": 60}
    # the attempts are still there for a question about failures
    assert result["status_breakdown"]["failed"] == {"count": 1, "amount": 30}
    assert result["status_breakdown"]["expired"]["count"] == 1
    assert result["status_breakdown"]["pending"]["count"] == 1
    assert result["status_breakdown"]["completed"]["amount"] == result["total_amount"]


def test_the_bot_is_told_attempts_are_not_money_made():
    from app.services.assistant import agent
    rules = agent.SYSTEM_PROMPT if hasattr(agent, "SYSTEM_PROMPT") else ""
    text = rules or open(agent.__file__, encoding="utf-8").read()
    assert "not a transaction and not money made" in text
