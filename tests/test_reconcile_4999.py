"""Reconcile sweep must not fail transactions Safaricom says are still processing."""
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

from app.db.models import MpesaTransaction, MpesaTransactionStatus
from tests.factories import make_customer, make_plan, make_reseller, make_router


async def _make_pending_txn(db, customer, *, age_minutes=5) -> MpesaTransaction:
    txn = MpesaTransaction(
        checkout_request_id=f"ws_CO_TEST_{customer.id}",
        phone_number="254700000001",
        amount=10.0,
        reference=f"HOTSPOT-{customer.id}",
        customer_id=customer.id,
        status=MpesaTransactionStatus.pending,
        created_at=datetime.utcnow() - timedelta(minutes=age_minutes),
        updated_at=datetime.utcnow() - timedelta(minutes=age_minutes),
    )
    db.add(txn)
    await db.commit()
    await db.refresh(txn)
    return txn


async def test_4999_keeps_transaction_pending(engine, session_factory):
    async with session_factory() as db:
        reseller = await make_reseller(db)
        plan = await make_plan(db, reseller)
        router = await make_router(db, reseller)
        customer = await make_customer(db, reseller, plan, router)
        txn = await _make_pending_txn(db, customer)
        txn_id = txn.id

    from app.services import mpesa_transactions as mt

    mt._reconcile_running = False

    with patch("app.services.mpesa.get_access_token", new=AsyncMock(return_value="tok")), \
         patch(
             "app.services.mpesa.query_stk_push_status",
             new=AsyncMock(return_value={"result_code": 4999,
                                         "result_desc": "The transaction is still under processing"}),
         ), \
         patch("app.services.mpesa_transactions.asyncio.sleep", new=AsyncMock()):
        await mt.reconcile_pending_mpesa_transactions()

    # Use a fresh session so we see the committed DB state, not stale identity map
    async with session_factory() as s:
        refreshed = (await s.execute(
            select(MpesaTransaction).where(MpesaTransaction.id == txn_id)
        )).scalar_one()
    assert refreshed.status == MpesaTransactionStatus.pending  # NOT failed


async def test_terminal_code_still_marks_failed(engine, session_factory):
    """Regression guard: genuine failures (e.g. 1032 cancelled) must still fail."""
    async with session_factory() as db:
        reseller = await make_reseller(db)
        plan = await make_plan(db, reseller)
        router = await make_router(db, reseller)
        customer = await make_customer(db, reseller, plan, router)
        txn = await _make_pending_txn(db, customer)
        txn_id = txn.id

    from app.services import mpesa_transactions as mt

    mt._reconcile_running = False

    with patch("app.services.mpesa.get_access_token", new=AsyncMock(return_value="tok")), \
         patch(
             "app.services.mpesa.query_stk_push_status",
             new=AsyncMock(return_value={"result_code": 1032,
                                         "result_desc": "Request Cancelled by user."}),
         ), \
         patch("app.services.mpesa_transactions.asyncio.sleep", new=AsyncMock()):
        await mt.reconcile_pending_mpesa_transactions()

    # Use a fresh session so we see the committed DB state, not stale identity map
    async with session_factory() as s:
        refreshed = (await s.execute(
            select(MpesaTransaction).where(MpesaTransaction.id == txn_id)
        )).scalar_one()
    assert refreshed.status == MpesaTransactionStatus.failed
