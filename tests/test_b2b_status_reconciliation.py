"""Lost-callback protection for B2B payouts (2026-07-18 incident).

Safaricom accepted 15 nightly payouts (money sent) but never delivered the
result callbacks. Pending transactions create no ResellerPayout, so balances
stayed "owed" and both the next scheduled run and manual re-sends duplicated
KES 12,713. These tests pin the two defenses:

1. In-flight guard: a PENDING/TIMEOUT transaction of ANY age blocks further
   payouts to that reseller (scheduled path here; route test covers manual).
2. Status reconciliation: a transaction-status query result settles stuck
   transactions — definitively completed → payout rows appear; definitively
   failed → reseller stays owed; anything ambiguous → still blocked.
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    ResellerPayout,
    ResellerTransactionCharge,
)
from tests.factories import make_reseller, make_router
from tests.conftest import running_on_postgres
from tests.test_b2b_payout_resilience import _patch_payout_env

pytestmark = pytest.mark.asyncio


async def _make_txn(db, reseller_id, *, status, age=timedelta(hours=30),
                    triggered_by="scheduled", conversation_id=None,
                    originator_id=None, net=95.0, fee=5.0, router_id=None):
    txn = B2BTransaction(
        reseller_id=reseller_id,
        conversation_id=conversation_id,
        originator_conversation_id=originator_id,
        amount=net + fee,
        fee=fee,
        net_amount=net,
        party_a="4159825",
        party_b="247247",
        account_reference="acc-1",
        status=status,
        triggered_by=triggered_by,
        router_id=router_id,
        created_at=datetime.utcnow() - age,
    )
    db.add(txn)
    await db.commit()
    await db.refresh(txn)
    return txn


def _status_result_body(conversation_id, *, result_code="0", status_text="Completed",
                        receipt="UGITESTRCPT"):
    return {
        "Result": {
            "ResultType": 0,
            "ResultCode": result_code,
            "ResultDesc": "The service request is processed successfully.",
            "OriginatorConversationID": f"orig-{conversation_id}",
            "ConversationID": conversation_id,
            "ResultParameters": {
                "ResultParameter": [
                    {"Key": "TransactionStatus", "Value": status_text},
                    {"Key": "ReceiptNo", "Value": receipt},
                ]
            },
        }
    }


def _result_body(txn, *, result_code="0", receipt="UGITESTRCPT"):
    return {
        "Result": {
            "ResultCode": result_code,
            "ResultDesc": "Completed" if result_code == "0" else "Failed",
            "ConversationID": txn.conversation_id,
            "OriginatorConversationID": txn.originator_conversation_id,
            "TransactionID": receipt,
        }
    }


# ---------------------------------------------------------------------------
# 1. In-flight guard — scheduled job
# ---------------------------------------------------------------------------

async def test_scheduled_run_skips_reseller_with_old_pending(
    engine, db, session_factory, monkeypatch
):
    """The exact 2026-07-18 shape: last night's payout stuck PENDING, ~24h old
    (outside the 20h dedupe window), balance still positive. The run must NOT
    send again."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                    age=timedelta(hours=24), conversation_id="AG_lost_callback")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=500.0))

    await b2b.run_daily_payouts()

    assert attempted == []


async def test_scheduled_run_skips_reseller_with_timeout_txn(
    engine, db, session_factory, monkeypatch
):
    """TIMEOUT is not a verdict — money may have moved. No blind nightly retry."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _make_txn(db, r1.id, status=B2BTransactionStatus.TIMEOUT,
                    age=timedelta(days=3), conversation_id="AG_timeout")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=500.0))

    await b2b.run_daily_payouts()

    assert attempted == []


async def test_scheduled_run_pays_after_txn_resolved_failed(
    engine, db, session_factory, monkeypatch
):
    """Once reconciliation marks the stuck txn FAILED, the reseller is owed
    again and the next run must pay them."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _make_txn(db, r1.id, status=B2BTransactionStatus.FAILED,
                    age=timedelta(hours=24), conversation_id="AG_resolved_failed")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=500.0))

    await b2b.run_daily_payouts()

    assert attempted == [r1.id]


async def test_manual_pending_blocks_scheduled_run(
    engine, db, session_factory, monkeypatch
):
    """The guard must not care who triggered the in-flight payment."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                    age=timedelta(hours=2), triggered_by="manual",
                    conversation_id="AG_manual_inflight")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=500.0))

    await b2b.run_daily_payouts()

    assert attempted == []


# ---------------------------------------------------------------------------
# 2. Status-query result processing
# ---------------------------------------------------------------------------

async def test_status_result_completed_settles_pending_txn(engine, db, monkeypatch):
    """A definitive 'Completed' verdict must produce the exact same ledger
    rows the lost callback would have: txn completed + payout + fee charge."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                          conversation_id="AG_orig_1", originator_id="orig-1",
                          net=827.0, fee=10.0)

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-1"] = txn.id

    settled = await b2b.process_b2b_status_result(db, _status_result_body("QCONV-1"))
    await db.commit()

    assert settled.id == txn.id
    assert settled.status == B2BTransactionStatus.COMPLETED
    assert settled.transaction_id == "UGITESTRCPT"

    payout = (await db.execute(
        select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
    )).scalar_one()
    assert payout.amount == 827.0
    assert payout.reference == "UGITESTRCPT"
    assert settled.payout_id == payout.id

    charge = (await db.execute(
        select(ResellerTransactionCharge).where(
            ResellerTransactionCharge.reseller_id == r1.id
        )
    )).scalar_one()
    assert charge.amount == 10.0


async def test_status_result_is_idempotent(engine, db, monkeypatch):
    """A duplicate status result (or one racing the real callback) must not
    create a second payout."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                          conversation_id="AG_orig_2", net=100.0, fee=5.0)

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-2"] = txn.id

    await b2b.process_b2b_status_result(db, _status_result_body("QCONV-2"))
    await db.commit()
    b2b._status_query_map["QCONV-2"] = txn.id
    await b2b.process_b2b_status_result(db, _status_result_body("QCONV-2"))
    await db.commit()

    payouts = (await db.execute(
        select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
    )).scalars().all()
    assert len(payouts) == 1


async def test_result_callback_is_idempotent(engine, db):
    """A repeated normal result callback must create one payout and one fee."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(
        db,
        r1.id,
        status=B2BTransactionStatus.PENDING,
        conversation_id="AG_RESULT_DUP",
        originator_id="orig-result-dup",
        net=4993.0,
        fee=42.0,
    )
    body = {
        "Result": {
            "ResultCode": "0",
            "ResultDesc": "Completed",
            "ConversationID": txn.conversation_id,
            "OriginatorConversationID": txn.originator_conversation_id,
            "TransactionID": "UI9TESTDUP",
        }
    }

    await b2b.process_b2b_result(db, body)
    await db.commit()
    await b2b.process_b2b_result(db, body)
    await db.commit()

    payouts = (
        await db.execute(
            select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
        )
    ).scalars().all()
    charges = (
        await db.execute(
            select(ResellerTransactionCharge).where(
                ResellerTransactionCharge.reseller_id == r1.id
            )
        )
    ).scalars().all()
    assert len(payouts) == 1
    assert len(charges) == 1


async def test_result_success_after_timeout_settles_immediately(engine, db):
    """TIMEOUT is unresolved; a later definitive success must create the ledger."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    txn = await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.TIMEOUT,
        conversation_id="AG_TIMEOUT_THEN_SUCCESS",
        originator_id="orig-timeout-success",
        net=4993.0,
        fee=42.0,
    )

    settled = await b2b.process_b2b_result(
        db, _result_body(txn, receipt="UI9TIMEOUTSUCCESS")
    )
    await db.commit()

    assert settled.status == B2BTransactionStatus.COMPLETED
    assert settled.transaction_id == "UI9TIMEOUTSUCCESS"
    payouts = (
        await db.execute(
            select(ResellerPayout).where(ResellerPayout.reseller_id == reseller.id)
        )
    ).scalars().all()
    charges = (
        await db.execute(
            select(ResellerTransactionCharge).where(
                ResellerTransactionCharge.reseller_id == reseller.id
            )
        )
    ).scalars().all()
    assert len(payouts) == 1
    assert len(charges) == 1
    assert not await b2b.has_unresolved_b2b(db, reseller.id)


async def test_result_failure_after_timeout_releases_balance(engine, db):
    """A definitive failure after TIMEOUT must unblock without a fake payout."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    txn = await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.TIMEOUT,
        conversation_id="AG_TIMEOUT_THEN_FAILURE",
        originator_id="orig-timeout-failure",
    )

    settled = await b2b.process_b2b_result(
        db, _result_body(txn, result_code="2001", receipt=None)
    )
    await db.commit()

    assert settled.status == B2BTransactionStatus.FAILED
    payouts = (
        await db.execute(
            select(ResellerPayout).where(ResellerPayout.reseller_id == reseller.id)
        )
    ).scalars().all()
    assert payouts == []
    assert not await b2b.has_unresolved_b2b(db, reseller.id)


@pytest.mark.skipif(
    not running_on_postgres(),
    reason="SELECT FOR UPDATE concurrency semantics require Postgres",
)
async def test_concurrent_result_callbacks_settle_once(
    engine, db, session_factory
):
    """Two callbacks that arrive together serialize on the B2B transaction.

    Regression for the 2026-09-09 SafoLink incident, where both sessions read
    PENDING and inserted payout/fee rows about 30 ms apart.
    """
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(
        db,
        r1.id,
        status=B2BTransactionStatus.PENDING,
        conversation_id="AG_RESULT_RACE",
        originator_id="orig-result-race",
        net=4993.0,
        fee=42.0,
    )
    body = {
        "Result": {
            "ResultCode": "0",
            "ResultDesc": "Completed",
            "ConversationID": txn.conversation_id,
            "OriginatorConversationID": txn.originator_conversation_id,
            "TransactionID": "UI9TESTRACE",
        }
    }

    async def deliver():
        async with session_factory() as session:
            await b2b.process_b2b_result(session, body)
            await session.commit()

    await asyncio.gather(deliver(), deliver())

    payouts = (
        await db.execute(
            select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
        )
    ).scalars().all()
    charges = (
        await db.execute(
            select(ResellerTransactionCharge).where(
                ResellerTransactionCharge.reseller_id == r1.id
            )
        )
    ).scalars().all()
    assert len(payouts) == 1
    assert len(charges) == 1


@pytest.mark.skipif(
    not running_on_postgres(),
    reason="SELECT FOR UPDATE concurrency semantics require Postgres",
)
async def test_timeout_commit_before_result_still_accepts_definitive_success(
    engine, db, session_factory
):
    """Force timeout to own the row lock first, then deliver the real result."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    txn = await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.PENDING,
        conversation_id="AG_TIMEOUT_RESULT_RACE",
        originator_id="orig-timeout-result-race",
        net=4993.0,
        fee=42.0,
    )
    timeout_body = {
        "Result": {
            "ConversationID": txn.conversation_id,
            "OriginatorConversationID": txn.originator_conversation_id,
            "ResultDesc": "Queue timeout",
        }
    }
    result_body = _result_body(txn, receipt="UI9TIMEOUTRACE")
    timeout_has_lock = asyncio.Event()
    allow_timeout_commit = asyncio.Event()

    async def deliver_timeout():
        async with session_factory() as session:
            await b2b.process_b2b_timeout(session, timeout_body)
            timeout_has_lock.set()
            await allow_timeout_commit.wait()
            await session.commit()

    async def deliver_result():
        await timeout_has_lock.wait()
        async with session_factory() as session:
            await b2b.process_b2b_result(session, result_body)
            await session.commit()

    timeout_task = asyncio.create_task(deliver_timeout())
    await timeout_has_lock.wait()
    result_task = asyncio.create_task(deliver_result())
    await asyncio.sleep(0.05)
    allow_timeout_commit.set()
    await asyncio.gather(timeout_task, result_task)

    await db.refresh(txn)
    assert txn.status == B2BTransactionStatus.COMPLETED
    assert txn.transaction_id == "UI9TIMEOUTRACE"
    payouts = (
        await db.execute(
            select(ResellerPayout).where(ResellerPayout.reseller_id == reseller.id)
        )
    ).scalars().all()
    charges = (
        await db.execute(
            select(ResellerTransactionCharge).where(
                ResellerTransactionCharge.reseller_id == reseller.id
            )
        )
    ).scalars().all()
    assert len(payouts) == 1
    assert len(charges) == 1


async def test_mpesa_payout_reference_is_unique(engine, db):
    """The DB is the last line of defense if callback locking regresses."""
    r1 = await make_reseller(db)
    db.add_all([
        ResellerPayout(
            reseller_id=r1.id,
            amount=4993,
            payment_method="mpesa_b2b",
            reference="UI9UNIQUE",
        ),
        ResellerPayout(
            reseller_id=r1.id,
            amount=4993,
            payment_method="mpesa_b2b",
            reference="UI9UNIQUE",
        ),
    ])
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_status_result_failed_marks_failed_no_payout(engine, db, monkeypatch):
    """A definitive failure verdict frees the reseller (still owed) without
    inventing a payout."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(db, r1.id, status=B2BTransactionStatus.TIMEOUT,
                          conversation_id="AG_orig_3")

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-3"] = txn.id

    settled = await b2b.process_b2b_status_result(
        db, _status_result_body("QCONV-3", status_text="Failed", receipt=None)
    )
    await db.commit()

    assert settled.status == B2BTransactionStatus.FAILED
    payouts = (await db.execute(
        select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
    )).scalars().all()
    assert payouts == []
    assert not await b2b.has_unresolved_b2b(db, r1.id)


async def test_status_result_2033_fresh_stays_blocked_and_accepts_late_success(
    engine, db, monkeypatch
):
    """Fresh 2033 can be provider lag; it must not release money for re-pay."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                          age=timedelta(hours=1), conversation_id="AG_orig_2033")

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-2033"] = txn.id
    settled = await b2b.process_b2b_status_result(
        db, _status_result_body("QCONV-2033", result_code="2033", status_text="")
    )
    await db.commit()

    assert settled.status == B2BTransactionStatus.PENDING
    assert not (settled.result_desc or "").startswith(b2b.MANUAL_REVIEW_MARKER)
    payouts = (await db.execute(
        select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
    )).scalars().all()
    assert payouts == []
    assert await b2b.has_unresolved_b2b(db, r1.id)

    # A real result may arrive after the status index said "not found".
    await b2b.process_b2b_result(
        db, _result_body(txn, receipt="UI9LATEAFTER2033")
    )
    await db.commit()
    await db.refresh(txn)
    assert txn.status == B2BTransactionStatus.COMPLETED
    payouts = (await db.execute(
        select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
    )).scalars().all()
    assert len(payouts) == 1
    assert payouts[0].reference == "UI9LATEAFTER2033"


async def test_status_result_2033_stale_stays_blocked(engine, db, monkeypatch):
    """2033 on an OLD transaction may just mean it aged out of Safaricom's
    status index — manual statement review required, keep blocking."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                          age=timedelta(days=20), conversation_id="AG_orig_2033_old")

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-2033-OLD"] = txn.id
    await b2b.process_b2b_status_result(
        db, _status_result_body("QCONV-2033-OLD", result_code="2033", status_text="")
    )
    await db.commit()

    await db.refresh(txn)
    assert txn.status == B2BTransactionStatus.PENDING
    assert await b2b.has_unresolved_b2b(db, r1.id)
    # ...and it is flagged for manual statement review so the reconciliation
    # job stops re-querying it (an admin resolves it from the B2B view).
    assert (txn.result_desc or "").startswith(b2b.MANUAL_REVIEW_MARKER)


async def test_status_result_2033_stale_with_history_still_requires_statement(
    engine, db, monkeypatch
):
    """Later payouts are not proof that an old ambiguous transfer failed."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                          age=timedelta(days=39), conversation_id="AG_zombie_hist")
    # Even two later reconciled payouts cannot prove this transfer failed.
    await _make_txn(db, r1.id, status=B2BTransactionStatus.COMPLETED,
                    age=timedelta(days=20), conversation_id="AG_later_1")
    await _make_txn(db, r1.id, status=B2BTransactionStatus.COMPLETED,
                    age=timedelta(days=5), conversation_id="AG_later_2")

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-2033-HIST"] = txn.id
    await b2b.process_b2b_status_result(
        db, _status_result_body("QCONV-2033-HIST", result_code="2033", status_text="")
    )
    await db.commit()

    await db.refresh(txn)
    assert txn.status == B2BTransactionStatus.PENDING
    assert (txn.result_desc or "").startswith(b2b.MANUAL_REVIEW_MARKER)
    payouts = (await db.execute(
        select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
    )).scalars().all()
    assert payouts == []  # failed = no ledger rows; the reseller stays owed
    assert await b2b.has_unresolved_b2b(db, r1.id)


async def test_status_result_2033_router_zombie_ignores_other_router_history(
    engine, db, monkeypatch
):
    """Router B payouts cannot prove that a stale router A transfer failed."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    router_a = await make_router(db, reseller, name="Site A")
    router_b = await make_router(db, reseller, name="Site B")
    zombie = await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.PENDING,
        age=timedelta(days=39),
        conversation_id="AG_ROUTER_ZOMBIE",
        router_id=router_a.id,
    )
    await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.COMPLETED,
        age=timedelta(days=10),
        conversation_id="AG_OTHER_ROUTER_1",
        router_id=router_b.id,
    )
    await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.COMPLETED,
        age=timedelta(days=2),
        conversation_id="AG_OTHER_ROUTER_2",
        router_id=router_b.id,
    )

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-ROUTER-ZOMBIE"] = zombie.id
    await b2b.process_b2b_status_result(
        db,
        _status_result_body(
            "QCONV-ROUTER-ZOMBIE", result_code="2033", status_text=""
        ),
    )
    await db.commit()

    await db.refresh(zombie)
    assert zombie.status == B2BTransactionStatus.PENDING
    assert (zombie.result_desc or "").startswith(b2b.MANUAL_REVIEW_MARKER)
    assert await b2b.has_unresolved_b2b(db, reseller.id, router_id=router_a.id)


async def test_status_result_2033_router_zombie_ignores_same_router_history(
    engine, db, monkeypatch
):
    """Same-router history is still not a provider or statement verdict."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Site A")
    zombie = await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.PENDING,
        age=timedelta(days=39),
        conversation_id="AG_SAME_ROUTER_ZOMBIE",
        router_id=router.id,
    )
    await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.COMPLETED,
        age=timedelta(days=10),
        conversation_id="AG_SAME_ROUTER_1",
        router_id=router.id,
    )
    await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.COMPLETED,
        age=timedelta(days=2),
        conversation_id="AG_SAME_ROUTER_2",
        router_id=router.id,
    )

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-SAME-ROUTER"] = zombie.id
    await b2b.process_b2b_status_result(
        db,
        _status_result_body(
            "QCONV-SAME-ROUTER", result_code="2033", status_text=""
        ),
    )
    await db.commit()

    await db.refresh(zombie)
    assert zombie.status == B2BTransactionStatus.PENDING
    assert (zombie.result_desc or "").startswith(b2b.MANUAL_REVIEW_MARKER)
    assert await b2b.has_unresolved_b2b(db, reseller.id, router_id=router.id)


async def test_status_result_2033_deleted_router_never_uses_null_bucket_history(
    engine, db, monkeypatch
):
    """ON DELETE SET NULL must not turn unrelated history into failure proof."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Deleted Site")
    zombie = await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.PENDING,
        age=timedelta(days=39),
        conversation_id="AG_DELETED_ROUTER_ZOMBIE",
        router_id=router.id,
    )
    await db.delete(router)
    # Production Postgres applies the FK's ON DELETE SET NULL. The local
    # SQLite harness does not enforce foreign keys, so mirror that transition.
    zombie.router_id = None
    await db.commit()
    await db.refresh(zombie)
    assert zombie.router_id is None

    await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.COMPLETED,
        age=timedelta(days=10),
        conversation_id="AG_NULL_BUCKET_1",
    )
    await _make_txn(
        db,
        reseller.id,
        status=B2BTransactionStatus.COMPLETED,
        age=timedelta(days=2),
        conversation_id="AG_NULL_BUCKET_2",
    )

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-DELETED-ROUTER"] = zombie.id
    await b2b.process_b2b_status_result(
        db,
        _status_result_body(
            "QCONV-DELETED-ROUTER", result_code="2033", status_text=""
        ),
    )
    await db.commit()

    await db.refresh(zombie)
    assert zombie.status == B2BTransactionStatus.PENDING
    assert (zombie.result_desc or "").startswith(b2b.MANUAL_REVIEW_MARKER)
    assert await b2b.has_unresolved_b2b(db, reseller.id)


async def test_reconciliation_sweep_never_auto_releases_flagged_zombies(
    engine, db, session_factory, monkeypatch
):
    """Manual-review rows stay blocked regardless of later ledger history."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    flagged = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                              age=timedelta(days=39), conversation_id="AG_flagged_hist")
    flagged.result_desc = f"{b2b.MANUAL_REVIEW_MARKER}: stale 2033"
    # Corroboration: two later reconciled payouts.
    await _make_txn(db, r1.id, status=B2BTransactionStatus.COMPLETED,
                    age=timedelta(days=10), conversation_id="AG_fl_later_1")
    await _make_txn(db, r1.id, status=B2BTransactionStatus.COMPLETED,
                    age=timedelta(days=2), conversation_id="AG_fl_later_2")

    # Control: a flagged zombie whose reseller has NO later payouts stays put.
    r2 = await make_reseller(db)
    stuck = await _make_txn(db, r2.id, status=B2BTransactionStatus.PENDING,
                            age=timedelta(days=39), conversation_id="AG_flagged_alone")
    stuck.result_desc = f"{b2b.MANUAL_REVIEW_MARKER}: stale 2033"
    await db.commit()

    monkeypatch.setattr(b2b, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "tester", raising=False)
    monkeypatch.setattr(b2b, "query_b2b_transaction_status", AsyncMock(return_value=True))

    await b2b.run_b2b_status_reconciliation()

    await db.refresh(flagged)
    await db.refresh(stuck)
    assert flagged.status == B2BTransactionStatus.PENDING
    assert await b2b.has_unresolved_b2b(db, r1.id)
    assert stuck.status == B2BTransactionStatus.PENDING
    assert await b2b.has_unresolved_b2b(db, r2.id)
    b2b.query_b2b_transaction_status.assert_not_awaited()


async def test_status_result_ambiguous_leaves_txn_blocked(engine, db, monkeypatch):
    """Query-level errors or unknown status strings must change nothing —
    uncertainty never releases money."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                          conversation_id="AG_orig_4")

    b2b._status_query_map.clear()
    b2b._status_query_map["QCONV-4"] = txn.id
    await b2b.process_b2b_status_result(
        db, _status_result_body("QCONV-4", result_code="2001", status_text="")
    )
    b2b._status_query_map["QCONV-4"] = txn.id
    await b2b.process_b2b_status_result(
        db, _status_result_body("QCONV-4", status_text="Being Processed")
    )
    await db.commit()

    await db.refresh(txn)
    assert txn.status == B2BTransactionStatus.PENDING
    assert await b2b.has_unresolved_b2b(db, r1.id)


async def test_status_result_with_unknown_correlation_is_ignored(engine, db):
    """No correlation entry (e.g. app restarted) → nothing settles."""
    from app.services import mpesa_b2b as b2b

    b2b._status_query_map.clear()
    result = await b2b.process_b2b_status_result(db, _status_result_body("QCONV-GONE"))
    assert result is None


# ---------------------------------------------------------------------------
# 3. Reconciliation job — selects the right transactions, no session held
# ---------------------------------------------------------------------------

async def test_reconciliation_queries_only_stale_unresolved(
    engine, db, session_factory, monkeypatch
):
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    stale_pending = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                                    age=timedelta(minutes=30), originator_id="orig-a")
    stale_timeout = await _make_txn(db, r1.id, status=B2BTransactionStatus.TIMEOUT,
                                    age=timedelta(days=2), originator_id="orig-b")
    await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                    age=timedelta(minutes=1), originator_id="orig-fresh")
    await _make_txn(db, r1.id, status=B2BTransactionStatus.COMPLETED,
                    age=timedelta(hours=5), originator_id="orig-done")
    # Any-age zombies MUST be queried: the in-flight guard blocks on any age,
    # so a bounded query window would deadlock the reseller (rid 10, txns
    # 710/711, 2026-07-19 — 39-day-old pendings nothing would ever resolve).
    ancient = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                              age=timedelta(days=60), originator_id="orig-ancient")
    # ...except rows already flagged for manual statement review.
    flagged = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                              age=timedelta(days=45), originator_id="orig-flagged")
    flagged.result_desc = f"{b2b.MANUAL_REVIEW_MARKER}: stale 2033"
    await db.commit()

    monkeypatch.setattr(b2b, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "tester", raising=False)

    queried = []

    async def fake_query(txn_id, originator_id, receipt):
        queried.append(txn_id)
        return True

    monkeypatch.setattr(b2b, "query_b2b_transaction_status", fake_query)

    await b2b.run_b2b_status_reconciliation()

    assert sorted(queried) == sorted([stale_pending.id, stale_timeout.id, ancient.id])
