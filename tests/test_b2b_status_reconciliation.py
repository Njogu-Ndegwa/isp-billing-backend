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

from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    ResellerPayout,
    ResellerTransactionCharge,
)
from tests.factories import make_reseller
from tests.test_b2b_payout_resilience import _patch_payout_env

pytestmark = pytest.mark.asyncio


async def _make_txn(db, reseller_id, *, status, age=timedelta(hours=30),
                    triggered_by="scheduled", conversation_id=None,
                    originator_id=None, net=95.0, fee=5.0):
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


async def test_status_result_2033_fresh_marks_failed(engine, db, monkeypatch):
    """Code 2033 (no record at Safaricom) on a FRESH transaction is a
    definitive 'never processed' — mark failed so the reseller stays owed."""
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

    assert settled.status == B2BTransactionStatus.FAILED
    payouts = (await db.execute(
        select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
    )).scalars().all()
    assert payouts == []
    assert not await b2b.has_unresolved_b2b(db, r1.id)


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


async def test_status_result_2033_stale_with_history_auto_fails(engine, db, monkeypatch):
    """Corroborating-evidence rule: a stale 2033 zombie whose reseller has had
    later payouts complete and reconcile is treated as never-processed —
    auto-failed, reseller stays owed and unblocked. (An actively-transacting
    reseller must not be deadlocked by ancient uncertainty.)"""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    txn = await _make_txn(db, r1.id, status=B2BTransactionStatus.PENDING,
                          age=timedelta(days=39), conversation_id="AG_zombie_hist")
    # Two later reconciled balance payouts = the corroboration threshold.
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
    assert txn.status == B2BTransactionStatus.FAILED
    assert "Auto-failed stale unresolved payout" in (txn.result_desc or "")
    payouts = (await db.execute(
        select(ResellerPayout).where(ResellerPayout.reseller_id == r1.id)
    )).scalars().all()
    assert payouts == []  # failed = no ledger rows; the reseller stays owed
    assert not await b2b.has_unresolved_b2b(db, r1.id)


async def test_reconciliation_sweep_unsticks_flagged_zombies_with_history(
    engine, db, session_factory, monkeypatch
):
    """Rows already flagged for manual review get retro-resolved by the same
    evidence rule on the next tick — no new Safaricom call needed."""
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
    assert flagged.status == B2BTransactionStatus.FAILED
    assert not await b2b.has_unresolved_b2b(db, r1.id)
    assert stuck.status == B2BTransactionStatus.PENDING
    assert await b2b.has_unresolved_b2b(db, r2.id)


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
