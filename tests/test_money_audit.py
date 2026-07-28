"""Tests for the read-only money auditor (app/services/money_audit.py).

Each detector is exercised against BOTH:
  * a clean state covering every legitimate recorder shape — must produce
    ZERO findings (false positives would make the ops report unusable), and
  * violating states — must be detected with a useful row summary.
"""

from datetime import datetime, timedelta

from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    C2BTransaction,
    C2BTransactionStatus,
    CollectionMode,
    CustomerPayment,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
    ResellerPayout,
)
from app.services.money_audit import (
    find_orphan_payouts,
    find_phantom_customer_payments,
    find_unsettled_pending_b2b,
    run_money_audit,
)
from tests.factories import make_reseller


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------

async def _payout(db, reseller, amount=500.0, *, method="mpesa_b2b", reference=None,
                  created_at=None):
    p = ResellerPayout(
        reseller_id=reseller.id,
        amount=amount,
        payment_method=method,
        reference=reference,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(p)
    await db.commit()
    return p


async def _b2b(db, reseller, *, status=B2BTransactionStatus.COMPLETED, payout=None,
               amount=513.0, net_amount=500.0, conversation_id=None, created_at=None):
    t = B2BTransaction(
        reseller_id=reseller.id,
        conversation_id=conversation_id,
        amount=amount,
        fee=amount - net_amount,
        net_amount=net_amount,
        party_a="600980",
        party_b="123456",
        status=status,
        payout_id=payout.id if payout else None,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(t)
    await db.commit()
    return t


async def _customer_payment(db, reseller, amount=100.0, *, reference,
                            collection_mode=CollectionMode.SYSTEM_COLLECTED,
                            method=PaymentMethod.MOBILE_MONEY):
    p = CustomerPayment(
        customer_id=None,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=method,
        payment_reference=reference,
        days_paid_for=30,
        status=PaymentStatus.COMPLETED,
        collection_mode=collection_mode,
    )
    db.add(p)
    await db.commit()
    return p


async def _c2b(db, trans_id, amount=100.0):
    t = C2BTransaction(
        trans_id=trans_id,
        trans_amount=amount,
        status=C2BTransactionStatus.PROCESSED,
    )
    db.add(t)
    await db.commit()
    return t


async def _stk(db, *, checkout_request_id, receipt=None, amount=100.0):
    t = MpesaTransaction(
        checkout_request_id=checkout_request_id,
        phone_number="254700000001",
        amount=amount,
        reference="REF",
        mpesa_receipt_number=receipt,
        status=MpesaTransactionStatus.completed,
    )
    db.add(t)
    await db.commit()
    return t


async def _seed_clean_state(db, reseller):
    """Every legitimate recorder shape at once — the auditor must stay silent."""
    # 1. auto B2B payout properly backed by a COMPLETED transaction
    backed = await _payout(db, reseller, 500.0, reference="TX-OK")
    await _b2b(db, reseller, payout=backed, conversation_id="AG_ok")
    # 2. manual admin payout — no B2B row by design
    await _payout(db, reseller, 250.0, method="mpesa", reference="MANUAL-1")
    await _payout(db, reseller, 100.0, method="bank_transfer")
    # 3. C2B-recorded system-collected payment
    await _c2b(db, "TGH12345", 100.0)
    await _customer_payment(db, reseller, 100.0, reference="TGH12345")
    # 4. direct-collected C2B payment (reseller's own paybill; out of scope)
    await _customer_payment(
        db, reseller, 80.0, reference="NO-RECORD-NEEDED",
        collection_mode=CollectionMode.DIRECT,
    )
    # 5. STK payment — collection_mode NULL (only C2B stamps it), receipt ref
    await _stk(db, checkout_request_id="ws_CO_1", receipt="SGQ77XYZ")
    await _customer_payment(db, reseller, 60.0, reference="SGQ77XYZ", collection_mode=None)
    # 6. manual mobile-money entry typed by the reseller (NULL mode, odd ref)
    await _customer_payment(db, reseller, 40.0, reference="till slip 17", collection_mode=None)
    # 7. cash payment, reference-free
    await _customer_payment(
        db, reseller, 20.0, reference=None,
        collection_mode=None, method=PaymentMethod.CASH,
    )
    # 8. defensive: SYSTEM_COLLECTED row whose ref is an STK receipt
    await _stk(db, checkout_request_id="ws_CO_2", receipt="SGQ88ABC")
    await _customer_payment(db, reseller, 50.0, reference="SGQ88ABC")
    # 9. recent PENDING B2B (inside the age threshold) + resolved old ones
    await _b2b(db, reseller, status=B2BTransactionStatus.PENDING,
               conversation_id="AG_recent",
               created_at=datetime.utcnow() - timedelta(hours=1))
    old = datetime.utcnow() - timedelta(days=5)
    await _b2b(db, reseller, status=B2BTransactionStatus.FAILED,
               conversation_id="AG_failed_old", created_at=old)
    completed_payout = await _payout(db, reseller, 300.0, reference="TX-OLD",
                                     created_at=old)
    await _b2b(db, reseller, payout=completed_payout,
               conversation_id="AG_completed_old", created_at=old)


# ---------------------------------------------------------------------------
# zero false positives on the clean state
# ---------------------------------------------------------------------------

async def test_clean_state_produces_zero_findings(db):
    reseller = await make_reseller(db)
    await _seed_clean_state(db, reseller)

    assert await find_orphan_payouts(db) == []
    assert await find_phantom_customer_payments(db) == []
    assert await find_unsettled_pending_b2b(db, older_than_hours=24) == []

    report = await run_money_audit(db, older_than_hours=24)
    assert report["counts"] == {
        "orphan_payouts": 0,
        "phantom_customer_payments": 0,
        "unsettled_pending_b2b": 0,
    }


# ---------------------------------------------------------------------------
# find_orphan_payouts
# ---------------------------------------------------------------------------

async def test_detects_b2b_payout_with_no_transaction(db):
    reseller = await make_reseller(db)
    await _seed_clean_state(db, reseller)
    orphan = await _payout(db, reseller, 777.0, reference="GHOST-1")

    rows = await find_orphan_payouts(db)

    assert [r["payout_id"] for r in rows] == [orphan.id]
    assert rows[0]["reseller_id"] == reseller.id
    assert rows[0]["amount"] == 777.0
    assert rows[0]["reference"] == "GHOST-1"
    assert "no COMPLETED B2BTransaction" in rows[0]["reason"]


async def test_detects_b2b_payout_backed_only_by_failed_transaction(db):
    """A payout row must be backed by a COMPLETED transaction; a FAILED one
    means the ledger credits money Safaricom says never moved."""
    reseller = await make_reseller(db)
    payout = await _payout(db, reseller, 400.0, reference="FAILED-BACKING")
    await _b2b(db, reseller, status=B2BTransactionStatus.FAILED, payout=payout,
               conversation_id="AG_failed_link")

    rows = await find_orphan_payouts(db)

    assert [r["payout_id"] for r in rows] == [payout.id]


async def test_manual_payouts_never_flagged(db):
    reseller = await make_reseller(db)
    await _payout(db, reseller, 900.0, method="mpesa", reference="MANUAL")
    await _payout(db, reseller, 900.0, method="cash")

    assert await find_orphan_payouts(db) == []


# ---------------------------------------------------------------------------
# find_phantom_customer_payments
# ---------------------------------------------------------------------------

async def test_detects_system_collected_payment_without_provider_record(db):
    reseller = await make_reseller(db)
    await _seed_clean_state(db, reseller)
    phantom = await _customer_payment(db, reseller, 999.0, reference="TGH-DOES-NOT-EXIST")

    rows = await find_phantom_customer_payments(db)

    assert [r["payment_id"] for r in rows] == [phantom.id]
    assert rows[0]["amount"] == 999.0
    assert rows[0]["payment_reference"] == "TGH-DOES-NOT-EXIST"
    assert "no C2BTransaction/MpesaTransaction" in rows[0]["reason"]


async def test_detects_system_collected_payment_with_null_reference(db):
    reseller = await make_reseller(db)
    phantom = await _customer_payment(db, reseller, 120.0, reference=None)

    rows = await find_phantom_customer_payments(db)

    assert [r["payment_id"] for r in rows] == [phantom.id]
    assert "no payment_reference" in rows[0]["reason"]


async def test_null_and_direct_collection_modes_are_out_of_scope(db):
    """NULL rows (STK/legacy/manual entries) and DIRECT rows (reseller's own
    paybill) must not be flagged even with unmatched references — documented
    limitation, keeps the report free of false positives."""
    reseller = await make_reseller(db)
    await _customer_payment(db, reseller, 10.0, reference="UNMATCHED-1",
                            collection_mode=None)
    await _customer_payment(db, reseller, 10.0, reference="UNMATCHED-2",
                            collection_mode=CollectionMode.DIRECT)

    assert await find_phantom_customer_payments(db) == []


async def test_stk_checkout_id_reference_accepted_as_evidence(db):
    """The manual-completion path can record reference = checkout_request_id
    when no receipt exists; that still counts as provider evidence."""
    reseller = await make_reseller(db)
    await _stk(db, checkout_request_id="ws_CO_MANUAL", receipt=None)
    await _customer_payment(db, reseller, 70.0, reference="ws_CO_MANUAL")

    assert await find_phantom_customer_payments(db) == []


# ---------------------------------------------------------------------------
# find_unsettled_pending_b2b
# ---------------------------------------------------------------------------

async def test_detects_old_pending_and_timeout_b2b(db):
    reseller = await make_reseller(db)
    await _seed_clean_state(db, reseller)
    old_pending = await _b2b(
        db, reseller, status=B2BTransactionStatus.PENDING,
        conversation_id="AG_stuck_pending",
        created_at=datetime.utcnow() - timedelta(hours=30),
    )
    old_timeout = await _b2b(
        db, reseller, status=B2BTransactionStatus.TIMEOUT,
        conversation_id="AG_stuck_timeout",
        created_at=datetime.utcnow() - timedelta(hours=48),
    )

    rows = await find_unsettled_pending_b2b(db, older_than_hours=24)

    ids = [r["b2b_transaction_id"] for r in rows]
    assert ids == [old_timeout.id, old_pending.id]  # oldest first
    by_id = {r["b2b_transaction_id"]: r for r in rows}
    assert by_id[old_pending.id]["status"] == "pending"
    assert by_id[old_timeout.id]["status"] == "timeout"
    assert by_id[old_pending.id]["age_hours"] >= 30
    assert by_id[old_pending.id]["reseller_id"] == reseller.id


async def test_age_threshold_is_respected(db):
    reseller = await make_reseller(db)
    await _b2b(db, reseller, status=B2BTransactionStatus.PENDING,
               conversation_id="AG_6h",
               created_at=datetime.utcnow() - timedelta(hours=6))

    assert await find_unsettled_pending_b2b(db, older_than_hours=24) == []
    assert len(await find_unsettled_pending_b2b(db, older_than_hours=5)) == 1


# ---------------------------------------------------------------------------
# aggregate report
# ---------------------------------------------------------------------------

async def test_run_money_audit_aggregates_all_detectors(db):
    reseller = await make_reseller(db)
    await _seed_clean_state(db, reseller)
    await _payout(db, reseller, 111.0, reference="GHOST")
    await _customer_payment(db, reseller, 222.0, reference="PHANTOM")
    await _b2b(db, reseller, status=B2BTransactionStatus.PENDING,
               conversation_id="AG_zombie",
               created_at=datetime.utcnow() - timedelta(hours=72))

    report = await run_money_audit(db, older_than_hours=24)

    assert report["counts"] == {
        "orphan_payouts": 1,
        "phantom_customer_payments": 1,
        "unsettled_pending_b2b": 1,
    }
    assert report["orphan_payouts"][0]["amount"] == 111.0
    assert report["phantom_customer_payments"][0]["amount"] == 222.0
    assert report["unsettled_pending_b2b"][0]["conversation_id"] == "AG_zombie"
