"""Fapshi pending-payment guard must not lock customers out (PR #295 follow-up).

Production, 4 Nov 2026: rows the sweep parked as legacy_purchase_snapshot_missing
or reconciliation_window_exhausted kept status PENDING/CREATED forever, their
NULL snapshot never matched a new purchase, and _initiate_fapshi refused every
new payment with "A different purchase is still pending". Twelve customers
could not pay; one was refused 30 times.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import func, select

from app.api.fapshi_routes import customer_payment_flags, payment_flags
from app.db.models import CustomerPayment, FapshiTransaction, FapshiTransactionStatus
from app.services import fapshi, fapshi_reconciliation as service
from app.services.payment_gateway import _initiate_fapshi
from tests.test_fapshi_reliability import purchase, remote

pytestmark = pytest.mark.asyncio


def prompt_mock(monkeypatch):
    prompt = AsyncMock(return_value={"transId": "new-transaction"})
    monkeypatch.setattr(fapshi, "initiate_direct_payment", prompt)
    return prompt


async def park(db, txn, *, reason, age, status=FapshiTransactionStatus.PENDING,
               provider_status=None, legacy=True):
    txn.review_reason = reason
    txn.created_at = datetime.utcnow() - age
    txn.status = status
    txn.provider_status = provider_status
    if legacy:
        txn.purchase_snapshot = None
    await db.commit()


@pytest.mark.parametrize("reason,provider_status,status", [
    ("legacy_purchase_snapshot_missing", "SUCCESSFUL", FapshiTransactionStatus.PENDING),
    ("reconciliation_window_exhausted", None, FapshiTransactionStatus.PENDING),
    ("reconciliation_window_exhausted", None, FapshiTransactionStatus.CREATED),
])
async def test_held_row_no_longer_locks_customer_out(db, monkeypatch, reason, provider_status, status):
    # Reproduces the production lockout: the held row has no snapshot, so the
    # old guard always answered "A different purchase is still pending".
    txn, customer, plan, pm = await purchase(db)
    await park(db, txn, reason=reason, age=timedelta(days=2), status=status,
               provider_status=provider_status)
    prompt = prompt_mock(monkeypatch)

    result = await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")

    assert prompt.await_count == 1
    assert result["trans_id"] == "new-transaction" and not result.get("reused")
    await db.refresh(txn)
    # The held row stays visible for review, untouched and uncredited.
    assert txn.status == status and txn.review_reason == reason
    assert await db.scalar(select(func.count(FapshiTransaction.id))) == 2
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0


async def test_recent_review_hold_does_not_block_either(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    await park(db, txn, reason="legacy_purchase_snapshot_missing", age=timedelta(minutes=1),
               provider_status="SUCCESSFUL")
    prompt = prompt_mock(monkeypatch)
    await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")
    assert prompt.await_count == 1


async def test_genuinely_in_flight_attempt_still_blocks_or_reuses(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    prompt = prompt_mock(monkeypatch)
    # Same purchase within the window: a double tap reuses the live prompt.
    result = await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")
    assert result["reused"] and result["trans_id"] == "test-transaction"
    # Different purchase within the window: refused, no second prompt.
    plan.price = 700
    await db.commit()
    with pytest.raises(ValueError, match="different purchase"):
        await _initiate_fapshi(db, pm, customer, customer.phone, 700, "test")
    prompt.assert_not_awaited()


async def test_stale_unheld_attempt_keeps_reconciling_but_does_not_block(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    txn.created_at = datetime.utcnow() - service.IN_FLIGHT_WINDOW - timedelta(minutes=1)
    await db.commit()
    prompt = prompt_mock(monkeypatch)
    await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")
    assert prompt.await_count == 1
    await db.refresh(txn)
    assert txn.status == FapshiTransactionStatus.PENDING and txn.review_reason is None


async def test_uncertain_initiation_stops_blocking_after_in_flight_window(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    await park(db, txn, reason="initiation_outcome_unknown", age=timedelta(minutes=5), legacy=False)
    txn.trans_id = None
    await db.commit()
    prompt = prompt_mock(monkeypatch)
    with pytest.raises(ValueError, match="do not pay again"):
        await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")
    txn.created_at = datetime.utcnow() - timedelta(hours=1)
    await db.commit()
    await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")
    assert prompt.await_count == 1
    await db.refresh(txn)
    assert txn.review_reason == "initiation_outcome_unknown"


@pytest.mark.parametrize("provider", ["FAILED", "EXPIRED"])
async def test_exhausted_row_gets_final_check_and_closes_when_provider_failed(db, monkeypatch, provider):
    txn, customer, plan, pm = await purchase(db)
    txn.created_at = datetime.utcnow() - timedelta(days=8)
    await db.commit()
    status = AsyncMock(return_value=remote(txn, provider))
    monkeypatch.setattr(fapshi, "get_payment_status", status)
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert status.await_count == 1
    assert txn.status == FapshiTransactionStatus(provider.lower())
    assert txn.review_reason is None and txn.provider_status == provider
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0


async def test_exhausted_row_paid_at_provider_is_held_not_credited(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    txn.created_at = datetime.utcnow() - timedelta(days=8)
    await db.commit()
    monkeypatch.setattr(fapshi, "get_payment_status", AsyncMock(return_value=remote(txn)))
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert txn.status == FapshiTransactionStatus.PENDING
    assert txn.review_reason == "reconciliation_window_exhausted"
    assert txn.provider_status == "SUCCESSFUL"
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0


async def test_exhausted_row_with_provider_error_is_still_parked(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    txn.created_at = datetime.utcnow() - timedelta(days=8)
    await db.commit()
    monkeypatch.setattr(fapshi, "get_payment_status", AsyncMock(side_effect=RuntimeError("boom")))
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert txn.review_reason == "reconciliation_window_exhausted"
    assert txn.status == FapshiTransactionStatus.PENDING and not txn.check_lease_token


async def test_explicit_check_closes_already_held_row_that_provider_failed(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    await park(db, txn, reason="reconciliation_window_exhausted", age=timedelta(days=30))
    status = AsyncMock(return_value=remote(txn, "FAILED"))
    monkeypatch.setattr(fapshi, "get_payment_status", status)
    # The sweep never re-queries held rows...
    await service.recheck_pending_fapshi_background()
    status.assert_not_awaited()
    # ...but an explicit status check (webhook / status endpoint) may close it.
    await service.reconcile_transaction(txn.id)
    await db.refresh(txn)
    assert status.await_count == 1
    assert txn.status == FapshiTransactionStatus.FAILED and txn.review_reason is None


async def test_explicit_check_skips_hold_provider_already_reported_paid(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    await park(db, txn, reason="legacy_purchase_snapshot_missing", age=timedelta(days=2),
               provider_status="SUCCESSFUL")
    status = AsyncMock()
    monkeypatch.setattr(fapshi, "get_payment_status", status)
    await service.reconcile_transaction(txn.id)
    status.assert_not_awaited()
    await db.refresh(txn)
    assert txn.review_reason == "legacy_purchase_snapshot_missing"


async def test_held_row_reports_distinct_review_hold_status(db):
    txn, customer, plan, pm = await purchase(db)
    assert payment_flags(txn)["payment_status"] == "pending"
    await park(db, txn, reason="reconciliation_window_exhausted", age=timedelta(days=9))
    flags = await customer_payment_flags(db, customer.id)
    assert flags["payment_status"] == "review_hold"
    assert flags["payment_review_required"] is True
    assert service.is_review_hold(txn)


async def test_one_off_close_is_dry_run_by_default_confirms_and_is_idempotent(db, monkeypatch):
    failed, customer, plan, pm = await purchase(db)
    await park(db, failed, reason="reconciliation_window_exhausted", age=timedelta(days=30))
    paid = FapshiTransaction(trans_id="paid-transaction", external_id="paid-external",
        reseller_id=failed.reseller_id, customer_id=customer.id, payment_method_id=pm.id,
        amount=500, phone="670000001", environment="sandbox",
        status=FapshiTransactionStatus.PENDING, review_reason="reconciliation_window_exhausted")
    db.add(paid)
    await db.commit()
    failed_tid, failed_id, paid_id = failed.trans_id, failed.id, paid.id
    failed_remote, paid_remote = remote(failed, "FAILED"), remote(paid, "SUCCESSFUL")

    async def provider(**kwargs):
        return failed_remote if kwargs["trans_id"] == failed_tid else paid_remote
    monkeypatch.setattr(fapshi, "get_payment_status", AsyncMock(side_effect=provider))

    preview = await service.close_provider_terminal_rows([failed_id, paid_id, 9999])
    assert [r["outcome"] for r in preview] == ["would_close_as_failed", "left_unchanged", "not_found"]
    await db.refresh(failed)
    assert failed.status == FapshiTransactionStatus.PENDING

    applied = await service.close_provider_terminal_rows([failed_id, paid_id], apply=True)
    assert [r["outcome"] for r in applied] == ["closed_as_failed", "left_unchanged"]
    await db.refresh(failed); await db.refresh(paid)
    assert failed.status == FapshiTransactionStatus.FAILED and failed.review_reason is None
    assert paid.status == FapshiTransactionStatus.PENDING
    assert paid.review_reason == "reconciliation_window_exhausted"

    again = await service.close_provider_terminal_rows([failed_id], apply=True)
    assert again[0]["outcome"] == "already_final"
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0


async def test_plan_below_fapshi_minimum_is_refused_before_any_prompt(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    await db.delete(txn)
    await db.commit()
    prompt = prompt_mock(monkeypatch)
    with pytest.raises(ValueError, match=r"costs 50 XAF.*100 XAF or more"):
        await _initiate_fapshi(db, pm, customer, customer.phone, 50.0, "test")
    prompt.assert_not_awaited()
    assert await db.scalar(select(func.count(FapshiTransaction.id))) == 0


@pytest.mark.parametrize("restore_error,delivered", [
    ("MAC-login user 4C:EB:00:00:00:01 not found", True),
    ("Failed to connect", False),
])
async def test_fup_lift_tolerates_user_removed_on_expiry(db, monkeypatch, restore_error, delivered):
    # Production, 4 Nov (txn 136): the old throttled user had been removed on
    # expiry, so lifting FUP failed "not found" and delivery waited for a
    # router check-in. A missing user carries no throttle; deliver anyway.
    from app.db.models import CustomerUsagePeriod
    from app.services import fup, hotspot_provisioning
    txn, customer, plan, pm = await purchase(db)
    period = CustomerUsagePeriod(customer_id=customer.id, period_start=datetime.utcnow() - timedelta(days=2),
                                 period_end=datetime.utcnow() - timedelta(days=1),
                                 fup_triggered_at=datetime.utcnow() - timedelta(days=1))
    db.add(period)
    await db.flush()
    txn.purchase_snapshot = dict(txn.purchase_snapshot, previous_usage_period_id=period.id)
    await db.commit()
    monkeypatch.setattr(fup, "restore_normal_profile", AsyncMock(return_value={"error": restore_error}))
    deliver = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", deliver)
    monkeypatch.setattr(fapshi, "get_payment_status", AsyncMock(return_value=remote(txn)))

    await service.recheck_pending_fapshi_background()

    await db.refresh(txn); await db.refresh(period)
    assert txn.status == FapshiTransactionStatus.SUCCESSFUL
    if delivered:
        assert deliver.await_count == 1 and not txn.fulfillment_pending
        assert period.fup_reverted_at is not None and txn.last_check_error is None
    else:
        deliver.assert_not_awaited()
        assert txn.fulfillment_pending and txn.last_check_error == "fup_restore_pending"
