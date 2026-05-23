"""
Tests for app/services/c2b_handler.py — the function the Safaricom
Confirmation URL ultimately calls.

These tests are the safety net for the auto-activate chain: each test
asserts a different branch of the confirmation handler (happy path,
overpayment, underpayment with/without wallet, unknown account, wrong
reseller, duplicate, invalid Luhn). PPPoE provisioning is patched at the
import site so we can assert it was queued without touching a real
MikroTik.
"""

import asyncio
from datetime import datetime, timedelta
from typing import List
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import BackgroundTasks
from sqlalchemy import select

from app.config import settings
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    UnmatchedC2BPayment,
    UnmatchedC2BReason,
)
from app.services.c2b_handler import (
    ACCEPT_RESPONSE,
    REJECT_INVALID_ACCOUNT,
    SUCCESS_RESPONSE,
    handle_confirmation,
    handle_validation,
)
from app.services.account_numbers import luhn_check_digit
from tests.factories import make_customer, make_plan, make_reseller, make_router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_payload(*, trans_id: str, bill_ref: str, amount: float, shortcode: str = None) -> dict:
    return {
        "TransactionType": "Pay Bill",
        "TransID": trans_id,
        "TransTime": "20260523120000",
        "TransAmount": str(amount),
        "BusinessShortCode": shortcode or settings.MPESA_SHORTCODE,
        "BillRefNumber": bill_ref,
        "MSISDN": "254712345678",
        "FirstName": "Test",
        "LastName": "Customer",
    }


def _valid_account(base: str) -> str:
    """Helper: build a Luhn-valid 8-digit account number from a 7-digit base."""
    return base + luhn_check_digit(base)


async def _seed_pppoe_customer(db, *, account_number=None, expiry=None, wallet=0):
    reseller = await make_reseller(db)
    plan = await make_plan(
        db, reseller,
        price=500,
        duration_value=30,
        duration_unit=DurationUnit.DAYS,
        connection_type=ConnectionType.PPPOE,
    )
    router = await make_router(db, reseller)
    acct = account_number or _valid_account("1000001")
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.INACTIVE,
        expiry=expiry,
        pppoe_username="pppoe_test",
        mac_address=None,
        account_number=acct,
        wallet_credit_kes=wallet,
    )
    return reseller, plan, router, customer


def _make_bg() -> tuple[BackgroundTasks, List[tuple]]:
    """Return (BackgroundTasks, list-of-calls) where the list records every
    queued task as (func, args, kwargs)."""
    bg = BackgroundTasks()
    calls = []
    original = bg.add_task

    def _spy(func, *args, **kwargs):
        calls.append((func, args, kwargs))
        return original(func, *args, **kwargs)

    bg.add_task = _spy  # type: ignore[assignment]
    return bg, calls


@pytest.fixture(autouse=True)
def _stub_router_calls(monkeypatch):
    """Stub out every MikroTik-facing call exercised by these tests.

    record_customer_payment -> on_renewal -> fup.revert -> restore_normal_profile
    opens a real RouterOS API connection. With our test factories pointing at
    a fake 10.0.0.2 router, this hangs on a long TCP retry. Replace it with a
    no-op coroutine so the chain returns instantly.
    """
    async def _noop(*args, **kwargs):
        return {"ok": True}

    monkeypatch.setattr("app.services.fup.restore_normal_profile", _noop)


# ---------------------------------------------------------------------------
# Confirmation: happy path
# ---------------------------------------------------------------------------


async def test_confirmation_happy_path_pppoe_exact_amount(db, session_factory):
    _, _, _, customer = await _seed_pppoe_customer(db)
    payload = _make_payload(trans_id="RJ001", bill_ref=customer.account_number, amount=500)
    bg, queued = _make_bg()

    with patch(
        "app.services.c2b_handler.call_pppoe_provision",
        new=AsyncMock(),
    ):
        result = await handle_confirmation(payload, db, background_tasks=bg)

    assert result == SUCCESS_RESPONSE

    async with session_factory() as s:
        refreshed = (await s.execute(select(Customer).where(Customer.id == customer.id))).scalar_one()
        assert refreshed.status == CustomerStatus.ACTIVE
        assert refreshed.expiry is not None
        assert refreshed.expiry > datetime.utcnow() + timedelta(days=29, hours=23)
        assert refreshed.wallet_credit_kes == 0  # exact amount, no leftover

        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "RJ001"))).scalar_one()
        assert txn.status == C2BTransactionStatus.PROCESSED
        assert txn.matched_customer_id == customer.id
        assert txn.matched_reseller_id == customer.user_id

        payments = (
            await s.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer.id))
        ).scalars().all()
        assert len(payments) == 1
        assert payments[0].payment_reference == "RJ001"
        assert payments[0].amount == 500.0

    # PPPoE provisioning was queued, with a payload pointing at this customer
    assert len(queued) == 1
    _func, args, _ = queued[0]
    queued_payload = args[0]
    assert queued_payload["pppoe_username"] == customer.pppoe_username
    assert queued_payload["router_ip"] == customer.router.ip_address


# ---------------------------------------------------------------------------
# Confirmation: overpayment → wallet credited
# ---------------------------------------------------------------------------


async def test_confirmation_overpayment_credits_wallet(db, session_factory):
    _, _, _, customer = await _seed_pppoe_customer(db, wallet=0)
    payload = _make_payload(trans_id="RJ002", bill_ref=customer.account_number, amount=750)
    bg, _ = _make_bg()

    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(payload, db, background_tasks=bg)

    async with session_factory() as s:
        refreshed = (await s.execute(select(Customer).where(Customer.id == customer.id))).scalar_one()
        assert refreshed.status == CustomerStatus.ACTIVE
        assert refreshed.wallet_credit_kes == 250  # 750 paid - 500 plan = 250 overage


# ---------------------------------------------------------------------------
# Confirmation: underpayment but wallet covers it → activated, wallet drained
# ---------------------------------------------------------------------------


async def test_confirmation_underpayment_drains_wallet(db, session_factory):
    """Customer pays 300 but has 200 in wallet -> 300+200=500 covers 500 plan."""
    _, _, _, customer = await _seed_pppoe_customer(db, wallet=200)
    payload = _make_payload(trans_id="RJ003", bill_ref=customer.account_number, amount=300)
    bg, _ = _make_bg()

    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(payload, db, background_tasks=bg)

    async with session_factory() as s:
        refreshed = (await s.execute(select(Customer).where(Customer.id == customer.id))).scalar_one()
        assert refreshed.status == CustomerStatus.ACTIVE
        assert refreshed.wallet_credit_kes == 0  # drained exactly

        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "RJ003"))).scalar_one()
        assert txn.status == C2BTransactionStatus.PROCESSED


# ---------------------------------------------------------------------------
# Confirmation: underpayment with insufficient wallet → unmatched, no activation
# ---------------------------------------------------------------------------


async def test_confirmation_underpayment_with_insufficient_wallet_unmatched(db, session_factory):
    _, _, _, customer = await _seed_pppoe_customer(db, wallet=100)
    payload = _make_payload(trans_id="RJ004", bill_ref=customer.account_number, amount=300)
    bg, queued = _make_bg()

    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(payload, db, background_tasks=bg)

    async with session_factory() as s:
        refreshed = (await s.execute(select(Customer).where(Customer.id == customer.id))).scalar_one()
        assert refreshed.status == CustomerStatus.INACTIVE  # not activated
        assert refreshed.wallet_credit_kes == 100  # untouched

        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "RJ004"))).scalar_one()
        assert txn.status == C2BTransactionStatus.UNMATCHED

        um = (
            await s.execute(select(UnmatchedC2BPayment).where(UnmatchedC2BPayment.c2b_transaction_id == txn.id))
        ).scalar_one()
        assert um.reason == UnmatchedC2BReason.AMOUNT_TOO_LOW
        assert um.assigned_reseller_id == customer.user_id

    assert queued == []


# ---------------------------------------------------------------------------
# Confirmation: unknown account number → unmatched bucket
# ---------------------------------------------------------------------------


async def test_confirmation_unknown_account_unmatched(db, session_factory):
    # Seed a reseller so the platform-paybill path resolves but no customer
    # has this specific account number
    await _seed_pppoe_customer(db, account_number=_valid_account("1000001"))
    unknown = _valid_account("9999999")
    payload = _make_payload(trans_id="RJ005", bill_ref=unknown, amount=500)
    bg, queued = _make_bg()

    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(payload, db, background_tasks=bg)

    async with session_factory() as s:
        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "RJ005"))).scalar_one()
        assert txn.status == C2BTransactionStatus.UNMATCHED
        assert txn.matched_customer_id is None

        um = (
            await s.execute(select(UnmatchedC2BPayment).where(UnmatchedC2BPayment.c2b_transaction_id == txn.id))
        ).scalar_one()
        assert um.reason == UnmatchedC2BReason.UNKNOWN_ACCOUNT

    assert queued == []


# ---------------------------------------------------------------------------
# Confirmation: invalid Luhn → unmatched (INVALID_LUHN reason)
# ---------------------------------------------------------------------------


async def test_confirmation_invalid_luhn_unmatched(db, session_factory):
    payload = _make_payload(trans_id="RJ006", bill_ref="11111111", amount=500)  # bad Luhn
    bg, _ = _make_bg()

    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(payload, db, background_tasks=bg)

    async with session_factory() as s:
        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "RJ006"))).scalar_one()
        assert txn.status == C2BTransactionStatus.UNMATCHED
        um = (
            await s.execute(select(UnmatchedC2BPayment).where(UnmatchedC2BPayment.c2b_transaction_id == txn.id))
        ).scalar_one()
        assert um.reason == UnmatchedC2BReason.INVALID_LUHN


# ---------------------------------------------------------------------------
# Confirmation: duplicate TransID → idempotent
# ---------------------------------------------------------------------------


async def test_confirmation_duplicate_trans_id_idempotent(db, session_factory):
    _, _, _, customer = await _seed_pppoe_customer(db)
    payload = _make_payload(trans_id="RJ007", bill_ref=customer.account_number, amount=500)
    bg, queued = _make_bg()

    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        # Fire twice
        r1 = await handle_confirmation(payload, db, background_tasks=bg)
        r2 = await handle_confirmation(payload, db, background_tasks=bg)

    assert r1 == r2 == SUCCESS_RESPONSE

    async with session_factory() as s:
        txns = (
            await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "RJ007"))
        ).scalars().all()
        assert len(txns) == 1  # idempotent: only one row

        payments = (
            await s.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer.id))
        ).scalars().all()
        assert len(payments) == 1

    assert len(queued) == 1  # only first call provisioned


# ---------------------------------------------------------------------------
# Confirmation: wrong reseller's paybill → unmatched WRONG_RESELLER
# ---------------------------------------------------------------------------


async def test_confirmation_wrong_reseller_paybill(db, session_factory):
    """Customer of reseller A; payment arrives on reseller B's paybill via a
    ResellerPaymentMethod with mpesa_shortcode != platform."""
    # Set up reseller A with the customer
    _, _, _, customer_a = await _seed_pppoe_customer(db, account_number=_valid_account("2000002"))

    # Set up reseller B with their own paybill shortcode = "987654"
    reseller_b = await make_reseller(db)
    pm_b = ResellerPaymentMethod(
        user_id=reseller_b.id,
        method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        label="B's Paybill",
        is_active=True,
        mpesa_shortcode="987654",
    )
    db.add(pm_b)
    await db.commit()

    # Payment comes in on B's shortcode, with A's customer's account number
    payload = _make_payload(
        trans_id="RJ008",
        bill_ref=customer_a.account_number,
        amount=500,
        shortcode="987654",
    )
    bg, queued = _make_bg()

    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(payload, db, background_tasks=bg)

    async with session_factory() as s:
        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "RJ008"))).scalar_one()
        assert txn.status == C2BTransactionStatus.UNMATCHED
        um = (
            await s.execute(select(UnmatchedC2BPayment).where(UnmatchedC2BPayment.c2b_transaction_id == txn.id))
        ).scalar_one()
        assert um.reason == UnmatchedC2BReason.WRONG_RESELLER
        # Bucket assigned to reseller B (the paybill owner)
        assert um.assigned_reseller_id == reseller_b.id

    # Customer A was not activated
    async with session_factory() as s:
        a_refreshed = (await s.execute(select(Customer).where(Customer.id == customer_a.id))).scalar_one()
        assert a_refreshed.status == CustomerStatus.INACTIVE
    assert queued == []


# ---------------------------------------------------------------------------
# Confirmation: unknown shortcode → REJECTED, no unmatched bucket
# ---------------------------------------------------------------------------


async def test_confirmation_unknown_shortcode_rejected(db, session_factory):
    payload = _make_payload(
        trans_id="RJ009",
        bill_ref=_valid_account("3000003"),
        amount=500,
        shortcode="111111",  # not platform, not any reseller's
    )
    bg, _ = _make_bg()

    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(payload, db, background_tasks=bg)

    async with session_factory() as s:
        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "RJ009"))).scalar_one()
        assert txn.status == C2BTransactionStatus.REJECTED
        um = (
            await s.execute(select(UnmatchedC2BPayment).where(UnmatchedC2BPayment.c2b_transaction_id == txn.id))
        ).scalar_one_or_none()
        assert um is None  # rejected, not bucketed for reseller triage


# ---------------------------------------------------------------------------
# Validation handler
# ---------------------------------------------------------------------------


async def test_validation_accepts_valid_existing_account(db):
    _, _, _, customer = await _seed_pppoe_customer(db)
    payload = _make_payload(trans_id="V001", bill_ref=customer.account_number, amount=500)
    result = await handle_validation(payload, db)
    assert result == ACCEPT_RESPONSE


async def test_validation_rejects_invalid_luhn(db):
    payload = _make_payload(trans_id="V002", bill_ref="11111111", amount=500)
    result = await handle_validation(payload, db)
    assert result == REJECT_INVALID_ACCOUNT


async def test_validation_rejects_unknown_account(db):
    payload = _make_payload(trans_id="V003", bill_ref=_valid_account("9999999"), amount=500)
    result = await handle_validation(payload, db)
    assert result == REJECT_INVALID_ACCOUNT
