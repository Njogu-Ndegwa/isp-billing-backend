"""One explanation per M-Pesa STK result (CR-1123-B5).

The assistant explained "The initiator information is invalid" (2001) three
different ways on the same day: payment setup, payment method setup, and an
unregistered number. It is a wrong PIN. The failed-payment lists now carry the
explanation from app/services/mpesa_results.py so the assistant reads it
instead of guessing.
"""
from types import SimpleNamespace

import pytest

from app.api import payment_routes
from app.db.models import FailureSource, MpesaTransaction, MpesaTransactionStatus, UserRole
from app.services import mpesa_results
from app.services.mpesa_results import BITWAVE, CUSTOMER, MERCHANT_SETUP, MPESA, NONE, UNKNOWN
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest.mark.parametrize("code, desc, fault, words", [
    ("0", "The service request is processed successfully.", NONE, "went through"),
    ("1", "The balance is insufficient for the transaction.", CUSTOMER, "balance was too low"),
    ("17", "Rule limited.", MPESA, "2 minutes"),
    ("1001", "Unable to lock subscriber, a transaction is already in process for the current subscriber",
     CUSTOMER, "busy with another M-Pesa request"),
    ("1019", "Transaction has expired", CUSTOMER, "expired"),
    ("1025", "An error occurred while sending a push request", MPESA, "could not send the prompt"),
    ("9999", "An error occurred while sending a push request", MPESA, "could not send the prompt"),
    ("1032", "Request Cancelled by user.", CUSTOMER, "cancelled"),
    ("1037", "DS timeout user cannot be reached", CUSTOMER, "could not reach the phone"),
    ("1038", "No response from user.", CUSTOMER, "did not enter the PIN"),
    ("2001", "The initiator information is invalid.", CUSTOMER, "wrong M-Pesa PIN"),
    ("2028", "The request is not permitted according to product assignment", MERCHANT_SETUP, "till/paybill"),
    ("8006", "The security credential is locked", CUSTOMER, "locked"),
    ("TIMEOUT", "Transaction expired due to timeout", MPESA, "No result came back"),
    ("STK_PUSH_FAILED", "STK Push initiation failed: boom", MPESA, "refused to start"),
    ("SERVER_ERROR", "Callback processing error", BITWAVE, "Bitwave's system"),
])
def test_each_mapped_code_has_one_fault_and_explanation(code, desc, fault, words):
    e = mpesa_results.explain(code, desc)
    assert e["fault"] == fault
    assert e["known"] is True
    assert words in e["explanation"]
    assert e["next_step"]


def test_code_given_as_int_matches_the_string_code():
    assert mpesa_results.explain(2001, None) == mpesa_results.explain("2001", "anything")


def test_initiator_invalid_is_a_wrong_pin_not_the_payment_setup():
    e = mpesa_results.explain("2001", "The initiator information is invalid.")
    assert e["fault"] == CUSTOMER
    assert "setup is not the cause" in e["explanation"]
    assert "payment method" not in e["next_step"].lower()


@pytest.mark.parametrize("desc, fault", [
    ("The initiator information is invalid.", CUSTOMER),
    ("DS timeout user cannot be reached", CUSTOMER),
    ("No response from user.", CUSTOMER),
    ("Request cancelled by user", CUSTOMER),
    ("The balance is insufficient for the transaction", CUSTOMER),
])
def test_known_words_without_a_code_are_still_explained(desc, fault):
    e = mpesa_results.explain(None, desc)
    assert e["known"] is True
    assert e["fault"] == fault


def test_unknown_code_says_unknown_instead_of_guessing():
    e = mpesa_results.explain("4242", "Something new from Safaricom")
    assert e["fault"] == UNKNOWN
    assert e["known"] is False
    assert "unknown" in e["explanation"]
    assert "4242" in e["explanation"] and "Something new from Safaricom" in e["explanation"]


def test_failure_reason_words_come_from_the_same_table():
    assert mpesa_results.failure_reason(2001, "The initiator information is invalid.").startswith(
        "the M-Pesa PIN was wrong (M-Pesa 2001:")
    assert mpesa_results.failure_reason(1032, "Request Cancelled by user.").startswith(
        "the prompt was cancelled on the phone")
    assert mpesa_results.failure_reason(4242, "x") == "M-Pesa 4242: x"


def _as(monkeypatch, reseller):
    async def _current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", _current_user)


async def test_failed_transactions_rows_and_summary_carry_the_explanation(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)

    def tx(ref, status, code, desc, source):
        return MpesaTransaction(
            checkout_request_id=ref, phone_number=customer.phone, amount=10, reference=ref,
            customer_id=customer.id, status=status, result_code=code, result_desc=desc,
            failure_source=source,
        )

    db.add_all([
        tx("pin", MpesaTransactionStatus.failed, "2001", "The initiator information is invalid.",
           FailureSource.CLIENT),
        tx("late", MpesaTransactionStatus.expired, None, None, None),
        tx("new", MpesaTransactionStatus.failed, "4242", "Something new", FailureSource.CLIENT),
        tx("ok", MpesaTransactionStatus.completed, "0", "ok", None),
    ])
    await db.commit()
    _as(monkeypatch, reseller)

    out = await payment_routes.get_failed_mpesa_transactions(
        router_id=None, start_date=None, end_date=None, db=db, token="test-token")

    rows = {r["reference"]: r for r in out["transactions"]}
    assert set(rows) == {"pin", "late", "new"}
    assert rows["pin"]["failure_fault"] == CUSTOMER
    assert "wrong M-Pesa PIN" in rows["pin"]["failure_explained"]
    assert rows["late"]["failure_fault"] == MPESA
    assert "No result came back" in rows["late"]["failure_explained"]
    assert rows["new"]["failure_fault"] == UNKNOWN

    summary = {s["reason"]: s for s in out["failure_summary"]}
    pin = summary["The initiator information is invalid."]
    assert pin["failure_fault"] == CUSTOMER
    assert "wrong M-Pesa PIN" in pin["failure_explained"]

    # the general transactions list explains failed rows too, and leaves paid ones alone
    listed = await payment_routes.get_mpesa_transactions(
        router_id=None, customer_id=None, payment_method=None, date=None, start_date=None,
        end_date=None, status=None, limit=200, offset=0, settlement=None, db=db, token="test-token")
    by_ref = {r["reference"]: r for r in listed}
    assert by_ref["pin"]["failure_fault"] == CUSTOMER
    assert "failure_explained" not in by_ref["ok"]
