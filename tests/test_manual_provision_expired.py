"""Manual provisioning must not replay access the customer has used up.

2026-10-10: a reseller re-ran "provision" on a completed 1-hour payment two
hours after it expired. The push put the customer back online, and expiry
cleanup (ACTIVE customers only) never removed them again.
"""

from datetime import datetime, timedelta

from app.api.payment_routes import _manual_provision_support
from app.db.models import (
    ConnectionType, Customer, MpesaTransactionStatus, PaymentMethod, Plan, Router,
    RouterAuthMethod,
)

MM = PaymentMethod.MOBILE_MONEY.value


def _objs(expiry):
    customer = Customer(mac_address="3E:84:AD:F2:56:66", expiry=expiry)
    router = Router(auth_method=RouterAuthMethod.DIRECT_API)
    plan = Plan(connection_type=ConnectionType.HOTSPOT)
    return customer, router, plan


def test_completed_payment_with_time_left_can_be_replayed():
    ok, reason = _manual_provision_support(MM, MpesaTransactionStatus.completed.value,
                                           *_objs(datetime.utcnow() + timedelta(minutes=30)))
    assert ok and reason is None


def test_completed_payment_after_expiry_is_refused():
    ok, reason = _manual_provision_support(MM, MpesaTransactionStatus.completed.value,
                                           *_objs(datetime.utcnow() - timedelta(hours=2)))
    assert not ok
    assert "paid time has ended" in reason


def test_cash_payment_after_expiry_is_refused():
    ok, _ = _manual_provision_support(PaymentMethod.CASH.value, "completed",
                                      *_objs(datetime.utcnow() - timedelta(minutes=1)))
    assert not ok


def test_customer_without_expiry_is_refused():
    ok, _ = _manual_provision_support(MM, MpesaTransactionStatus.completed.value, *_objs(None))
    assert not ok


def test_pending_payment_is_still_allowed_because_it_extends_expiry():
    ok, _ = _manual_provision_support(MM, MpesaTransactionStatus.pending.value,
                                      *_objs(datetime.utcnow() - timedelta(days=3)))
    assert ok
