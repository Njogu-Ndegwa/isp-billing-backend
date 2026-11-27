"""When a payment's money came, one rule for every figure we show.

A ``customer_payments`` row is the ledger entry. It is written when the money
is applied, which can be later than when the money came:

* an STK prompt sent at 23:59:50 whose callback lands at 00:00:15 (seconds);
* a paybill payment received at 23:26 and attributed by hand the next
  morning, or days later (hours or days).

The transactions summary (what the assistant's chat says, and the
Transactions page) counts the M-Pesa record itself, by the prompt time or the
paybill receipt time. Dashboard figures read the ledger, so they must place
each ledger row on that same moment, or the same day shows different money
on different screens (reported 2026-11-27: home screen KES 683, chat KES 707).

``payment_moment()`` is that moment as a SQL expression on ``CustomerPayment``:
the STK prompt's time when the row's reference is its receipt or checkout id,
the paybill receipt time when the reference is its transaction id, otherwise
the ledger's own ``created_at``. All naive UTC, as stored.

The ledger row is never written before the money came, so
``created_at >= start`` is always true for a row whose moment is after
``start``: ``moment_since`` / ``moment_between`` keep that plain condition as
well, so the database can still use the ``created_at`` index.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import and_, func, select

from app.db.models import C2BTransaction, CustomerPayment, MpesaTransaction


def payment_moment():
    """When the money of a ``customer_payments`` row came (naive UTC)."""
    by_receipt = (
        select(func.min(MpesaTransaction.created_at))
        .where(MpesaTransaction.mpesa_receipt_number == CustomerPayment.payment_reference)
        .correlate(CustomerPayment)
        .scalar_subquery()
    )
    by_checkout = (
        select(func.min(MpesaTransaction.created_at))
        .where(MpesaTransaction.checkout_request_id == CustomerPayment.payment_reference)
        .correlate(CustomerPayment)
        .scalar_subquery()
    )
    by_paybill = (
        select(func.min(C2BTransaction.received_at))
        .where(C2BTransaction.trans_id == CustomerPayment.payment_reference)
        .correlate(CustomerPayment)
        .scalar_subquery()
    )
    return func.coalesce(by_receipt, by_checkout, by_paybill, CustomerPayment.created_at)


def moment_since(start: datetime):
    """Rows whose money came at or after ``start`` (naive UTC)."""
    return and_(CustomerPayment.created_at >= start, payment_moment() >= start)


def moment_between(start: Optional[datetime], end: Optional[datetime]):
    """Rows whose money came in [start, end) (naive UTC; either may be None)."""
    conditions = []
    if start is not None:
        conditions.append(moment_since(start))
    if end is not None:
        conditions.append(payment_moment() < end)
    return and_(*conditions) if conditions else and_(True)
