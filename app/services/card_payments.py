"""Automatic confirmation of card subscription payments.

A card payment (``SubscriptionPayment.payment_method == 'card'``) is created
pending when the reseller opens a PayAfrica/Paystack checkout. When
``PAYSTACK_SECRET_KEY`` is configured this module asks Paystack whether it was
paid and, only if Paystack reports success for the exact amount and currency,
completes it through the same path as an admin confirmation
(``_complete_subscription_payment``: invoice paid, reseller activated).

Three triggers call ``reconcile_card_payment``:
  * the reseller returning from checkout (instant activation),
  * a signed Paystack webhook (if the account's webhook points at us),
  * ``reconcile_pending_card_payments`` every few minutes (catches everyone
    who closed the tab).
It is idempotent: the completion helper locks the row and ignores payments
that are no longer pending.

Database discipline: every DB read/write is a short session closed before
the Paystack HTTP call.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import or_, select

from app.db.models import SubscriptionPayment, SubscriptionPaymentStatus

logger = logging.getLogger(__name__)

CARD = "card"
# A checkout nobody paid is marked failed after this long.
CHECKOUT_EXPIRY = timedelta(hours=48)
# Paystack statuses that are final failures.
_FAILED_STATUSES = {"failed", "reversed"}

_batch_running = False


def _async_session():
    from app.db.database import async_session
    return async_session()


async def _load(payment_id: int) -> dict | None:
    async with _async_session() as db:
        p = await db.get(SubscriptionPayment, payment_id)
        if not p or p.payment_method != CARD:
            return None
        status = p.status.value if hasattr(p.status, "value") else p.status
        data = {
            "id": p.id,
            "status": status,
            "amount": float(p.amount),
            "currency": (p.currency or "").upper(),
            "references": [r for r in (p.provider_reference, p.payment_reference) if r],
            "created_at": p.created_at,
        }
        await db.commit()
        return data


async def _mark(payment_id: int, status: SubscriptionPaymentStatus, reference: str | None = None) -> None:
    async with _async_session() as db:
        p = await db.get(SubscriptionPayment, payment_id)
        if p and (p.status.value if hasattr(p.status, "value") else p.status) == "pending":
            p.status = status
            if reference:
                p.payment_reference = reference[:255]
        await db.commit()


async def _set_receipt(payment_id: int, reference: str) -> None:
    async with _async_session() as db:
        p = await db.get(SubscriptionPayment, payment_id)
        if p and (p.status.value if hasattr(p.status, "value") else p.status) == "pending":
            p.payment_reference = reference[:255]
        await db.commit()


async def reconcile_card_payment(payment_id: int) -> str:
    """Check one card payment with Paystack. Returns one of:
    completed, pending, failed, expired, mismatch, not_configured, not_found,
    already_<status>."""
    from app.services import paystack
    from app.services.subscription import _complete_subscription_payment

    if not paystack.is_configured():
        return "not_configured"

    payment = await _load(payment_id)
    if not payment:
        return "not_found"
    if payment["status"] != "pending":
        return f"already_{payment['status']}"

    # PayAfrica's reference (PAF-...) is what it gives Paystack; fall back to
    # ours in case it forwards that instead.
    tx = None
    for ref in payment["references"]:
        tx = await paystack.verify_transaction(ref)
        if tx:
            break

    if not tx:
        if payment["created_at"] and datetime.utcnow() - payment["created_at"] > CHECKOUT_EXPIRY:
            await _mark(payment_id, SubscriptionPaymentStatus.FAILED)
            return "expired"
        return "pending"

    tx_status = str(tx.get("status") or "").lower()
    if tx_status == "success":
        expected_minor = paystack.to_minor_units(payment["amount"])
        tx_currency = str(tx.get("currency") or "").upper()
        if int(tx.get("amount") or 0) != expected_minor or tx_currency != payment["currency"]:
            # Never activate on a different amount/currency; leave it for an
            # admin to look at.
            logger.error(
                "[CARD] Paystack amount/currency mismatch for payment %s: expected %s %s (minor), got %s %s",
                payment_id, expected_minor, payment["currency"], tx.get("amount"), tx_currency,
            )
            return "mismatch"
        await _set_receipt(payment_id, f"PAYSTACK-{tx.get('reference') or tx.get('id')}")
        completed = await _complete_subscription_payment(payment_id)
        logger.info("[CARD] Payment %s verified with Paystack, completed=%s", payment_id, completed)
        return "completed" if completed else "already_completed"

    if tx_status in _FAILED_STATUSES:
        await _mark(payment_id, SubscriptionPaymentStatus.FAILED)
        return "failed"

    # abandoned / ongoing / pending / processing: the payer may still finish.
    if payment["created_at"] and datetime.utcnow() - payment["created_at"] > CHECKOUT_EXPIRY:
        await _mark(payment_id, SubscriptionPaymentStatus.FAILED)
        return "expired"
    return "pending"


async def reconcile_pending_card_payments(limit: int = 20) -> dict:
    """Scheduler job: check recent pending card payments one at a time."""
    global _batch_running
    from app.services import paystack

    if not paystack.is_configured() or _batch_running:
        return {"skipped": True}
    _batch_running = True
    try:
        cutoff_recent = datetime.utcnow() - timedelta(minutes=1)
        async with _async_session() as db:
            ids = (await db.execute(
                select(SubscriptionPayment.id)
                .where(
                    SubscriptionPayment.payment_method == CARD,
                    SubscriptionPayment.status == SubscriptionPaymentStatus.PENDING,
                    SubscriptionPayment.created_at < cutoff_recent,
                )
                .order_by(SubscriptionPayment.created_at.asc())
                .limit(limit)
            )).scalars().all()
            await db.commit()

        results: dict[str, int] = {}
        for payment_id in ids:
            try:
                outcome = await reconcile_card_payment(payment_id)
            except Exception as exc:  # one bad payment must not stop the batch
                logger.warning("[CARD] Reconcile failed for payment %s: %s", payment_id, exc)
                outcome = "error"
            results[outcome] = results.get(outcome, 0) + 1
        if ids:
            logger.info("[CARD] Reconciled %d pending card payments: %s", len(ids), results)
        return {"checked": len(ids), "results": results}
    finally:
        _batch_running = False


async def find_pending_card_payment_ids(reference: str) -> list[int]:
    """Pending card payments matching a Paystack/PayAfrica/our reference."""
    async with _async_session() as db:
        ids = (await db.execute(
            select(SubscriptionPayment.id).where(
                SubscriptionPayment.payment_method == CARD,
                SubscriptionPayment.status == SubscriptionPaymentStatus.PENDING,
                or_(
                    SubscriptionPayment.provider_reference == reference,
                    SubscriptionPayment.payment_reference == reference,
                ),
            )
        )).scalars().all()
        await db.commit()
        return list(ids)
