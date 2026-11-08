"""Credit an unmatched platform-paybill payment to a reseller as earnings.

Used when a customer paid the platform paybill with an account number that
matches nobody (a typo, usually) and the right outcome is to give the money
to the reseller rather than to a customer: the customer was already served
some other way (say, the reseller activated them as cash), so attributing the
payment to the customer would hand them a second 30 days for one payment.

The credit is one ordinary platform-collected ``customer_payments`` row with
no customer, plan or router: mobile money, completed, counts as revenue,
``collection_mode=system_collected``. That is the exact shape every payout
reader already counts (``mpesa_b2b.PAYOUT_REVENUE_FILTERS``), so the money

* shows in the reseller's earnings and withdrawable balance at once,
* is paid by the nightly B2B job or the Withdraw button with the usual
  Safaricom transfer fee taken at payout time, like any other payment, and
* survives the repair-balance job, which counts these rows on both sides of
  its comparison and never touches them.

No customer, subscription, wallet or expiry is touched. The C2B row and its
unmatched row are marked resolved in the same transaction, the receipt is
checked against every recorded payment, and an audit row lands in the
reseller's activity log, so the same payment can never be credited twice.
DB only, no network I/O.
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.config import settings
from app.db.models import (
    C2BTransactionStatus,
    CollectionMode,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    StaffActivityLog,
    UnmatchedC2BPayment,
    User,
    UserRole,
)

logger = logging.getLogger(__name__)

AUDIT_ACTION = "POST admin credit unmatched c2b to reseller"
MAX_REASON_LENGTH = 300


async def credit_unmatched_to_reseller(
    db: AsyncSession,
    *,
    unmatched_id: int,
    reseller_id: int,
    reason: str,
    admin: User,
    path: str = "",
) -> dict:
    """Credit one unmatched C2B payment to ``reseller_id``. Commits.

    Raises HTTPException: 403 non-admin, 404 unknown row or reseller,
    409 already resolved / already recorded, 400 bad input or a payment the
    platform never collected.
    """
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    reason = (reason or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A reason is required")
    if len(reason) > MAX_REASON_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Reason is too long (max {MAX_REASON_LENGTH} characters)",
        )

    unmatched = (
        await db.execute(
            select(UnmatchedC2BPayment)
            .options(joinedload(UnmatchedC2BPayment.c2b_transaction))
            .where(UnmatchedC2BPayment.id == unmatched_id)
            # Same lock the customer attribution path takes: two admins (or an
            # admin and a reseller attributing it) cannot both apply this row.
            .with_for_update(of=UnmatchedC2BPayment)
        )
    ).scalar_one_or_none()
    if unmatched is None:
        raise HTTPException(status_code=404, detail="Unmatched payment not found")
    if unmatched.resolved_at is not None:
        raise HTTPException(status_code=409, detail="This payment has already been resolved")

    txn = unmatched.c2b_transaction
    if txn.status != C2BTransactionStatus.UNMATCHED:
        raise HTTPException(
            status_code=409,
            detail=f"Paybill payment is '{txn.status.value}', not unmatched; nothing was changed",
        )
    # Only money that landed on the platform paybill is ours to pay out. A
    # payment to a reseller's own paybill is already in their account; adding
    # it to their withdrawable balance would pay it to them a second time.
    if str(txn.business_shortcode or "") != str(settings.MPESA_SHORTCODE):
        raise HTTPException(
            status_code=400,
            detail=(
                "This payment went to a reseller's own paybill, not the platform paybill, "
                "so the platform never held the money and cannot pay it out"
            ),
        )
    amount = float(txn.trans_amount or 0)
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Payment amount is not positive")

    already = (
        await db.execute(
            select(CustomerPayment.id, CustomerPayment.customer_id, CustomerPayment.reseller_id)
            .where(CustomerPayment.payment_reference == txn.trans_id)
            .limit(1)
        )
    ).first()
    if already is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"M-Pesa receipt {txn.trans_id} is already recorded as payment {already.id} "
                f"(reseller {already.reseller_id}, customer {already.customer_id}); "
                "crediting it again would pay the same money twice, so nothing was changed"
            ),
        )

    reseller = (
        await db.execute(
            select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
        )
    ).scalar_one_or_none()
    if reseller is None:
        raise HTTPException(status_code=404, detail="Reseller not found")

    now = datetime.utcnow()
    received = txn.received_at.strftime("%Y-%m-%d %H:%M UTC") if txn.received_at else "unknown time"
    payment = CustomerPayment(
        customer_id=None,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        payment_reference=txn.trans_id,
        payment_date=now,
        days_paid_for=0,
        plan_id=None,
        router_id=None,
        status=PaymentStatus.COMPLETED,
        customer_name="Unmatched paybill payment",
        notes=(
            f"Unmatched paybill payment credited to reseller by admin {admin.id}. "
            f"Account entered: {txn.bill_ref_number or '-'}; received {received}. "
            f"Reason: {reason}"
        )[:500],
        collection_mode=CollectionMode.SYSTEM_COLLECTED,
        counts_as_revenue=True,
        created_at=now,
    )
    db.add(payment)
    await db.flush()

    txn.status = C2BTransactionStatus.PROCESSED
    txn.matched_reseller_id = reseller.id
    txn.matched_customer_id = None
    txn.processed_at = now

    unmatched.resolved_at = now
    unmatched.resolved_by_user_id = admin.id
    unmatched.resolution_customer_id = None
    unmatched.notes = (
        f"Credited to reseller {reseller.id} as earnings (payment {payment.id}). {reason}"
    )[:500]

    summary = (
        f"Bitwave credited KES {amount:,.0f} paybill payment {txn.trans_id} to your earnings "
        f"(no customer). Reason: {reason}"
    )[:300]
    db.add(StaffActivityLog(
        owner_id=reseller.id,
        staff_id=None,
        actor_label=f"Bitwave admin (user {admin.id})",
        action=AUDIT_ACTION,
        permission=None,
        method="POST",
        path=(path or f"/api/admin/c2b/unmatched/{unmatched_id}/credit-reseller")[:300],
        status_code=200,
        summary=summary,
        created_at=now,
    ))

    from app.services.reseller_payments import update_reseller_financials

    await update_reseller_financials(db, reseller.id)
    await db.commit()

    from app.services.mpesa_b2b import compute_fee_breakdown, get_unpaid_balance

    balance = await get_unpaid_balance(db, reseller.id)
    fee, _kadogo, net = compute_fee_breakdown(amount)
    logger.info(
        "[C2B] Unmatched %s (receipt %s, KES %.2f) credited to reseller %s by admin %s",
        unmatched.id, txn.trans_id, amount, reseller.id, admin.id,
    )
    return {
        "ok": True,
        "unmatched_id": unmatched.id,
        "c2b_transaction_id": txn.id,
        "receipt": txn.trans_id,
        "reseller_id": reseller.id,
        "payment_id": payment.id,
        "amount": amount,
        "payout_fee_if_paid_alone": fee,
        "net_if_paid_alone": net,
        "unpaid_balance": balance,
    }
