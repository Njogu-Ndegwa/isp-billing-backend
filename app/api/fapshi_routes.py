"""Fapshi notification/poll adapters; all confirmations share durable reconciliation."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import get_db
from app.db.models import Customer, FapshiTransaction
from app.services.fapshi_reconciliation import (
    FINAL_STATUSES as _FINAL_STATUSES, apply_remote_status as _apply_remote_status,
    reconcile_transaction, validate_remote_transaction as _validate_remote_transaction,
)
router = APIRouter(tags=["fapshi"])

def _parse_provider_datetime(value: object) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
        # The rest of this codebase stores naive UTC datetimes.
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def payment_flags(txn):
    if txn is None:
        return {}
    status = txn.status.value if hasattr(txn.status, "value") else txn.status
    fulfillment = ("review_required" if txn.review_reason else
                   "pending" if txn.fulfillment_pending else
                   "delivered" if txn.customer_payment_id else None)
    return {"payment_status": status,
            "payment_review_required": bool(txn.review_reason),
            "payment_fulfillment_status": fulfillment}


async def customer_payment_flags(db, customer_id):
    txn = await db.scalar(select(FapshiTransaction).where(
        FapshiTransaction.customer_id == customer_id,
    ).order_by(FapshiTransaction.created_at.desc(), FapshiTransaction.id.desc()).limit(1))
    flags = payment_flags(txn)
    if txn and txn.customer_payment_id:
        from app.services.fapshi_reconciliation import _latest_payment_id, _target_baseline
        customer = await db.get(Customer, customer_id)
        snap = txn.purchase_snapshot or {}
        if (not customer or customer.expiry != txn.applied_expiry
                or _target_baseline(customer) != snap.get("delivery_baseline")
                or await _latest_payment_id(db, customer_id) != txn.customer_payment_id):
            flags["payment_fulfillment_status"] = None
    return flags


def _serialize_transaction(txn):
    return {
        "trans_id": txn.trans_id, "external_id": txn.external_id,
        "status": txn.status.value, "amount": float(txn.amount), "currency": "XAF",
        "phone": txn.phone, "medium": txn.medium,
        "financial_transaction_id": txn.financial_transaction_id,
        "failure_reason": txn.failure_reason, "customer_id": txn.customer_id,
        "environment": txn.environment,
        "created_at": txn.created_at.isoformat() if txn.created_at else None,
        "updated_at": txn.updated_at.isoformat() if txn.updated_at else None,
        "confirmed_at": txn.confirmed_at.isoformat() if txn.confirmed_at else None,
        **payment_flags(txn),
    }


async def kick_pending_fapshi_check(customer_id):
    from app.db import database
    async with database.async_session() as db:
        txn = await db.scalar(select(FapshiTransaction).where(
            FapshiTransaction.customer_id == customer_id,
        ).order_by(FapshiTransaction.created_at.desc(), FapshiTransaction.id.desc()).limit(1))
        transaction_id = txn.id if txn else None
        await db.commit()
    if transaction_id is not None:
        await reconcile_transaction(transaction_id)


@router.post("/api/fapshi/webhook")
async def fapshi_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    trans_id, external_id = payload.get("transId"), payload.get("externalId")
    if not trans_id and not external_id:
        return {"status": "error", "message": "Missing transId/externalId"}
    condition = (FapshiTransaction.external_id == external_id if external_id
                 else FapshiTransaction.trans_id == trans_id)
    txn = await db.scalar(select(FapshiTransaction).where(condition))
    if not txn:
        return {"status": "error", "message": "Transaction not found"}
    if trans_id and txn.trans_id and trans_id != txn.trans_id:
        raise HTTPException(status_code=400, detail="Transaction correlation mismatch")
    transaction_id = txn.id
    await db.commit()
    # Notification is a hint only; provider response must pass the same exact
    # validation, lease/rate limit and atomic fulfillment path as every poll.
    await reconcile_transaction(transaction_id, provider_trans_id=trans_id)
    return {"status": "received"}


@router.get("/api/fapshi/status/{trans_id}")
async def get_fapshi_status(trans_id: str, db: AsyncSession = Depends(get_db)):
    txn = await db.scalar(select(FapshiTransaction).where(FapshiTransaction.trans_id == trans_id))
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    transaction_id = txn.id
    await db.commit()
    await reconcile_transaction(transaction_id)
    txn = await db.scalar(select(FapshiTransaction).where(
        FapshiTransaction.id == transaction_id,
    ).execution_options(populate_existing=True))
    response = _serialize_transaction(txn)
    if txn.customer_id:
        customer = await db.scalar(select(Customer).options(selectinload(Customer.plan)).where(
            Customer.id == txn.customer_id,
        ).execution_options(populate_existing=True))
        response.update({"customer_status": customer.status.value if customer else None,
                         "plan_name": customer.plan.name if customer and customer.plan else None,
                         "expiry": customer.expiry.isoformat() if customer and customer.expiry else None})
    return response
