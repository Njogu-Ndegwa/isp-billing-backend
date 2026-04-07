"""
B2B payout routes: Safaricom callbacks, admin manual trigger, transaction history.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    User,
    UserRole,
)
from app.services.auth import verify_token, get_current_user
from app.services.mpesa_b2b import (
    get_b2b_fee,
    get_unpaid_balance,
    payout_reseller,
    process_b2b_result,
    process_b2b_timeout,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["b2b-payouts"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ---------------------------------------------------------------------------
# Safaricom callbacks (no auth — called by Safaricom servers)
# ---------------------------------------------------------------------------

@router.post("/api/mpesa/b2b/result")
async def b2b_result_callback(request: Request, db: AsyncSession = Depends(get_db)):
    """Safaricom ResultURL handler for B2B payments."""
    body = await request.json()
    logger.info("B2B result callback received: %s", body)
    txn = await process_b2b_result(db, body)
    await db.commit()
    return {"ResultCode": "0", "ResultDesc": "Accepted"}


@router.post("/api/mpesa/b2b/timeout")
async def b2b_timeout_callback(request: Request, db: AsyncSession = Depends(get_db)):
    """Safaricom QueueTimeOutURL handler for B2B payments."""
    body = await request.json()
    logger.info("B2B timeout callback received: %s", body)
    txn = await process_b2b_timeout(db, body)
    await db.commit()
    return {"ResultCode": "0", "ResultDesc": "Accepted"}


# ---------------------------------------------------------------------------
# Admin: Manual payout trigger
# ---------------------------------------------------------------------------

class ManualPayoutRequest(BaseModel):
    payment_method_id: Optional[int] = None


@router.post("/api/admin/resellers/{reseller_id}/b2b-payout")
async def trigger_b2b_payout(
    reseller_id: int,
    request: ManualPayoutRequest = ManualPayoutRequest(),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Manually trigger a B2B payout to a reseller.

    Optionally specify payment_method_id; otherwise the first eligible
    active payment method (bank_account or mpesa_paybill) is used.
    """
    await _require_admin(token, db)

    reseller = await db.get(User, reseller_id)
    if not reseller or reseller.role != UserRole.RESELLER:
        raise HTTPException(status_code=404, detail="Reseller not found")

    balance = await get_unpaid_balance(db, reseller_id)
    if balance <= 0:
        raise HTTPException(status_code=400, detail="No unpaid balance to pay out")

    if request.payment_method_id:
        pm = await db.get(ResellerPaymentMethod, request.payment_method_id)
        if not pm or pm.user_id != reseller_id:
            raise HTTPException(status_code=404, detail="Payment method not found for this reseller")
    else:
        pm_stmt = (
            select(ResellerPaymentMethod)
            .where(
                ResellerPaymentMethod.user_id == reseller_id,
                ResellerPaymentMethod.is_active == True,
                ResellerPaymentMethod.method_type.in_([
                    ResellerPaymentMethodType.BANK_ACCOUNT,
                    ResellerPaymentMethodType.MPESA_PAYBILL,
                ]),
            )
            .limit(1)
        )
        pm = (await db.execute(pm_stmt)).scalar_one_or_none()

    if not pm:
        raise HTTPException(
            status_code=400,
            detail="No eligible payment method (bank_account or mpesa_paybill) found for this reseller",
        )

    method_type = pm.method_type
    if isinstance(method_type, str):
        method_type = ResellerPaymentMethodType(method_type)
    if method_type not in (ResellerPaymentMethodType.BANK_ACCOUNT, ResellerPaymentMethodType.MPESA_PAYBILL):
        raise HTTPException(
            status_code=400,
            detail=f"Payment method type '{method_type.value}' is not eligible for B2B payout",
        )

    try:
        txn = await payout_reseller(db, reseller_id, pm, balance)
        await db.commit()
        await db.refresh(txn)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("B2B payout failed for reseller %s: %s", reseller_id, e)
        raise HTTPException(status_code=500, detail=f"B2B payout initiation failed: {e}")

    return {
        "transaction": _serialize_b2b_txn(txn),
        "balance_before": balance,
        "fee": txn.fee,
        "net_payout": txn.net_amount,
    }


# ---------------------------------------------------------------------------
# Admin: Fee preview
# ---------------------------------------------------------------------------

@router.get("/api/admin/resellers/{reseller_id}/b2b-fee-preview")
async def b2b_fee_preview(
    reseller_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Preview what the B2B fee would be for a reseller's current balance."""
    await _require_admin(token, db)

    reseller = await db.get(User, reseller_id)
    if not reseller or reseller.role != UserRole.RESELLER:
        raise HTTPException(status_code=404, detail="Reseller not found")

    balance = await get_unpaid_balance(db, reseller_id)
    tier_gap = False

    if balance > 0:
        fee = get_b2b_fee(balance)
        net = int(balance - fee)
        actual_fee = get_b2b_fee(net)
        if actual_fee != fee:
            fee = actual_fee
            net = int(balance - fee)
            if get_b2b_fee(net) != fee:
                tier_gap = True
                fee = 0
                net = 0
    else:
        fee = 0
        net = 0

    result = {
        "reseller_id": reseller_id,
        "unpaid_balance": balance,
        "safaricom_fee": fee,
        "net_payout": net,
    }
    if tier_gap:
        result["note"] = (
            "Balance falls in a fee tier gap — payout will proceed "
            "on the next cycle when more revenue accumulates"
        )
    return result


# ---------------------------------------------------------------------------
# Admin: B2B transaction history
# ---------------------------------------------------------------------------

def _serialize_b2b_txn(txn: B2BTransaction) -> dict:
    return {
        "id": txn.id,
        "reseller_id": txn.reseller_id,
        "conversation_id": txn.conversation_id,
        "amount": txn.amount,
        "fee": txn.fee,
        "net_amount": txn.net_amount,
        "party_a": txn.party_a,
        "party_b": txn.party_b,
        "account_reference": txn.account_reference,
        "command_id": txn.command_id,
        "remarks": txn.remarks,
        "status": txn.status.value if hasattr(txn.status, "value") else txn.status,
        "result_code": txn.result_code,
        "result_desc": txn.result_desc,
        "transaction_id": txn.transaction_id,
        "created_at": txn.created_at.isoformat() if txn.created_at else None,
        "completed_at": txn.completed_at.isoformat() if txn.completed_at else None,
    }


@router.get("/api/admin/b2b-transactions")
async def list_b2b_transactions(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None, description="Filter by status: pending, completed, failed, timeout"),
    reseller_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List all B2B transactions (admin only)."""
    await _require_admin(token, db)

    filters = []
    if status:
        try:
            filters.append(B2BTransaction.status == B2BTransactionStatus(status))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    if reseller_id:
        filters.append(B2BTransaction.reseller_id == reseller_id)
    if start_date:
        try:
            filters.append(B2BTransaction.created_at >= datetime.strptime(start_date, "%Y-%m-%d"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_date format, use YYYY-MM-DD")
    if end_date:
        try:
            filters.append(
                B2BTransaction.created_at < datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_date format, use YYYY-MM-DD")

    total = (await db.execute(
        select(func.count(B2BTransaction.id)).where(*filters) if filters
        else select(func.count(B2BTransaction.id))
    )).scalar()

    total_amount = float((await db.execute(
        select(func.coalesce(func.sum(B2BTransaction.net_amount), 0)).where(
            B2BTransaction.status == B2BTransactionStatus.COMPLETED,
            *(filters if filters else []),
        )
    )).scalar())

    total_fees = float((await db.execute(
        select(func.coalesce(func.sum(B2BTransaction.fee), 0)).where(
            B2BTransaction.status == B2BTransactionStatus.COMPLETED,
            *(filters if filters else []),
        )
    )).scalar())

    offset = (page - 1) * per_page
    stmt = (
        select(B2BTransaction, User.email, User.organization_name)
        .join(User, B2BTransaction.reseller_id == User.id)
    )
    if filters:
        stmt = stmt.where(*filters)
    stmt = stmt.order_by(B2BTransaction.created_at.desc()).offset(offset).limit(per_page)

    result = await db.execute(stmt)
    transactions = [
        {
            **_serialize_b2b_txn(txn),
            "reseller_email": email,
            "reseller_name": org_name,
        }
        for txn, email, org_name in result
    ]

    return {
        "page": page,
        "per_page": per_page,
        "total_count": total,
        "total_pages": (total + per_page - 1) // per_page,
        "summary": {
            "total_paid_out": round(total_amount, 2),
            "total_fees": round(total_fees, 2),
        },
        "transactions": transactions,
    }


@router.get("/api/admin/resellers/{reseller_id}/b2b-transactions")
async def list_reseller_b2b_transactions(
    reseller_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List B2B transactions for a specific reseller."""
    await _require_admin(token, db)

    reseller = await db.get(User, reseller_id)
    if not reseller or reseller.role != UserRole.RESELLER:
        raise HTTPException(status_code=404, detail="Reseller not found")

    base_filter = B2BTransaction.reseller_id == reseller_id

    total = (await db.execute(
        select(func.count(B2BTransaction.id)).where(base_filter)
    )).scalar()

    offset = (page - 1) * per_page
    stmt = (
        select(B2BTransaction)
        .where(base_filter)
        .order_by(B2BTransaction.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(stmt)
    transactions = [_serialize_b2b_txn(txn) for txn in result.scalars().all()]

    return {
        "reseller_id": reseller_id,
        "page": page,
        "per_page": per_page,
        "total_count": total,
        "total_pages": (total + per_page - 1) // per_page,
        "transactions": transactions,
    }
