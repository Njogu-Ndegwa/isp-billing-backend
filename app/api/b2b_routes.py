"""
B2B payout routes: Safaricom callbacks, admin manual trigger, reseller
self-service withdrawals + payout schedule, transaction history.
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
    MAX_CUSTOM_INTERVAL_DAYS,
    MIN_CUSTOM_INTERVAL_DAYS,
    RESELLER_TRIGGER,
    UNRESOLVED_STATUSES,
    VALID_PAYOUT_FREQUENCIES,
    PayoutInFlightError,
    _settle_completed_transaction,
    compute_fee_breakdown,
    get_payout_schedule,
    get_unpaid_balance,
    has_unresolved_b2b,
    payout_lock,
    payout_reseller,
    process_b2b_result,
    process_b2b_status_result,
    process_b2b_timeout,
    resolve_b2b_payment_method,
    set_payout_frequency,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["b2b-payouts"])

# Minimum self-service withdrawal: matches the nightly job's floor — KES 1 can
# never net positive after the KES 1 Kadogo fee.
MIN_WITHDRAWAL_KES = 2

# Anti-abuse throttle on self-service withdrawals: at most one initiation
# attempt per reseller per window, whatever its outcome. Their own balance is
# all they can move, but unthrottled retries would hammer Safaricom's API
# with our credentials. Admin/scheduled payouts are not throttled.
WITHDRAWAL_COOLDOWN = timedelta(minutes=10)


async def _withdrawal_cooldown_remaining(db: AsyncSession, reseller_id: int) -> int:
    """Seconds until this reseller may attempt another self-withdrawal (0 = now)."""
    last_at = (await db.execute(
        select(func.max(B2BTransaction.created_at)).where(
            B2BTransaction.reseller_id == reseller_id,
            B2BTransaction.triggered_by == RESELLER_TRIGGER,
        )
    )).scalar()
    if not last_at:
        return 0
    elapsed = datetime.utcnow() - last_at
    if elapsed >= WITHDRAWAL_COOLDOWN:
        return 0
    return max(1, int((WITHDRAWAL_COOLDOWN - elapsed).total_seconds()))


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def _require_reseller(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Reseller access required")
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


@router.post("/api/mpesa/b2b/status-result")
async def b2b_status_result_callback(request: Request, db: AsyncSession = Depends(get_db)):
    """Safaricom ResultURL handler for transaction-status queries — settles
    pending/timeout B2B transactions whose original callback was lost."""
    body = await request.json()
    logger.info("B2B status-query result received: %s", body)
    await process_b2b_status_result(db, body)
    await db.commit()
    return {"ResultCode": "0", "ResultDesc": "Accepted"}


@router.post("/api/mpesa/b2b/status-timeout")
async def b2b_status_timeout_callback(request: Request):
    """Status-query timeout: ignore — the reconciliation job re-queries."""
    body = await request.json()
    logger.warning("B2B status-query timeout received: %s", body)
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

    lock = payout_lock(reseller_id)
    if lock.locked():
        raise HTTPException(
            status_code=409,
            detail="A payout for this reseller is already being processed",
        )
    async with lock:
        # A pending/timeout transaction means money may already be in flight with
        # no verdict from Safaricom. Manually re-sending on top of one is exactly
        # how the 2026-07-18 double-payouts happened (KES 12,713 duplicated).
        if await has_unresolved_b2b(db, reseller_id):
            raise HTTPException(
                status_code=409,
                detail=(
                    "This reseller has a payout whose outcome Safaricom has not yet "
                    "confirmed. It is being verified automatically (usually within "
                    "~10 minutes) — sending again now risks paying twice. Check the "
                    "B2B transaction history for the pending/timeout entry."
                ),
            )

        balance = await get_unpaid_balance(db, reseller_id)
        if balance <= 0:
            raise HTTPException(status_code=400, detail="No unpaid balance to pay out")

        if request.payment_method_id:
            pm = await db.get(ResellerPaymentMethod, request.payment_method_id)
            if not pm or pm.user_id != reseller_id:
                raise HTTPException(status_code=404, detail="Payment method not found for this reseller")
        else:
            pm = await resolve_b2b_payment_method(db, reseller_id)

        if not pm:
            raise HTTPException(
                status_code=400,
                detail="No eligible payment method (bank_account or mpesa_paybill) found for this reseller",
            )

        try:
            txn = await payout_reseller(db, reseller_id, pm, balance)
            await db.commit()
            await db.refresh(txn)
        except PayoutInFlightError:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Another payout for this reseller is already in flight. "
                    "Check the B2B transaction history for the pending entry."
                ),
            )
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
    if balance > 0:
        fee, kadogo, net = compute_fee_breakdown(balance)
    else:
        fee, kadogo, net = 0, 0, 0

    return {
        "reseller_id": reseller_id,
        "unpaid_balance": balance,
        "safaricom_fee": fee - kadogo,
        "kadogo_surcharge": kadogo,
        "total_fee": fee,
        "net_payout": net,
    }


# ---------------------------------------------------------------------------
# Reseller self-service: payout settings + manual withdrawal
# (rendered on the Account Statement page)
# ---------------------------------------------------------------------------

class PayoutSettingsUpdate(BaseModel):
    payout_frequency: str
    payout_interval_days: Optional[int] = None


def _serialize_withdrawal_txn(txn: B2BTransaction) -> dict:
    """Reseller-facing subset of a B2B transaction."""
    return {
        "id": txn.id,
        "amount": txn.amount,
        "fee": txn.fee,
        "net_amount": txn.net_amount,
        "status": txn.status.value if hasattr(txn.status, "value") else txn.status,
        "transaction_id": txn.transaction_id,
        "created_at": txn.created_at.isoformat() if txn.created_at else None,
        "completed_at": txn.completed_at.isoformat() if txn.completed_at else None,
    }


@router.get("/api/reseller/payout-settings")
async def get_reseller_payout_settings(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Everything the Account Statement page needs to render the withdrawal card:
    balance, fee preview, destination, payout schedule, and — when a
    withdrawal is currently blocked — why.
    """
    user = await _require_reseller(token, db)

    frequency, interval_days = await get_payout_schedule(db, user.id)
    balance = await get_unpaid_balance(db, user.id)
    pm = await resolve_b2b_payment_method(db, user.id)

    unresolved = (await db.execute(
        select(B2BTransaction)
        .where(
            B2BTransaction.reseller_id == user.id,
            B2BTransaction.status.in_(UNRESOLVED_STATUSES),
        )
        .order_by(B2BTransaction.created_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    if balance > 0:
        fee, kadogo, net = compute_fee_breakdown(balance)
    else:
        fee, kadogo, net = 0, 0, 0

    cooldown_remaining = await _withdrawal_cooldown_remaining(db, user.id)

    blocked_reason = None
    if unresolved is not None:
        blocked_reason = "pending_withdrawal"
    elif pm is None:
        blocked_reason = "no_payment_method"
    elif balance < MIN_WITHDRAWAL_KES:
        blocked_reason = "balance_too_low"
    elif cooldown_remaining > 0:
        blocked_reason = "cooldown"

    return {
        "payout_frequency": frequency,
        "payout_interval_days": interval_days,
        "custom_interval_min_days": MIN_CUSTOM_INTERVAL_DAYS,
        "custom_interval_max_days": MAX_CUSTOM_INTERVAL_DAYS,
        "available_frequencies": list(VALID_PAYOUT_FREQUENCIES),
        "unpaid_balance": balance,
        "minimum_withdrawal": MIN_WITHDRAWAL_KES,
        "cooldown_seconds_remaining": cooldown_remaining,
        "fee_preview": {
            "safaricom_fee": fee - kadogo,
            "kadogo_surcharge": kadogo,
            "total_fee": fee,
            "net_payout": net,
        },
        "payment_method": (
            {
                "id": pm.id,
                "label": pm.label,
                "method_type": pm.method_type.value if hasattr(pm.method_type, "value") else pm.method_type,
                "destination": pm.bank_paybill_number or pm.mpesa_paybill_number,
            }
            if pm
            else None
        ),
        "can_withdraw": blocked_reason is None,
        "blocked_reason": blocked_reason,
        "pending_withdrawal": _serialize_withdrawal_txn(unresolved) if unresolved else None,
    }


@router.put("/api/reseller/payout-settings")
async def update_reseller_payout_settings(
    request: PayoutSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Set how often the scheduled job pays this reseller out. 'manual' disables
    automatic payouts entirely — money only moves when the reseller withdraws.
    """
    user = await _require_reseller(token, db)

    frequency = request.payout_frequency.strip().lower()
    if frequency not in VALID_PAYOUT_FREQUENCIES:
        raise HTTPException(
            status_code=400,
            detail=f"payout_frequency must be one of: {', '.join(VALID_PAYOUT_FREQUENCIES)}",
        )

    try:
        await set_payout_frequency(db, user.id, frequency, request.payout_interval_days)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await db.commit()
    logger.info(
        "Reseller %s set payout schedule to %s (interval_days=%s)",
        user.id, frequency, request.payout_interval_days,
    )
    return {
        "payout_frequency": frequency,
        "payout_interval_days": request.payout_interval_days if frequency == "custom" else None,
    }


@router.post("/api/reseller/withdraw")
async def reseller_withdraw(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Reseller-triggered B2B payout of their full unpaid balance to their
    configured bank account / M-Pesa paybill.
    """
    user = await _require_reseller(token, db)

    lock = payout_lock(user.id)
    if lock.locked():
        raise HTTPException(
            status_code=409,
            detail="A withdrawal is already being processed",
        )
    async with lock:
        # Same in-flight guard as the admin endpoint: an unresolved transaction
        # means money may already be moving with no verdict from Safaricom.
        if await has_unresolved_b2b(db, user.id):
            raise HTTPException(
                status_code=409,
                detail=(
                    "Your previous withdrawal is still being confirmed with "
                    "Safaricom (usually within ~10 minutes). Withdrawing again "
                    "now could pay you twice — please try again shortly."
                ),
            )

        cooldown_remaining = await _withdrawal_cooldown_remaining(db, user.id)
        if cooldown_remaining > 0:
            raise HTTPException(
                status_code=429,
                detail=(
                    "Please wait a few minutes between withdrawals "
                    f"(about {max(1, cooldown_remaining // 60)} min remaining)."
                ),
            )

        balance = await get_unpaid_balance(db, user.id)
        if balance < MIN_WITHDRAWAL_KES:
            raise HTTPException(
                status_code=400,
                detail=f"Balance is below the KES {MIN_WITHDRAWAL_KES} minimum withdrawal",
            )

        pm = await resolve_b2b_payment_method(db, user.id)
        if not pm:
            raise HTTPException(
                status_code=400,
                detail=(
                    "No eligible payout destination. Add a bank account or "
                    "M-Pesa paybill under payment methods first."
                ),
            )

        try:
            txn = await payout_reseller(
                db, user.id, pm, balance, triggered_by=RESELLER_TRIGGER
            )
            await db.commit()
            await db.refresh(txn)
        except PayoutInFlightError:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Another payout to you is already in flight — "
                    "please try again once it completes."
                ),
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error("Self-service withdrawal failed for reseller %s: %s", user.id, e)
            raise HTTPException(
                status_code=500,
                detail="Withdrawal could not be initiated. Please try again later.",
            )

    if txn.status == B2BTransactionStatus.FAILED:
        # Safaricom rejected it synchronously (e.g. invalid paybill). The failed
        # transaction is already committed for audit; surface a clear error.
        raise HTTPException(
            status_code=502,
            detail=f"Safaricom rejected the withdrawal: {txn.result_desc or 'unknown error'}",
        )

    logger.info(
        "Self-service withdrawal initiated: reseller=%s amount=%s net=%s fee=%s -> %s",
        user.id, txn.amount, txn.net_amount, txn.fee, txn.party_b,
    )
    return {
        "transaction": _serialize_withdrawal_txn(txn),
        "balance_before": balance,
        "fee": txn.fee,
        "net_payout": txn.net_amount,
        "destination_label": pm.label,
    }


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


class ResolveB2BRequest(BaseModel):
    outcome: str  # 'completed' | 'failed'
    receipt: Optional[str] = None
    note: str


@router.post("/api/admin/b2b-transactions/{txn_id}/resolve")
async def resolve_b2b_transaction(
    txn_id: int,
    request: ResolveB2BRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Manually close a stuck (pending/timeout) B2B transaction after verifying
    it on the M-Pesa org/bank statement — the escape hatch for transactions
    Safaricom's status API can no longer answer for (stale 2033).

    outcome='completed' requires the real M-Pesa receipt from the statement
    and creates the same payout + fee ledger rows as a normal callback;
    outcome='failed' releases the balance (the reseller stays owed).
    """
    admin = await _require_admin(token, db)

    if not request.note or not request.note.strip():
        raise HTTPException(
            status_code=400,
            detail="A note is required — say what you verified on the statement",
        )

    outcome = request.outcome.strip().lower()
    if outcome not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="outcome must be 'completed' or 'failed'")

    txn = await db.get(B2BTransaction, txn_id)
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if txn.status not in UNRESOLVED_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=f"Transaction is already {txn.status.value if hasattr(txn.status, 'value') else txn.status} — only pending/timeout transactions can be resolved",
        )

    note = request.note.strip()
    if outcome == "completed":
        receipt = (request.receipt or "").strip()
        if not receipt:
            raise HTTPException(
                status_code=400,
                detail="The M-Pesa receipt from the statement is required to mark a payment completed",
            )
        txn.result_code = "0"
        txn.result_desc = f"Manually resolved as completed by admin {admin.id}: {note}"[:500]
        await _settle_completed_transaction(db, txn, receipt)
    else:
        txn.status = B2BTransactionStatus.FAILED
        txn.result_code = txn.result_code or "MANUAL"
        txn.result_desc = f"Manually resolved as failed by admin {admin.id}: {note}"[:500]

    await db.commit()
    await db.refresh(txn)
    logger.warning(
        "B2B txn %s manually resolved as %s by admin %s (reseller %s)",
        txn.id, outcome, admin.id, txn.reseller_id,
    )
    return {"transaction": _serialize_b2b_txn(txn)}


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
