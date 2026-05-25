"""
M-Pesa C2B Paybill routes.

Two flavors of endpoint live here:

1. Public webhooks Safaricom calls (no auth — they don't authenticate):
   - POST /api/c2b/validation     (optional pre-payment account check)
   - POST /api/c2b/confirmation   (the main settlement webhook)

2. Authenticated admin/reseller endpoints for operating the integration:
   - POST /api/admin/c2b/register-platform-paybill
   - POST /api/payment-methods/{id}/register-c2b
   - GET  /api/c2b/unmatched
   - POST /api/c2b/unmatched/{id}/attribute

The handler logic itself lives in app/services/c2b_handler.py so it stays
unit-testable without spinning up an HTTP client.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.config import settings
from app.db.database import get_db
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    ConnectionType,
    Customer,
    PaymentMethod,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    UnmatchedC2BPayment,
    User,
    UserRole,
)
from app.services.auth import verify_token, get_current_user
from app.services.account_numbers import is_valid_account_number
from app.services.c2b_handler import (
    SUCCESS_RESPONSE,
    handle_confirmation,
    handle_validation,
)
from app.services.payment_gateway import decrypt_credential
from app.services.pppoe_provisioning import build_pppoe_payload, call_pppoe_provision
from app.services.mpesa import get_access_token, SAFARICOM_TIMEOUT
from app.services.reseller_payments import record_customer_payment


logger = logging.getLogger(__name__)

router = APIRouter(tags=["c2b-paybill"])


# ---------------------------------------------------------------------------
# Safaricom webhooks (unauthenticated)
# ---------------------------------------------------------------------------


@router.post("/api/c2b/validation")
async def c2b_validation(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Safaricom calls this before debiting the customer. We say yes/no based
    on whether the BillRefNumber maps to a real customer."""
    try:
        payload = await request.json()
    except Exception:
        logger.warning("[C2B] Validation called with non-JSON body")
        # Per Safaricom: any 2xx is treated as accept; we'd rather reject loudly
        from app.services.c2b_handler import REJECT_INVALID_ACCOUNT
        return REJECT_INVALID_ACCOUNT
    return await handle_validation(payload, db)


@router.post("/api/c2b/confirmation")
async def c2b_confirmation(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Main C2B settlement webhook. We always return 200/Success — Safaricom
    treats anything else as a retry signal and we don't want them retrying
    on application bugs."""
    try:
        payload = await request.json()
    except Exception:
        logger.warning("[C2B] Confirmation called with non-JSON body")
        return SUCCESS_RESPONSE
    return await handle_confirmation(payload, db, background_tasks=background_tasks)


# ---------------------------------------------------------------------------
# Admin: register platform paybill URLs with Safaricom
# ---------------------------------------------------------------------------


class RegisterPlatformPaybillRequest(BaseModel):
    confirmation_url: str
    validation_url: str
    # "Completed" or "Cancelled" — what Safaricom does if our Validation URL is
    # unreachable. "Cancelled" is the safer default for production.
    response_type: str = "Completed"


@router.post("/api/admin/c2b/register-platform-paybill")
async def register_platform_paybill(
    request: RegisterPlatformPaybillRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
) -> dict:
    """Register the PLATFORM owner's paybill with Safaricom Daraja
    /mpesa/c2b/v1/registerurl."""
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    return await _call_daraja_registerurl(
        shortcode=settings.MPESA_SHORTCODE,
        consumer_key=settings.MPESA_CONSUMER_KEY,
        consumer_secret=settings.MPESA_CONSUMER_SECRET,
        confirmation_url=request.confirmation_url,
        validation_url=request.validation_url,
        response_type=request.response_type,
    )


# ---------------------------------------------------------------------------
# Reseller: register own paybill URLs with Safaricom
# ---------------------------------------------------------------------------


class RegisterResellerC2BRequest(BaseModel):
    confirmation_url: str
    validation_url: str
    response_type: str = "Completed"


@router.post("/api/payment-methods/{method_id}/register-c2b")
async def register_reseller_c2b(
    method_id: int,
    request: RegisterResellerC2BRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
) -> dict:
    """Register a reseller's own paybill with Safaricom using credentials
    stored on the ResellerPaymentMethod row."""
    user = await get_current_user(token, db)
    pm = (
        await db.execute(
            select(ResellerPaymentMethod).where(
                ResellerPaymentMethod.id == method_id,
                ResellerPaymentMethod.user_id == user.id,
            )
        )
    ).scalar_one_or_none()
    if pm is None:
        raise HTTPException(status_code=404, detail="Payment method not found")
    if pm.method_type != ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS:
        raise HTTPException(
            status_code=400,
            detail="C2B registration only applies to mpesa_paybill_with_keys methods",
        )
    if not pm.mpesa_consumer_key_encrypted or not pm.mpesa_consumer_secret_encrypted or not pm.mpesa_shortcode:
        raise HTTPException(
            status_code=400,
            detail="Payment method is missing mpesa_shortcode / consumer_key / consumer_secret",
        )

    result = await _call_daraja_registerurl(
        shortcode=pm.mpesa_shortcode,
        consumer_key=decrypt_credential(pm.mpesa_consumer_key_encrypted),
        consumer_secret=decrypt_credential(pm.mpesa_consumer_secret_encrypted),
        confirmation_url=request.confirmation_url,
        validation_url=request.validation_url,
        response_type=request.response_type,
    )

    pm.c2b_validation_url = request.validation_url
    pm.c2b_confirmation_url = request.confirmation_url
    pm.c2b_registered_at = datetime.utcnow()
    await db.commit()

    return result


# ---------------------------------------------------------------------------
# Reseller: list unmatched payments
# ---------------------------------------------------------------------------


@router.get("/api/c2b/unmatched")
async def list_unmatched_c2b(
    resolved: bool = False,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
) -> list[dict]:
    """List unmatched C2B payments assigned to the current reseller for triage.
    Admins see all rows (no reseller scope)."""
    user = await get_current_user(token, db)
    stmt = (
        select(UnmatchedC2BPayment)
        .options(joinedload(UnmatchedC2BPayment.c2b_transaction))
        .order_by(UnmatchedC2BPayment.id.desc())
        .limit(min(limit, 500))
    )
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(UnmatchedC2BPayment.assigned_reseller_id == user.id)
    if not resolved:
        stmt = stmt.where(UnmatchedC2BPayment.resolved_at.is_(None))

    rows = (await db.execute(stmt)).scalars().all()
    return [_serialize_unmatched(r) for r in rows]


# ---------------------------------------------------------------------------
# Reseller: manually attribute an unmatched payment to a customer
# ---------------------------------------------------------------------------


class AttributeUnmatchedRequest(BaseModel):
    customer_id: int
    notes: Optional[str] = None


@router.post("/api/c2b/unmatched/{unmatched_id}/attribute")
async def attribute_unmatched_c2b(
    unmatched_id: int,
    request: AttributeUnmatchedRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
) -> dict:
    """Manually credit an unmatched payment to a specific customer. Runs the
    same activate-and-provision pipeline as a fresh confirmation, then marks
    the unmatched row resolved."""
    user = await get_current_user(token, db)

    unmatched = (
        await db.execute(
            select(UnmatchedC2BPayment)
            .options(joinedload(UnmatchedC2BPayment.c2b_transaction))
            .where(UnmatchedC2BPayment.id == unmatched_id)
        )
    ).scalar_one_or_none()
    if unmatched is None:
        raise HTTPException(status_code=404, detail="Unmatched payment not found")
    if user.role != UserRole.ADMIN and unmatched.assigned_reseller_id != user.id:
        raise HTTPException(status_code=403, detail="Not your unmatched payment")
    if unmatched.resolved_at is not None:
        raise HTTPException(status_code=409, detail="Already resolved")

    customer = (
        await db.execute(
            select(Customer)
            .options(joinedload(Customer.plan), joinedload(Customer.router))
            .where(Customer.id == request.customer_id)
        )
    ).scalar_one_or_none()
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    if user.role != UserRole.ADMIN and customer.user_id != user.id:
        raise HTTPException(status_code=403, detail="Customer belongs to another reseller")

    txn = unmatched.c2b_transaction
    plan_price = float(customer.plan.price) if customer.plan else 0.0
    effective_amount = float(txn.trans_amount) + float(customer.wallet_credit_kes or 0)

    if plan_price > 0 and effective_amount < plan_price:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Amount {txn.trans_amount} + wallet {customer.wallet_credit_kes} "
                f"is below plan price {plan_price}; cannot activate."
            ),
        )

    plan_duration_value = customer.plan.duration_value
    plan_duration_unit = customer.plan.duration_unit.value.upper()
    if plan_duration_unit == "MINUTES":
        days_paid_for = max(1, plan_duration_value // (24 * 60))
    elif plan_duration_unit == "HOURS":
        days_paid_for = max(1, plan_duration_value // 24)
    else:
        days_paid_for = plan_duration_value

    is_platform_paybill = txn.business_shortcode == settings.MPESA_SHORTCODE
    from app.db.models import CollectionMode
    collection = (
        CollectionMode.SYSTEM_COLLECTED if is_platform_paybill
        else CollectionMode.DIRECT
    )

    await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=customer.user_id,
        amount=float(txn.trans_amount),
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=days_paid_for,
        payment_reference=txn.trans_id,
        notes=f"C2B manually attributed by user {user.id}: {request.notes or ''}".strip(),
        duration_value=plan_duration_value,
        duration_unit=plan_duration_unit,
        collection_mode=collection,
    )

    new_wallet = int(round(effective_amount - plan_price)) if plan_price > 0 else 0
    customer.wallet_credit_kes = max(0, new_wallet)

    # Update the C2B row + mark unmatched as resolved
    txn.status = C2BTransactionStatus.PROCESSED
    txn.matched_customer_id = customer.id
    txn.matched_reseller_id = customer.user_id
    txn.processed_at = datetime.utcnow()
    unmatched.resolved_at = datetime.utcnow()
    unmatched.resolved_by_user_id = user.id
    unmatched.resolution_customer_id = customer.id
    if request.notes:
        unmatched.notes = request.notes

    await db.commit()

    # PPPoE provisioning (same as the auto path)
    if (
        customer.plan
        and customer.plan.connection_type == ConnectionType.PPPOE
        and customer.pppoe_username
        and customer.router
    ):
        background_tasks.add_task(call_pppoe_provision, build_pppoe_payload(customer, customer.router))

    return {
        "ok": True,
        "customer_id": customer.id,
        "new_wallet_credit_kes": customer.wallet_credit_kes,
        "c2b_transaction_id": txn.id,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _call_daraja_registerurl(
    *,
    shortcode: str,
    consumer_key: str,
    consumer_secret: str,
    confirmation_url: str,
    validation_url: str,
    response_type: str = "Completed",
) -> dict:
    """Call Safaricom Daraja /mpesa/c2b/v2/registerurl. Returns Safaricom's
    response verbatim so the caller can show ResponseDescription / errors
    back to the operator."""
    access_token = await get_access_token(
        consumer_key=consumer_key, consumer_secret=consumer_secret
    )
    base_url = (
        "https://api.safaricom.co.ke"
        if settings.MPESA_ENVIRONMENT == "production"
        else "https://sandbox.safaricom.co.ke"
    )
    payload = {
        "ShortCode": shortcode,
        "ResponseType": response_type,
        "ConfirmationURL": confirmation_url,
        "ValidationURL": validation_url,
    }
    async with httpx.AsyncClient(timeout=SAFARICOM_TIMEOUT) as client:
        resp = await client.post(
            f"{base_url}/mpesa/c2b/v2/registerurl",
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
        )
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail={"safaricom_status": resp.status_code, "body": body})
        return body


def _serialize_unmatched(row: UnmatchedC2BPayment) -> dict:
    txn = row.c2b_transaction
    return {
        "id": row.id,
        "reason": row.reason.value,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "resolved_by_user_id": row.resolved_by_user_id,
        "resolution_customer_id": row.resolution_customer_id,
        "notes": row.notes,
        "assigned_reseller_id": row.assigned_reseller_id,
        "transaction": {
            "id": txn.id,
            "trans_id": txn.trans_id,
            "bill_ref_number": txn.bill_ref_number,
            "trans_amount": txn.trans_amount,
            "msisdn": txn.msisdn,
            "business_shortcode": txn.business_shortcode,
            "received_at": txn.received_at.isoformat() if txn.received_at else None,
        },
    }
