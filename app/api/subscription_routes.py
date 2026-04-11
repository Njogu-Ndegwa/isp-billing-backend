from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import (
    User, UserRole, Subscription, SubscriptionInvoice, SubscriptionPayment,
    SubscriptionStatus, InvoiceStatus, SubscriptionPaymentStatus,
)
from app.services.auth import verify_token, get_current_user
from app.services.subscription import (
    get_subscription_summary, get_pending_invoice, enrich_invoice,
    get_invoice_amount_paid,
    activate_subscription, deactivate_subscription,
    generate_monthly_invoices, calculate_reseller_charges,
    generate_invoice_for_reseller, record_subscription_payment,
    get_invoice_alert_for_user,
    TRIAL_DAYS, GRACE_PERIOD_DAYS,
)
from app.services.mpesa import initiate_stk_push_direct
from app.config import settings

import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["subscriptions"])


# ============================================================
# Reseller-facing endpoints
# ============================================================

@router.get("/api/subscription")
async def get_my_subscription(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get the current reseller's subscription status and summary."""
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Only resellers have subscriptions")
    return await get_subscription_summary(db, user.id)


@router.get("/api/subscription/current-invoice")
async def get_current_invoice(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Get the latest unpaid invoice with due-date awareness fields.
    Returns null if no pending invoice exists.
    """
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Only resellers have subscriptions")

    invoice = await get_pending_invoice(db, user.id)
    if not invoice:
        return {"current_invoice": None}

    paid = await get_invoice_amount_paid(db, invoice.id)
    return {"current_invoice": enrich_invoice(invoice, paid)}


@router.get("/api/subscription/invoices")
async def list_my_invoices(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, description="Filter by status: pending, paid, overdue, waived"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List all invoices for the current reseller."""
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Only resellers have subscriptions")

    filters = [SubscriptionInvoice.user_id == user.id]
    if status:
        try:
            status_enum = InvoiceStatus(status)
            filters.append(SubscriptionInvoice.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status. Use: pending, paid, overdue, waived")

    total = (await db.execute(
        select(func.count(SubscriptionInvoice.id)).where(*filters)
    )).scalar() or 0

    offset = (page - 1) * per_page
    invoices = (await db.execute(
        select(SubscriptionInvoice)
        .where(*filters)
        .order_by(SubscriptionInvoice.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )).scalars().all()

    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": (total + per_page - 1) // per_page,
        "invoices": [
            enrich_invoice(inv, await get_invoice_amount_paid(db, inv.id))
            for inv in invoices
        ],
    }


@router.get("/api/subscription/invoices/{invoice_id}")
async def get_invoice_detail(
    invoice_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get detailed invoice breakdown."""
    user = await get_current_user(token, db)

    invoice = (await db.execute(
        select(SubscriptionInvoice).where(SubscriptionInvoice.id == invoice_id)
    )).scalar_one_or_none()

    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")

    if user.role != UserRole.ADMIN and invoice.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    payments = (await db.execute(
        select(SubscriptionPayment)
        .where(SubscriptionPayment.invoice_id == invoice_id)
        .order_by(SubscriptionPayment.created_at.desc())
    )).scalars().all()

    paid = await get_invoice_amount_paid(db, invoice.id)
    enriched = enrich_invoice(invoice, paid)
    enriched["payments"] = [
        {
            "id": p.id,
            "amount": p.amount,
            "payment_method": p.payment_method,
            "payment_reference": p.payment_reference,
            "phone_number": p.phone_number,
            "status": p.status.value if hasattr(p.status, 'value') else p.status,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in payments
    ]

    return enriched


class SubscriptionPayRequest(BaseModel):
    invoice_id: int
    phone_number: str
    amount: Optional[float] = None


@router.post("/api/subscription/pay")
async def pay_subscription(
    request: SubscriptionPayRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Initiate M-Pesa STK push to pay a subscription invoice.
    Supports partial payments — omit amount to pay the remaining balance."""
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Only resellers can pay subscriptions")

    invoice = (await db.execute(
        select(SubscriptionInvoice).where(
            SubscriptionInvoice.id == request.invoice_id,
            SubscriptionInvoice.user_id == user.id,
        )
    )).scalar_one_or_none()

    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")

    if invoice.status in (InvoiceStatus.PAID, InvoiceStatus.WAIVED):
        raise HTTPException(status_code=400, detail="Invoice is already paid or waived")

    already_paid = await get_invoice_amount_paid(db, invoice.id)
    balance = round(invoice.final_charge - already_paid, 2)

    if balance <= 0:
        raise HTTPException(status_code=400, detail="Invoice is already fully paid")

    amount = request.amount if request.amount else balance
    if amount < 1:
        raise HTTPException(status_code=400, detail="Amount must be at least KES 1")

    phone = request.phone_number.strip()
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    elif phone.startswith("+"):
        phone = phone[1:]

    reference = f"SUB-{invoice.id}"

    callback_url = settings.MPESA_CALLBACK_URL.rstrip("/")
    if "/api/mpesa/callback" in callback_url:
        callback_url = callback_url.replace("/api/mpesa/callback", "/api/subscription/mpesa/callback")
    else:
        callback_url = callback_url.rstrip("/") + "/api/subscription/mpesa/callback"

    pending_payment = SubscriptionPayment(
        invoice_id=invoice.id,
        user_id=user.id,
        amount=amount,
        payment_method="mpesa",
        phone_number=phone,
        status=SubscriptionPaymentStatus.PENDING,
    )
    db.add(pending_payment)
    await db.flush()

    try:
        stk_response = await initiate_stk_push_direct(
            phone_number=phone,
            amount=amount,
            reference=reference,
            callback_url=callback_url,
            account_reference=f"Subscription Invoice #{invoice.id}",
        )
    except Exception as e:
        pending_payment.status = SubscriptionPaymentStatus.FAILED
        await db.commit()
        logger.error(f"[SUBSCRIPTION] STK push failed for reseller {user.id}: {e}")
        raise HTTPException(status_code=502, detail=f"M-Pesa STK push failed: {str(e)}")

    if stk_response:
        pending_payment.mpesa_checkout_request_id = stk_response.checkout_request_id
    await db.commit()

    return {
        "message": "STK push sent. Check your phone to complete payment.",
        "payment_id": pending_payment.id,
        "checkout_request_id": stk_response.checkout_request_id if stk_response else None,
        "amount": amount,
        "invoice_total": invoice.final_charge,
        "already_paid": round(already_paid, 2),
        "balance_after_this": round(max(balance - amount, 0), 2),
        "phone_number": phone,
    }


@router.post("/api/subscription/mpesa/callback")
async def subscription_mpesa_callback(request: Request, db: AsyncSession = Depends(get_db)):
    """M-Pesa callback handler for subscription payments."""
    try:
        body = await request.json()

        stk_callback = body.get("Body", {}).get("stkCallback", {})
        result_code = stk_callback.get("ResultCode")
        checkout_request_id = stk_callback.get("CheckoutRequestID")

        if not checkout_request_id:
            logger.warning("[SUBSCRIPTION] Callback missing CheckoutRequestID")
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        payment = (await db.execute(
            select(SubscriptionPayment).where(
                SubscriptionPayment.mpesa_checkout_request_id == checkout_request_id
            )
        )).scalar_one_or_none()

        if not payment:
            logger.warning(f"[SUBSCRIPTION] No payment found for checkout {checkout_request_id}")
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        # Idempotency: skip if already processed
        pay_status = payment.status.value if hasattr(payment.status, 'value') else payment.status
        if pay_status != "pending":
            logger.info(f"[SUBSCRIPTION] Duplicate callback for {checkout_request_id}, status={pay_status}")
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        if result_code == 0:
            metadata_items = stk_callback.get("CallbackMetadata", {}).get("Item", [])
            receipt_number = None
            for item in metadata_items:
                if item.get("Name") == "MpesaReceiptNumber":
                    receipt_number = item.get("Value")
                    break

            payment.status = SubscriptionPaymentStatus.COMPLETED
            payment.payment_reference = receipt_number

            fully_paid = False
            if payment.invoice_id:
                invoice = (await db.execute(
                    select(SubscriptionInvoice).where(
                        SubscriptionInvoice.id == payment.invoice_id
                    )
                )).scalar_one_or_none()
                if invoice:
                    await db.flush()
                    total_paid = await get_invoice_amount_paid(db, invoice.id)
                    if total_paid >= invoice.final_charge:
                        invoice.status = InvoiceStatus.PAID
                        invoice.paid_at = datetime.utcnow()
                        fully_paid = True
                        logger.info(
                            f"[SUBSCRIPTION] Invoice #{invoice.id} fully paid "
                            f"({total_paid:,.0f} / {invoice.final_charge:,.0f})"
                        )
                    else:
                        logger.info(
                            f"[SUBSCRIPTION] Partial payment for invoice #{invoice.id}: "
                            f"{total_paid:,.0f} / {invoice.final_charge:,.0f}"
                        )

            if fully_paid:
                await activate_subscription(db, payment.user_id, months=1)

            logger.info(
                f"[SUBSCRIPTION] Payment completed for reseller {payment.user_id}, "
                f"invoice #{payment.invoice_id}, receipt={receipt_number}, "
                f"amount={payment.amount}, activated={fully_paid}"
            )
        else:
            payment.status = SubscriptionPaymentStatus.FAILED
            logger.info(
                f"[SUBSCRIPTION] Payment failed for reseller {payment.user_id}, "
                f"code={result_code}, desc={stk_callback.get('ResultDesc')}"
            )

        await db.commit()
    except Exception:
        logger.exception("[SUBSCRIPTION] Error processing M-Pesa callback")
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


@router.get("/api/subscription/payments")
async def list_my_payments(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List all subscription payments for the current reseller."""
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Only resellers have subscriptions")

    total = (await db.execute(
        select(func.count(SubscriptionPayment.id)).where(
            SubscriptionPayment.user_id == user.id,
        )
    )).scalar() or 0

    offset = (page - 1) * per_page
    payments = (await db.execute(
        select(SubscriptionPayment)
        .where(SubscriptionPayment.user_id == user.id)
        .order_by(SubscriptionPayment.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )).scalars().all()

    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": (total + per_page - 1) // per_page,
        "payments": [
            {
                "id": p.id,
                "invoice_id": p.invoice_id,
                "amount": p.amount,
                "payment_method": p.payment_method,
                "payment_reference": p.payment_reference,
                "phone_number": p.phone_number,
                "status": p.status.value if hasattr(p.status, 'value') else p.status,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p in payments
        ],
    }


# ============================================================
# Admin-facing endpoints
# ============================================================

async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@router.get("/api/admin/subscriptions")
async def admin_list_subscriptions(
    status: Optional[str] = Query(None, description="Filter: active, trial, suspended, inactive"),
    sort_by: Optional[str] = Query(None, description="Sort: expires_at, revenue, created_at"),
    sort_order: Optional[str] = Query("desc", pattern="^(asc|desc)$"),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List all reseller subscriptions with status, expiry, and financials."""
    await _require_admin(token, db)

    stmt = select(User).where(User.role == UserRole.RESELLER)

    if status:
        try:
            status_enum = SubscriptionStatus(status)
            stmt = stmt.where(User.subscription_status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status filter")

    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            User.email.ilike(pattern) | User.organization_name.ilike(pattern)
        )

    stmt = stmt.order_by(User.created_at.desc())
    resellers = (await db.execute(stmt)).scalars().all()

    items = []
    for r in resellers:
        pending_inv = await get_pending_invoice(db, r.id)
        total_paid = float((await db.execute(
            select(func.coalesce(func.sum(SubscriptionPayment.amount), 0)).where(
                SubscriptionPayment.user_id == r.id,
                SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            )
        )).scalar())

        inv_paid = await get_invoice_amount_paid(db, pending_inv.id) if pending_inv else 0.0
        outstanding = round(pending_inv.final_charge - inv_paid, 2) if pending_inv else 0.0

        sub_status = r.subscription_status
        sub_status_val = sub_status.value if hasattr(sub_status, 'value') else sub_status

        items.append({
            "id": r.id,
            "email": r.email,
            "organization_name": r.organization_name,
            "business_name": r.business_name,
            "subscription_status": sub_status_val,
            "subscription_expires_at": r.subscription_expires_at.isoformat() if r.subscription_expires_at else None,
            "total_paid": total_paid,
            "outstanding": outstanding,
            "pending_invoice": enrich_invoice(pending_inv, inv_paid) if pending_inv else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_login_at": r.last_login_at.isoformat() if r.last_login_at else None,
        })

    sort_key_map = {
        "expires_at": lambda x: x["subscription_expires_at"] or "",
        "revenue": lambda x: x["total_paid"],
        "created_at": lambda x: x["created_at"] or "",
    }
    if sort_by and sort_by in sort_key_map:
        items.sort(key=sort_key_map[sort_by], reverse=(sort_order != "asc"))

    return {"total": len(items), "subscriptions": items}


@router.get("/api/admin/subscriptions/revenue")
async def admin_subscription_revenue(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Subscription revenue dashboard for admin."""
    await _require_admin(token, db)

    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)

    total_collected = float((await db.execute(
        select(func.coalesce(func.sum(SubscriptionPayment.amount), 0)).where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
        )
    )).scalar())

    this_month_collected = float((await db.execute(
        select(func.coalesce(func.sum(SubscriptionPayment.amount), 0)).where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            SubscriptionPayment.created_at >= month_start,
        )
    )).scalar())

    total_outstanding = float((await db.execute(
        select(func.coalesce(func.sum(SubscriptionInvoice.final_charge), 0)).where(
            SubscriptionInvoice.status.in_([InvoiceStatus.PENDING, InvoiceStatus.OVERDUE]),
        )
    )).scalar())

    total_invoices = (await db.execute(
        select(func.count(SubscriptionInvoice.id))
    )).scalar() or 0

    overdue_count = (await db.execute(
        select(func.count(SubscriptionInvoice.id)).where(
            SubscriptionInvoice.status == InvoiceStatus.OVERDUE,
        )
    )).scalar() or 0

    active_count = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.subscription_status == SubscriptionStatus.ACTIVE,
        )
    )).scalar() or 0

    trial_count = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.subscription_status == SubscriptionStatus.TRIAL,
        )
    )).scalar() or 0

    suspended_count = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.subscription_status == SubscriptionStatus.SUSPENDED,
        )
    )).scalar() or 0

    return {
        "total_collected": total_collected,
        "this_month_collected": this_month_collected,
        "total_outstanding": total_outstanding,
        "total_invoices": total_invoices,
        "overdue_invoices": overdue_count,
        "resellers": {
            "active": active_count,
            "trial": trial_count,
            "suspended": suspended_count,
        },
    }


@router.get("/api/admin/subscriptions/expiring-soon")
async def admin_expiring_soon(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List resellers whose subscriptions expire within N days."""
    await _require_admin(token, db)

    now = datetime.utcnow()
    cutoff = now + timedelta(days=days)

    resellers = (await db.execute(
        select(User).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL]),
            User.subscription_expires_at.isnot(None),
            User.subscription_expires_at <= cutoff,
        ).order_by(User.subscription_expires_at.asc())
    )).scalars().all()

    return {
        "days_threshold": days,
        "total": len(resellers),
        "resellers": [
            {
                "id": r.id,
                "email": r.email,
                "organization_name": r.organization_name,
                "subscription_status": r.subscription_status.value if hasattr(r.subscription_status, 'value') else r.subscription_status,
                "subscription_expires_at": r.subscription_expires_at.isoformat() if r.subscription_expires_at else None,
                "days_until_expiry": (r.subscription_expires_at - now).days if r.subscription_expires_at else None,
            }
            for r in resellers
        ],
    }


@router.get("/api/admin/subscriptions/{reseller_id}")
async def admin_get_subscription_detail(
    reseller_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Full subscription detail for a specific reseller."""
    await _require_admin(token, db)

    user = (await db.execute(
        select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Reseller not found")

    summary = await get_subscription_summary(db, reseller_id)

    invoices = (await db.execute(
        select(SubscriptionInvoice)
        .where(SubscriptionInvoice.user_id == reseller_id)
        .order_by(SubscriptionInvoice.created_at.desc())
        .limit(50)
    )).scalars().all()

    payments = (await db.execute(
        select(SubscriptionPayment)
        .where(SubscriptionPayment.user_id == reseller_id)
        .order_by(SubscriptionPayment.created_at.desc())
        .limit(50)
    )).scalars().all()

    return {
        "reseller": {
            "id": user.id,
            "email": user.email,
            "organization_name": user.organization_name,
            "business_name": user.business_name,
        },
        "subscription": summary,
        "invoices": [
            enrich_invoice(inv, await get_invoice_amount_paid(db, inv.id))
            for inv in invoices
        ],
        "payments": [
            {
                "id": p.id,
                "invoice_id": p.invoice_id,
                "amount": p.amount,
                "payment_method": p.payment_method,
                "payment_reference": p.payment_reference,
                "phone_number": p.phone_number,
                "status": p.status.value if hasattr(p.status, 'value') else p.status,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p in payments
        ],
    }


class AdminSubscriptionPatch(BaseModel):
    subscription_status: Optional[str] = None
    subscription_expires_at: Optional[str] = None
    adjust_days: Optional[int] = None


@router.patch("/api/admin/subscriptions/{reseller_id}")
async def admin_edit_subscription(
    reseller_id: int,
    body: AdminSubscriptionPatch,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Edit a reseller's subscription: change status or expiry date."""
    await _require_admin(token, db)

    user = (await db.execute(
        select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Reseller not found")

    if body.subscription_status:
        try:
            new_status = SubscriptionStatus(body.subscription_status)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status. Use: active, inactive, trial, suspended")
        user.subscription_status = new_status

        sub = (await db.execute(
            select(Subscription).where(Subscription.user_id == reseller_id)
        )).scalar_one_or_none()
        if sub:
            sub.status = new_status
            sub.updated_at = datetime.utcnow()

    if body.subscription_expires_at:
        try:
            new_expiry = datetime.fromisoformat(body.subscription_expires_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use ISO format: YYYY-MM-DDTHH:MM:SS")
        user.subscription_expires_at = new_expiry

        sub = (await db.execute(
            select(Subscription).where(Subscription.user_id == reseller_id)
        )).scalar_one_or_none()
        if sub:
            sub.current_period_end = new_expiry
            sub.updated_at = datetime.utcnow()

    if body.adjust_days is not None:
        base = user.subscription_expires_at or datetime.utcnow()
        new_expiry = base + timedelta(days=body.adjust_days)
        user.subscription_expires_at = new_expiry

        sub = (await db.execute(
            select(Subscription).where(Subscription.user_id == reseller_id)
        )).scalar_one_or_none()
        if sub:
            sub.current_period_end = new_expiry
            sub.updated_at = datetime.utcnow()

    await db.commit()

    sub_status = user.subscription_status
    expires_at = user.subscription_expires_at
    days_remaining = (expires_at - datetime.utcnow()).days if expires_at else None
    return {
        "message": "Subscription updated",
        "reseller_id": reseller_id,
        "subscription_status": sub_status.value if hasattr(sub_status, 'value') else sub_status,
        "subscription_expires_at": expires_at.isoformat() if expires_at else None,
        "days_remaining": days_remaining,
    }


@router.post("/api/admin/subscriptions/{reseller_id}/activate")
async def admin_activate_subscription(
    reseller_id: int,
    months: int = Query(1, ge=1, le=12),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Manually activate a reseller's subscription."""
    await _require_admin(token, db)

    user = (await db.execute(
        select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Reseller not found")

    await activate_subscription(db, reseller_id, months=months)
    await db.commit()

    return {
        "message": f"Subscription activated for {months} month(s)",
        "reseller_id": reseller_id,
        "subscription_status": "active",
        "subscription_expires_at": user.subscription_expires_at.isoformat() if user.subscription_expires_at else None,
    }


@router.post("/api/admin/subscriptions/{reseller_id}/deactivate")
async def admin_deactivate_subscription(
    reseller_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Manually deactivate/suspend a reseller's subscription."""
    await _require_admin(token, db)

    user = (await db.execute(
        select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Reseller not found")

    await deactivate_subscription(db, reseller_id, status=SubscriptionStatus.SUSPENDED)
    await db.commit()

    return {
        "message": "Subscription suspended",
        "reseller_id": reseller_id,
        "subscription_status": "suspended",
    }


@router.post("/api/admin/subscriptions/{reseller_id}/waive/{invoice_id}")
async def admin_waive_invoice(
    reseller_id: int,
    invoice_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Waive a specific invoice for a reseller."""
    await _require_admin(token, db)

    invoice = (await db.execute(
        select(SubscriptionInvoice).where(
            SubscriptionInvoice.id == invoice_id,
            SubscriptionInvoice.user_id == reseller_id,
        )
    )).scalar_one_or_none()

    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")

    if invoice.status == InvoiceStatus.PAID:
        raise HTTPException(status_code=400, detail="Cannot waive an already paid invoice")

    invoice.status = InvoiceStatus.WAIVED
    await db.commit()

    return {
        "message": "Invoice waived",
        "invoice_id": invoice.id,
        "reseller_id": reseller_id,
    }


@router.post("/api/admin/subscriptions/generate-invoices")
async def admin_generate_invoices(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Manually trigger invoice generation for the previous month."""
    await _require_admin(token, db)
    result = await generate_monthly_invoices(db)
    return {"message": "Invoice generation complete", **result}
