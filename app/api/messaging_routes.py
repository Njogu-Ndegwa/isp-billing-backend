import logging
import math
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.database import get_db
from app.db.models import (
    User, UserRole,
    MessagingSettings, MessageTemplate,
    SmsCreditOrder, SmsCreditOrderStatus, SmsCreditTxnKind,
    SmsCampaign, SmsCampaignStatus, SmsMessage, SmsMessageStatus, SmsMessageKind,
    ResellerInboxMessage,
)
from app.services.auth import verify_token, get_current_user
from app.services import sms_credits, sms_dispatch
from app.services.messaging import count_segments
from app.services.mpesa import initiate_stk_push_direct

logger = logging.getLogger(__name__)
router = APIRouter(tags=["messaging"])


async def _require_reseller(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Resellers only")
    return user


async def _get_settings(db: AsyncSession) -> MessagingSettings:
    s = await db.get(MessagingSettings, 1)
    if s is None:
        s = MessagingSettings(id=1)
        db.add(s)
        await db.flush()
    return s


# ---- Credits --------------------------------------------------------------

@router.get("/api/messaging/credits")
async def get_credits(db: AsyncSession = Depends(get_db),
                      token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    acct = await sms_credits.get_or_create_account(db, user.id)
    s = await _get_settings(db)
    return {
        "balance": acct.balance,
        "total_purchased": acct.total_purchased,
        "total_spent": acct.total_spent,
        "price_per_sms_kes": float(s.price_per_sms_kes),
        "min_purchase_credits": s.min_purchase_credits,
        "bundles": s.bundles or [],
        "enabled": s.enabled,
    }


class PurchaseRequest(BaseModel):
    quantity: int = Field(..., ge=1)
    phone_number: str


@router.post("/api/messaging/credits/purchase")
async def purchase_credits(req: PurchaseRequest,
                           db: AsyncSession = Depends(get_db),
                           token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    s = await _get_settings(db)
    if not s.enabled:
        raise HTTPException(status_code=400, detail="Messaging is disabled")
    if req.quantity < s.min_purchase_credits:
        raise HTTPException(status_code=400,
                            detail=f"Minimum purchase is {s.min_purchase_credits} credits")
    unit_price = float(s.price_per_sms_kes)
    amount = math.ceil(req.quantity * unit_price)
    if amount < 1:
        raise HTTPException(status_code=400, detail="Computed amount too small")

    phone = req.phone_number.strip()
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    elif phone.startswith("+"):
        phone = phone[1:]

    order = SmsCreditOrder(user_id=user.id, quantity=req.quantity,
                           unit_price=s.price_per_sms_kes, amount=amount,
                           phone_number=phone, status=SmsCreditOrderStatus.PENDING)
    db.add(order)
    await db.flush()

    callback_url = settings.MPESA_CALLBACK_URL.rstrip("/")
    if "/api/mpesa/callback" in callback_url:
        callback_url = callback_url.replace("/api/mpesa/callback",
                                            "/api/messaging/credits/mpesa/callback")
    else:
        callback_url = callback_url + "/api/messaging/credits/mpesa/callback"

    try:
        stk = await initiate_stk_push_direct(
            phone_number=phone, amount=amount, reference=f"SMS-{order.id}",
            callback_url=callback_url, account_reference="SMS Credits",
        )
    except Exception as e:
        order.status = SmsCreditOrderStatus.FAILED
        await db.commit()
        raise HTTPException(status_code=502, detail=f"STK push failed: {e}")

    if stk:
        order.mpesa_checkout_request_id = stk.checkout_request_id
        order.mpesa_merchant_request_id = stk.merchant_request_id
    else:
        # Provider returned no response object — no checkout id will ever
        # match a callback, so fail the order now rather than leave it PENDING.
        order.status = SmsCreditOrderStatus.FAILED
        await db.commit()
        raise HTTPException(status_code=502, detail="STK push returned no response")
    await db.commit()
    return {
        "message": "STK push sent. Confirm on your phone.",
        "order_id": order.id,
        "quantity": order.quantity,
        "amount": amount,
        "checkout_request_id": stk.checkout_request_id,
    }


@router.post("/api/messaging/credits/mpesa/callback")
async def credits_callback(request: Request, db: AsyncSession = Depends(get_db)):
    # Always ack with ResultCode 0 — any non-2xx makes Safaricom retry. Errors
    # are logged and swallowed, mirroring subscription_mpesa_callback.
    try:
        body = await request.json()
        cb = body.get("Body", {}).get("stkCallback", {})
        checkout_id = cb.get("CheckoutRequestID")
        # Safaricom usually sends ResultCode as an int, but coerce defensively
        # (a string "0" otherwise silently skips the grant).
        try:
            result_code = int(cb.get("ResultCode"))
        except (TypeError, ValueError):
            result_code = -1
        if not checkout_id:
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        order = (await db.execute(
            select(SmsCreditOrder).where(
                SmsCreditOrder.mpesa_checkout_request_id == checkout_id)
        )).scalar_one_or_none()
        if not order or order.status != SmsCreditOrderStatus.PENDING:
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        if result_code == 0:
            receipt = None
            for item in cb.get("CallbackMetadata", {}).get("Item", []):
                if item.get("Name") == "MpesaReceiptNumber":
                    receipt = item.get("Value")
            order.status = SmsCreditOrderStatus.COMPLETED
            order.payment_reference = receipt
            await sms_credits.grant(db, order.user_id, order.quantity,
                                    SmsCreditTxnKind.PURCHASE,
                                    reference=f"SMS-{order.id}")
            logger.info("SMS credits granted: order %s, qty %s", order.id, order.quantity)
        else:
            order.status = SmsCreditOrderStatus.FAILED
        await db.commit()
    except Exception:
        logger.exception("SMS credits callback error")
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


# ---- Recipients + send ----------------------------------------------------

@router.get("/api/messaging/recipients")
async def list_recipients(filter: str = Query("all"),
                          plan_id: Optional[int] = None,
                          db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    recips = await sms_dispatch.resolve_recipients(db, user.id, filter=filter,
                                                   plan_id=plan_id)
    return {"count": len(recips), "recipients": recips}


class SendRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=1000)
    filter: str = "all"
    plan_id: Optional[int] = None
    customer_ids: Optional[list[int]] = None
    template_id: Optional[int] = None


@router.post("/api/messaging/send")
async def send_messages(req: SendRequest, background: BackgroundTasks,
                        db: AsyncSession = Depends(get_db),
                        token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    s = await _get_settings(db)
    if not s.enabled:
        raise HTTPException(status_code=400, detail="Messaging is disabled")

    recips = await sms_dispatch.resolve_recipients(
        db, user.id, filter=req.filter, plan_id=req.plan_id,
        customer_ids=req.customer_ids)
    if not recips:
        raise HTTPException(status_code=400, detail="No recipients matched")

    segments = count_segments(req.body)
    total = segments * len(recips)
    acct = await sms_credits.get_or_create_account(db, user.id)
    if acct.balance < total:
        raise HTTPException(status_code=400, detail={
            "message": "Insufficient SMS credits",
            "required": total, "balance": acct.balance,
            "shortfall": total - acct.balance,
        })

    sender_id = s.sender_id or settings.AT_SENDER_ID
    camp = SmsCampaign(user_id=user.id, body=req.body, recipient_count=len(recips),
                       segments_per_message=segments, total_credits=total,
                       sender_id=sender_id, status=SmsCampaignStatus.QUEUED)
    db.add(camp)
    await db.flush()
    # Reserve credits with the campaign id as the ledger reference, so the
    # send_debit and any later refunds share one reference for clean auditing.
    ok = await sms_credits.try_deduct(db, user.id, total,
                                      reference=f"campaign:{camp.id}")
    if not ok:
        raise HTTPException(status_code=400, detail="Insufficient SMS credits")
    for r in recips:
        db.add(SmsMessage(campaign_id=camp.id, user_id=user.id,
                          customer_id=r["customer_id"], recipient_phone=r["phone"],
                          body=req.body, segments=segments, credits_charged=segments,
                          kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
                          status=SmsMessageStatus.QUEUED))
    await db.commit()
    campaign_id = camp.id

    background.add_task(sms_dispatch.dispatch_campaign, campaign_id)
    return {"message": "Send queued", "campaign_id": campaign_id,
            "recipient_count": len(recips), "segments": segments,
            "credits_reserved": total}


# ---- Templates ------------------------------------------------------------

class TemplateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    body: str = Field(..., min_length=1, max_length=1000)


@router.get("/api/messaging/templates")
async def list_templates(db: AsyncSession = Depends(get_db),
                         token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    rows = (await db.execute(
        select(MessageTemplate).where(MessageTemplate.user_id == user.id)
        .order_by(MessageTemplate.created_at.desc())
    )).scalars().all()
    return {"templates": [{"id": t.id, "name": t.name, "body": t.body} for t in rows]}


@router.post("/api/messaging/templates")
async def create_template(t: TemplateIn, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    tpl = MessageTemplate(user_id=user.id, name=t.name, body=t.body)
    db.add(tpl)
    await db.commit()
    await db.refresh(tpl)
    return {"id": tpl.id, "name": tpl.name, "body": tpl.body}


@router.delete("/api/messaging/templates/{template_id}")
async def delete_template(template_id: int, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    tpl = (await db.execute(
        select(MessageTemplate).where(MessageTemplate.id == template_id,
                                      MessageTemplate.user_id == user.id)
    )).scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    await db.delete(tpl)
    await db.commit()
    return {"deleted": template_id}


# ---- Campaign history -----------------------------------------------------

@router.get("/api/messaging/campaigns")
async def list_campaigns(db: AsyncSession = Depends(get_db),
                         token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    rows = (await db.execute(
        select(SmsCampaign).where(SmsCampaign.user_id == user.id)
        .order_by(SmsCampaign.created_at.desc()).limit(100)
    )).scalars().all()
    return {"campaigns": [{
        "id": c.id, "body": c.body, "recipient_count": c.recipient_count,
        "segments_per_message": c.segments_per_message, "total_credits": c.total_credits,
        "sent_count": c.sent_count, "failed_count": c.failed_count,
        "refunded_credits": c.refunded_credits,
        "status": c.status.value if hasattr(c.status, "value") else c.status,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    } for c in rows]}


@router.get("/api/messaging/campaigns/{campaign_id}")
async def campaign_detail(campaign_id: int, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    camp = (await db.execute(
        select(SmsCampaign).where(SmsCampaign.id == campaign_id,
                                  SmsCampaign.user_id == user.id)
    )).scalar_one_or_none()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    msgs = (await db.execute(
        select(SmsMessage).where(SmsMessage.campaign_id == campaign_id).limit(2000)
    )).scalars().all()
    return {
        "id": camp.id,
        "status": camp.status.value if hasattr(camp.status, "value") else camp.status,
        "messages": [{
            "phone": m.recipient_phone,
            "status": m.status.value if hasattr(m.status, "value") else m.status,
            "error": m.error,
        } for m in msgs],
    }


# ---- Inbox (admin -> reseller) --------------------------------------------

@router.get("/api/messaging/inbox")
async def get_inbox(db: AsyncSession = Depends(get_db),
                    token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    rows = (await db.execute(
        select(ResellerInboxMessage)
        .where(ResellerInboxMessage.recipient_user_id == user.id)
        .order_by(ResellerInboxMessage.created_at.desc()).limit(100)
    )).scalars().all()
    unread = (await db.execute(
        select(func.count(ResellerInboxMessage.id)).where(
            ResellerInboxMessage.recipient_user_id == user.id,
            ResellerInboxMessage.is_read == False)  # noqa: E712
    )).scalar() or 0
    return {"unread": unread, "messages": [{
        "id": m.id, "subject": m.subject, "body": m.body, "is_read": m.is_read,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    } for m in rows]}


@router.post("/api/messaging/inbox/{message_id}/read")
async def mark_read(message_id: int, db: AsyncSession = Depends(get_db),
                    token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    msg = (await db.execute(
        select(ResellerInboxMessage).where(
            ResellerInboxMessage.id == message_id,
            ResellerInboxMessage.recipient_user_id == user.id)
    )).scalar_one_or_none()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    msg.is_read = True
    msg.read_at = datetime.utcnow()
    await db.commit()
    return {"id": message_id, "is_read": True}
