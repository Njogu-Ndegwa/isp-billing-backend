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
    MessagingSettings, MessageTemplate, CustomerExpirySmsSettings,
    SmsCreditOrder, SmsCreditOrderStatus, SmsCreditTxnKind, SmsCreditTransaction,
    SmsCampaign, SmsCampaignStatus, SmsMessage, SmsMessageStatus, SmsMessageKind,
    ResellerInboxMessage, Customer,
)
from app.services.auth import verify_token, get_current_user
from app.services import customer_expiry_notifications, sms_credits, sms_dispatch
from app.services import customer_sms_templates as sms_templates
from app.services.markets import reseller_market
from app.services.messaging import accounts as provider_accounts
from app.services.messaging import count_segments, gateway_health, resolve_sender_id
from app.services.messaging.failure_reasons import describe as describe_failure
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
    # Which gateway this reseller sends on, and therefore whether portal
    # credits apply at all. Without this the Credits screen would quote a
    # price per SMS to someone who is not being charged per SMS.
    gateway = await provider_accounts.gateway_summary(db, user.id)
    return {
        "balance": acct.balance,
        "total_purchased": acct.total_purchased,
        "total_spent": acct.total_spent,
        "price_per_sms_kes": float(s.price_per_sms_kes),
        "min_purchase_credits": s.min_purchase_credits,
        "bundles": s.bundles or [],
        "enabled": s.enabled,
        "gateway": gateway,
        "bills_platform_credits": gateway["bills_platform_credits"],
    }


@router.get("/api/messaging/gateway/status")
async def get_gateway_status(refresh: bool = Query(False),
                             db: AsyncSession = Depends(get_db),
                             token: str = Depends(verify_token)):
    """Is SMS going out, and if not, why — plus the own gateway's live balance.

    `refresh=true` skips the ~60 s balance cache (the "check now" button).
    """
    user = await _require_reseller(token, db)
    return await gateway_health.status(db, user.id, force_balance=refresh)


# ---- Automatic expiry reminders -----------------------------------------

class ExpirySettingsIn(BaseModel):
    enabled: bool
    reminder_offsets_minutes: list[int]
    send_at_expiry: bool


def _expiry_settings_payload(row: CustomerExpirySmsSettings) -> dict:
    return {
        "enabled": row.enabled,
        "reminder_offsets_minutes": row.reminder_offsets_minutes or [],
        "send_at_expiry": row.send_at_expiry,
    }


@router.get("/api/messaging/expiry-settings")
async def get_expiry_settings(db: AsyncSession = Depends(get_db),
                              token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    row = await db.get(CustomerExpirySmsSettings, user.id)
    if row is None:
        row = CustomerExpirySmsSettings(
            user_id=user.id,
            reminder_offsets_minutes=list(
                customer_expiry_notifications.DEFAULT_REMINDER_OFFSETS_MINUTES
            ),
        )
        db.add(row)
        await db.flush()
    return _expiry_settings_payload(row)


@router.put("/api/messaging/expiry-settings")
async def update_expiry_settings(body: ExpirySettingsIn,
                                 db: AsyncSession = Depends(get_db),
                                 token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    offsets = sorted(set(body.reminder_offsets_minutes), reverse=True)
    if body.enabled and not offsets:
        raise HTTPException(
            status_code=400,
            detail="Choose at least one reminder time before expiry",
        )
    if len(offsets) > customer_expiry_notifications.MAX_REMINDER_OFFSETS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Choose no more than "
                f"{customer_expiry_notifications.MAX_REMINDER_OFFSETS} reminder times"
            ),
        )
    invalid = [
        value for value in offsets
        if value < customer_expiry_notifications.MIN_REMINDER_OFFSET_MINUTES
        or value > customer_expiry_notifications.MAX_REMINDER_OFFSET_MINUTES
    ]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=(
                "Reminder times must be between 30 minutes and 30 days "
                "before expiry"
            ),
        )

    row = await db.get(CustomerExpirySmsSettings, user.id)
    if row is None:
        row = CustomerExpirySmsSettings(user_id=user.id)
        db.add(row)
    row.enabled = body.enabled
    row.reminder_offsets_minutes = offsets
    row.send_at_expiry = body.send_at_expiry
    await db.commit()
    await db.refresh(row)
    return _expiry_settings_payload(row)


# ---- Customer event messages and message wording --------------------------

class CustomerEventSettingsIn(BaseModel):
    payment_receipt_enabled: bool
    receipt_include_hotspot: bool
    welcome_enabled: bool
    # {event: text}; null or "" restores the built-in wording.
    templates: dict[str, Optional[str]] = Field(default_factory=dict)


class TemplatePreviewIn(BaseModel):
    event: str
    body: Optional[str] = None


def _customer_event_payload(row: CustomerExpirySmsSettings) -> dict:
    saved = row.custom_templates if isinstance(row.custom_templates, dict) else {}
    return {
        "payment_receipt_enabled": bool(row.payment_receipt_enabled),
        "receipt_include_hotspot": bool(row.receipt_include_hotspot),
        "welcome_enabled": bool(row.welcome_enabled),
        "templates": {
            event: sms_templates.custom_template(saved, event)
            for event in sms_templates.EVENTS
        },
        "defaults": dict(sms_templates.DEFAULT_TEMPLATE_TEXT),
        "placeholders": {
            event: list(names)
            for event, names in sms_templates.EVENT_PLACEHOLDERS.items()
        },
        "max_length": sms_templates.MAX_TEMPLATE_LENGTH,
    }


@router.get("/api/messaging/customer-events")
async def get_customer_event_settings(db: AsyncSession = Depends(get_db),
                                      token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    row = await db.get(CustomerExpirySmsSettings, user.id)
    if row is None:
        # Not persisted: a GET must not create settings rows.
        row = CustomerExpirySmsSettings(
            user_id=user.id,
            payment_receipt_enabled=False,
            receipt_include_hotspot=False,
            welcome_enabled=False,
            custom_templates=None,
        )
    return _customer_event_payload(row)


@router.put("/api/messaging/customer-events")
async def update_customer_event_settings(body: CustomerEventSettingsIn,
                                         db: AsyncSession = Depends(get_db),
                                         token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    cleaned: dict[str, str] = {}
    for event, text in body.templates.items():
        if event not in sms_templates.EVENT_PLACEHOLDERS:
            raise HTTPException(status_code=400, detail=f"Unknown message type '{event}'")
        if text is None or not text.strip():
            continue
        error = sms_templates.validate_template(event, text)
        if error:
            raise HTTPException(status_code=400, detail=error)
        cleaned[event] = text.strip()

    row = await db.get(CustomerExpirySmsSettings, user.id)
    if row is None:
        row = CustomerExpirySmsSettings(
            user_id=user.id,
            reminder_offsets_minutes=list(
                customer_expiry_notifications.DEFAULT_REMINDER_OFFSETS_MINUTES
            ),
        )
        db.add(row)
    row.payment_receipt_enabled = body.payment_receipt_enabled
    row.receipt_include_hotspot = body.receipt_include_hotspot
    row.welcome_enabled = body.welcome_enabled
    row.custom_templates = cleaned or None
    await db.commit()
    await db.refresh(row)
    return _customer_event_payload(row)


@router.post("/api/messaging/customer-events/preview")
async def preview_customer_event_message(body: TemplatePreviewIn,
                                         db: AsyncSession = Depends(get_db),
                                         token: str = Depends(verify_token)):
    """Render a message with sample customer data, as the customer would see it."""
    user = await _require_reseller(token, db)
    if body.event not in sms_templates.EVENT_PLACEHOLDERS:
        raise HTTPException(status_code=400, detail=f"Unknown message type '{body.event}'")
    custom = (body.body or "").strip()
    if custom:
        error = sms_templates.validate_template(body.event, custom)
        if error:
            raise HTTPException(status_code=400, detail=error)

    market = reseller_market(user)
    context = {**sms_templates.SAMPLE_CONTEXT, "brand": sms_templates.brand_name(user)}
    context["amount"] = sms_templates.format_amount(1500, market.currency)
    if market.code != "KE":
        context["paybill"] = ""
        context["account"] = ""
    text = sms_templates.render(
        body.event, context, {body.event: custom} if custom else None
    )
    return {"text": text, "characters": len(text), "segments": count_segments(text)}


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


@router.get("/api/messaging/credits/ledger")
async def credit_ledger(limit: int = Query(50, ge=1, le=200),
                        offset: int = Query(0, ge=0),
                        db: AsyncSession = Depends(get_db),
                        token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    rows = (await db.execute(
        select(SmsCreditTransaction)
        .where(SmsCreditTransaction.user_id == user.id)
        .order_by(SmsCreditTransaction.created_at.desc(),
                  SmsCreditTransaction.id.desc())
        .limit(limit).offset(offset)
    )).scalars().all()
    return {"transactions": [{
        "id": t.id,
        "kind": t.kind.value if hasattr(t.kind, "value") else t.kind,
        "change": t.change, "balance_after": t.balance_after,
        "reference": t.reference, "note": t.note,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    } for t in rows]}


# ---- Recipients + send ----------------------------------------------------

@router.get("/api/messaging/recipients")
async def list_recipients(filter: str = Query("all"),
                          plan_id: Optional[int] = None,
                          search: Optional[str] = None,
                          exclude_customer_ids: Optional[str] = Query(None),
                          limit: int = Query(50, ge=1, le=500),
                          offset: int = Query(0, ge=0),
                          db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    exclude = [int(x) for x in exclude_customer_ids.split(",") if x.strip().isdigit()] \
        if exclude_customer_ids else None
    recips = await sms_dispatch.resolve_recipients(
        db, user.id, filter=filter, plan_id=plan_id, search=search,
        exclude_customer_ids=exclude)
    page = recips[offset:offset + limit]
    return {"count": len(recips), "recipients": page,
            "has_more": offset + limit < len(recips)}


class SendRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=1000)
    filter: str = "all"
    plan_id: Optional[int] = None
    customer_ids: Optional[list[int]] = None
    exclude_customer_ids: Optional[list[int]] = None
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
        customer_ids=req.customer_ids,
        exclude_customer_ids=req.exclude_customer_ids)
    if not recips:
        raise HTTPException(status_code=400, detail="No recipients matched")

    segments = count_segments(req.body)
    # Portal credits are resale of the platform's own SMS. A reseller on their
    # own gateway already pays their vendor for this message, so it costs them
    # nothing here and the balance gate does not apply.
    bills_credits = await provider_accounts.bills_platform_credits(db, user.id)
    per_message_credits = segments if bills_credits else 0
    total = per_message_credits * len(recips)
    if bills_credits:
        acct = await sms_credits.get_or_create_account(db, user.id)
        if acct.balance < total:
            raise HTTPException(status_code=400, detail={
                "message": "Insufficient SMS credits",
                "required": total, "balance": acct.balance,
                "shortfall": total - acct.balance,
            })

    # Stamp the sender ID of the gateway that will actually carry this
    # campaign — a reseller on their own gateway has their own approved
    # sender ID, and the platform's would be rejected by it.
    sender_id = await provider_accounts.resolve_sender_id_for(
        db, user.id, s.sender_id
    )
    camp = SmsCampaign(user_id=user.id, body=req.body, recipient_count=len(recips),
                       segments_per_message=segments, total_credits=total,
                       sender_id=sender_id, status=SmsCampaignStatus.QUEUED)
    db.add(camp)
    await db.flush()
    if bills_credits:
        # Reserve credits with the campaign id as the ledger reference, so the
        # send_debit and any later refunds share one reference for clean auditing.
        ok = await sms_credits.try_deduct(db, user.id, total,
                                          reference=f"campaign:{camp.id}")
        if not ok:
            raise HTTPException(status_code=400, detail="Insufficient SMS credits")
    for r in recips:
        db.add(SmsMessage(campaign_id=camp.id, user_id=user.id,
                          customer_id=r["customer_id"], recipient_phone=r["phone"],
                          body=req.body, segments=segments,
                          credits_charged=per_message_credits,
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
    rows = (await db.execute(
        select(SmsMessage, Customer.name)
        .outerjoin(Customer, (SmsMessage.customer_id == Customer.id) & (Customer.user_id == user.id))
        .where(SmsMessage.campaign_id == campaign_id).limit(2000)
    )).all()
    # Which of these rows went out on the reseller's own gateway decides who a
    # failure reason addresses: them (fix your key) or us (platform problem).
    own_accounts = {
        a.id: a.provider
        for a in await provider_accounts.list_accounts(db, user.id)
    }
    counts = {"total": 0, "sent": 0, "failed": 0, "queued": 0, "delivered": 0}
    messages = []
    by_reason: dict[str, dict] = {}
    for m, name in rows:
        st = m.status.value if hasattr(m.status, "value") else m.status
        counts["total"] += 1
        if st in counts:
            counts[st] += 1
        reason = None
        if st == "failed":
            own_provider = own_accounts.get(m.provider_account_id)
            reason = describe_failure(
                m.error, own_gateway=own_provider is not None,
                provider_label=gateway_health.provider_label(own_provider),
            )
            summary = by_reason.setdefault(reason["code"], {
                k: reason[k] for k in ("code", "title", "explanation", "action", "severity")
            } | {"count": 0})
            summary["count"] += 1
        messages.append({"phone": m.recipient_phone, "name": name,
                         "status": st, "error": m.error, "reason": reason})
    return {"id": camp.id,
            "status": camp.status.value if hasattr(camp.status, "value") else camp.status,
            "counts": counts, "messages": messages,
            "failure_reasons": sorted(by_reason.values(), key=lambda r: -r["count"])}


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
