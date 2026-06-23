import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    User, UserRole, MessagingSettings, SmsCreditOrder, ResellerInboxMessage,
    SmsMessage, SmsMessageKind, SmsMessageStatus,
)
from app.services.auth import verify_token, get_current_user
from app.services import sms_credits, sms_dispatch
from app.services.messaging import count_segments, resolve_sender_id

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-messaging"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


class SettingsIn(BaseModel):
    price_per_sms_kes: Optional[float] = None
    min_purchase_credits: Optional[int] = None
    sender_id: Optional[str] = None
    enabled: Optional[bool] = None
    message_retention_days: Optional[int] = None
    bundles: Optional[list] = None


@router.get("/api/admin/messaging/settings")
async def get_settings(db: AsyncSession = Depends(get_db),
                       token: str = Depends(verify_token)):
    await _require_admin(token, db)
    s = await db.get(MessagingSettings, 1)
    if s is None:
        s = MessagingSettings(id=1)
        db.add(s)
        await db.flush()
    return {
        "price_per_sms_kes": float(s.price_per_sms_kes),
        "min_purchase_credits": s.min_purchase_credits,
        "sender_id": s.sender_id,
        "enabled": s.enabled,
        "message_retention_days": s.message_retention_days,
        "bundles": s.bundles or [],
    }


@router.put("/api/admin/messaging/settings")
async def update_settings(body: SettingsIn, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    await _require_admin(token, db)
    s = await db.get(MessagingSettings, 1)
    if s is None:
        s = MessagingSettings(id=1)
        db.add(s)
    if body.price_per_sms_kes is not None:
        s.price_per_sms_kes = body.price_per_sms_kes
    if body.min_purchase_credits is not None:
        s.min_purchase_credits = body.min_purchase_credits
    if body.sender_id is not None:
        s.sender_id = body.sender_id or None
    if body.enabled is not None:
        s.enabled = body.enabled
    if body.message_retention_days is not None:
        s.message_retention_days = body.message_retention_days
    if body.bundles is not None:
        s.bundles = body.bundles
    await db.commit()
    return {"message": "Settings updated"}


@router.get("/api/admin/messaging/credits/orders")
async def list_orders(db: AsyncSession = Depends(get_db),
                      token: str = Depends(verify_token)):
    await _require_admin(token, db)
    rows = (await db.execute(
        select(SmsCreditOrder).order_by(SmsCreditOrder.created_at.desc()).limit(200)
    )).scalars().all()
    return {"orders": [{
        "id": o.id, "user_id": o.user_id, "quantity": o.quantity,
        "amount": o.amount,
        "status": o.status.value if hasattr(o.status, "value") else o.status,
        "payment_reference": o.payment_reference,
        "created_at": o.created_at.isoformat() if o.created_at else None,
    } for o in rows]}


class AdjustIn(BaseModel):
    delta: int
    note: Optional[str] = None


@router.post("/api/admin/messaging/resellers/{reseller_id}/credits/adjust")
async def adjust_credits(reseller_id: int, body: AdjustIn,
                         db: AsyncSession = Depends(get_db),
                         token: str = Depends(verify_token)):
    await _require_admin(token, db)
    reseller = (await db.execute(
        select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
    )).scalar_one_or_none()
    if not reseller:
        raise HTTPException(status_code=404, detail="Reseller not found")
    new_balance = await sms_credits.adjust(db, reseller_id, body.delta, note=body.note)
    await db.commit()
    return {"reseller_id": reseller_id, "balance": new_balance}


class InboxSendIn(BaseModel):
    reseller_ids: Optional[list[int]] = None
    all_resellers: bool = False
    subject: Optional[str] = Field(None, max_length=200)
    body: str = Field(..., min_length=1, max_length=2000)
    also_sms: bool = False


@router.post("/api/admin/messaging/inbox")
async def send_inbox(req: InboxSendIn, background: BackgroundTasks,
                     db: AsyncSession = Depends(get_db),
                     token: str = Depends(verify_token)):
    admin = await _require_admin(token, db)
    if req.all_resellers:
        resellers = (await db.execute(
            select(User).where(User.role == UserRole.RESELLER))).scalars().all()
    elif req.reseller_ids:
        resellers = (await db.execute(
            select(User).where(User.id.in_(req.reseller_ids),
                               User.role == UserRole.RESELLER))).scalars().all()
        if not resellers:
            raise HTTPException(status_code=404, detail="No matching resellers")
    else:
        raise HTTPException(status_code=400,
                            detail="Select resellers or choose all")
    broadcast_id = str(uuid.uuid4()) if req.all_resellers else None
    sms_rows: list[SmsMessage] = []
    segments = count_segments(req.body) if req.also_sms else 0
    for r in resellers:
        db.add(ResellerInboxMessage(
            recipient_user_id=r.id, sender_user_id=admin.id, subject=req.subject,
            body=req.body, sent_sms=req.also_sms, broadcast_id=broadcast_id))
        phone = (r.support_phone or "").strip()
        if req.also_sms and phone:
            row = SmsMessage(
                user_id=r.id,
                recipient_phone=phone,
                body=req.body,
                segments=segments,
                credits_charged=segments,
                kind=SmsMessageKind.ADMIN_TO_RESELLER,
                status=SmsMessageStatus.QUEUED,
            )
            db.add(row)
            sms_rows.append(row)

    # Resolve sender the same way the reseller send path does; SMS_SENDER_ID is
    # an operational override for provider migrations.
    settings_row = await db.get(MessagingSettings, 1)
    sender_id = resolve_sender_id(
        settings_row.sender_id if settings_row and settings_row.sender_id else None
    )
    await db.flush()
    sms_message_ids = [row.id for row in sms_rows]
    await db.commit()

    if sms_message_ids:
        background.add_task(sms_dispatch.dispatch_admin_sms_messages,
                            sms_message_ids, sender_id)

    return {
        "message": "Inbox message sent",
        "recipients": len(resellers),
        "sms_queued": len(sms_message_ids),
        "sms_skipped_no_phone": (len(resellers) - len(sms_message_ids)
                                 if req.also_sms else 0),
    }


@router.get("/api/admin/messaging/sms")
async def list_admin_sms(limit: int = Query(100, ge=1, le=500),
                         db: AsyncSession = Depends(get_db),
                         token: str = Depends(verify_token)):
    await _require_admin(token, db)
    kind = SmsMessageKind.ADMIN_TO_RESELLER

    count_rows = (await db.execute(
        select(SmsMessage.status, func.count(SmsMessage.id))
        .where(SmsMessage.kind == kind)
        .group_by(SmsMessage.status)
    )).all()
    summary = {status.value: 0 for status in SmsMessageStatus}
    for status, count in count_rows:
        key = status.value if hasattr(status, "value") else status
        summary[key] = count

    rows = (await db.execute(
        select(SmsMessage, User)
        .join(User, SmsMessage.user_id == User.id)
        .where(SmsMessage.kind == kind)
        .order_by(SmsMessage.created_at.desc())
        .limit(limit)
    )).all()

    return {
        "summary": summary,
        "messages": [{
            "id": m.id,
            "reseller_id": r.id,
            "reseller_name": r.organization_name or r.email,
            "phone": m.recipient_phone,
            "body": m.body,
            "segments": m.segments,
            "credits_charged": m.credits_charged,
            "provider": m.provider,
            "provider_message_id": m.provider_message_id,
            "status": m.status.value if hasattr(m.status, "value") else m.status,
            "error": m.error,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "updated_at": m.updated_at.isoformat() if m.updated_at else None,
        } for m, r in rows],
    }
