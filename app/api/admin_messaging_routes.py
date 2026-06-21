import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    User, UserRole, MessagingSettings, SmsCreditOrder, ResellerInboxMessage,
)
from app.services.auth import verify_token, get_current_user
from app.services import sms_credits
from app.services.messaging import default_sender_id, get_provider

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
    s = await db.get(MessagingSettings, 1) or MessagingSettings(id=1)
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
    recipient: str = Field(..., description='reseller id (as string) or "all"')
    subject: Optional[str] = Field(None, max_length=200)
    body: str = Field(..., min_length=1, max_length=2000)
    also_sms: bool = False


@router.post("/api/admin/messaging/inbox")
async def send_inbox(req: InboxSendIn, background: BackgroundTasks,
                     db: AsyncSession = Depends(get_db),
                     token: str = Depends(verify_token)):
    admin = await _require_admin(token, db)
    if req.recipient == "all":
        resellers = (await db.execute(
            select(User).where(User.role == UserRole.RESELLER)
        )).scalars().all()
    else:
        try:
            rid = int(req.recipient)
        except ValueError:
            raise HTTPException(status_code=400, detail="recipient must be id or 'all'")
        resellers = (await db.execute(
            select(User).where(User.id == rid, User.role == UserRole.RESELLER)
        )).scalars().all()
        if not resellers:
            raise HTTPException(status_code=404, detail="Reseller not found")

    broadcast_id = str(uuid.uuid4()) if req.recipient == "all" else None
    targets = []
    for r in resellers:
        db.add(ResellerInboxMessage(
            recipient_user_id=r.id, sender_user_id=admin.id, subject=req.subject,
            body=req.body, sent_sms=req.also_sms, broadcast_id=broadcast_id))
        if req.also_sms and r.support_phone:
            targets.append(r.support_phone)

    # Honor the admin-configured sender id (same fallback the reseller send
    # path uses), not just the env default.
    settings_row = await db.get(MessagingSettings, 1)
    sender_id = (settings_row.sender_id if settings_row and settings_row.sender_id
                 else default_sender_id())
    await db.commit()

    if req.also_sms and targets:
        background.add_task(_send_admin_sms, targets, req.body, sender_id)

    return {"message": "Inbox message sent", "recipients": len(resellers)}


async def _send_admin_sms(phones: list[str], body: str, sender_id: str):
    """Admin->reseller SMS. Platform cost, no reseller credit deduction.
    No DB session is held across the provider call."""
    try:
        provider = get_provider()
        await provider.send_bulk(phones, body, sender_id)
    except Exception as e:
        logger.error("Admin SMS send failed: %s", e)
