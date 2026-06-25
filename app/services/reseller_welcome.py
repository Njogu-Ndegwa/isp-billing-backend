"""Welcome message for newly-registered resellers.

On reseller signup we always create an in-app inbox message and, when the
reseller has a phone number on file, queue a welcome SMS via the existing
admin->reseller dispatch path. All work here is DB-only; the provider send
happens later in sms_dispatch.dispatch_admin_sms_messages with no session held.
"""

import logging
from typing import Optional

from sqlalchemy import select

from app.db.models import (
    MessagingSettings,
    ResellerInboxMessage,
    SmsMessage, SmsMessageKind, SmsMessageStatus,
    User, UserRole,
)
from app.services.messaging import count_segments

logger = logging.getLogger(__name__)

WELCOME_CATEGORY = "reseller_welcome"

DEFAULT_WELCOME_SUBJECT = "Welcome to Bitwave Technologies"
DEFAULT_WELCOME_BODY = (
    "Welcome to Bitwave Technologies, {org}! Your reseller account is ready. "
    "Need help adding your first router? We'll set it up for you for FREE - "
    "just call us on {support_phone}. Log in any time to get started."
)
# Default contact number rendered into {support_phone} when the admin has not
# configured one in messaging settings. Editable via welcome_support_phone.
DEFAULT_WELCOME_SUPPORT_PHONE = "+254795635364"


def effective_welcome_settings(settings_row: Optional[MessagingSettings]) -> dict:
    """Resolve welcome settings, applying code defaults for null/missing fields."""
    enabled = True
    subject = DEFAULT_WELCOME_SUBJECT
    body = DEFAULT_WELCOME_BODY
    support_phone = DEFAULT_WELCOME_SUPPORT_PHONE
    if settings_row is not None:
        if settings_row.welcome_enabled is not None:
            enabled = settings_row.welcome_enabled
        if settings_row.welcome_subject:
            subject = settings_row.welcome_subject
        if settings_row.welcome_message_body:
            body = settings_row.welcome_message_body
        support_phone = settings_row.welcome_support_phone or DEFAULT_WELCOME_SUPPORT_PHONE
    return {"enabled": enabled, "subject": subject, "body": body,
            "support_phone": support_phone}


def render_welcome_body(body_template: str, *, org: str,
                        support_phone: Optional[str]) -> str:
    """Substitute {org} and {support_phone}; never leak a literal placeholder."""
    phone = support_phone or DEFAULT_WELCOME_SUPPORT_PHONE
    out = body_template.replace("{org}", org or "there")
    out = out.replace("{support_phone}", phone)
    return out


async def _resolve_sender_admin_id(db, reseller: User) -> Optional[int]:
    """Pick an admin user id to attribute the inbox message to."""
    if reseller.created_by:
        admin = (await db.execute(
            select(User.id).where(User.id == reseller.created_by,
                                  User.role == UserRole.ADMIN)
        )).scalar_one_or_none()
        if admin is not None:
            return admin
    return (await db.execute(
        select(User.id).where(User.role == UserRole.ADMIN)
        .order_by(User.id).limit(1)
    )).scalar_one_or_none()


async def queue_reseller_welcome(db, reseller: User) -> list[int]:
    """Create welcome inbox + optional SMS rows. DB-only; caller commits.

    Returns ids of QUEUED SmsMessage rows to hand to the dispatcher.
    """
    settings_row = await db.get(MessagingSettings, 1)
    cfg = effective_welcome_settings(settings_row)
    if not cfg["enabled"]:
        return []

    body = render_welcome_body(cfg["body"], org=reseller.organization_name,
                               support_phone=cfg["support_phone"])

    phone = (reseller.support_phone or "").strip()
    messaging_enabled = bool(settings_row.enabled) if settings_row else True
    send_sms = bool(phone) and messaging_enabled

    sender_admin_id = await _resolve_sender_admin_id(db, reseller)
    if sender_admin_id is not None:
        db.add(ResellerInboxMessage(
            recipient_user_id=reseller.id,
            sender_user_id=sender_admin_id,
            subject=cfg["subject"],
            body=body,
            sent_sms=send_sms,
        ))
    else:
        logger.warning(
            "No admin user found; skipping welcome inbox for reseller %s",
            reseller.id)

    sms_ids: list[int] = []
    if send_sms:
        segments = count_segments(body)
        row = SmsMessage(
            user_id=reseller.id,
            recipient_phone=phone,
            body=body,
            segments=segments,
            credits_charged=segments,
            kind=SmsMessageKind.ADMIN_TO_RESELLER,
            category=WELCOME_CATEGORY,
            status=SmsMessageStatus.QUEUED,
        )
        db.add(row)
        await db.flush()
        sms_ids.append(row.id)

    return sms_ids
