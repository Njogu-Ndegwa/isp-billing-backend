"""Audit trail + owner alert for every change to where a reseller's money goes.

Why this exists
---------------
Payment-method rows (``reseller_payment_methods``) decide the destination of a
reseller's daily B2B payout. Until now, editing one was silent and anonymous:
no actor was recorded and the account owner was never told. On 2026-06-11 a
reseller's real destination was deactivated, a third-party paybill was added,
and four days of payouts (KES 4,845) were aimed at it. Only Safaricom rejecting
the receiver as invalid kept the money from leaving. Nothing in the database
could say who made the change.

So: every create / edit / deactivate / reactivate of a payment method, and every
re-assignment of a router to a different method, now writes an append-only
``PayoutDestinationChangeLog`` row AND notifies the account owner (inbox +
SMS when they have a phone and credits).

Session discipline (AGENTS.md)
------------------------------
``record_and_notify`` opens its OWN short session and is called AFTER the
endpoint has committed its change, so the request's transaction is never held
open across the notification write. The provider SMS send is fire-and-forget
after that commit -- these are customer-facing request paths and must not wait
on the network. Never raises: an alert failure must not fail the edit the user
just made, because the audit row is the safety net, not the edit's validation.
"""

import logging
from typing import Optional

from app.config import settings
from app.db import database
from app.db.models import (
    MessagingSettings,
    PayoutDestinationAction,
    PayoutDestinationChangeLog,
    ResellerInboxMessage,
    ResellerPaymentMethod,
    SmsMessage, SmsMessageKind, SmsMessageStatus,
    User,
)
from app.services import sms_credits
from app.services.messaging import count_segments, resolve_sender_id
from app.services.reseller_welcome import _resolve_sender_admin_id
from app.services.router_status_alerts import _spawn_alert_sms_dispatch

logger = logging.getLogger(__name__)

ALERT_SMS_CATEGORY = "payout_destination_alert"

_ACTION_VERB = {
    PayoutDestinationAction.CREATED: "added",
    PayoutDestinationAction.UPDATED: "changed",
    PayoutDestinationAction.DEACTIVATED: "switched off",
    PayoutDestinationAction.REACTIVATED: "switched back on",
    PayoutDestinationAction.ROUTER_ASSIGNED: "re-pointed",
}


def describe_destination(pm: Optional[ResellerPaymentMethod]) -> str:
    """One-line, human-readable account number(s) for a payment method.

    Deliberately plain text, not JSON: it is read by a reseller in an SMS, and
    it is stored as a snapshot that must stay meaningful after the row changes.
    Never includes secrets -- only the publicly-visible destination numbers.
    """
    if pm is None:
        return "none"
    bits = []
    if pm.bank_paybill_number:
        acct = f" / acct {pm.bank_account_number}" if pm.bank_account_number else ""
        bits.append(f"paybill {pm.bank_paybill_number}{acct}")
    if pm.mpesa_paybill_number:
        bits.append(f"paybill {pm.mpesa_paybill_number}")
    if pm.mpesa_till_number:
        bits.append(f"till {pm.mpesa_till_number}")
    if pm.mpesa_shortcode:
        bits.append(f"shortcode {pm.mpesa_shortcode}")
    if not bits:
        # ZenoPay / MTN and any future type: no bare number to show.
        mt = getattr(pm.method_type, "value", pm.method_type)
        bits.append(str(mt))
    return ", ".join(bits)


def render_change_notification(
    action: PayoutDestinationAction,
    label: Optional[str],
    before: Optional[str],
    after: Optional[str],
    actor_is_owner: bool,
    actor_email: Optional[str] = None,
) -> tuple[str, str]:
    """Pure renderer -> (subject, body). No DB, so tests can assert on text."""
    verb = _ACTION_VERB.get(action, "changed")
    name = f"'{label}'" if label else "a payment method"
    subject = f"Payout account {verb}"

    lines = [f"Your payout destination was {verb} ({name})."]
    if action == PayoutDestinationAction.ROUTER_ASSIGNED:
        lines = [f"A router was {verb} to a different payout destination ({name})."]
    if before and after and before != after:
        lines.append(f"Was: {before}")
        lines.append(f"Now: {after}")
    elif after:
        lines.append(f"Destination: {after}")
    elif before:
        lines.append(f"Was: {before}")

    if not actor_is_owner:
        who = actor_email or "an administrator"
        lines.append(f"Made by: {who}")

    lines.append(
        "If this was not you, contact support immediately and change your "
        "password - anyone with your login can redirect your money."
    )
    return subject, "\n".join(lines)


async def _queue_alert_sms(db, owner: User, body: str,
                           log_ref: str) -> tuple[Optional[int], Optional[str]]:
    """Charge credits and add the QUEUED SMS row. Caller commits.

    Returns (None, None) on every skip path (dispatch off, messaging off, no
    phone, no credits) -- the inbox message still goes out.
    """
    if not settings.SMS_DISPATCH_ENABLED:
        return None, None
    phone = (owner.support_phone or "").strip()
    if not phone:
        return None, None
    settings_row = await db.get(MessagingSettings, 1)
    if settings_row is not None and not settings_row.enabled:
        return None, None
    segments = count_segments(body)
    if not await sms_credits.try_deduct(
            db, owner.id, segments,
            reference=log_ref,
            note="Payout destination change alert"):
        logger.info("Payout alert SMS skipped: user %s has insufficient credits",
                    owner.id)
        return None, None
    row = SmsMessage(
        user_id=owner.id,
        recipient_phone=phone,
        body=body,
        segments=segments,
        credits_charged=segments,
        kind=SmsMessageKind.ADMIN_TO_RESELLER,
        category=ALERT_SMS_CATEGORY,
        status=SmsMessageStatus.QUEUED,
    )
    db.add(row)
    await db.flush()
    return row.id, resolve_sender_id(settings_row.sender_id if settings_row else None)


async def record_and_notify(
    *,
    user_id: int,
    actor_user_id: Optional[int],
    action: PayoutDestinationAction,
    payment_method_id: Optional[int] = None,
    method_type: Optional[str] = None,
    label: Optional[str] = None,
    destination_before: Optional[str] = None,
    destination_after: Optional[str] = None,
    router_id: Optional[int] = None,
) -> Optional[int]:
    """Write the audit row and alert the owner. Own session. Never raises.

    Call AFTER the payment-method change has been committed. Returns the log
    row id, or None if nothing was written.

    The audit row is written even when the notification cannot go out (no admin
    sender, deleted owner): losing the alert is recoverable, losing the trail is
    not -- that is the whole point of this module.
    """
    sms_id = provider_sender = None
    log_id = None
    try:
        async with database.async_session() as db:
            owner = await db.get(User, user_id)
            log = PayoutDestinationChangeLog(
                user_id=user_id,
                actor_user_id=actor_user_id,
                action=action,
                payment_method_id=payment_method_id,
                method_type=method_type,
                label=label,
                destination_before=destination_before,
                destination_after=destination_after,
                router_id=router_id,
            )
            db.add(log)
            await db.flush()
            log_id = log.id

            if owner is not None:
                admin_id = await _resolve_sender_admin_id(db, owner)
                if admin_id is not None:
                    actor_email = None
                    if actor_user_id and actor_user_id != user_id:
                        actor = await db.get(User, actor_user_id)
                        actor_email = actor.email if actor else None
                    subject, body = render_change_notification(
                        action, label, destination_before, destination_after,
                        actor_is_owner=(actor_user_id == user_id),
                        actor_email=actor_email,
                    )
                    sms_id, provider_sender = await _queue_alert_sms(
                        db, owner, body, f"payout_destination_change:{log_id}")
                    db.add(ResellerInboxMessage(
                        recipient_user_id=owner.id,
                        sender_user_id=admin_id,
                        subject=subject,
                        body=body,
                        sent_sms=sms_id is not None,
                    ))
                    log.notified = True
            await db.commit()

        logger.info(
            "Payout destination %s: user=%s actor=%s method=%s '%s' -> '%s' (log=%s)",
            action.value, user_id, actor_user_id, payment_method_id,
            destination_before, destination_after, log_id,
        )
    except Exception:
        logger.exception(
            "Payout destination alert failed (user=%s, method=%s, action=%s)",
            user_id, payment_method_id, action,
        )
        return log_id

    if sms_id is not None:
        _spawn_alert_sms_dispatch(sms_id, provider_sender)
    return log_id
