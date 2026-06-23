"""Recipient resolution + background SMS campaign dispatch.

DB discipline: dispatch_campaign() takes a campaign id (not a session). It
opens short sessions, calls the provider with NO session held, and persists
per-recipient results in fresh sessions. Credits for failed recipients are
refunded in their own short transaction.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, delete

from app.config import settings
from app.db.database import async_session
from app.db.models import (
    Customer, CustomerStatus,
    SmsCampaign, SmsCampaignStatus,
    SmsMessage, SmsMessageStatus, SmsMessageKind,
    MessagingSettings,
)
from app.services import sms_credits
from app.services.messaging import default_sender_id, get_provider

logger = logging.getLogger(__name__)


async def resolve_recipients(db, reseller_id: int, *, filter: str = "all",
                             plan_id: Optional[int] = None,
                             customer_ids: Optional[list[int]] = None,
                             expiring_days: int = 7) -> list[dict]:
    """Return [{customer_id, phone}] for a reseller, de-duplicated by phone."""
    stmt = select(Customer.id, Customer.phone).where(Customer.user_id == reseller_id)
    stmt = stmt.where(Customer.phone.isnot(None))
    if customer_ids:
        stmt = stmt.where(Customer.id.in_(customer_ids))
    elif filter == "by_plan" and plan_id:
        stmt = stmt.where(Customer.plan_id == plan_id)
    elif filter == "active":
        stmt = stmt.where(Customer.status == CustomerStatus.ACTIVE)
    elif filter == "expiring":
        cutoff = datetime.utcnow() + timedelta(days=expiring_days)
        stmt = stmt.where(Customer.expiry.isnot(None), Customer.expiry <= cutoff)
    rows = (await db.execute(stmt)).all()
    seen, out = set(), []
    for cid, phone in rows:
        phone = (phone or "").strip()
        if not phone or phone in seen:
            continue
        seen.add(phone)
        out.append({"customer_id": cid, "phone": phone})
    return out


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _phone_key(phone: str | None) -> str:
    """Normalize only for matching provider results back to queued rows."""
    return (phone or "").strip().replace(" ", "").lstrip("+")


async def dispatch_campaign(campaign_id: int) -> None:
    """Send all queued messages for a campaign. Self-managed sessions only."""
    if not settings.SMS_DISPATCH_ENABLED:
        logger.warning("SMS dispatch disabled; campaign %s left queued", campaign_id)
        return

    # --- Short DB session: read campaign + queued messages, mark SENDING ---
    async with async_session() as db:
        camp = await db.get(SmsCampaign, campaign_id)
        if camp is None or camp.status not in (SmsCampaignStatus.QUEUED,
                                               SmsCampaignStatus.SENDING):
            return
        camp.status = SmsCampaignStatus.SENDING
        msgs = (await db.execute(
            select(SmsMessage.id, SmsMessage.recipient_phone)
            .where(SmsMessage.campaign_id == campaign_id,
                   SmsMessage.status == SmsMessageStatus.QUEUED)
        )).all()
        body = camp.body
        sender_id = camp.sender_id or default_sender_id()
        user_id = camp.user_id
        await db.commit()
    # --- DB session closed; no connection held from here ---

    if not msgs:
        await _finalize(campaign_id)
        return

    provider = get_provider()
    chunk_size = settings.SMS_DISPATCH_CHUNK_SIZE

    for chunk in _chunks(msgs, chunk_size):
        phones = [m.recipient_phone for m in chunk]

        # --- Network call: no DB session held ---
        try:
            results = await provider.send_bulk(phones, body, sender_id)
        except Exception as e:
            logger.error("Provider send failed for campaign %s: %s", campaign_id, e)
            results = []
        # --- End network call ---

        by_phone = {_phone_key(r.recipient): r for r in results}

        failed_credits = 0
        sent_count = 0
        failed_count = 0
        # --- Short DB session: persist per-message results ---
        async with async_session() as db:
            for m in chunk:
                row = await db.get(SmsMessage, m.id)
                res = by_phone.get(_phone_key(m.recipient_phone))
                if res is not None and res.success:
                    row.status = SmsMessageStatus.SENT
                    row.provider_message_id = res.provider_message_id
                    row.provider = provider.name
                    row.error = None
                    sent_count += 1
                else:
                    row.status = SmsMessageStatus.FAILED
                    row.error = (res.error if res else "no_response")[:255]
                    failed_credits += row.credits_charged
                    failed_count += 1
            await db.commit()
        # --- DB session closed ---

        logger.info(
            "SMS campaign %s provider batch settled: provider=%s requested=%s "
            "sent=%s failed=%s",
            campaign_id, provider.name, len(chunk), sent_count, failed_count,
        )

        if failed_credits:
            # --- Short DB session: refund failed credits ---
            async with async_session() as db:
                await sms_credits.refund(db, user_id, failed_credits,
                                         reference=f"campaign:{campaign_id}",
                                         note="failed recipients")
                camp = await db.get(SmsCampaign, campaign_id)
                camp.refunded_credits += failed_credits
                await db.commit()
            # --- DB session closed ---

    await _finalize(campaign_id)


async def _finalize(campaign_id: int) -> None:
    async with async_session() as db:
        camp = await db.get(SmsCampaign, campaign_id)
        if camp is None:
            return
        counts = (await db.execute(
            select(SmsMessage.status).where(SmsMessage.campaign_id == campaign_id)
        )).scalars().all()
        sent = sum(1 for s in counts if s == SmsMessageStatus.SENT)
        failed = sum(1 for s in counts if s == SmsMessageStatus.FAILED)
        camp.sent_count = sent
        camp.failed_count = failed
        if failed == 0:
            camp.status = SmsCampaignStatus.COMPLETED
        elif sent == 0:
            camp.status = SmsCampaignStatus.FAILED
        else:
            camp.status = SmsCampaignStatus.PARTIAL
        await db.commit()
        logger.info(
            "SMS campaign %s finalized: status=%s sent=%s failed=%s",
            campaign_id,
            camp.status.value if hasattr(camp.status, "value") else camp.status,
            sent,
            failed,
        )


async def dispatch_admin_sms_messages(message_ids: list[int], sender_id: str) -> None:
    """Send queued admin->reseller SMS rows and persist provider outcomes.

    The rows are created and committed by the request handler first. This worker
    owns its own short DB sessions and never holds a DB connection while calling
    the SMS provider.
    """
    if not message_ids:
        return
    if not settings.SMS_DISPATCH_ENABLED:
        logger.warning("SMS dispatch disabled; admin message ids left queued: %s", message_ids)
        return

    # --- Short DB session: read queued rows only ---
    async with async_session() as db:
        rows = (await db.execute(
            select(SmsMessage.id, SmsMessage.recipient_phone, SmsMessage.body)
            .where(
                SmsMessage.id.in_(message_ids),
                SmsMessage.kind == SmsMessageKind.ADMIN_TO_RESELLER,
                SmsMessage.status == SmsMessageStatus.QUEUED,
            )
        )).all()
        await db.commit()
    # --- DB session closed; provider I/O starts below ---

    if not rows:
        return

    provider = get_provider()
    chunk_size = settings.SMS_DISPATCH_CHUNK_SIZE
    total_sent = 0
    total_failed = 0

    # All rows from one admin send normally share a body, but group defensively
    # so a future caller cannot accidentally send the wrong body to a row.
    rows_by_body: dict[str, list] = {}
    for row in rows:
        rows_by_body.setdefault(row.body, []).append(row)

    for body, body_rows in rows_by_body.items():
        for chunk in _chunks(body_rows, chunk_size):
            phones = [m.recipient_phone for m in chunk]
            provider_error: str | None = None

            try:
                results = await provider.send_bulk(phones, body, sender_id)
            except Exception as e:
                provider_error = str(e)[:255]
                logger.error("Admin SMS provider send failed: %s", e)
                results = []

            by_phone = {_phone_key(r.recipient): r for r in results}
            sent_count = 0
            failed_count = 0

            # --- Short DB session: persist provider results ---
            async with async_session() as db:
                for m in chunk:
                    row = await db.get(SmsMessage, m.id)
                    if row is None:
                        continue
                    res = by_phone.get(_phone_key(m.recipient_phone))
                    if res is not None and res.success:
                        row.status = SmsMessageStatus.SENT
                        row.provider_message_id = res.provider_message_id
                        row.provider = provider.name
                        row.error = None
                        sent_count += 1
                    else:
                        row.status = SmsMessageStatus.FAILED
                        row.provider = provider.name
                        row.error = ((res.error if res else provider_error) or "no_response")[:255]
                        failed_count += 1
                await db.commit()
            # --- DB session closed ---

            total_sent += sent_count
            total_failed += failed_count
            logger.info(
                "Admin SMS provider batch settled: provider=%s requested=%s "
                "sent=%s failed=%s",
                provider.name, len(chunk), sent_count, failed_count,
            )

    logger.info(
        "Admin SMS dispatch complete: messages=%s sent=%s failed=%s",
        len(rows), total_sent, total_failed,
    )


async def prune_old_messages() -> int:
    """Retention: delete sent/delivered rows past the window. Returns count.

    Load-sheds under DB pool pressure; deletes in bounded batches.
    """
    from app.db.database import db_pool_snapshot
    level = db_pool_snapshot().get("pressure", {}).get("level", "healthy")
    if level in ("warning", "critical"):
        logger.info("Skip SMS retention prune (pool pressure: %s)", level)
        return 0

    async with async_session() as db:
        settings_row = await db.get(MessagingSettings, 1)
        days = settings_row.message_retention_days if settings_row else 60
    cutoff = datetime.utcnow() - timedelta(days=days)

    total = 0
    while True:
        async with async_session() as db:
            ids = (await db.execute(
                select(SmsMessage.id).where(
                    SmsMessage.status.in_([SmsMessageStatus.SENT,
                                           SmsMessageStatus.DELIVERED]),
                    SmsMessage.created_at < cutoff,
                ).limit(500)
            )).scalars().all()
            if not ids:
                break
            await db.execute(delete(SmsMessage).where(SmsMessage.id.in_(ids)))
            await db.commit()
            total += len(ids)
    if total:
        logger.info("SMS retention: pruned %s old message rows", total)
    return total
