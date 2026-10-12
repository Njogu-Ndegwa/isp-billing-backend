"""Customer audit log: one timeline of everything that happened to a customer.

GET  /api/customers/{id}/audit-log              the merged timeline (newest first)
POST /api/customers/{id}/audit-log/router-logs  read the router's log now and keep
                                                 the lines about this customer
POST /api/customers/{id}/reset-session          drop the live PPPoE session (logged)

The timeline merges, at read time:

* ``customer_events`` — session connects/drops seen in router push reports,
  router log lines naming the customer, and record changes (who, what);
* ``customer_payments`` — money that reached the customer's account;
* ``mpesa_transactions`` — STK prompts that failed, expired or are pending
  (completed ones already appear as payments);
* ``provisioning_attempts`` / ``provisioning_logs`` — the system putting the
  customer on, or taking them off, the router;
* ``reconnection_attempts`` — self-service reconnects from the portal;
* ``sms_messages`` — every SMS sent to the customer, with its delivery result.

Paging is by time: pass the ``next_before`` of one page as ``before`` for the
next. Each source is read with the same bound and limit, then merged.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import (
    Customer, CustomerEvent, CustomerPayment, MpesaTransaction,
    MpesaTransactionStatus, Plan, ProvisioningAttempt, ProvisioningLog,
    ReconnectionAttempt, Router, RouterAvailabilityCheck, SmsMessage,
)
from app.services import realtime_state
from app.services.auth import get_current_user, verify_token
from app.services.subscription import enforce_active_subscription
from app.services.customer_events import record_customer_event
from app.services.customer_router_logs import CustomerIndex, capture_router_logs, router_info_of
from app.services.router_availability import record_router_availability

logger = logging.getLogger(__name__)

router = APIRouter(tags=["customer-audit"])

CATEGORIES = ("session", "router_log", "router", "change", "billing", "provisioning", "messages")
DEFAULT_LIMIT = 150
MAX_LIMIT = 500

# One live router read per customer per this many seconds, whoever asks, and
# per router across all its customers (a reseller looping over customers must
# not keep one router's diagnostic slots busy).
ROUTER_LOG_PULL_COOLDOWN_SECONDS = 20
ROUTER_LOG_PULL_ROUTER_COOLDOWN_SECONDS = 10
_last_pull: dict[int, datetime] = {}
_last_router_pull: dict[int, datetime] = {}


def _trim(store: dict, now: datetime, keep_seconds: int = 300) -> None:
    """Forget cooldowns long expired, so the maps never grow with the fleet."""
    if len(store) > 1000:
        for key in [k for k, at in store.items() if (now - at).total_seconds() > keep_seconds]:
            store.pop(key, None)

# Router reachability is folded into the timeline for at most this far back.
ROUTER_STATUS_WINDOW = timedelta(days=14)
ROUTER_STATUS_LOOKBACK = timedelta(days=1)
ROUTER_STATUS_MAX_CHECKS = 20000

# "Password: abc123" in a stored SMS (the welcome template sends it). The
# timeline never shows it: viewing credentials is an audited action of its own.
_RE_SECRET_IN_SMS = re.compile(r"(?i)(\bpass(?:word|wd)?\b\s*[:=]?\s*)([^\s.,;]+)")


def redact_sms(body: Optional[str], secret: Optional[str] = None) -> Optional[str]:
    """Mask passwords in an SMS body.

    The pattern catches the built-in wording; a reseller's own template may say
    it any way ("Nenosiri: ..."), so the customer's actual password is blanked
    wherever it appears too.
    """
    if not body:
        return body
    if secret and len(secret) >= 4:
        body = body.replace(secret, "\u2022" * 6)
    return _RE_SECRET_IN_SMS.sub(lambda m: m.group(1) + "\u2022" * 6, body)


async def _load_customer(db: AsyncSession, customer_id: int, token) -> tuple[Customer, object]:
    user = await get_current_user(token, db)
    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan), selectinload(Customer.router))
        .where(Customer.id == customer_id)
    )
    if user.role.value != "admin":
        stmt = stmt.where(Customer.user_id == user.id)
    customer = (await db.execute(stmt)).scalar_one_or_none()
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer, user


def _item(at, category, event_type, message, *, severity="info", source="system",
          actor=None, router_id=None, details=None, ref=None) -> dict:
    return {
        "id": ref,
        "occurred_at": at.isoformat() if at else None,
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "actor": actor,
        "router_id": router_id,
        "message": message,
        "details": details or {},
    }


def _money(amount) -> str:
    try:
        value = float(amount)
    except (TypeError, ValueError):
        return str(amount)
    return f"{value:,.0f}" if value == int(value) else f"{value:,.2f}"


def _bounded(stmt, column, before, after, inclusive=False):
    if before is not None:
        stmt = stmt.where(column <= before if inclusive else column < before)
    if after is not None:
        stmt = stmt.where(column >= after)
    return stmt


def _naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Stored times are naive UTC; an offset like +03:00 is converted, not dropped."""
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _in_window(at, before, after, inclusive=False) -> bool:
    if at is None:
        return False
    if before is not None and (at > before if inclusive else at >= before):
        return False
    return after is None or at >= after


def _router_status_items(checks, router_id, *, window_start, window_end, inclusive=False) -> list[dict]:
    """Site offline / back online entries, from the same outage rules as uptime.

    ``uptime_outages`` decides what an outage is: for a router that sends
    usage reports, a gap of more than 15 minutes in them; otherwise from a
    failed check to the next success. Anything under five minutes, and any
    failed connection made while the router was still reporting, is never
    shown as the site going offline.
    """
    from app.services.customer_events import format_duration
    from app.services.router_availability import uptime_outages

    if not checks:
        return []
    judged = uptime_outages(checks, now=window_end)
    reporting = judged["judged_by"] == "router_reports"
    out: list[dict] = []
    for outage in judged["outages"]:
        started = datetime.fromisoformat(outage["started_at"])
        ended = datetime.fromisoformat(outage["ended_at"]) if outage.get("ended_at") else None
        if _in_window(started, window_end, window_start, inclusive):
            out.append(_item(
                started, "router", "router_offline",
                ("Site went offline: the router stopped reporting to Bitwave. "
                 if reporting else "Site went offline: the router stopped answering Bitwave. ")
                + "Power or the site's internet may be down, so customers on it may be offline too.",
                severity="warning", router_id=router_id,
                ref=f"rt-down:{router_id}:{started.isoformat()}",
            ))
        if ended is not None and _in_window(ended, window_end, window_start, inclusive):
            out.append(_item(
                ended, "router", "router_online",
                f"Site back online after {format_duration(int((ended - started).total_seconds()))}",
                router_id=router_id, ref=f"rt-up:{router_id}:{ended.isoformat()}",
            ))
    return out


async def _summary(db: AsyncSession, customer: Customer) -> dict:
    """The few facts a technician asks first, so they need not scroll for them."""
    now = datetime.utcnow()

    async def latest(stmt):
        return (await db.execute(stmt.limit(1))).scalars().first()

    last_drop = await latest(
        select(CustomerEvent).where(
            CustomerEvent.customer_id == customer.id,
            CustomerEvent.event_type.in_(("session_disconnected", "session_reconnected", "device_offline")),
        ).order_by(CustomerEvent.occurred_at.desc())
    )
    last_problem = await latest(
        select(CustomerEvent).where(
            CustomerEvent.customer_id == customer.id,
            CustomerEvent.category == "router_log",
            CustomerEvent.severity.in_(("warning", "error")),
        ).order_by(CustomerEvent.occurred_at.desc())
    )
    drops_24h = (await db.execute(
        select(func.count()).select_from(CustomerEvent).where(
            CustomerEvent.customer_id == customer.id,
            CustomerEvent.event_type.in_(("session_disconnected", "session_reconnected")),
            CustomerEvent.occurred_at >= now - timedelta(hours=24),
        )
    )).scalar_one()
    last_payment = (await db.execute(
        select(CustomerPayment.created_at, CustomerPayment.amount)
        .where(CustomerPayment.customer_id == customer.id)
        .order_by(CustomerPayment.created_at.desc())
        .limit(1)
    )).first()

    def ev(e):
        return {"at": e.occurred_at.isoformat(), "message": e.message} if e else None

    return {
        "last_drop": ev(last_drop),
        "last_problem": ev(last_problem),
        "drops_24h": int(drops_24h or 0),
        "last_payment": {
            "at": last_payment.created_at.isoformat() if last_payment.created_at else None,
            "amount": last_payment.amount,
        } if last_payment else None,
    }


_ENTRYPOINT_WORDS = {
    "hotspot_payment": "a payment",
    "hotspot_reconciliation": "a payment check",
    "voucher_direct_api": "a voucher",
    "manual_transaction_provision": "a manual activation",
    "subscription_share": "a shared subscription",
    "outage_compensation": "outage compensation",
    "free_trial": "a free trial",
}
_STATE_WORDS = {
    "scheduled": "queued",
    "in_progress": "in progress",
    "retry_pending": "router not reached yet, will retry",
    "router_updated": "done",
    "failed": "failed",
}


@router.get("/api/customers/{customer_id}/audit-log")
async def customer_audit_log(
    customer_id: int,
    before: Optional[datetime] = Query(None, description="Only entries strictly older than this (UTC)"),
    after: Optional[datetime] = Query(None, description="Only entries at or after this (UTC)"),
    cursor: Optional[datetime] = Query(
        None,
        description="Paging: entries at or older than this (UTC) — the next_before of the previous "
                    "page. Inclusive so entries sharing that second are not skipped; the client "
                    "drops the ones it already has by id.",
    ),
    categories: Optional[str] = Query(None, description=f"Comma list of {', '.join(CATEGORIES)}"),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    customer, _user = await _load_customer(db, customer_id, token)
    before = _naive_utc(before)
    after = _naive_utc(after)
    inclusive = cursor is not None
    if cursor is not None:
        before = _naive_utc(cursor)
    wanted = set(CATEGORIES)
    if categories:
        wanted = {c.strip() for c in categories.split(",") if c.strip()}
        unknown = wanted - set(CATEGORIES)
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown categories: {', '.join(sorted(unknown))}")

    items: list[dict] = []
    # Oldest time returned by each source that hit its limit: anything older
    # from that source was not read, so the page must stop there.
    saturated: list[datetime] = []

    def _note(rows, time_of):
        if len(rows) >= limit and rows:
            saturated.append(time_of(rows[-1]))
        return rows

    event_categories = wanted & {"session", "router_log", "change"}
    if event_categories:
        stmt = _bounded(
            select(CustomerEvent).where(
                CustomerEvent.customer_id == customer_id,
                CustomerEvent.category.in_(event_categories),
            ),
            CustomerEvent.occurred_at, before, after, inclusive,
        ).order_by(CustomerEvent.occurred_at.desc(), CustomerEvent.id.desc()).limit(limit)
        for ev in _note((await db.execute(stmt)).scalars().all(), lambda r: r.occurred_at):
            items.append(_item(
                ev.occurred_at, ev.category, ev.event_type, ev.message,
                severity=ev.severity, source=ev.source, actor=ev.actor_label,
                router_id=ev.router_id, details=ev.details, ref=f"ev:{ev.id}",
            ))

    if "billing" in wanted:
        stmt = _bounded(
            select(CustomerPayment, Plan.name)
            .outerjoin(Plan, CustomerPayment.plan_id == Plan.id)
            .where(CustomerPayment.customer_id == customer_id),
            CustomerPayment.created_at, before, after, inclusive,
        ).order_by(CustomerPayment.created_at.desc()).limit(limit)
        for pay, plan_name in _note((await db.execute(stmt)).all(), lambda r: r[0].created_at):
            method = pay.payment_method.value.replace("_", " ") if pay.payment_method else "payment"
            status = pay.status.value if pay.status else "completed"
            text = f"Payment of {_money(pay.amount)} received by {method} for {pay.days_paid_for} day(s)"
            if plan_name:
                text += f" — {plan_name}"
            if status != "completed":
                text += f" ({status})"
            items.append(_item(
                pay.created_at, "billing", f"payment_{status}", text,
                severity="info" if status == "completed" else "warning",
                router_id=pay.router_id,
                details={"amount": pay.amount, "method": method, "reference": pay.payment_reference,
                         "days": pay.days_paid_for, "plan": plan_name, "notes": pay.notes},
                ref=f"pay:{pay.id}",
            ))

        stmt = _bounded(
            select(MpesaTransaction).where(
                MpesaTransaction.customer_id == customer_id,
                MpesaTransaction.status != MpesaTransactionStatus.completed,
            ),
            MpesaTransaction.created_at, before, after, inclusive,
        ).order_by(MpesaTransaction.created_at.desc()).limit(limit)
        for tx in _note((await db.execute(stmt)).scalars().all(), lambda r: r.created_at):
            status = tx.status.value if tx.status else "pending"
            reason = tx.result_desc or ""
            text = {
                "pending": f"M-Pesa prompt of {_money(tx.amount)} sent to {tx.phone_number}, no answer yet",
                "failed": f"M-Pesa payment of {_money(tx.amount)} failed",
                "expired": f"M-Pesa prompt of {_money(tx.amount)} expired unanswered",
            }.get(status, f"M-Pesa payment {status}")
            if reason and status != "pending":
                text += f": {reason}"
            items.append(_item(
                tx.created_at, "billing", f"mpesa_{status}", text,
                severity="info" if status == "pending" else "warning",
                details={"amount": float(tx.amount) if tx.amount is not None else None,
                         "phone": tx.phone_number, "result_code": tx.result_code,
                         "reason": reason or None,
                         "failure_source": tx.failure_source.value if tx.failure_source else None},
                ref=f"mpesa:{tx.id}",
            ))

    if "provisioning" in wanted:
        stmt = _bounded(
            select(ProvisioningAttempt).where(ProvisioningAttempt.customer_id == customer_id),
            ProvisioningAttempt.created_at, before, after, inclusive,
        ).order_by(ProvisioningAttempt.created_at.desc()).limit(limit)
        for att in _note((await db.execute(stmt)).scalars().all(), lambda r: r.created_at):
            state = att.provisioning_state.value if att.provisioning_state else "scheduled"
            entry = att.entrypoint.value if att.entrypoint else ""
            text = (f"Giving internet access after {_ENTRYPOINT_WORDS.get(entry, entry.replace('_', ' '))}: "
                    f"{_STATE_WORDS.get(state, state.replace('_', ' '))}")
            if att.attempt_count and att.attempt_count > 1:
                text += f" after {att.attempt_count} tries"
            if att.last_error and state != "router_updated":
                text += f" — {att.last_error}"
            items.append(_item(
                att.created_at, "provisioning", "provisioning_attempt", text,
                severity="error" if "fail" in state else "info",
                router_id=att.router_id,
                details={"state": state, "attempts": att.attempt_count, "last_error": att.last_error,
                         "delivered_via": att.delivered_via, "mac": att.mac_address,
                         "access_seen_at": att.access_seen_at.isoformat() if att.access_seen_at else None,
                         "reference": att.external_reference},
                ref=f"att:{att.id}",
            ))

        # Read by their own time, so a confirmation is shown even when the
        # attempt it belongs to falls on another page.
        stmt = _bounded(
            select(ProvisioningAttempt).where(
                ProvisioningAttempt.customer_id == customer_id,
                ProvisioningAttempt.access_seen_at.isnot(None),
            ),
            ProvisioningAttempt.access_seen_at, before, after, inclusive,
        ).order_by(ProvisioningAttempt.access_seen_at.desc()).limit(limit)
        for att in _note((await db.execute(stmt)).scalars().all(), lambda r: r.access_seen_at):
            items.append(_item(
                att.access_seen_at, "provisioning", "access_confirmed",
                "Internet access confirmed on the router",
                router_id=att.router_id, ref=f"att-ok:{att.id}",
            ))

        stmt = _bounded(
            select(ProvisioningLog).where(ProvisioningLog.customer_id == customer_id),
            ProvisioningLog.log_date, before, after, inclusive,
        ).order_by(ProvisioningLog.log_date.desc()).limit(limit)
        for log in _note((await db.execute(stmt)).scalars().all(), lambda r: r.log_date):
            text = f"{(log.action or '').replace('_', ' ').capitalize()}: {log.status}"
            if log.details:
                text += f" — {log.details}"
            if log.error:
                text += f" ({log.error})"
            failed = (log.status or "").lower() in ("failed", "error")
            items.append(_item(
                log.log_date, "provisioning", log.action or "provisioning", text,
                severity="error" if failed else "info",
                router_id=log.router_id,
                details={"mac": log.mac_address, "status": log.status},
                ref=f"plog:{log.id}",
            ))

        stmt = _bounded(
            select(ReconnectionAttempt).where(ReconnectionAttempt.customer_id == customer_id),
            ReconnectionAttempt.created_at, before, after, inclusive,
        ).order_by(ReconnectionAttempt.created_at.desc()).limit(limit)
        for rc in _note((await db.execute(stmt)).scalars().all(), lambda r: r.created_at):
            text = ("Customer reconnected a device from the portal" if rc.success
                    else f"Portal reconnect failed: {rc.failure_reason or 'unknown reason'}")
            if rc.old_mac_address and rc.old_mac_address != rc.mac_address:
                text += f" (device {rc.old_mac_address} -> {rc.mac_address})"
            items.append(_item(
                rc.created_at, "provisioning", "portal_reconnect", text,
                severity="info" if rc.success else "warning",
                router_id=rc.router_id, source="customer",
                details={"mac": rc.mac_address, "old_mac": rc.old_mac_address},
                ref=f"rc:{rc.id}",
            ))

    if "messages" in wanted:
        stmt = _bounded(
            select(SmsMessage).where(SmsMessage.customer_id == customer_id),
            SmsMessage.created_at, before, after, inclusive,
        ).order_by(SmsMessage.created_at.desc()).limit(limit)
        for sms in _note((await db.execute(stmt)).scalars().all(), lambda r: r.created_at):
            status = sms.status.value if sms.status else "queued"
            label = {"failed": "SMS failed", "delivered": "SMS delivered",
                     "sent": "SMS sent", "queued": "SMS queued"}.get(status, f"SMS {status}")
            text = f"{label} to {sms.recipient_phone}"
            if sms.error:
                text += f": {sms.error}"
            items.append(_item(
                sms.created_at, "messages", f"sms_{status}", text,
                severity="warning" if status == "failed" else "info",
                details={"body": redact_sms(sms.body, customer.pppoe_password), "provider": sms.provider, "category": sms.category,
                         "segments": sms.segments},
                ref=f"sms:{sms.id}",
            ))

    registered = any(i["event_type"] == "customer_created" for i in items)
    if "change" in wanted and not registered and _in_window(customer.created_at, before, after, inclusive):
        items.append(_item(
            customer.created_at, "change", "customer_created", "Customer record created",
            ref="created",
        ))

    items.sort(key=lambda i: i["occurred_at"] or "", reverse=True)
    if saturated:
        floor = max(saturated).isoformat()
        items = [i for i in items if (i["occurred_at"] or "") >= floor]
    has_more = bool(saturated) or len(items) > limit
    page = items[:limit]
    next_before = page[-1]["occurred_at"] if page and has_more else None
    if inclusive and next_before is not None and next_before == before.isoformat():
        # More rows share this exact second than fit on a page; step past it
        # rather than serve the same page forever.
        next_before = (before - timedelta(microseconds=1)).isoformat()

    # Router reachability over the span this page covers: a quiet stretch in
    # the timeline means something different when the whole site was down.
    if "router" in wanted and customer.router_id:
        window_end = before or datetime.utcnow()
        oldest_on_page = page[-1]["occurred_at"] if page and has_more else None
        window_start = max(
            datetime.fromisoformat(oldest_on_page) if oldest_on_page else window_end - ROUTER_STATUS_WINDOW,
            window_end - ROUTER_STATUS_WINDOW,
            after or datetime.min,
        )
        # Read from a day before the window so an outage already in progress
        # when it starts is measured from its real start.
        checks = (await db.execute(
            select(
                RouterAvailabilityCheck.checked_at,
                RouterAvailabilityCheck.is_online,
                RouterAvailabilityCheck.source,
            )
            .where(
                RouterAvailabilityCheck.router_id == customer.router_id,
                RouterAvailabilityCheck.checked_at >= window_start - ROUTER_STATUS_LOOKBACK,
                RouterAvailabilityCheck.checked_at <= window_end,
            )
            .order_by(RouterAvailabilityCheck.checked_at.desc())
            .limit(ROUTER_STATUS_MAX_CHECKS)
        )).all()
        status_items = _router_status_items(
            [{"checked_at": c.checked_at, "is_online": c.is_online, "source": c.source} for c in reversed(checks)],
            customer.router_id,
            window_start=window_start,
            window_end=window_end,
            inclusive=inclusive,
        )
        if status_items:
            page = sorted(page + status_items, key=lambda i: i["occurred_at"] or "", reverse=True)

    summary = await _summary(db, customer)

    router_name = customer.router.name if customer.router else None
    router_live = realtime_state.get_router_live(customer.router_id) if customer.router_id else None
    connection_type = (
        customer.plan.connection_type.value
        if customer.plan and customer.plan.connection_type else None
    )
    device = (
        realtime_state.get_pppoe_live(customer.router_id, customer.pppoe_username)
        if connection_type == "pppoe"
        else realtime_state.get_device_live(customer.router_id, customer.mac_address)
    )
    live = {
        "online": device.online,
        "ip": device.ip or None,
        "uptime": device.uptime or None,
        "seen_at": device.seen_at.isoformat() if device.seen_at else None,
    } if device is not None else None
    await db.commit()

    return {
        "customer": {
            "id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "status": customer.status.value if customer.status else None,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "connection_type": connection_type,
            "plan": customer.plan.name if customer.plan else None,
            "pppoe_username": customer.pppoe_username,
            "mac_address": customer.mac_address,
            "router_id": customer.router_id,
            "router_name": router_name,
        },
        "live": live,
        # How fresh the session entries can be: they come from these reports.
        "router_reported_at": router_live.received_at.isoformat() if router_live else None,
        "summary": summary,
        "items": page,
        "count": len(page),
        "has_more": next_before is not None,
        "next_before": next_before,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.post("/api/customers/{customer_id}/audit-log/router-logs")
async def pull_customer_router_logs(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Read the customer's router log now and keep every line that names them.

    The router only holds its last ~1000 lines in RAM; whatever is still there
    is saved, so the answer to "what did the router say at 3 pm" survives the
    next reboot. Safe to press repeatedly: stored lines are not duplicated.
    """
    customer, user = await _load_customer(db, customer_id, token)
    enforce_active_subscription(user)
    router_obj: Optional[Router] = customer.router
    if router_obj is None:
        raise HTTPException(status_code=400, detail="Customer has no router assigned")

    now = datetime.utcnow()
    for key, store, cooldown in (
        (customer_id, _last_pull, ROUTER_LOG_PULL_COOLDOWN_SECONDS),
        (router_obj.id, _last_router_pull, ROUTER_LOG_PULL_ROUTER_COOLDOWN_SECONDS),
    ):
        last = store.get(key)
        if last is not None and (now - last).total_seconds() < cooldown:
            wait = int(cooldown - (now - last).total_seconds()) + 1
            raise HTTPException(status_code=429, detail=f"This router's log was just read; try again in {wait}s")

    # Caller-ids seen in this customer's PPPoE sessions are the MACs the router
    # names before authentication ("<pppoe-AA:BB:..>: waiting for call").
    seen_macs = set()
    recent = (await db.execute(
        select(CustomerEvent.details).where(
            CustomerEvent.customer_id == customer_id,
            CustomerEvent.category == "session",
            CustomerEvent.occurred_at >= now - timedelta(days=30),
        ).order_by(CustomerEvent.occurred_at.desc()).limit(50)
    )).scalars().all()
    for details in recent:
        if isinstance(details, dict):
            seen_macs.update(filter(None, [details.get("caller_id"), details.get("mac")]))

    index = CustomerIndex()
    index.add(customer.id, customer.user_id, customer.pppoe_username, [customer.mac_address, *seen_macs])
    if not len(index):
        raise HTTPException(
            status_code=400,
            detail="Customer has no PPPoE username or MAC address to look for in the router log",
        )
    router_id = router_obj.id
    info = router_info_of(router_obj)
    await db.commit()  # nothing held across the router read

    _trim(_last_pull, now)
    _trim(_last_router_pull, now)
    _last_pull[customer_id] = now
    _last_router_pull[router_id] = now
    ppp_customer = (customer.id, customer.user_id, customer.pppoe_username) if customer.pppoe_username else None
    result = await capture_router_logs(
        router_id, info, index, acquire_timeout_seconds=2.0, ppp_customer=ppp_customer,
    )
    error = result.get("error")
    if error == "busy":
        _last_pull.pop(customer_id, None)
        _last_router_pull.pop(router_id, None)
        raise HTTPException(status_code=429, detail="Router is busy with other diagnostics; try again shortly")
    if error == "connect_failed":
        await record_router_availability(db, router_id, False, "customer_audit_router_logs")
        raise HTTPException(
            status_code=503,
            detail="Could not reach the router; only previously saved log lines are shown",
        )
    if error == "timeout":
        # A slow log read is not proof the router is down; do not record it as such.
        raise HTTPException(
            status_code=504,
            detail="The router took too long to send its log; try again in a minute",
        )
    if error:
        raise HTTPException(status_code=502, detail=f"Router log read failed: {error}")
    await record_router_availability(db, router_id, True, "customer_audit_router_logs")
    return {"customer_id": customer_id, "router_id": router_id, **result}


# ---------------------------------------------------------------------------
# Reset session
# ---------------------------------------------------------------------------

RESET_SESSION_COOLDOWN_SECONDS = 15
_last_reset: dict[int, datetime] = {}


def _reset_pppoe_session_sync(router_info: dict, username: str) -> dict:
    from app.services.mikrotik_api import MikroTikAPI

    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        return api.disconnect_pppoe_session(username)
    finally:
        api.disconnect()


@router.post("/api/customers/{customer_id}/reset-session")
async def reset_customer_session(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Drop the customer's live PPPoE session so their router dials again.

    The PPP secret is untouched: a paid customer is back online within
    seconds, with a fresh session (new IP, current plan speed). The usual
    first step when a customer says "connected but no internet".
    """
    customer, user = await _load_customer(db, customer_id, token)
    enforce_active_subscription(user)
    if not customer.pppoe_username:
        raise HTTPException(status_code=400, detail="Only PPPoE customers have a session to reset")
    router_obj: Optional[Router] = customer.router
    if router_obj is None:
        raise HTTPException(status_code=400, detail="Customer has no router assigned")

    now = datetime.utcnow()
    last = _last_reset.get(customer_id)
    if last is not None and (now - last).total_seconds() < RESET_SESSION_COOLDOWN_SECONDS:
        raise HTTPException(status_code=429, detail="The session was just reset; give it a few seconds")

    router_id = router_obj.id
    info = router_info_of(router_obj)
    username = customer.pppoe_username
    owner_id = customer.user_id
    await db.commit()  # nothing held across the router call

    _trim(_last_reset, now)
    _last_reset[customer_id] = now
    from app.services.router_concurrency import run_with_guard

    result = await run_with_guard(router_id, _reset_pppoe_session_sync, info, username,
                                  acquire_timeout_seconds=2.0)
    error = result.get("error")
    if error == "busy":
        _last_reset.pop(customer_id, None)
        raise HTTPException(status_code=429, detail="Router is busy with other diagnostics; try again shortly")
    if error == "connect_failed":
        _last_reset.pop(customer_id, None)
        await record_router_availability(db, router_id, False, "customer_reset_session")
        raise HTTPException(status_code=503, detail="Could not reach the router")
    if error:
        _last_reset.pop(customer_id, None)
        raise HTTPException(status_code=502, detail=f"Router refused the reset: {error}")

    disconnected = int(result.get("disconnected") or 0)
    await record_router_availability(db, router_id, True, "customer_reset_session")
    await record_customer_event(
        customer_id, "session_reset",
        "Session reset from the dashboard; the customer's router will reconnect"
        if disconnected else "Session reset requested, but the customer had no active session",
        actor=user, user_id=owner_id, router_id=router_id,
        details={"disconnected": disconnected},
    )
    return {"customer_id": customer_id, "router_id": router_id, "disconnected": disconnected}
