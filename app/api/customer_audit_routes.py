"""Customer audit log: one timeline of everything that happened to a customer.

GET  /api/customers/{id}/audit-log              the merged timeline (newest first)
POST /api/customers/{id}/audit-log/router-logs  read the router's log now and keep
                                                 the lines about this customer

The timeline merges, at read time:

* ``customer_events`` — session connects/drops seen in router push reports,
  router log lines naming the customer, and record changes (who, what);
* ``customer_payments`` — money that reached the customer's account;
* ``mpesa_transactions`` — STK prompts that failed, expired or are pending
  (completed ones already appear as payments);
* ``provisioning_attempts`` / ``provisioning_logs`` — the system putting the
  customer on, or taking them off, the router;
* ``reconnection_attempts`` — self-service reconnects from the portal.

Paging is by time: pass the ``next_before`` of one page as ``before`` for the
next. Each source is read with the same bound and limit, then merged.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import (
    Customer, CustomerEvent, CustomerPayment, MpesaTransaction,
    MpesaTransactionStatus, Plan, ProvisioningAttempt, ProvisioningLog,
    ReconnectionAttempt, Router,
)
from app.services import realtime_state
from app.services.auth import get_current_user, verify_token
from app.services.customer_router_logs import CustomerIndex, capture_router_logs, router_info_of
from app.services.router_availability import record_router_availability

logger = logging.getLogger(__name__)

router = APIRouter(tags=["customer-audit"])

CATEGORIES = ("session", "router_log", "change", "billing", "provisioning")
DEFAULT_LIMIT = 150
MAX_LIMIT = 500

# One live router read per customer per this many seconds, whoever asks.
ROUTER_LOG_PULL_COOLDOWN_SECONDS = 20
_last_pull: dict[int, datetime] = {}


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


def _bounded(stmt, column, before, after):
    if before is not None:
        stmt = stmt.where(column < before)
    if after is not None:
        stmt = stmt.where(column >= after)
    return stmt


@router.get("/api/customers/{customer_id}/audit-log")
async def customer_audit_log(
    customer_id: int,
    before: Optional[datetime] = Query(None, description="Only entries strictly older than this (UTC)"),
    after: Optional[datetime] = Query(None, description="Only entries at or after this (UTC)"),
    categories: Optional[str] = Query(None, description=f"Comma list of {', '.join(CATEGORIES)}"),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    customer, _user = await _load_customer(db, customer_id, token)
    before = before.replace(tzinfo=None) if before else None
    after = after.replace(tzinfo=None) if after else None
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
            CustomerEvent.occurred_at, before, after,
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
            CustomerPayment.created_at, before, after,
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
            MpesaTransaction.created_at, before, after,
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
            ProvisioningAttempt.created_at, before, after,
        ).order_by(ProvisioningAttempt.created_at.desc()).limit(limit)
        for att in _note((await db.execute(stmt)).scalars().all(), lambda r: r.created_at):
            state = att.provisioning_state.value if att.provisioning_state else "scheduled"
            text = f"Putting customer on the router after {att.entrypoint.value.replace('_', ' ')}: {state.replace('_', ' ')}"
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
            if att.access_seen_at and (before is None or att.access_seen_at < before) and (
                    after is None or att.access_seen_at >= after):
                items.append(_item(
                    att.access_seen_at, "provisioning", "access_confirmed",
                    f"Access confirmed on the router{' via ' + att.delivered_via if att.delivered_via else ''}",
                    router_id=att.router_id, ref=f"att-ok:{att.id}",
                ))

        stmt = _bounded(
            select(ProvisioningLog).where(ProvisioningLog.customer_id == customer_id),
            ProvisioningLog.log_date, before, after,
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
            ReconnectionAttempt.created_at, before, after,
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

    registered = any(i["event_type"] == "customer_created" for i in items)
    if "change" in wanted and not registered and customer.created_at and (
            before is None or customer.created_at < before) and (
            after is None or customer.created_at >= after):
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

    router_name = customer.router.name if customer.router else None
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
    customer, _user = await _load_customer(db, customer_id, token)
    router_obj: Optional[Router] = customer.router
    if router_obj is None:
        raise HTTPException(status_code=400, detail="Customer has no router assigned")

    now = datetime.utcnow()
    last = _last_pull.get(customer_id)
    if last is not None and (now - last).total_seconds() < ROUTER_LOG_PULL_COOLDOWN_SECONDS:
        wait = int(ROUTER_LOG_PULL_COOLDOWN_SECONDS - (now - last).total_seconds()) + 1
        raise HTTPException(status_code=429, detail=f"Router logs were just read; try again in {wait}s")

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

    _last_pull[customer_id] = now
    result = await capture_router_logs(router_id, info, index, acquire_timeout_seconds=2.0)
    error = result.get("error")
    if error == "busy":
        _last_pull.pop(customer_id, None)
        raise HTTPException(status_code=429, detail="Router is busy with other diagnostics; try again shortly")
    if error in ("connect_failed", "timeout"):
        await record_router_availability(db, router_id, False, "customer_audit_router_logs")
        raise HTTPException(
            status_code=503 if error == "connect_failed" else 504,
            detail="Could not reach the router; only previously saved log lines are shown",
        )
    if error:
        raise HTTPException(status_code=502, detail=f"Router log read failed: {error}")
    await record_router_availability(db, router_id, True, "customer_audit_router_logs")
    return {"customer_id": customer_id, "router_id": router_id, **result}
