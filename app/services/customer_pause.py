"""Pause and resume a customer's subscription (PPPoE and static IP).

A reseller can freeze a paying customer's subscription -- the customer is
travelling, the house is empty for a month -- and continue it later with the
same paid time left. Before this existed the only option was Deactivate, which
throws the remaining paid time away.

State (all on ``customers``):

* ``paused_at``                - when the pause started; NULL = not paused.
* ``paused_remaining_seconds`` - the paid time that was left (expiry - now).
* ``pause_resume_at``          - optional time the scheduler resumes them.

While paused the customer is ``INACTIVE`` and ``expiry`` is frozen at the
pause moment. That is deliberate: every job in this app decides access from
``status == ACTIVE`` and/or "expiry still in the future", so a paused customer
looks exactly like one whose time has run out to all of them, and none of them
needs to know pauses exist:

* expiry cleanup, reminders and expiry SMS only look at ACTIVE customers;
* the PPPoE retry worker and recovery sweep only re-add secrets for ACTIVE,
  unexpired customers;
* the inactive-PPPoE safety net keeps removing a paused customer's secret if
  it ever reappears; static-IP enforcement keeps their binding disabled;
* grace never applies while paused (``customer_grace.effective_expiry``).

A payment while paused (paybill, M-Pesa, cash activation) makes the customer
ACTIVE through the normal renewal path; a ``before_flush`` hook in
``app/db/models.py`` then ends the pause and adds the paused time on top of the
new expiry (:func:`end_pause_on_activation`), so nobody loses paid days and a
pause can never be left behind on a paying customer.

Router writes reuse the existing paths: PPPoE pause = the same secret removal
and session drop as Deactivate (the username/password stay in the DB, so on
resume the secret comes back unchanged and the customer's router simply dials
again); PPPoE resume = ``push_active_pppoe_customer`` (retrying delivery);
static IP = ``provision_static_customer`` with access forced off / back on.

Database Session Discipline (AGENTS.md): every DB read/write happens in a
short session that is closed before any RouterOS I/O.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import database as db_module
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    FupAction,
    ProvisioningLog,
    UserRole,
)
from app.services.customer_events import actor_label, enqueue_events, record_customer_event
from app.services.pppoe_provisioning import (
    active_fup_restriction,
    build_pppoe_remove_payload,
    call_pppoe_remove,
)
from app.services.pppoe_resync import push_active_pppoe_customer
from app.services.static_ip import normalize_static_ip, provision_static_customer

logger = logging.getLogger("customer_pause")

KIND_PPPOE = "pppoe"
KIND_STATIC = "static"

# An auto-resume date further out than this is almost certainly a typo.
MAX_AUTO_RESUME_AHEAD = timedelta(days=366)
AUTO_RESUME_BATCH = 20


class PauseError(Exception):
    """A pause/resume request that cannot be carried out (HTTP status + reason)."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


# ---------------------------------------------------------------------------
# Small helpers (also used by the customer API serializers)
# ---------------------------------------------------------------------------

def is_paused(customer: Any) -> bool:
    return getattr(customer, "paused_at", None) is not None


def format_duration(seconds: Optional[int]) -> str:
    """'12d 4h', '3h 20m', '45m' -- the remaining-time wording in audit lines."""
    seconds = max(0, int(seconds or 0))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def pause_fields(customer: Any) -> dict:
    paused_at = getattr(customer, "paused_at", None)
    resume_at = getattr(customer, "pause_resume_at", None)
    return {
        "is_paused": paused_at is not None,
        "paused_at": paused_at.isoformat() if paused_at else None,
        "paused_remaining_seconds": (
            getattr(customer, "paused_remaining_seconds", None) if paused_at else None
        ),
        "pause_resume_at": resume_at.isoformat() if (paused_at and resume_at) else None,
    }


def normalize_resume_at(value: Optional[datetime], now: datetime) -> Optional[datetime]:
    """Validate an optional auto-resume time; returns naive UTC or None."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    if value <= now + timedelta(minutes=1):
        raise PauseError(400, "The auto-resume date must be in the future.")
    if value > now + MAX_AUTO_RESUME_AHEAD:
        raise PauseError(400, "The auto-resume date is more than a year away. Check the year.")
    return value


def _clear_pause(customer: Customer) -> None:
    customer.paused_at = None
    customer.paused_remaining_seconds = None
    customer.pause_resume_at = None


def end_pause_on_activation(customer: Customer, now: Optional[datetime] = None) -> None:
    """Called from the ``before_flush`` hook when a paused customer turns ACTIVE.

    Sync and side-effect free apart from queuing an audit row: it runs inside
    the caller's flush.
    """
    now = now or datetime.utcnow()
    remaining = max(0, int(customer.paused_remaining_seconds or 0))
    base = customer.expiry if customer.expiry is not None and customer.expiry > now else now
    customer.expiry = base + timedelta(seconds=remaining)
    _clear_pause(customer)
    logger.info(
        "[PAUSE] customer %s became active while paused; pause ended, %ss added (expiry %s)",
        customer.id, remaining, customer.expiry,
    )
    try:
        enqueue_events([{
            "customer_id": customer.id,
            "user_id": customer.user_id,
            "router_id": customer.router_id,
            "category": "change",
            "event_type": "customer_pause_ended",
            "severity": "info",
            "source": "system",
            "actor_user_id": None,
            "actor_label": None,
            "message": (
                f"Pause ended by a renewal: {format_duration(remaining)} of paused time added, "
                f"new expiry {customer.expiry:%Y-%m-%d %H:%M} UTC"
            ),
            "details": {"added_seconds": remaining},
        }])
    except Exception as exc:  # audit is best-effort; never break the payment flush
        logger.warning("[PAUSE] could not queue pause-ended event for %s: %s", customer.id, exc)


def _kind(customer: Customer) -> Optional[str]:
    plan = customer.plan
    if plan is None:
        return None
    if plan.connection_type == ConnectionType.PPPOE:
        return KIND_PPPOE
    if plan.connection_type == ConnectionType.STATIC_IP:
        return KIND_STATIC
    return None


async def _load(db, customer_id: int, actor) -> Customer:
    """The customer, scoped to the actor: the owning reseller, a platform admin,
    or the system (actor=None, scheduler only). Anyone else gets a 404."""
    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan), selectinload(Customer.router))
        .where(Customer.id == customer_id)
    )
    if actor is not None and getattr(actor, "role", None) != UserRole.ADMIN:
        stmt = stmt.where(Customer.user_id == actor.id)
    customer = (await db.execute(stmt)).scalar_one_or_none()
    if customer is None:
        raise PauseError(404, "Customer not found")
    return customer


def _result(customer: Customer, **extra) -> dict:
    return {
        "success": True,
        "customer_id": customer.id,
        "status": customer.status.value if customer.status else None,
        "expiry": customer.expiry.isoformat() if customer.expiry else None,
        **pause_fields(customer),
        **extra,
    }


def _who(actor, source: str) -> str:
    if actor is None:
        return "the auto-resume schedule" if source == "system" else "the system"
    return actor_label(actor) or "the reseller"


# ---------------------------------------------------------------------------
# Pause
# ---------------------------------------------------------------------------

async def pause_customer(
    customer_id: int,
    *,
    actor,
    resume_at: Optional[datetime] = None,
) -> dict:
    """Pause one customer: router first, then the DB (like Deactivate).

    Idempotent: pausing a paused customer returns its current pause unchanged.
    Raises :class:`PauseError` when the customer cannot be paused or the
    router did not confirm the cut (nothing is changed then).
    """
    now = datetime.utcnow()

    # 1. Validate and build the router payload (short session).
    async with db_module.async_session() as db:
        customer = await _load(db, customer_id, actor)
        if is_paused(customer):
            await db.commit()
            return _result(customer, already_paused=True, router_result="unchanged")
        kind = _kind(customer)
        if kind is None:
            raise PauseError(400, "Only PPPoE and static-IP customers can be paused.")
        if customer.subscription_owner_id is not None:
            raise PauseError(
                400, "This device shares another customer's subscription. Pause that customer instead.",
            )
        if customer.router is None:
            raise PauseError(400, "Customer has no router assigned")
        if customer.status != CustomerStatus.ACTIVE or customer.expiry is None or customer.expiry <= now:
            raise PauseError(
                400, "This customer has no paid time left to pause. Only an active, unexpired customer can be paused.",
            )
        resume_at = normalize_resume_at(resume_at, now)
        if kind == KIND_PPPOE:
            if not customer.pppoe_username:
                raise PauseError(400, "Customer does not have PPPoE credentials")
            if not customer.pppoe_password:
                # Pausing removes the secret; without the stored password we
                # could not put it back unchanged on resume.
                raise PauseError(
                    400, "This customer's PPPoE password is not saved. Save it on the customer first, then pause.",
                )
            payload = build_pppoe_remove_payload(customer, customer.router)
        else:
            if not normalize_static_ip(customer.static_ip):
                raise PauseError(400, "Customer has no valid static IP")
            payload = None
        await db.commit()

    # 2. Cut access on the router (no session held).
    if kind == KIND_PPPOE:
        router_out = await call_pppoe_remove(payload)
    else:
        router_out = await provision_static_customer(
            customer_id, action="customer_pause", force_enabled=False,
        )
    if not router_out or not router_out.get("success"):
        error = (router_out or {}).get("error") or "the router did not confirm"
        raise PauseError(
            503,
            "Could not pause this customer on the router; nothing was changed. "
            f"Please retry. Router error: {error}",
        )

    # 3. Record the pause (short session).
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        customer = await _load(db, customer_id, actor)
        if is_paused(customer):  # a concurrent click won the race
            await db.commit()
            return _result(customer, already_paused=True, router_result="ok")
        remaining = int((customer.expiry - now).total_seconds()) if customer.expiry else 0
        if customer.status != CustomerStatus.ACTIVE or remaining <= 0:
            # Expired (or changed) while the router was being updated: access
            # is already cut, so record it like a normal expiry.
            if customer.status == CustomerStatus.ACTIVE:
                customer.status = CustomerStatus.INACTIVE
            await db.commit()
            raise PauseError(409, "The subscription ran out while pausing; the customer is now inactive.")
        customer.paused_at = now
        customer.paused_remaining_seconds = remaining
        customer.pause_resume_at = resume_at
        customer.expiry = now
        customer.status = CustomerStatus.INACTIVE
        db.add(ProvisioningLog(
            customer_id=customer.id,
            router_id=customer.router_id,
            action="pppoe_deactivation" if kind == KIND_PPPOE else "static_ip_deactivation",
            status="success",
            details=(
                "Paused: session disconnected and secret removed from the router"
                if kind == KIND_PPPOE else "Paused: static-IP binding disabled on the router"
            ),
        ))
        await db.commit()
        out = _result(customer, already_paused=False, router_result="ok")
        router_id = customer.router_id
        owner_id = customer.user_id

    message = f"Paused by {_who(actor, 'admin')}, {format_duration(remaining)} left"
    if resume_at is not None:
        message += f"; auto-resume {resume_at:%Y-%m-%d %H:%M} UTC"
    message += (
        " (PPPoE session dropped, secret removed from the router)"
        if kind == KIND_PPPOE else " (static-IP access suspended on the router)"
    )
    await record_customer_event(
        customer_id, "customer_paused", message,
        actor=actor, user_id=owner_id, router_id=router_id,
        details={"remaining_seconds": remaining,
                 "resume_at": resume_at.isoformat() if resume_at else None},
    )
    return out


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------

async def _resume_pppoe_on_router(customer_id: int) -> dict:
    """Put a resumed PPPoE customer's secret back, keeping a FUP hold."""
    async with db_module.async_session() as db:
        hold = await active_fup_restriction(db, customer_id)
        await db.commit()
    if hold == FupAction.BLOCK:
        # Over the data cap this period: leave them off, exactly as before the
        # pause. Renewal or the daily FUP reset restores them.
        return {"result": "fup_blocked", "error": None}
    pushed = await push_active_pppoe_customer(customer_id, action="pppoe_resume")
    if hold == FupAction.THROTTLE and pushed.get("result") == "ok":
        from app.services.fup import apply_throttle

        async with db_module.async_session() as db:
            customer = (
                await db.execute(
                    select(Customer).options(selectinload(Customer.plan))
                    .where(Customer.id == customer_id)
                )
            ).scalar_one_or_none()
            if customer is not None:
                throttle = await apply_throttle(db, customer, customer.plan)  # commits before I/O
                if throttle.get("error"):
                    logger.warning("[PAUSE] re-throttle after resume failed for %s: %s",
                                   customer_id, throttle["error"])
            await db.commit()
    return pushed


async def resume_customer(customer_id: int, *, actor, source: str = "admin") -> dict:
    """Resume a paused customer: expiry = now + paused time, ACTIVE, router back on.

    The DB change is committed first; a router that cannot be reached right
    now does not undo the resume -- PPPoE delivery retries on its own and the
    static-IP enforcement job re-applies access on its next full pass.
    Resuming an ACTIVE, unpaused customer is a no-op.
    """
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        customer = await _load(db, customer_id, actor)
        if not is_paused(customer):
            await db.commit()
            if customer.status == CustomerStatus.ACTIVE:
                return _result(customer, already_active=True, router_result="unchanged")
            raise PauseError(400, "This customer is not paused.")
        kind = _kind(customer)
        remaining = max(0, int(customer.paused_remaining_seconds or 0))
        new_expiry = now + timedelta(seconds=remaining)
        # Clear the pause before flipping status so the before_flush hook
        # (which credits paused time on other activations) has nothing to do.
        _clear_pause(customer)
        customer.expiry = new_expiry
        customer.status = CustomerStatus.ACTIVE
        await db.commit()
        out = _result(customer, already_active=False)
        router_id = customer.router_id
        owner_id = customer.user_id

    # Router I/O, no session held.
    router_error = None
    if kind == KIND_PPPOE:
        pushed = await _resume_pppoe_on_router(customer_id)
        router_result = pushed.get("result") or "failed"
        router_error = pushed.get("error")
    elif kind == KIND_STATIC:
        applied = await provision_static_customer(customer_id, action="static_ip_resume")
        router_result = "ok" if applied.get("success") else "retry_pending"
        router_error = applied.get("error")
    else:  # plan changed to hotspot while paused: nothing of ours on a router
        router_result = "skipped"
    out["router_result"] = router_result
    out["router_error"] = router_error

    who = "Auto-resumed on schedule" if (actor is None and source == "system") else f"Resumed by {_who(actor, source)}"
    router_note = {
        "ok": "router updated, the customer can dial again",
        "fup_blocked": "router left off: data cap reached this period",
        "skipped": "no router change needed",
    }.get(router_result, f"router not updated yet: {router_error or 'will retry'}")
    await record_customer_event(
        customer_id, "customer_resumed",
        f"{who}, new expiry {new_expiry:%Y-%m-%d %H:%M} UTC "
        f"({format_duration(remaining)} restored); {router_note}",
        severity="info" if router_result in ("ok", "skipped", "fup_blocked") else "warning",
        source=source, actor=actor, user_id=owner_id, router_id=router_id,
        details={"restored_seconds": remaining, "router_result": router_result},
    )
    return out


# ---------------------------------------------------------------------------
# Scheduler: auto-resume
# ---------------------------------------------------------------------------

async def auto_resume_due_customers_background() -> dict:
    """Resume paused customers whose auto-resume time has come. Bounded batch."""
    from app.services.mikrotik_background import _background_db_pool_is_busy

    if _background_db_pool_is_busy("AUTO-RESUME"):
        return {"skipped": "db_pool_busy"}
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        due = (
            await db.execute(
                select(Customer.id)
                .where(
                    Customer.paused_at.isnot(None),
                    Customer.pause_resume_at.isnot(None),
                    Customer.pause_resume_at <= now,
                )
                .order_by(Customer.pause_resume_at, Customer.id)
                .limit(AUTO_RESUME_BATCH)
            )
        ).scalars().all()
        await db.commit()
    resumed, failed = 0, 0
    for customer_id in due:
        try:
            await resume_customer(customer_id, actor=None, source="system")
            resumed += 1
        except Exception as exc:
            failed += 1
            logger.warning("[PAUSE] auto-resume of customer %s failed: %s", customer_id, exc)
    if due:
        logger.info("[PAUSE] auto-resume: %d resumed, %d failed", resumed, failed)
    return {"due": len(due), "resumed": resumed, "failed": failed}
