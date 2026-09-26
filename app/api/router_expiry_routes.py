"""Router-facing expiry endpoint: the platform side of the expiry reaper.

The router asks before it removes anyone and reports after; the protocol and
its reasoning are in ``app/services/router_expiry.py``.

This handler touches only the database (one short session) and returns. Anything
slow that a report can trigger (re-provisioning a customer the router removed
although they had renewed, expiry SMS) runs after the commit in background tasks
that open their own sessions (AGENTS.md, Database Session Discipline).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.db.database import async_session, db_pool_snapshot
from app.db.models import Customer, CustomerStatus, ProvisioningLog, Router as RouterModel
from app.services import customer_expiry_notifications
from app.services.router_expiry import (
    DONE_MINUTE_MAX_SKEW,
    done_time_to_datetime,
    CustomerRow,
    clock_ok,
    decide,
    parse_request,
    render_reply,
)
from app.services.usage_push_auth import verify_router_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["router-expiry"])

# A healthy reaper calls at most once a minute (plus retries). Anything faster
# is a loop on the router; refuse it cheaply.
MIN_SECONDS_BETWEEN_CALLS = 20
POOL_PRESSURE_PERCENT = 60
RETRY_AFTER_ON_PRESSURE = 60
REAPER_LOG_DETAILS = "Router expiry reaper removed hotspot access"

_last_call_at: dict[str, float] = {}
_background_tasks: set = set()
# identity -> (last call, router clock trusted?) for diagnostics; process state.
last_seen: dict[str, tuple[datetime, bool]] = {}


def reset_rate_limiter() -> None:
    """Test hook: the limiter is process state."""
    _last_call_at.clear()
    last_seen.clear()


def _pool_under_pressure() -> bool:
    percent = db_pool_snapshot().get("checked_out_percent")
    try:
        return percent is not None and float(percent) >= POOL_PRESSURE_PERCENT
    except (TypeError, ValueError):
        return False


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def _repair_renewed(repairs: list[tuple[int, int, dict]]) -> None:
    """Re-provision customers the router removed although they had renewed
    (possible only when the router fell back to its own deadline offline)."""
    from app.services.hotspot_provisioning import provision_hotspot_customer

    for customer_id, router_id, payload in repairs:
        try:
            await provision_hotspot_customer(
                customer_id=customer_id, router_id=router_id,
                hotspot_payload=payload, action="expiry_reaper_repair",
            )
        except Exception as exc:  # the payment retry job remains the backstop
            logger.error("[EXPIRY-REAPER] repair of customer %s failed: %s", customer_id, exc)


async def _notify(customer_ids: list[int], now: datetime) -> None:
    try:
        campaign_ids = await customer_expiry_notifications.queue_customer_expiry_notifications(
            customer_ids, session_factory=async_session, now=now,
        )
        customer_expiry_notifications.spawn_expiry_campaign_dispatch(campaign_ids)
    except Exception as exc:
        logger.exception("[EXPIRY-REAPER] expiry notification queue failed: %s", exc)


@router.post("/api/router/expiry-check", response_class=PlainTextResponse)
async def expiry_check(request: Request, authorization: Optional[str] = Header(default=None)):
    raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        req = parse_request(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Bad request")

    presented = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else ""
    # Same 401 for every failure so the endpoint cannot enumerate routers.
    if not verify_router_token(req.identity, presented):
        raise HTTPException(status_code=401, detail="Unauthorized")

    mono = time.monotonic()
    last = _last_call_at.get(req.identity)
    if last is not None and mono - last < MIN_SECONDS_BETWEEN_CALLS:
        raise HTTPException(status_code=429, detail="Too many calls")
    if _pool_under_pressure():
        # Safe to refuse: the router keeps both lists and asks again later.
        raise HTTPException(status_code=503, detail="Busy, retry later",
                            headers={"Retry-After": str(RETRY_AFTER_ON_PRESSURE)})
    _last_call_at[req.identity] = mono

    now = datetime.utcnow()
    trusted = clock_ok(req.router_now, now)
    macs = sorted({m for m in req.due} | {m for m, _ in req.done})
    deactivated: list[int] = []
    repairs: list[tuple[int, int, dict]] = []

    async with async_session() as db:
        router_row = (await db.execute(
            select(RouterModel).where(RouterModel.identity == req.identity)
        )).scalars().first()
        if router_row is None:
            await db.commit()
            raise HTTPException(status_code=401, detail="Unauthorized")

        customers: list[Customer] = []
        if macs:
            customers = list((await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan))
                .where(Customer.router_id == router_row.id,
                       func.upper(Customer.mac_address).in_(macs))
            )).scalars().all())
        rows = [CustomerRow(c.id, (c.mac_address or "").upper(),
                            c.status == CustomerStatus.ACTIVE, c.expiry) for c in customers]
        remove, keep, forget = decide(req.due, rows, now)

        # Confirmed removals. The router removed these MACs on its own, after we
        # said "remove" (or offline, past its deadline). Record each ACTIVE row
        # whose expiry has passed; a row that renewed meanwhile gets its access
        # put back instead.
        by_mac: dict[str, list[Customer]] = {}
        for c in customers:
            by_mac.setdefault((c.mac_address or "").upper(), []).append(c)
        for mac, minute in req.done:
            removed_at = now
            if trusted and minute is not None:
                reported = done_time_to_datetime(minute)
                if abs((reported - now).total_seconds()) <= DONE_MINUTE_MAX_SKEW * 60:
                    removed_at = min(reported, now)
            for c in by_mac.get(mac, []):
                if c.status != CustomerStatus.ACTIVE or c.expiry is None:
                    continue
                if c.expiry > now:
                    if c.plan is not None:
                        from app.services.hotspot_provisioning import build_hotspot_payload
                        repairs.append((c.id, router_row.id, build_hotspot_payload(
                            c, c.plan, router_row, f"CID:{c.id}|expiry-reaper-repair")))
                    continue
                c.status = CustomerStatus.INACTIVE
                db.add(ProvisioningLog(
                    customer_id=c.id, router_id=router_row.id, mac_address=c.mac_address,
                    action="hotspot_deactivation", status="success",
                    details=REAPER_LOG_DETAILS, log_date=removed_at,
                ))
                deactivated.append(c.id)
        await db.commit()

    last_seen[req.identity] = (now, trusted)
    if remove or req.done or not trusted:
        logger.info(
            "[EXPIRY-REAPER] %s: clock %s, due=%d remove=%d keep=%d forget=%d confirmed=%d repaired=%d",
            req.identity, "ok" if trusted else f"OFF (router {req.router_now})", len(req.due),
            len(remove), len(keep), len(forget), len(deactivated), len(repairs),
        )
    if repairs:
        _spawn(_repair_renewed(repairs))
    if deactivated:
        _spawn(_notify(deactivated, now))
    return render_reply(trusted, remove, keep, forget)
