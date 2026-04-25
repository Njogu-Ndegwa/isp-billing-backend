"""Fair Usage Policy (FUP) enforcement for PPPoE customers.

Called once per snapshot cycle from the bandwidth collection job, and from
renewal hooks (payment / mpesa / momo / zenopay reconciliation) to revert.

Idempotency rules
-----------------
* :func:`evaluate_and_enforce` only takes router action when
  ``period.fup_triggered_at`` is ``None`` (transition into FUP) or when the
  user falls back below the cap and a previous trigger has not been reverted
  (transition out of FUP).
* :func:`revert` is safe to call any number of times; if there is no trigger
  to undo, it is a no-op.

All router I/O runs in a thread pool via :func:`asyncio.to_thread` so the
snapshot job's event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerUsagePeriod,
    FupAction,
    Plan,
    Router,
)
from app.services.mikrotik_api import MikroTikAPI

logger = logging.getLogger("fup")


# --------------------------- Helpers ---------------------------


def _cap_bytes(period: CustomerUsagePeriod, plan: Optional[Plan]) -> Optional[int]:
    """Return the byte cap for this period, or ``None`` if uncapped."""
    cap_mb = period.cap_mb_snapshot if period.cap_mb_snapshot is not None else (
        plan.data_cap_mb if plan else None
    )
    if not cap_mb or cap_mb <= 0:
        return None
    return int(cap_mb) * 1024 * 1024


def _effective_action(period: CustomerUsagePeriod, plan: Optional[Plan]) -> FupAction:
    """Action to apply when the cap is hit.  Snapshot wins, plan is fallback."""
    return (
        period.fup_action_snapshot
        or (plan.fup_action if plan else None)
        or FupAction.THROTTLE
    )


async def _load_router(db: AsyncSession, router_id: int) -> Optional[Router]:
    if not router_id:
        return None
    r = await db.execute(select(Router).where(Router.id == router_id))
    return r.scalar_one_or_none()


def _router_info(router: Router) -> dict:
    return {
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port,
    }


# --------------------------- Sync MikroTik helpers ---------------------------


def _set_secret_profile_sync(router_info: dict, username: str, profile: str) -> dict:
    """Set the PPP secret's ``profile`` and re-enable it; disconnect active session."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        result = api.send_command("/ppp/secret/set", {
            "numbers": username,
            "profile": profile,
            "disabled": "no",
        })
        api.disconnect_pppoe_session(username)
        return result
    finally:
        api.disconnect()


def _disable_secret_sync(router_info: dict, username: str) -> dict:
    """Set ``disabled=yes`` on the PPP secret and disconnect any active session."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        result = api.send_command("/ppp/secret/set", {
            "numbers": username,
            "disabled": "yes",
        })
        api.disconnect_pppoe_session(username)
        return result
    finally:
        api.disconnect()


# --------------------------- Public API ---------------------------


async def apply_throttle(
    db: AsyncSession, customer: Customer, plan: Optional[Plan]
) -> dict:
    """Switch the user's PPP secret to the plan's throttle profile."""
    if not customer.pppoe_username:
        return {"error": "no_pppoe_username"}
    profile = (plan.fup_throttle_profile if plan else None) or "default"
    router = await _load_router(db, customer.router_id)
    if not router:
        return {"error": "no_router"}
    info = _router_info(router)
    return await asyncio.to_thread(
        _set_secret_profile_sync, info, customer.pppoe_username, profile
    )


async def apply_block(db: AsyncSession, customer: Customer) -> dict:
    """Disable the user's PPP secret and kick any active session."""
    if not customer.pppoe_username:
        return {"error": "no_pppoe_username"}
    router = await _load_router(db, customer.router_id)
    if not router:
        return {"error": "no_router"}
    info = _router_info(router)
    return await asyncio.to_thread(
        _disable_secret_sync, info, customer.pppoe_username
    )


async def restore_normal_profile(
    db: AsyncSession, customer: Customer, plan: Optional[Plan]
) -> dict:
    """Restore the user's PPP secret to the plan's normal ``router_profile``."""
    if not customer.pppoe_username:
        return {"error": "no_pppoe_username"}
    profile = (plan.router_profile if plan else None) or "default"
    router = await _load_router(db, customer.router_id)
    if not router:
        return {"error": "no_router"}
    info = _router_info(router)
    return await asyncio.to_thread(
        _set_secret_profile_sync, info, customer.pppoe_username, profile
    )


async def evaluate_and_enforce(
    db: AsyncSession,
    customer: Customer,
    period: CustomerUsagePeriod,
    plan: Optional[Plan] = None,
    now: Optional[datetime] = None,
) -> Optional[FupAction]:
    """Decide whether to trigger or release FUP, taking router action as needed.

    Returns the action that was applied (if any), or ``None`` if no change.
    """
    plan = plan if plan is not None else customer.plan
    if not plan or plan.connection_type != ConnectionType.PPPOE:
        return None

    cap_bytes = _cap_bytes(period, plan)
    if cap_bytes is None:
        # Uncapped plan: if a stale trigger exists, clear it.
        if period.fup_triggered_at and not period.fup_reverted_at:
            await restore_normal_profile(db, customer, plan)
            period.fup_reverted_at = now or datetime.utcnow()
        return None

    now = now or datetime.utcnow()
    over_cap = (period.total_bytes or 0) >= cap_bytes

    if over_cap and period.fup_triggered_at is None:
        action = _effective_action(period, plan)
        logger.info(
            f"[FUP] Trigger {action.value} for customer={customer.id} "
            f"({customer.pppoe_username}) used={period.total_bytes} cap={cap_bytes}"
        )
        if action == FupAction.THROTTLE:
            res = await apply_throttle(db, customer, plan)
            if res.get("error"):
                logger.error(f"[FUP] Throttle failed for {customer.pppoe_username}: {res}")
                return None
        elif action == FupAction.BLOCK:
            res = await apply_block(db, customer)
            if res.get("error"):
                logger.error(f"[FUP] Block failed for {customer.pppoe_username}: {res}")
                return None
        elif action == FupAction.NOTIFY_ONLY:
            pass

        period.fup_triggered_at = now
        period.fup_action_taken = action
        period.fup_reverted_at = None
        return action

    if not over_cap and period.fup_triggered_at and not period.fup_reverted_at:
        # User dropped below the cap (rare mid-period; mostly via renewal).
        logger.info(
            f"[FUP] Auto-revert for customer={customer.id} ({customer.pppoe_username}) "
            f"used={period.total_bytes} < cap={cap_bytes}"
        )
        if period.fup_action_taken in (FupAction.THROTTLE, FupAction.BLOCK):
            await restore_normal_profile(db, customer, plan)
        period.fup_reverted_at = now
        return None

    return None


async def revert(
    db: AsyncSession,
    customer: Customer,
    plan: Optional[Plan] = None,
    period: Optional[CustomerUsagePeriod] = None,
    now: Optional[datetime] = None,
) -> bool:
    """Unconditionally restore the user's normal profile / re-enable secret.

    Called from renewal hooks after payment.  If ``period`` is supplied (the
    just-closed previous period), its ``fup_reverted_at`` is set so the
    history reflects the revert.  Returns True if router action was taken.
    """
    plan = plan if plan is not None else customer.plan
    if not customer.pppoe_username or not plan or plan.connection_type != ConnectionType.PPPOE:
        return False

    needs_action = True
    if period is not None and period.fup_triggered_at is None:
        needs_action = False

    if needs_action:
        try:
            res = await restore_normal_profile(db, customer, plan)
            if res.get("error"):
                logger.warning(
                    f"[FUP] Revert profile failed for {customer.pppoe_username}: {res}"
                )
        except Exception as e:
            logger.error(f"[FUP] Revert error for {customer.pppoe_username}: {e}")

    if period is not None and period.fup_triggered_at and not period.fup_reverted_at:
        period.fup_reverted_at = now or datetime.utcnow()

    return needs_action
