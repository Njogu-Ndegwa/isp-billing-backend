"""Tell a reseller when the safety net cut off a device that had free internet.

Why (BD-8, OPIC NETWORKS, 2026-11-23): "Always inform me whenever one is
connected without paying". The safety-net bypass scan in
``mikrotik_background._cleanup_bypassing_for_all_routers`` already finds
``bypassed`` ip-bindings whose MAC has no active plan, no grace and no active
access credential, re-checks them against the database, and removes them. A
bypassed binding gets internet without the hotspot login, so each removal is a
device that was online without paying. This module only reports those
removals: it never contacts a router and adds no scheduler job.

* One inbox message per router, at most once every ``THROTTLE`` (in memory, so
  a restart can send one extra message; no schema change). Devices removed
  while a router is throttled are not reported.
* Devices are shown by the last two MAC octets only, never the full MAC.
* No message for admin-owned routers, owners who are suspended/inactive, or
  routers with status alerts switched off (``routers.status_alerts_enabled``).
* Own short DB session, called after all router I/O. Never raises.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Dict, Iterable, Optional

from sqlalchemy import select

from app.core.local_time import to_local
from app.db import database
from app.db.models import ResellerInboxMessage, Router, User, UserRole
from app.services.ops_health import is_owner_cut_off
from app.services.reseller_welcome import _resolve_sender_admin_id

logger = logging.getLogger(__name__)

THROTTLE = timedelta(hours=6)
MAX_DEVICES_LISTED = 5

# router_id -> when the last message for it was written.
_last_sent: Dict[int, datetime] = {}


def mac_tail(mac: str) -> str:
    """``AA:BB:CC:DD:EE:01`` -> ``...EE:01``."""
    compact = (mac or "").replace(":", "").replace("-", "").upper()
    tail = compact[-4:]
    return f"...{tail[:2]}:{tail[2:]}" if len(tail) == 4 else "..."


def render(router_name: str, macs: Iterable[str], at: datetime) -> tuple[str, str]:
    tails = sorted({mac_tail(m) for m in macs if m})
    shown = ", ".join(tails[:MAX_DEVICES_LISTED])
    if len(tails) > MAX_DEVICES_LISTED:
        shown += f" and {len(tails) - MAX_DEVICES_LISTED} more"
    count = len(tails)
    devices = "1 device" if count == 1 else f"{count} devices"
    when = to_local(at).strftime("%d %b %H:%M")
    subject = f"Unpaid device cut off: {router_name}"
    body = (
        f"Bitwave: on your router '{router_name}', {devices} had internet without an "
        f"active plan and {'was' if count == 1 else 'were'} cut off at {when} "
        f"(device {shown}). If one of them should stay online, give it a plan or a "
        f"voucher from the dashboard."
    )
    return subject, body


async def notify_unpaid_devices_removed(
    removed_by_router: Dict[int, Iterable[str]],
    now: Optional[datetime] = None,
) -> int:
    """Write one inbox message per eligible, unthrottled router. Returns messages written."""
    now = now or datetime.utcnow()
    try:
        due = {
            rid: set(macs)
            for rid, macs in removed_by_router.items()
            if macs and (rid not in _last_sent or now - _last_sent[rid] >= THROTTLE)
        }
        if not due:
            return 0
        written: list[int] = []
        async with database.async_session() as db:
            rows = (await db.execute(
                select(Router.id, Router.name, Router.status_alerts_enabled, User)
                .join(User, User.id == Router.user_id)
                .where(Router.id.in_(list(due)))
            )).all()
            for router_id, name, alerts_on, owner in rows:
                if (owner.role != UserRole.RESELLER
                        or is_owner_cut_off(owner.subscription_status)
                        or alerts_on is False):
                    continue
                sender_id = await _resolve_sender_admin_id(db, owner)
                if sender_id is None:
                    continue
                subject, body = render(name or f"#{router_id}", due[router_id], now)
                db.add(ResellerInboxMessage(
                    recipient_user_id=owner.id, sender_user_id=sender_id,
                    subject=subject, body=body,
                ))
                written.append(router_id)
            await db.commit()
        for router_id in written:
            _last_sent[router_id] = now
        if written:
            logger.info("[SAFETY-NET] Unpaid-device notice sent for router(s) %s", written)
        return len(written)
    except Exception as err:
        logger.warning("[SAFETY-NET] Could not send unpaid-device notices: %s", err)
        return 0
