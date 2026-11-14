"""Access-credential router changes that could not be made yet (2026-11-14).

Before this, creating or revoking an access credential while its router was
unreachable changed the DB and silently skipped the router: credentials 330
and 331 on router 118 existed only in the DB, and revoked 322/314/303 kept
their hotspot logins on the router (the revoke ignored the failed call).

Now the DB change stands (a revoked credential is refused by our login page at
once) and the router change still owed is recorded on the row
(``access_credentials.router_sync``: ``add`` / ``remove`` / ``delete``). It is
delivered by whichever comes first:

* **the API retry** (``retry_pending_credentials_background``, every 3 min):
  per router, with a growing back-off while it stays unreachable;
* **the check-in queue** (``router_checkin_actions``,
  ``sync_access_credentials``) for routers whose applier is v3: those keep
  checking in over public HTTPS when the tunnel is down.

Both are idempotent (add = upsert, remove = remove-if-present), and a router
write only clears the flag if the row still asks for the same change
(compare-and-set), so a change made in the meantime is never lost.

DB discipline: rows are read in one short session, the session is closed
before any RouterOS call, and each result is written in its own short session.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import delete, select, update

from app.db import database
from app.db.models import AccessCredential, Router, RouterAuthMethod

logger = logging.getLogger(__name__)

SYNC_ADD = "add"
SYNC_REMOVE = "remove"
SYNC_DELETE = "delete"
SYNC_STATES = (SYNC_ADD, SYNC_REMOVE, SYNC_DELETE)

RETRY_BATCH = 40
BACKOFF_START_SECONDS = 180
BACKOFF_MAX_SECONDS = 1800
POOL_PRESSURE_PERCENT = 60

UNREACHABLE_TEXT = "pending: router unreachable"

_backoff: dict[int, tuple[float, int]] = {}  # router_id -> (next try mono, delay s)


def reset_state() -> None:
    _backoff.clear()


def mark_pending(cred: AccessCredential, kind: str, *, error: Optional[str] = None,
                 mac: Optional[str] = None, now: Optional[datetime] = None) -> None:
    """Record on the (session-attached) row the router change still owed.

    The caller commits. A pending ``remove``/``delete`` keeps the MAC whose
    binding must go too (the row's own ``bound_mac_address`` is cleared by
    the revoke).
    """
    if kind not in SYNC_STATES:
        raise ValueError(f"unknown credential sync state {kind!r}")
    cred.router_sync = kind
    cred.router_sync_since = cred.router_sync_since or now or datetime.utcnow()
    cred.router_sync_error = (error or "")[:255] or None
    if kind == SYNC_ADD:
        cred.router_sync_mac = None
    elif mac:
        cred.router_sync_mac = mac


def clear_pending(cred: AccessCredential) -> None:
    cred.router_sync = None
    cred.router_sync_since = None
    cred.router_sync_error = None
    cred.router_sync_mac = None


async def queue_checkin_sync(router_id: int) -> None:
    """Also offer the change over the check-in queue. Never raises."""
    try:
        from app.services import router_checkin_actions as actions

        await actions.enqueue(router_id, actions.ACTION_SYNC_CREDENTIALS)
    except Exception:
        logger.exception("[ACCESS-CRED SYNC] could not queue check-in sync for router %s", router_id)


def pending_response_fields(cred: AccessCredential, message: Optional[str]) -> dict:
    """Extra keys for an API response about a credential left pending."""
    return {
        "provisioned": False,
        "pending": True,
        "router_status": UNREACHABLE_TEXT,
        "warning": (
            f"{message or 'Router could not be reached'}. Saved; it will be applied on the "
            "router as soon as the router is reachable (pending: router unreachable)."
        ),
    }


# ---------------------------------------------------------------------------
# Retry job
# ---------------------------------------------------------------------------

@dataclass
class _Work:
    cred_id: int
    kind: str
    router_id: int
    router_info: dict
    payload: dict


def _pool_busy() -> bool:
    try:
        percent = database.db_pool_snapshot().get("checked_out_percent")
        return percent is not None and float(percent) >= POOL_PRESSURE_PERCENT
    except Exception:
        return False


def _due(router_id: int, now_mono: float) -> bool:
    entry = _backoff.get(router_id)
    return entry is None or now_mono >= entry[0]


def _note_failure(router_id: int, now_mono: float) -> None:
    _, delay = _backoff.get(router_id, (0.0, 0))
    delay = BACKOFF_START_SECONDS if delay == 0 else min(BACKOFF_MAX_SECONDS, delay * 2)
    _backoff[router_id] = (now_mono + delay, delay)


async def _load_work(now_mono: float) -> tuple[list[_Work], set[int]]:
    from app.services.access_credentials import _router_info, comment_for_credential

    async with database.async_session() as db:
        rows = (await db.execute(
            select(AccessCredential, Router)
            .join(Router, Router.id == AccessCredential.router_id)
            .where(AccessCredential.router_sync.isnot(None))
            .order_by(AccessCredential.router_sync_since.asc().nullsfirst(), AccessCredential.id.asc())
            .limit(RETRY_BATCH)
        )).all()
        work = []
        routers: set[int] = set()
        for cred, router in rows:
            if router.auth_method != RouterAuthMethod.RADIUS:
                routers.add(router.id)
            if not _due(router.id, now_mono):
                continue
            if router.auth_method == RouterAuthMethod.RADIUS:
                # RADIUS credentials live in our DB; nothing is owed on the router.
                continue
            if cred.router_sync == SYNC_ADD:
                payload = {
                    "username": cred.username, "password": cred.password,
                    "rate_limit": cred.rate_limit or "", "comment": comment_for_credential(cred),
                }
            else:
                payload = {
                    "cred_id": cred.id, "username": cred.username,
                    "bound_mac_address": cred.router_sync_mac,
                }
            work.append(_Work(cred.id, cred.router_sync, router.id, _router_info(router), payload))
        await db.commit()
    return work, routers


async def _record(item: _Work, result: dict) -> None:
    async with database.async_session() as db:
        same = (AccessCredential.id == item.cred_id) & (AccessCredential.router_sync == item.kind)
        if result.get("error"):
            await db.execute(update(AccessCredential).where(same).values(
                router_sync_error=str(result.get("message") or result["error"])[:255]))
        elif item.kind == SYNC_DELETE:
            await db.execute(delete(AccessCredential).where(same))
        else:
            await db.execute(update(AccessCredential).where(same).values(
                router_sync=None, router_sync_since=None, router_sync_error=None, router_sync_mac=None))
        await db.commit()


async def retry_pending_credentials_background(*, now_mono: Optional[float] = None) -> dict:
    """Push owed credential changes to routers whose API answers again."""
    from app.services.access_credentials import (
        _deprovision_direct_api_sync,
        _provision_direct_api_sync,
    )

    now_mono = time.monotonic() if now_mono is None else now_mono
    stats = {"tried": 0, "applied": 0, "failed": 0}
    if _pool_busy():
        return stats
    work, routers = await _load_work(now_mono)
    # Keep the check-in route open for routers that check in with applier v3
    # (the queued sync action expires after a day; this re-queues it).
    from app.services import router_checkin_actions as actions

    for router_id in routers:
        if actions.router_can_take_actions(router_id):
            await queue_checkin_sync(router_id)
    failed_routers: set[int] = set()
    for item in work:
        if item.router_id in failed_routers:
            continue  # one unreachable router costs one connect per run, not one per credential
        fn = _provision_direct_api_sync if item.kind == SYNC_ADD else _deprovision_direct_api_sync
        stats["tried"] += 1
        try:
            result = await asyncio.to_thread(fn, item.router_info, item.payload)
        except Exception as exc:  # one bad router must not stop the batch
            result = {"error": "exception", "message": str(exc)[:200]}
        await _record(item, result)
        if result.get("error"):
            stats["failed"] += 1
            if result.get("error") == "connection_failed":
                failed_routers.add(item.router_id)
                _note_failure(item.router_id, now_mono)
        else:
            stats["applied"] += 1
            _backoff.pop(item.router_id, None)
            logger.info("[ACCESS-CRED SYNC] credential %s: %s applied on router %s",
                        item.cred_id, item.kind, item.router_id)
    return stats
