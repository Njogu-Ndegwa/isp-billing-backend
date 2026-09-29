"""Keep every router's expiry reaper script on the current version.

The router reports its script version on each expiry-check call (``v=``;
scripts before v2 send none). When a router on the reaper reports an older
version than ``SCRIPT_VERSION``, the server rewrites the script's source in
place. The scheduler and the script's globals are kept, so a pending removal
report and the server-confirmed clock survive the upgrade.

The call itself proves the router is online and reachable, so routers that
were offline during a fleet rollout (9 of 67 on 2026-09-29, when v2 taught the
script MAC-login users) catch up on their own the next time they check in.
New routers get the current script at enrolment (expiry_reaper_enrol.py).

At most one attempt per router per ``UPGRADE_RETRY``. Only the source is
rewritten; nothing on the router that grants or limits access is touched.

DB discipline (AGENTS.md): the router's address and credentials are read in a
short session that is closed before any RouterOS I/O.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import Router
from app.services.expiry_reaper_script import (
    SCRIPT_NAME, SCRIPT_VERSION, render_expiry_reaper_script, script_source,
)
from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI

logger = logging.getLogger(__name__)

UPGRADE_RETRY_SECONDS = 6 * 3600
# A router that checks in while its management tunnel is still coming up
# (2026-09-29: router 210 reported v1 a few seconds before its tunnel was up)
# is tried again soon, not in 6 hours.
UNREACHABLE_RETRY_SECONDS = 10 * 60

_attempted: dict[str, float] = {}
_tasks: set = set()


def version_marker(version: int = SCRIPT_VERSION) -> str:
    """What the current script sends; present in its source."""
    return f"&v={version}&"


def reset_state() -> None:
    """Test hook."""
    _attempted.clear()


def upgrade_script_sync(ip: str, username: str, password: str, port: int, identity: str) -> str:
    """Rewrite the reaper script source if it is not current. Returns an outcome
    word: ``upgraded``, ``current``, ``no script``, ``unreachable`` or an error."""
    api = MikroTikAPI(ip, username, password, port or 8728, timeout=30, connect_timeout=8,
                      lane=LANE_BACKGROUND)
    if not api.connect():
        return "unreachable"
    try:
        scripts = [s for s in api.send_command("/system/script/print").get("data") or []
                   if s.get("name") == SCRIPT_NAME]
        if not scripts:
            return "no script"
        if version_marker() in str(scripts[0].get("source", "")):
            return "current"
        rendered = render_expiry_reaper_script(
            identity=identity,
            tunnel_url=settings.EXPIRY_REAPER_TUNNEL_URL,
            public_url=settings.EXPIRY_REAPER_PUBLIC_URL,
        )
        result = api.send_command("/system/script/set",
                                  {".id": scripts[0][".id"], "source": script_source(rendered)})
        if result.get("error"):
            return f"error: {result['error']}"[:120]
        return "upgraded"
    finally:
        api.disconnect()


async def upgrade_router(identity: str) -> Optional[str]:
    """Upgrade one router's script. Never raises."""
    try:
        async with database.async_session() as db:
            r = (await db.execute(
                select(Router.id, Router.ip_address, Router.username, Router.password,
                       Router.port, Router.identity, Router.expiry_reaper_enabled)
                .where(Router.identity == identity)
            )).first()
            await db.commit()
        if r is None or not r.expiry_reaper_enabled or not r.ip_address:
            return None
        from app.services.mikrotik_background import router_locks

        async with router_locks.acquire_router_only(f"{r.ip_address}:{r.port}"):
            outcome = await asyncio.to_thread(
                upgrade_script_sync, r.ip_address, r.username, r.password, r.port, r.identity)
        if outcome == "unreachable" and identity in _attempted:
            _attempted[identity] -= UPGRADE_RETRY_SECONDS - UNREACHABLE_RETRY_SECONDS
        log = logger.info if outcome in ("upgraded", "current") else logger.warning
        log("[REAPER-UPGRADE] router %s (%s): %s to v%s", r.id, identity, outcome, SCRIPT_VERSION)
        return outcome
    except Exception:  # noqa: BLE001 - background task: log, never raise
        logger.exception("[REAPER-UPGRADE] upgrade of %s failed", identity)
        return None


def maybe_schedule_upgrade(identity: str, reported_version: int,
                           now_mono: Optional[float] = None) -> bool:
    """Called by the expiry-check endpoint after it answers. Schedules an
    in-place upgrade when the router runs an older script. Never raises."""
    try:
        if not settings.EXPIRY_REAPER_AUTO_UPGRADE or reported_version >= SCRIPT_VERSION:
            return False
        now_mono = time.monotonic() if now_mono is None else now_mono
        last = _attempted.get(identity)
        if last is not None and now_mono - last < UPGRADE_RETRY_SECONDS:
            return False
        _attempted[identity] = now_mono
        task = asyncio.get_running_loop().create_task(upgrade_router(identity))
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
        return True
    except Exception:  # noqa: BLE001
        logger.exception("[REAPER-UPGRADE] could not schedule upgrade of %s", identity)
        return False
