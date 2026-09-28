"""Keep the routers' EXP deadlines in step when an expiry moves later outside
a payment.

The router-side reaper (``router_expiry.py``) enforces the ``EXP:`` tag in each
ip-binding comment. Payments rewrite that tag when they deliver, but several
paths extend a customer's expiry in the database only:

* outage compensation (``outage_compensation.py``) - found on 2026-09-28, when
  a 6 h credit on router 141 left six bindings tagged at the old expiry;
* an admin editing the expiry (``PUT /api/customers/{id}``);
* device pairing / plan sharing mirroring the owner's expiry.

A tag that is too early is harmless while the router can reach the server (it
asks before removing, and the server answers "keep, until <new deadline>"),
but if the router cannot reach the server at that moment it falls back to its
own deadline and would remove a customer who has paid.

Two layers close that gap:

1. ``schedule_expiry_tag_sync(customer_ids)`` - called right after such a
   change commits; re-tags those customers' bindings within seconds.
2. ``expiry_tag_reconcile_background()`` - every 15 minutes, reads the bindings
   of every reaper router and corrects any tag earlier than the paid expiry,
   whatever changed it (including paths that forgot to call layer 1, or a
   router that was offline when layer 1 ran).

Both only ever move a deadline LATER. A tag later than the database (an expiry
shortened by an admin) is left alone: the server backstop removes that customer
at the database expiry, and nothing here can cut a paying customer short.

Before a tag is rewritten, the paid expiry is re-read from the database and the
binding is re-read from the router, so a payment that lands meanwhile (and
writes a later tag itself) is never overwritten with an earlier one.

DB discipline (AGENTS.md): every DB read/write is a short session closed before
any RouterOS I/O.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import Customer, CustomerStatus, ProvisioningLog, Router, RouterAuthMethod
from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI
from app.services.router_expiry import expiry_second, normalize_mac, to_seconds

logger = logging.getLogger(__name__)

LOG_ACTION = "expiry_tag_resync"
RECONCILE_CONCURRENCY = 3
RECONCILE_BUDGET_SECONDS = 600
# Skip a router the health check saw offline this recently.
OFFLINE_SKIP = timedelta(minutes=10)

_TAG_RE = re.compile(r"EXP:(\d+)")

_running = False
_tasks: set = set()


@dataclass
class Target:
    id: int
    name: str
    ip: str
    username: str
    password: str
    port: int
    # MAC -> (customer id, latest paid expiry) over every paid row with that MAC.
    wanted: dict[str, tuple[int, datetime]] = field(default_factory=dict)


@dataclass
class TagFix:
    binding_id: str
    mac: str
    customer_id: int
    old_tag: int
    new_tag: int
    new_comment: str


def tag_seconds(comment: str) -> Optional[int]:
    m = _TAG_RE.search(comment or "")
    return to_seconds(int(m.group(1))) if m else None


def plan_fixes(bindings: Iterable[dict], wanted: dict[str, tuple[int, datetime]]) -> list[TagFix]:
    """Bindings whose EXP deadline is earlier than the customer's paid expiry.

    Only raises. The tag digits are replaced in place, so the rest of the
    comment (USER:, CHECKIN, the timestamp) keeps its layout. Bindings with no
    EXP tag (not enforced by the reaper) or an EXX tag (forgotten) are left.
    """
    fixes: list[TagFix] = []
    for b in bindings:
        mac = normalize_mac(b.get("mac-address", ""))
        if not mac or mac not in wanted or not b.get(".id"):
            continue
        comment = b.get("comment", "") or ""
        old = tag_seconds(comment)
        if old is None:
            continue
        customer_id, expiry = wanted[mac]
        new = expiry_second(expiry)
        if old >= new:
            continue
        fixes.append(TagFix(b[".id"], mac, customer_id, old, new,
                            _TAG_RE.sub(f"EXP:{new}", comment, count=1)))
    return fixes


# ---------------------------------------------------------------------------
# Database (short sessions only)
# ---------------------------------------------------------------------------

async def load_targets(now: datetime, customer_ids: Optional[list[int]] = None) -> list[Target]:
    """Reaper routers and the paid-up hotspot MACs on them.

    With ``customer_ids``: only those customers' routers and MACs (the latest
    expiry per MAC still counts every paid row with that MAC).
    """
    async with database.async_session() as db:
        router_q = select(Router).where(
            Router.expiry_reaper_enabled.is_(True),
            Router.ip_address.isnot(None),
        )
        macs_filter: Optional[set[tuple[int, str]]] = None
        if customer_ids:
            rows = (await db.execute(
                select(Customer.router_id, Customer.mac_address)
                .where(Customer.id.in_(list(customer_ids)),
                       Customer.pppoe_username.is_(None),
                       Customer.mac_address.isnot(None),
                       Customer.router_id.isnot(None))
            )).all()
            macs_filter = {(rid, normalize_mac(mac)) for rid, mac in rows if normalize_mac(mac)}
            if not macs_filter:
                await db.commit()
                return []
            router_q = router_q.where(Router.id.in_({rid for rid, _ in macs_filter}))
        routers = (await db.execute(router_q)).scalars().all()
        targets: dict[int, Target] = {}
        for r in routers:
            if getattr(r, "auth_method", None) == RouterAuthMethod.RADIUS:
                continue
            if customer_ids is None and r.last_status is False and r.last_checked_at \
                    and now - r.last_checked_at < OFFLINE_SKIP:
                continue
            targets[r.id] = Target(r.id, r.name or f"router {r.id}", r.ip_address,
                                   r.username, r.password, r.port or 8728)
        if targets:
            paid = (await db.execute(
                select(Customer.id, Customer.router_id, Customer.mac_address, Customer.expiry)
                .where(Customer.router_id.in_(list(targets)),
                       Customer.status == CustomerStatus.ACTIVE,
                       Customer.pppoe_username.is_(None),
                       Customer.mac_address.isnot(None),
                       Customer.expiry > now)
            )).all()
            for cid, rid, raw_mac, expiry in paid:
                mac = normalize_mac(raw_mac)
                if not mac or (macs_filter is not None and (rid, mac) not in macs_filter):
                    continue
                cur = targets[rid].wanted.get(mac)
                if cur is None or expiry > cur[1]:
                    targets[rid].wanted[mac] = (cid, expiry)
        await db.commit()
    return [t for t in targets.values() if t.wanted]


async def fresh_wanted(router_id: int, macs: Iterable[str], now: datetime) -> dict[str, tuple[int, datetime]]:
    """The latest paid expiry for these MACs, read again just before writing."""
    macs = set(macs)
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Customer.id, Customer.mac_address, Customer.expiry)
            .where(Customer.router_id == router_id,
                   Customer.status == CustomerStatus.ACTIVE,
                   Customer.pppoe_username.is_(None),
                   Customer.mac_address.isnot(None),
                   Customer.expiry > now)
        )).all()
        await db.commit()
    out: dict[str, tuple[int, datetime]] = {}
    for cid, raw_mac, expiry in rows:
        mac = normalize_mac(raw_mac)
        if mac in macs and (mac not in out or expiry > out[mac][1]):
            out[mac] = (cid, expiry)
    return out


async def record_fixes(router_id: int, fixes: list[TagFix], reason: str) -> None:
    if not fixes:
        return
    now = datetime.utcnow()
    async with database.async_session() as db:
        for f in fixes:
            db.add(ProvisioningLog(
                customer_id=f.customer_id, router_id=router_id, mac_address=f.mac,
                action=LOG_ACTION, status="success", log_date=now,
                details=(f"Router deadline moved later by {f.new_tag - f.old_tag}s "
                         f"({f.old_tag} -> {f.new_tag}) after {reason}")[:255],
            ))
        await db.commit()


# ---------------------------------------------------------------------------
# RouterOS (sync; run in a worker thread with no DB session open)
# ---------------------------------------------------------------------------

def _api(t: Target) -> MikroTikAPI:
    return MikroTikAPI(t.ip, t.username, t.password, t.port,
                       timeout=15, connect_timeout=5, lane=LANE_BACKGROUND)


def read_bindings_sync(t: Target) -> Optional[list[dict]]:
    api = _api(t)
    if not api.connect():
        return None
    try:
        res = api.send_command("/ip/hotspot/ip-binding/print")
        return None if res.get("error") else (res.get("data") or [])
    finally:
        api.disconnect()


def apply_fixes_sync(t: Target, wanted: dict[str, tuple[int, datetime]]) -> list[TagFix]:
    """Re-read the bindings and raise whatever is still early against the
    freshly read ``wanted``. Returns what was written."""
    api = _api(t)
    if not api.connect():
        return []
    done: list[TagFix] = []
    try:
        res = api.send_command("/ip/hotspot/ip-binding/print")
        if res.get("error"):
            return []
        for f in plan_fixes(res.get("data") or [], wanted):
            out = api.send_command("/ip/hotspot/ip-binding/set",
                                   {".id": f.binding_id, "comment": f.new_comment})
            if not out.get("error"):
                done.append(f)
        return done
    finally:
        api.disconnect()


async def sync_router(t: Target, reason: str, now: datetime) -> int:
    from app.services.mikrotik_background import router_locks

    key = f"{t.ip}:{t.port}"
    async with router_locks.acquire_router_only(key):
        bindings = await asyncio.to_thread(read_bindings_sync, t)
    if not bindings:
        return 0
    early = plan_fixes(bindings, t.wanted)
    if not early:
        return 0
    wanted = await fresh_wanted(t.id, {f.mac for f in early}, now)
    if not wanted:
        return 0
    async with router_locks.acquire_router_only(key):
        done = await asyncio.to_thread(apply_fixes_sync, t, wanted)
    await record_fixes(t.id, done, reason)
    if done:
        logger.warning(
            "[EXPIRY-TAG] router %s (%s): moved %d early deadline(s) later after %s: %s",
            t.id, t.name, len(done), reason,
            ", ".join(f"customer {f.customer_id} +{f.new_tag - f.old_tag}s" for f in done[:20]),
        )
    return len(done)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

async def sync_expiry_tags(customer_ids: list[int], reason: str) -> int:
    """Re-tag these customers' bindings now. Never raises."""
    if not settings.EXPIRY_TAG_SYNC_ENABLED or not customer_ids:
        return 0
    try:
        now = datetime.utcnow()
        targets = await load_targets(now, customer_ids=list(customer_ids))
        results = await asyncio.gather(*[sync_router(t, reason, now) for t in targets],
                                       return_exceptions=True)
        for t, r in zip(targets, results):
            if isinstance(r, Exception):
                logger.warning("[EXPIRY-TAG] router %s sync after %s failed: %s", t.id, reason, r)
        return sum(r for r in results if isinstance(r, int))
    except Exception:  # noqa: BLE001 - background task: log, never raise
        logger.exception("[EXPIRY-TAG] sync after %s failed", reason)
        return 0


def schedule_expiry_tag_sync(customer_ids: Iterable[int], reason: str) -> None:
    """Fire-and-forget, AFTER the expiry change has committed. Never raises.

    The reaper only enforces tags on hotspot bindings; PPPoE customers and
    routers not on the reaper are filtered out inside."""
    try:
        ids = sorted({int(c) for c in customer_ids if c is not None})
        if not ids or not settings.EXPIRY_TAG_SYNC_ENABLED:
            return
        task = asyncio.get_running_loop().create_task(sync_expiry_tags(ids, reason))
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
    except Exception:  # noqa: BLE001
        logger.exception("[EXPIRY-TAG] could not schedule sync after %s", reason)


async def expiry_tag_reconcile_background() -> int:
    """Every 15 min: correct early deadlines on every reaper router."""
    global _running
    if not settings.EXPIRY_TAG_SYNC_ENABLED or _running:
        return 0
    from app.services.mikrotik_background import _background_db_pool_is_busy

    if _background_db_pool_is_busy("EXPIRY-TAG"):
        return 0
    _running = True
    started = time.monotonic()
    try:
        now = datetime.utcnow()
        targets = await load_targets(now)
        sem = asyncio.Semaphore(RECONCILE_CONCURRENCY)

        async def one(t: Target) -> int:
            if time.monotonic() - started > RECONCILE_BUDGET_SECONDS:
                return 0
            async with sem:
                if time.monotonic() - started > RECONCILE_BUDGET_SECONDS:
                    return 0
                return await sync_router(t, "reconcile", now)

        results = await asyncio.gather(*[one(t) for t in targets], return_exceptions=True)
        fixed = sum(r for r in results if isinstance(r, int))
        errors = sum(1 for r in results if isinstance(r, Exception))
        logger.info("[EXPIRY-TAG] reconcile: %d router(s), %d deadline(s) moved later, %d error(s), %.0fs",
                    len(targets), fixed, errors, time.monotonic() - started)
        return fixed
    except Exception:  # noqa: BLE001
        logger.exception("[EXPIRY-TAG] reconcile failed")
        return 0
    finally:
        _running = False
