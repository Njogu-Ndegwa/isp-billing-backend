"""PPPoE device lock: a customer's PPPoE login only works from their own router.

Without it, a PPPoE username/password can be typed into any router (a
neighbour's, a second house) and used there. With the lock on, the customer's
PPP secret carries ``caller-id=<MAC>``: RouterOS then accepts the login only
from that MAC (the customer's CPE WAN MAC, which RouterOS reports as the
session's ``caller-id``), and rejects it from any other device.

State on ``customers`` (all off/NULL by default, so nobody is affected until a
reseller turns it on):

* ``pppoe_device_lock``       - the switch.
* ``pppoe_bound_mac``         - the device the login is locked to. Learned from
  the first session seen after the lock was turned on (or after "Allow new
  router" cleared it), or set by hand.
* ``pppoe_lock_learn_after``  - only a session that STARTED after this moment
  may be learned. "Allow new router" sets it, so the old router, if it is still
  connected, is not simply learned again.
* ``pppoe_lock_applied_mac``  - what we last wrote to the router's caller-id
  (NULL = nothing of ours there). Lets a lock that was turned off while the
  router was unreachable still be cleared later.

Every PPPoE provisioning path builds its payload with :func:`desired_caller_id`
so a renewal, plan change, recovery sweep or router move writes the same
caller-id again instead of wiping it. ``None`` there means "leave caller-id
alone", which is what every unlocked customer gets: their secrets are never
touched by this feature.

The reconcile job (:func:`reconcile_device_locks_background`) learns MACs and
retries router writes that did not land. It only looks at customers with the
lock on or a caller-id of ours still on the router, so with nobody locked it is
one small query per tick.

DB discipline (AGENTS.md): reads in a short session, router I/O with no session
held, results in a fresh short session.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("pppoe_device_lock")

_MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")

# Scheduler tuning. Locked customers are few; keep each tick small anyway.
RECONCILE_ROUTERS_PER_TICK = 8
RECONCILE_TIME_BUDGET_SECONDS = 60
RECONCILE_ACQUIRE_TIMEOUT_SECONDS = 2.0


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def normalize_mac(value: Any) -> Optional[str]:
    """``aa-bb-cc-dd-ee-ff`` / ``aabb.ccdd.eeff`` / ``AABBCCDDEEFF`` -> ``AA:BB:CC:DD:EE:FF``.

    Returns None for anything that is not a single 48-bit MAC, so a caller-id
    that is not a MAC (some PPPoE relays report other things) is never learned
    or written.
    """
    text = str(value or "").strip().upper()
    if not text:
        return None
    hex_only = re.sub(r"[^0-9A-F]", "", text)
    if len(hex_only) != 12 or re.search(r"[^0-9A-F:\-.\s]", text):
        return None
    mac = ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else None


def desired_caller_id(customer: Any) -> Optional[str]:
    """The caller-id a PPPoE push should write for this customer.

    * lock on and a device bound  -> that MAC
    * otherwise, a caller-id of ours is still on the router -> "" (clear it)
    * otherwise -> None: leave the secret's caller-id alone

    Works on a Customer row or anything with the same attributes.
    """
    lock = bool(getattr(customer, "pppoe_device_lock", False))
    bound = normalize_mac(getattr(customer, "pppoe_bound_mac", None))
    if lock and bound:
        return bound
    if getattr(customer, "pppoe_lock_applied_mac", None):
        return ""
    return None


def add_caller_id(payload: Dict[str, Any], customer: Any) -> Dict[str, Any]:
    """Put ``caller_id`` into a PPPoE provisioning payload when there is one.

    Unlocked customers get no key at all, so their payloads (and their
    secrets) are exactly as before this feature.
    """
    caller_id = desired_caller_id(customer)
    if caller_id is not None:
        payload["caller_id"] = caller_id
    return payload


def lock_fields(customer: Any) -> Dict[str, Any]:
    """The lock state as the admin API returns it."""
    bound_at = getattr(customer, "pppoe_bound_at", None)
    learn_after = getattr(customer, "pppoe_lock_learn_after", None)
    lock = bool(getattr(customer, "pppoe_device_lock", False))
    bound = getattr(customer, "pppoe_bound_mac", None)
    applied = getattr(customer, "pppoe_lock_applied_mac", None)
    desired = desired_caller_id(customer)
    return {
        "pppoe_device_lock": lock,
        "pppoe_bound_mac": bound,
        "pppoe_bound_at": bound_at.isoformat() if bound_at else None,
        "pppoe_lock_learn_after": learn_after.isoformat() if learn_after else None,
        "pppoe_lock_applied_mac": applied,
        # True while the router does not yet carry what the DB says
        # (router unreachable at the time; the reconcile job retries).
        "pppoe_lock_router_pending": desired is not None and (desired or None) != (applied or None),
        "pppoe_lock_state": (
            "off" if not lock else ("locked" if bound else "learning")
        ),
    }


def session_started_at(uptime: Any, now: datetime) -> Optional[datetime]:
    from app.services.customer_events import parse_uptime

    seconds = parse_uptime(str(uptime or ""))
    if seconds is None:
        return None
    return now - timedelta(seconds=seconds)


def learnable_mac(session: Optional[Dict[str, Any]], learn_after: Optional[datetime],
                  now: datetime) -> Optional[str]:
    """The MAC to bind from a live session, or None.

    With ``learn_after`` set, the session must have started after it (with a
    few seconds of slack for the router clock): a session that was already up
    when "Allow new router" was pressed belongs to the old device.
    """
    if not session:
        return None
    mac = normalize_mac(session.get("caller-id") or session.get("caller_id"))
    if not mac:
        return None
    if learn_after is not None:
        started = session_started_at(session.get("uptime"), now)
        if started is None or started < learn_after - timedelta(seconds=5):
            return None
    return mac


# ---------------------------------------------------------------------------
# RouterOS I/O (synchronous; run through run_with_guard)
# ---------------------------------------------------------------------------

def _connect(router_info: Dict[str, Any]):
    from app.services.mikrotik_api import MikroTikAPI

    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"],
        router_info.get("port") or 8728, timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return None
    return api


def _rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(result, dict) or not result.get("success"):
        return []
    data = result.get("data")
    return list(data) if isinstance(data, list) else []


def _active_sessions(api, usernames: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    wanted = {u for u in usernames if u}
    if not wanted:
        return {}
    result = api.send_command_optimized(
        "/ppp/active/print", proplist=["name", "caller-id", "uptime", "address"],
    )
    if not result.get("success"):
        raise RuntimeError(result.get("error") or "could not read /ppp active")
    sessions: Dict[str, Dict[str, Any]] = {}
    for row in _rows(result):
        name = str(row.get("name") or "").strip()
        if name in wanted and name not in sessions:
            sessions[name] = row
    return sessions


def _set_secret_caller_id(api, username: str, caller_id: str) -> Dict[str, Any]:
    """Write caller-id on one existing secret. A missing secret is not an error:
    the next provisioning push adds it with the caller-id from the payload."""
    found = api.send_command_optimized(
        "/ppp/secret/print", proplist=[".id", "name", "caller-id"], query=f"?name={username}",
    )
    if not found.get("success"):
        return {"error": found.get("error") or "could not read /ppp secret"}
    secret = next((r for r in _rows(found) if r.get("name") == username), None)
    if secret is None:
        return {"success": True, "absent": True}
    if (secret.get("caller-id") or "") == caller_id:
        return {"success": True, "unchanged": True}
    result = api.send_command("/ppp/secret/set", {
        "numbers": secret.get(".id") or username,
        "caller-id": caller_id,
    })
    if result.get("error"):
        return {"error": result["error"]}
    return {"success": True, "changed": True}


@dataclass
class LockWork:
    """One customer's lock work on one router, read from the DB."""
    customer_id: int
    username: str
    lock: bool
    bound_mac: Optional[str]
    learn_after: Optional[datetime]
    applied_mac: Optional[str]

    @property
    def needs_learning(self) -> bool:
        return self.lock and not self.bound_mac

    def target(self, learned: Optional[str] = None) -> Optional[str]:
        if self.lock and (learned or self.bound_mac):
            return learned or self.bound_mac
        if self.applied_mac:
            return ""
        return None


def reconcile_router_sync(router_info: Dict[str, Any], work: List[LockWork]) -> Dict[str, Any]:
    """Learn MACs from live sessions and bring each secret's caller-id in line.

    Returns ``{"results": {customer_id: {...}}}`` or ``{"error": ...}``. Never
    disconnects anyone: the session that taught us the MAC is the right device,
    and a session that is up is not re-checked by RouterOS anyway.
    """
    api = _connect(router_info)
    if api is None:
        return {"error": "Failed to connect to router"}
    try:
        now = datetime.utcnow()
        learners = [w for w in work if w.needs_learning]
        sessions = _active_sessions(api, (w.username for w in learners)) if learners else {}
        results: Dict[int, Dict[str, Any]] = {}
        for item in work:
            learned = None
            if item.needs_learning:
                learned = learnable_mac(sessions.get(item.username), item.learn_after, now)
            target = item.target(learned)
            outcome: Dict[str, Any] = {"learned_mac": learned}
            if target is not None and (target or None) != (item.applied_mac or None):
                write = _set_secret_caller_id(api, item.username, target)
                outcome.update(write)
                if write.get("success"):
                    outcome["applied_mac"] = target or None
            elif target is not None:
                outcome.update({"success": True, "unchanged": True, "applied_mac": item.applied_mac})
            results[item.customer_id] = outcome
        return {"success": True, "results": results}
    except Exception as exc:
        logger.warning("[PPPOE-LOCK] router %s reconcile failed: %s", router_info.get("ip"), exc)
        return {"error": str(exc)}
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Persisting outcomes
# ---------------------------------------------------------------------------

async def persist_outcomes(router_id: Optional[int], outcomes: Dict[int, Dict[str, Any]],
                           *, actor=None, source: str = "system") -> List[Dict[str, Any]]:
    """Write learned MACs and applied caller-ids in one short session.

    Re-checks each row first: a reseller may have turned the lock off or
    pressed "Allow new router" while the router I/O ran, and that wins.
    Returns the bind events to record.
    """
    from app.db import database as db_module
    from app.db.models import Customer

    if not outcomes:
        return []
    events: List[Dict[str, Any]] = []
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        for customer_id, outcome in outcomes.items():
            row = await db.get(Customer, customer_id)
            if row is None:
                continue
            learned = outcome.get("learned_mac")
            if learned and row.pppoe_device_lock and not row.pppoe_bound_mac:
                row.pppoe_bound_mac = learned
                row.pppoe_bound_at = now
                row.pppoe_lock_learn_after = None
                events.append({
                    "customer_id": row.id, "user_id": row.user_id, "router_id": row.router_id,
                    "mac": learned,
                })
            if outcome.get("success") and "applied_mac" in outcome:
                applied = outcome.get("applied_mac") or None
                # Only record it if it is still what the row wants; otherwise
                # the next tick writes the newer value.
                want = desired_caller_id(row)
                if want is not None and (want or None) == applied:
                    row.pppoe_lock_applied_mac = applied
                elif want is None and applied is None:
                    row.pppoe_lock_applied_mac = None
        await db.commit()

    if events:
        from app.services.customer_events import record_customer_event

        for ev in events:
            await record_customer_event(
                ev["customer_id"], "pppoe_device_locked",
                f"PPPoE login locked to device {ev['mac']} (learned from its first connection)",
                source=source, actor=actor, user_id=ev["user_id"], router_id=ev["router_id"],
                details={"mac": ev["mac"]},
            )
    return events


def work_from_customer(customer: Any) -> LockWork:
    return LockWork(
        customer_id=customer.id,
        username=customer.pppoe_username,
        lock=bool(customer.pppoe_device_lock),
        bound_mac=normalize_mac(customer.pppoe_bound_mac),
        learn_after=customer.pppoe_lock_learn_after,
        applied_mac=customer.pppoe_lock_applied_mac,
    )


def router_info_of(router: Any) -> Dict[str, Any]:
    return {
        "id": router.id,
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port or 8728,
    }


async def reconcile_customer_now(customer_id: int, *, actor=None,
                                 acquire_timeout_seconds: Optional[float] = 10.0) -> Dict[str, Any]:
    """Run one customer's learn + caller-id write right away (admin actions).

    Returns ``{"router_updated": bool, "error": str|None, "learned_mac": ...}``.
    A router that cannot be reached is not an error for the caller: the DB
    already says what should be there and the reconcile job retries.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.db import database as db_module
    from app.db.models import Customer
    from app.services.router_concurrency import run_with_guard

    async with db_module.async_session() as db:
        customer = (await db.execute(
            select(Customer).options(selectinload(Customer.router)).where(Customer.id == customer_id)
        )).scalar_one_or_none()
        if customer is None or not customer.pppoe_username or customer.router is None:
            await db.commit()
            return {"router_updated": False, "error": "Customer has no PPPoE login on a router"}
        router_id = customer.router.id
        info = router_info_of(customer.router)
        work = work_from_customer(customer)
        await db.commit()

    if work.target() is None and not work.needs_learning:
        return {"router_updated": True, "error": None, "learned_mac": None}
    try:
        raw = await run_with_guard(
            router_id, reconcile_router_sync, info, [work],
            acquire_timeout_seconds=acquire_timeout_seconds,
        )
    except Exception as exc:  # timeout / busy router
        raw = {"error": str(exc) or exc.__class__.__name__}
    if not isinstance(raw, dict) or raw.get("error"):
        return {"router_updated": False, "error": (raw or {}).get("error") if isinstance(raw, dict) else str(raw)}
    outcome = (raw.get("results") or {}).get(customer_id) or {}
    await persist_outcomes(router_id, {customer_id: outcome}, actor=actor,
                           source="admin" if actor is not None else "system")
    return {
        "router_updated": not outcome.get("error"),
        "error": outcome.get("error"),
        "learned_mac": outcome.get("learned_mac"),
        "secret_absent": bool(outcome.get("absent")),
    }


# ---------------------------------------------------------------------------
# Scheduler job
# ---------------------------------------------------------------------------

def _needs_work_clause():
    from sqlalchemy import and_, or_

    from app.db.models import Customer

    return and_(
        Customer.pppoe_username.isnot(None),
        Customer.router_id.isnot(None),
        or_(
            # learning, or locked but the router may not carry it yet
            and_(
                Customer.pppoe_device_lock.is_(True),
                or_(
                    Customer.pppoe_bound_mac.is_(None),
                    Customer.pppoe_lock_applied_mac.is_(None),
                    Customer.pppoe_lock_applied_mac != Customer.pppoe_bound_mac,
                ),
            ),
            # a caller-id of ours is still on the router but should not be
            and_(
                Customer.pppoe_lock_applied_mac.isnot(None),
                or_(Customer.pppoe_device_lock.is_(False), Customer.pppoe_bound_mac.is_(None)),
            ),
        ),
    )


async def reconcile_device_locks_background() -> Dict[str, Any]:
    """Scheduler job: learn device MACs and retry caller-id writes.

    Only customers with work to do are read; routers recently offline are
    skipped; sheds when the DB pool is busy; time-budgeted.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.db import database as db_module
    from app.db.models import Customer
    from app.services.customer_events import _pool_busy
    from app.services.router_availability import router_recently_offline
    from app.services.router_concurrency import run_with_guard

    if _pool_busy():
        return {"skipped": True}
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        customers = (await db.execute(
            select(Customer).options(selectinload(Customer.router)).where(_needs_work_clause())
        )).scalars().all()
        by_router: Dict[int, tuple] = {}
        for c in customers:
            if c.router is None or router_recently_offline(c.router, now):
                continue
            entry = by_router.setdefault(c.router.id, (router_info_of(c.router), []))
            entry[1].append(work_from_customer(c))
        await db.commit()

    summary = {"routers": 0, "learned": 0, "written": 0, "errors": 0}
    started = time.monotonic()
    for router_id, (info, work) in list(by_router.items())[:RECONCILE_ROUTERS_PER_TICK]:
        if time.monotonic() - started > RECONCILE_TIME_BUDGET_SECONDS:
            break
        try:
            raw = await run_with_guard(
                router_id, reconcile_router_sync, info, work,
                acquire_timeout_seconds=RECONCILE_ACQUIRE_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.info("[PPPOE-LOCK] router %s skipped: %s", router_id, exc)
            summary["errors"] += 1
            continue
        if not isinstance(raw, dict) or raw.get("error"):
            summary["errors"] += 1
            continue
        summary["routers"] += 1
        outcomes = raw.get("results") or {}
        summary["written"] += sum(1 for o in outcomes.values() if o.get("changed"))
        events = await persist_outcomes(router_id, outcomes)
        summary["learned"] += len(events)
    if summary["learned"] or summary["written"] or summary["errors"]:
        logger.info("[PPPOE-LOCK] reconcile: %s", summary)
    return summary
