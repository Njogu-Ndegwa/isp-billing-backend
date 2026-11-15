"""Router actions delivered over the check-in channel (2026-11-14).

Why this exists
---------------
A router whose management tunnel is dead can still have internet and keep
checking in to ``POST /api/router/checkin`` over public HTTPS (router 118,
11-13 Nov 2026: 386 hotspot purchases delivered that way while every API call
failed). Anything that needed the RouterOS API (reboot, access credentials,
tunnel repair) failed silently. This module lets the server hand such a
router a small, fixed set of actions on its next check-in.

Safety model
------------
* **Strict allowlist.** ``ACTIONS`` is the whole vocabulary. Nobody can send
  text to a router: the reply carries an action letter and numbers, and the
  applier (``checkin_applier_script``, v3) owns every RouterOS command it runs.
  Line formats (all fields whitelisted here before a line is emitted):

    ``R,<action id, 12 digits>``                       reboot
    ``H,<action id, 12 digits>``                       heal the mgmt tunnel
    ``C,<cred id>,<user id>,<rate|->,<username>,<password>``  add/update an
                                                       access-credential user
    ``D,<cred id>,<mac|->,<username>``                 remove one

* **Only v3 appliers get these lines.** An older applier rejects the whole
  frame on an unknown line, which would also drop that check-in's hotspot
  deliveries; the endpoint only calls ``exchange`` for ``v>=3`` reports.
* **Idempotent and expiring.** heal/sync are safe to run twice, are re-sent
  when no ack comes back (``REDELIVER_AFTER``), at most ``MAX_DELIVERIES``
  times, and expire (``TTL``).
* **Reboot runs at most once.** It is sent exactly once (``delivery_count``
  never goes past 1) and never re-sent, whatever happens next. The router
  acks it just before rebooting (``accepted``); the next report whose uptime
  is shorter than the time since delivery marks it ``done``. No confirmation
  within ``REBOOT_CONFIRM_WINDOW`` = ``unconfirmed``, never a retry. The
  applier also refuses a reboot when the router has been up for less than
  5 minutes, and ``enqueue`` refuses a new reboot within ``REBOOT_COOLDOWN``
  of the last one, so a server bug cannot make a router boot-loop.
* **Authentication** is the check-in's own token: the endpoint verifies it
  before anything here runs, and the action's router is the token's router.

DB discipline (AGENTS.md): the check-in path does nothing here unless the
router has an active action (process-local hint, refreshed from the table
once a minute) or the report carries acks; then ONE short session reads and
writes the router's rows. No router I/O ever happens in this module.
"""

from __future__ import annotations

import logging
import math
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from app.db import database
from app.db.models import AccessCredential, RouterCheckinAction

logger = logging.getLogger(__name__)

ACTION_REBOOT = "reboot"
ACTION_HEAL_TUNNEL = "heal_tunnel"
ACTION_SYNC_CREDENTIALS = "sync_access_credentials"
ACTIONS = (ACTION_REBOOT, ACTION_HEAL_TUNNEL, ACTION_SYNC_CREDENTIALS)
# Actions a person may queue by hand. Credential sync is queued by the
# credential code itself, from the rows that are actually pending.
USER_ACTIONS = (ACTION_REBOOT, ACTION_HEAL_TUNNEL)

STATE_PENDING = "pending"
STATE_DELIVERED = "delivered"
STATE_ACCEPTED = "accepted"  # reboot: router acked, about to reboot
STATE_DONE = "done"
STATE_FAILED = "failed"
STATE_EXPIRED = "expired"
STATE_UNCONFIRMED = "unconfirmed"  # reboot sent, never confirmed; not retried
STATE_CANCELLED = "cancelled"
ACTIVE_STATES = (STATE_PENDING, STATE_DELIVERED, STATE_ACCEPTED)

APPLIER_VERSION_ACTIONS = 3

TTL = {
    # A reboot that has not reached the router in 30 min is dropped: nobody
    # wants a surprise restart hours after they asked.
    ACTION_REBOOT: timedelta(minutes=30),
    ACTION_HEAL_TUNNEL: timedelta(minutes=30),
    ACTION_SYNC_CREDENTIALS: timedelta(hours=24),
}
REDELIVER_AFTER = timedelta(minutes=2)
MAX_DELIVERIES = {ACTION_HEAL_TUNNEL: 3, ACTION_SYNC_CREDENTIALS: 20}
REBOOT_CONFIRM_WINDOW = timedelta(minutes=20)
REBOOT_COOLDOWN = timedelta(minutes=10)
# Slack between our clock and the router's uptime when confirming a reboot.
REBOOT_CONFIRM_SLACK_SECONDS = 60
MAX_CREDENTIAL_LINES = 4
# The router reads the reply with ``/tool fetch output=user``; keep the whole
# frame well under the 4 KB RouterOS 6 limit (A/Q lines take up to ~1.3 KB).
MAX_ACTION_BYTES = 1200
CAPABILITY_FRESH_SECONDS = 15 * 60
HINT_REFRESH_SECONDS = 60

_LINE_ID_RE = re.compile(r"^\d{12}$")
_CRED_ID_RE = re.compile(r"^\d{1,10}$")
_CRED_USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
# Printable ASCII only: the password is the LAST field and may contain commas,
# but never a newline (it would end the line) or bytes the applier cannot
# count by position.
_CRED_PASSWORD_RE = re.compile(r"^[\x20-\x7e]{1,128}$")
_RATE_PART = r"\d{1,10}(?:\.\d{1,3})?[kKMG]?"
_RATE_RE = re.compile(rf"^{_RATE_PART}/{_RATE_PART}$")
_MAC_RE = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
_ACK_RE = re.compile(r"^([RHCD])(\d{1,12})$")


class ActionRefused(ValueError):
    """The action cannot be queued for this router (message is user-facing)."""


# ---------------------------------------------------------------------------
# What the router told us about itself (process memory, single worker)
# ---------------------------------------------------------------------------

@dataclass
class RouterCaps:
    version: int
    heal: bool
    uptime_seconds: Optional[int]
    seen_mono: float
    seen_at: datetime
    next_s: int = 60


_caps: dict[int, RouterCaps] = {}
_pending_routers: set[int] = set()
_hint_refreshed_mono: float = 0.0


def reset_state() -> None:
    global _hint_refreshed_mono
    _caps.clear()
    _pending_routers.clear()
    _hint_refreshed_mono = 0.0


def note_checkin(router_id: int, *, version: int, heal: bool, uptime_seconds: Optional[int],
                 now: datetime, now_mono: Optional[float] = None) -> None:
    prev = _caps.get(router_id)
    _caps[router_id] = RouterCaps(
        version=version, heal=heal, uptime_seconds=uptime_seconds,
        seen_mono=time.monotonic() if now_mono is None else now_mono, seen_at=now,
        next_s=prev.next_s if prev else 60,
    )


def note_next_poll(router_id: int, next_s: int) -> None:
    caps = _caps.get(router_id)
    if caps is not None:
        caps.next_s = int(next_s)


def router_caps(router_id: int, now_mono: Optional[float] = None) -> Optional[RouterCaps]:
    """The router's last v3 check-in, if it was recent enough to rely on."""
    caps = _caps.get(router_id)
    now_mono = time.monotonic() if now_mono is None else now_mono
    if caps is None or caps.version < APPLIER_VERSION_ACTIONS:
        return None
    if now_mono - caps.seen_mono > CAPABILITY_FRESH_SECONDS:
        return None
    return caps


def eta_minutes(router_id: int) -> int:
    caps = _caps.get(router_id)
    seconds = caps.next_s if caps else 60
    return max(1, math.ceil(seconds / 60))


def parse_uptime(raw: str) -> Optional[int]:
    """RouterOS uptime as seconds: v7 ``1w2d3h4m5s`` or v6 ``1w2d03:04:05``."""
    text = str(raw or "").strip()
    if not text or len(text) > 40:
        return None
    total = 0
    clock = re.search(r"(\d{1,2}):(\d{2}):(\d{2})$", text)
    if clock:
        total += int(clock.group(1)) * 3600 + int(clock.group(2)) * 60 + int(clock.group(3))
        text = text[: clock.start()]
    factors = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    parts = re.findall(r"(\d+)([wdhms])", text)
    if "".join(n + u for n, u in parts) != text:
        return None
    if not parts and not clock:
        return None
    return total + sum(int(n) * factors[u] for n, u in parts)


def parse_acks(raw: str, limit: int = 40) -> list[tuple[str, int]]:
    out = []
    for token in str(raw or "").split(",")[:limit]:
        m = _ACK_RE.match(token.strip())
        if m:
            out.append((m.group(1), int(m.group(2))))
    return out


# ---------------------------------------------------------------------------
# Line rendering (every field whitelisted; None = unsafe, never emitted)
# ---------------------------------------------------------------------------

def _line_id(action_id: int) -> str:
    return f"{int(action_id):012d}"


def format_action_line(action: str, action_id: int) -> Optional[str]:
    letter = {ACTION_REBOOT: "R", ACTION_HEAL_TUNNEL: "H"}.get(action)
    ident = _line_id(action_id)
    if letter is None or not _LINE_ID_RE.match(ident):
        return None
    return f"{letter},{ident}"


def router_rate(rate_limit: Optional[str]) -> str:
    from app.services.access_credentials import router_rate_limit

    return router_rate_limit(rate_limit) or "-"


def format_credential_add_line(cred_id: int, user_id: int, rate: str, username: str,
                               password: str) -> Optional[str]:
    cid, uid = str(cred_id), str(user_id)
    if not (_CRED_ID_RE.match(cid) and _CRED_ID_RE.match(uid)
            and (rate == "-" or _RATE_RE.match(rate))
            and _CRED_USER_RE.match(username) and _CRED_PASSWORD_RE.match(password)):
        return None
    return f"C,{cid},{uid},{rate},{username},{password}"


def format_credential_remove_line(cred_id: int, mac: Optional[str], username: str) -> Optional[str]:
    cid = str(cred_id)
    mac_field = "-"
    if mac:
        from app.services.mikrotik_api import normalize_mac_address

        mac_field = normalize_mac_address(mac)
        if not _MAC_RE.match(mac_field):
            return None
    if not (_CRED_ID_RE.match(cid) and _CRED_USER_RE.match(username)):
        return None
    return f"D,{cid},{mac_field},{username}"


_ACTION_LINE_RES = (
    re.compile(r"^[RH],\d{12}$"),
    re.compile(r"^C,\d{1,10},\d{1,10},(?:-|" + _RATE_PART + "/" + _RATE_PART
               + r"),[a-z0-9][a-z0-9._-]{2,63},[\x20-\x7e]{1,128}$"),
    re.compile(r"^D,\d{1,10},(?:-|(?:[0-9A-F]{2}:){5}[0-9A-F]{2}),[a-z0-9][a-z0-9._-]{2,63}$"),
)


def valid_action_line(line: str) -> bool:
    """Last check before a line goes in a frame (``checkin_delivery.render_frame``)."""
    text = str(line or "")
    return len(text) <= 240 and any(rx.match(text) for rx in _ACTION_LINE_RES)


def credential_line(cred: AccessCredential) -> Optional[str]:
    if cred.router_sync == "add":
        return format_credential_add_line(
            cred.id, cred.user_id, router_rate(cred.rate_limit), cred.username, cred.password or "")
    if cred.router_sync in ("remove", "delete"):
        from app.services.access_credentials import SHARED_ACCESS_OWNER_IDS

        # The installed check-in applier can remove one MAC per credential
        # action. Let the API retry remove all tagged bindings before ACK.
        if cred.user_id in SHARED_ACCESS_OWNER_IDS:
            return None
        return format_credential_remove_line(cred.id, cred.router_sync_mac, cred.username)
    return None


# ---------------------------------------------------------------------------
# Queueing
# ---------------------------------------------------------------------------

def _mark_pending(router_id: int) -> None:
    _pending_routers.add(int(router_id))


async def enqueue(
    router_id: int,
    action: str,
    *,
    requested_by_user_id: Optional[int] = None,
    reason: Optional[str] = None,
    now: Optional[datetime] = None,
) -> RouterCheckinAction:
    """Queue ``action`` for ``router_id``. Idempotent per router and action.

    An active (pending/delivered/accepted) row for the same router and action
    is returned as it is, so pressing a button twice queues one action.
    Raises ``ActionRefused`` for an unknown action or a reboot inside the
    cooldown.
    """
    if action not in ACTIONS:
        raise ActionRefused(f"Unknown router action {action!r}")
    now = now or datetime.utcnow()
    async with database.async_session() as db:
        active = (await db.execute(
            select(RouterCheckinAction).where(
                RouterCheckinAction.router_id == router_id,
                RouterCheckinAction.action == action,
                RouterCheckinAction.state.in_(ACTIVE_STATES),
                RouterCheckinAction.expires_at > now,
            ).order_by(RouterCheckinAction.id.desc()).limit(1)
        )).scalar_one_or_none()
        if active is not None:
            await db.commit()
            _mark_pending(router_id)
            return active
        if action == ACTION_REBOOT:
            recent = (await db.execute(
                select(RouterCheckinAction.id).where(
                    RouterCheckinAction.router_id == router_id,
                    RouterCheckinAction.action == ACTION_REBOOT,
                    RouterCheckinAction.state.in_((STATE_DONE, STATE_UNCONFIRMED)),
                    RouterCheckinAction.delivered_at > now - REBOOT_COOLDOWN,
                ).limit(1)
            )).scalar_one_or_none()
            if recent is not None:
                await db.commit()
                raise ActionRefused(
                    "This router was restarted in the last 10 minutes; wait before restarting it again")
        row = RouterCheckinAction(
            router_id=router_id,
            action=action,
            state=STATE_PENDING,
            idempotency_key=f"{action}:{router_id}:{uuid.uuid4().hex}",
            requested_by_user_id=requested_by_user_id,
            reason=(reason or None) and str(reason)[:500],
            created_at=now,
            expires_at=now + TTL[action],
            updated_at=now,
        )
        db.add(row)
        try:
            await db.commit()
        except IntegrityError:  # astronomically unlikely uuid clash
            await db.rollback()
            raise
        await db.refresh(row)
    _mark_pending(router_id)
    logger.info("[CHECKIN-ACTION] queued %s #%s for router %s", action, row.id, router_id)
    return row


async def recent_actions(router_id: int, limit: int = 20) -> list[RouterCheckinAction]:
    async with database.async_session() as db:
        rows = (await db.execute(
            select(RouterCheckinAction)
            .where(RouterCheckinAction.router_id == router_id)
            .order_by(RouterCheckinAction.id.desc())
            .limit(limit)
        )).scalars().all()
        await db.commit()
    return list(rows)


def serialize_action(row: RouterCheckinAction) -> dict:
    def iso(v):
        return v.isoformat() if v else None

    return {
        "id": row.id,
        "router_id": row.router_id,
        "action": row.action,
        "state": row.state,
        "reason": row.reason,
        "delivery_count": row.delivery_count,
        "created_at": iso(row.created_at),
        "expires_at": iso(row.expires_at),
        "delivered_at": iso(row.delivered_at),
        "acknowledged_at": iso(row.acknowledged_at),
        "finished_at": iso(row.finished_at),
        "last_error": row.last_error,
    }


# ---------------------------------------------------------------------------
# The check-in exchange
# ---------------------------------------------------------------------------

async def _refresh_hint(now: datetime, now_mono: float) -> None:
    global _hint_refreshed_mono
    if now_mono - _hint_refreshed_mono < HINT_REFRESH_SECONDS and _hint_refreshed_mono:
        return
    _hint_refreshed_mono = now_mono
    async with database.async_session() as db:
        ids = (await db.execute(
            select(RouterCheckinAction.router_id).where(
                RouterCheckinAction.state.in_(ACTIVE_STATES)
            ).distinct()
        )).scalars().all()
        await db.commit()
    _pending_routers.clear()
    _pending_routers.update(int(i) for i in ids)


def _finish(row: RouterCheckinAction, state: str, now: datetime, error: Optional[str] = None) -> None:
    row.state = state
    row.finished_at = now
    row.updated_at = now
    if error:
        row.last_error = error[:255]


async def exchange(
    router_id: int,
    *,
    acks: Iterable[tuple[str, int]] = (),
    fails: Iterable[tuple[str, int]] = (),
    uptime_seconds: Optional[int] = None,
    heal_available: bool = False,
    send: bool = True,
    now: Optional[datetime] = None,
    now_mono: Optional[float] = None,
) -> list[str]:
    """Apply the router's acks, then return the action lines for this reply.

    Called by the check-in endpoint for v3 reports only, after the token
    check. Returns ``[]`` without touching the DB when the router has no
    active action and sent no acks. ``send=False`` (the applier's ack POST,
    whose reply it ignores) settles acks and expiries but hands nothing out:
    a reboot marked delivered there would never run.
    """
    now = now or datetime.utcnow()
    now_mono = time.monotonic() if now_mono is None else now_mono
    acks, fails = list(acks), list(fails)
    try:
        await _refresh_hint(now, now_mono)
    except Exception:  # the hint is an optimisation; the table stays authoritative
        logger.exception("[CHECKIN-ACTION] hint refresh failed")
    if router_id not in _pending_routers and not acks and not fails:
        return []

    lines: list[str] = []
    async with database.async_session() as db:
        rows = (await db.execute(
            select(RouterCheckinAction).where(
                RouterCheckinAction.router_id == router_id,
                RouterCheckinAction.state.in_(ACTIVE_STATES),
            ).order_by(RouterCheckinAction.id.asc()).limit(20).with_for_update()
        )).scalars().all()
        by_id = {r.id: r for r in rows}

        # 1. Acks for R/H lines.
        for ok, items in ((True, acks), (False, fails)):
            for kind, ident in items:
                row = by_id.get(ident)
                if kind not in ("R", "H") or row is None:
                    continue
                expected = "R" if row.action == ACTION_REBOOT else "H"
                if kind != expected or row.state != STATE_DELIVERED:
                    continue
                row.acknowledged_at = now
                row.updated_at = now
                if row.action == ACTION_REBOOT:
                    if ok:
                        row.state = STATE_ACCEPTED
                    else:
                        _finish(row, STATE_FAILED, now, "Router refused the restart (up for under 5 min)")
                else:
                    _finish(row, STATE_DONE if ok else STATE_FAILED, now,
                            None if ok else "Router could not run the tunnel repair")

        # 2. Credential acks.
        cred_acks = [(ok, kind, ident) for ok, items in ((True, acks), (False, fails))
                     for kind, ident in items if kind in ("C", "D")]
        if cred_acks:
            creds = {
                c.id: c for c in (await db.execute(
                    select(AccessCredential).where(
                        AccessCredential.router_id == router_id,
                        AccessCredential.id.in_([i for _, _, i in cred_acks]),
                    )
                )).scalars().all()
            }
            sync_row = next((r for r in rows if r.action == ACTION_SYNC_CREDENTIALS
                             and r.delivered_at is not None), None)
            for ok, kind, ident in cred_acks:
                cred = creds.get(ident)
                if cred is None or sync_row is None:
                    continue
                expected = "C" if cred.router_sync == "add" else "D" if cred.router_sync in ("remove", "delete") else None
                if kind != expected:
                    continue  # stale ack (state changed since the line was sent)
                if cred.updated_at and cred.updated_at > sync_row.delivered_at:
                    # Changed after the line went out (e.g. a new password): the
                    # router has the old version; it is sent again instead.
                    continue
                if ok:
                    if cred.router_sync == "delete":
                        await db.delete(cred)
                    else:
                        cred.router_sync = None
                        cred.router_sync_since = None
                        cred.router_sync_error = None
                        cred.router_sync_mac = None
                else:
                    cred.router_sync_error = "Router could not apply it over check-in"

        # 3. Expire, confirm, and pick what to send.
        cred_rows: list[AccessCredential] = []
        for row in rows:
            if row.state not in ACTIVE_STATES:
                continue
            if row.action == ACTION_REBOOT and row.state in (STATE_DELIVERED, STATE_ACCEPTED):
                since = (now - row.delivered_at).total_seconds() if row.delivered_at else None
                if (uptime_seconds is not None and since is not None
                        and uptime_seconds < since + REBOOT_CONFIRM_SLACK_SECONDS
                        and since >= 5):
                    _finish(row, STATE_DONE, now)
                elif row.delivered_at and now - row.delivered_at > REBOOT_CONFIRM_WINDOW:
                    _finish(row, STATE_UNCONFIRMED, now, "No restart seen after the command was sent")
                continue  # never re-sent
            if row.state == STATE_PENDING and row.expires_at <= now:
                _finish(row, STATE_EXPIRED, now, "The router did not check in before it expired")
                continue
            if row.state == STATE_DELIVERED and row.expires_at <= now:
                _finish(row, STATE_EXPIRED, now, "No acknowledgement before it expired")
                continue
            if not send:
                continue
            if row.action == ACTION_SYNC_CREDENTIALS:
                if not cred_rows:
                    cred_rows = list((await db.execute(
                        select(AccessCredential).where(
                            AccessCredential.router_id == router_id,
                            AccessCredential.router_sync.isnot(None),
                        ).order_by(AccessCredential.id.asc()).limit(MAX_CREDENTIAL_LINES)
                    )).scalars().all())
                    # Rows the acks above just settled are gone from the set.
                    cred_rows = [c for c in cred_rows if c.router_sync is not None]
                if not cred_rows:
                    _finish(row, STATE_DONE, now)
                    continue
            due = (row.state == STATE_PENDING
                   or (row.delivered_at is not None and now - row.delivered_at >= REDELIVER_AFTER))
            if not due:
                continue
            if row.delivery_count >= MAX_DELIVERIES.get(row.action, 1):
                _finish(row, STATE_FAILED, now, "No acknowledgement after repeated deliveries")
                continue
            if row.action == ACTION_HEAL_TUNNEL and not heal_available:
                _finish(row, STATE_FAILED, now, "The router has no tunnel repair script installed")
                continue
            if row.action == ACTION_SYNC_CREDENTIALS:
                new = [ln for ln in (credential_line(c) for c in cred_rows) if ln]
                for c in cred_rows:
                    if credential_line(c) is None:
                        c.router_sync_error = "Cannot be sent over check-in (unsupported characters)"
                if not new:
                    continue
                lines.extend(new)
            else:
                line = format_action_line(row.action, row.id)
                if line is None:
                    _finish(row, STATE_FAILED, now, "Unsafe action line")
                    continue
                lines.append(line)
            row.state = STATE_DELIVERED
            row.delivery_count += 1
            row.delivered_at = now
            row.updated_at = now

        # The reboot always goes last: the applier runs it after everything else.
        lines.sort(key=lambda ln: ln.startswith("R,"))
        # Byte budget: drop credential lines first (they come back next time).
        while lines and sum(len(ln) + 1 for ln in lines) > MAX_ACTION_BYTES:
            drop = next((i for i, ln in enumerate(lines) if ln[0] in "CD"), None)
            if drop is None:
                break
            lines.pop(drop)
        await db.commit()

    if not any(r.state in ACTIVE_STATES for r in rows):
        _pending_routers.discard(router_id)
    for line in lines:
        logger.info("[CHECKIN-ACTION] router %s <- %s", router_id, line.split(",")[0] + "," + line.split(",")[1])
    return lines


async def expire_stale(now: Optional[datetime] = None) -> int:
    """Terminalize actions of routers that stopped checking in. Cheap; no I/O."""
    now = now or datetime.utcnow()
    count = 0
    async with database.async_session() as db:
        rows = (await db.execute(
            select(RouterCheckinAction).where(
                RouterCheckinAction.state.in_(ACTIVE_STATES),
                or_(
                    RouterCheckinAction.expires_at <= now,
                    RouterCheckinAction.delivered_at <= now - REBOOT_CONFIRM_WINDOW,
                ),
            ).limit(200)
        )).scalars().all()
        for row in rows:
            if row.action == ACTION_REBOOT and row.state in (STATE_DELIVERED, STATE_ACCEPTED):
                if row.delivered_at and now - row.delivered_at > REBOOT_CONFIRM_WINDOW:
                    _finish(row, STATE_UNCONFIRMED, now, "No restart seen after the command was sent")
                    count += 1
            elif row.expires_at <= now:
                _finish(row, STATE_EXPIRED, now, "Expired before the router acknowledged it")
                count += 1
        await db.commit()
    return count


def router_can_take_actions(router_id: int) -> bool:
    return router_caps(router_id) is not None


