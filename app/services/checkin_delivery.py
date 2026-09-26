"""Router check-in delivery (pilot): the router asks, the server answers with data.

Why this exists
---------------
Every paid-delivery miss we have seen has the same shape: the server could not
open a RouterOS API session to the router at the moment of payment (dead or
blocked management tunnel). A router that cannot be reached can still reach
*us* — its HTTPS usage reports arrive through Cloudflare in >90% of minutes at
the worst site. So the router checks in, reports what it holds, and the server
replies with what it is missing.

Protocol (plain text both ways, no JSON, no script):

  router -> server   POST /api/router/checkin
                     Authorization: Bearer <check-in token>
                     body: ``v=1&id=<identity>&n=<count>&macs=AA:..,BB:..&q=CC:..``
                     (``macs``: the MACs of its ``USER:``-tagged ip-bindings;
                     ``q``: the subset with no ``plan_<ref>`` simple queue.
                     ``q`` is optional: appliers older than 2026-09-26 omit it)

  server -> router   BWE1,<seq>,<count>,<next_s>
                     A,<mac>,<rate-limit>,<expiry-epoch>,<ref>     (A and Q
                     Q,<mac>,<rate-limit>,<ref>                     lines, x count)
                     END

The router's fixed applier script (``checkin_applier_script.py``) applies
nothing unless the frame is complete and every line validates. ``A`` means
"ensure this MAC is bypassed exactly like the API push would". ``Q`` means
"this check-in binding has no speed-limit queue yet; create it now if the
device's IP is known". Q lines are only ever sent to a router whose report
carried ``q=`` (an older applier would reject the whole frame). There is no
remove line in the pilot: expired MACs the router still reports are only
counted and logged ("unknown").

An ``A`` line is offered only after the MAC has been missing from the
router's reports for ``CHECKIN_MISSING_GRACE_SECONDS``. The Reconnect flow
removes the OLD MAC's binding seconds before the customer row switches to the
NEW MAC, and an immediate offer re-added the OLD MAC as an orphan binding the
expiry cleanup never removes (2026-09-26).

Design rules (see AGENTS.md "Database Session Discipline"):

* Desired state is derived from existing tables — ACTIVE, unexpired hotspot
  customers on the router with a MAC.
* One short read per check-in, released before anything else happens. The
  only write is ``record_checkin_deliveries``: when the report shows a paid
  customer present whose provisioning attempt is still undelivered, one short
  session marks it delivered (``delivered_via='checkin'``) so the dashboard,
  retry job and overload alerts stop treating it as waiting. It runs after
  the reply is decided, only when there is something to mark, and never
  touches the hot ``routers`` row. Pilot observations live in process memory
  (single worker), like ``realtime_state``.
* Every emitted field is whitelisted, so no quote, ``$``, ``;`` or bracket can
  ever reach a router, and a server bug can at worst produce a line the router
  rejects.
"""

from __future__ import annotations

import calendar
import logging
import math
import random
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy import exists, select
from sqlalchemy.orm import aliased

from app.config import settings
from app.db.database import async_session
from app.db.models import (
    DELIVERED_VIA_CHECKIN,
    DELIVERED_VIA_PUSH,
    ConnectionType,
    Customer,
    CustomerStatus,
    Plan,
    ProvisioningAttempt,
    ProvisioningLog,
    ProvisioningOnlineState,
    ProvisioningState,
    Router,
    RouterAuthMethod,
)
from app.services.mikrotik_api import parse_speed_to_mikrotik

logger = logging.getLogger(__name__)

FRAME_MAGIC = "BWE1"
MODE_SHADOW = "shadow"
MODE_ADD = "add"

# Poll cadence handed back in every reply (seconds).
NORMAL_POLL_SECONDS = 60
NORMAL_POLL_JITTER_SECONDS = 6  # +-10% so a fleet never re-aligns after an outage
FAST_POLL_SECONDS = 10  # a payment is in flight / undelivered on this router
CONFIRM_POLL_SECONDS = 5  # lines were just sent: confirm them on the next report
IDLE_POLL_SECONDS = 600  # disabled / kill switch / not in the pilot

# How long after an STK push (or an undelivered provisioning attempt) the
# router stays on the fast cadence.
PAYMENT_HOT_SECONDS = 300

# One router may check in at most this often; faster calls get an empty frame.
MIN_SECONDS_BETWEEN_CHECKINS = 3

# A MAC offered this many times without appearing in the router's report is
# not converging (e.g. a foreign binding the applier deliberately leaves
# alone). Stop offering it for a while instead of pinning the router at 5 s.
MAX_OFFERS_BEFORE_BACKOFF = 3
OFFER_BACKOFF_SECONDS = 600

# Q lines (queue for a device whose IP was unknown at bypass time) converge
# once the device connects; until then they are cheap no-ops on the router.
MAX_QUEUE_OFFERS_BEFORE_BACKOFF = 5
QUEUE_OFFER_BACKOFF_SECONDS = 300

DEFAULT_MISSING_GRACE_SECONDS = 60

# Recording check-in deliveries on provisioning_attempts.
UNDELIVERED_STATES = (
    ProvisioningState.SCHEDULED,
    ProvisioningState.IN_PROGRESS,
    ProvisioningState.RETRY_PENDING,
    # Includes attempts the retry job gave up on (retry window exhausted):
    # if the customer is still ACTIVE and the router shows them present, they
    # have access and must stop counting as a failure.
    ProvisioningState.FAILED,
)
RECORD_LOOKBACK = timedelta(hours=24)
PENDING_READ_LIMIT = 50
MAX_RECORDS_PER_CHECKIN = 10
SENT_MEMORY_SECONDS = 3600

UNKNOWN_LOG_EVERY_SECONDS = 600
ROUTER_CACHE_SECONDS = 300

MAX_BODY_BYTES = 32 * 1024
MAX_REPORTED_MACS = 2000
HARD_MAX_LINES_PER_REPLY = 20  # ~1.3 KB; well under any v6 fetch limit

# --- field whitelists -------------------------------------------------------
_MAC_RE = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
# Raw bps ("10000000/10000000") is a valid push rate too, hence 10 digits.
_RATE_PART = r"\d{1,10}(?:\.\d{1,3})?[KMG]?"
_RATE_RE = re.compile(rf"^{_RATE_PART}/{_RATE_PART}$")
_EPOCH_RE = re.compile(r"^\d{10}$")
_REF_RE = re.compile(r"^[0-9A-F]{12}$")
_DIGITS_RE = re.compile(r"^\d{1,12}$")
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ADD_LINE_RE = re.compile(
    r"^A,(?:[0-9A-F]{2}:){5}[0-9A-F]{2}," + _RATE_PART + "/" + _RATE_PART
    + r",\d{10},[0-9A-F]{12}$"
)
_QUEUE_LINE_RE = re.compile(
    r"^Q,(?:[0-9A-F]{2}:){5}[0-9A-F]{2}," + _RATE_PART + "/" + _RATE_PART
    + r",[0-9A-F]{12}$"
)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def checkin_router_ids() -> frozenset[int]:
    ids = set()
    for part in str(settings.CHECKIN_ROUTER_IDS or "").split(","):
        part = part.strip()
        if part.isdigit():
            ids.add(int(part))
    return frozenset(ids)


def checkin_mode() -> str:
    mode = str(settings.CHECKIN_MODE or "").strip().lower()
    # Anything unrecognised falls back to the harmless mode.
    return MODE_ADD if mode == MODE_ADD else MODE_SHADOW


def checkin_active() -> bool:
    """The channel answers with real data only when enabled and not killed."""
    return bool(settings.CHECKIN_ENABLED) and not bool(settings.CHECKIN_KILL_SWITCH)


def missing_grace_seconds() -> int:
    try:
        n = int(settings.CHECKIN_MISSING_GRACE_SECONDS)
    except (TypeError, ValueError, AttributeError):
        n = DEFAULT_MISSING_GRACE_SECONDS
    return max(0, min(3600, n))


def max_lines_per_reply() -> int:
    try:
        n = int(settings.CHECKIN_MAX_LINES_PER_REPLY)
    except (TypeError, ValueError):
        n = 10
    return max(1, min(HARD_MAX_LINES_PER_REPLY, n))


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckinReport:
    identity: str
    declared_count: Optional[int]
    macs: frozenset[str]
    tokens: int  # MAC tokens received, valid or not
    invalid: int
    # Reported MACs whose binding has no plan_<ref> queue (subset of macs).
    queue_missing: frozenset[str] = frozenset()
    # The applier sent ``q=`` at all, i.e. it understands Q lines.
    reports_queues: bool = False

    @property
    def count_matches(self) -> bool:
        return self.declared_count is not None and self.declared_count == self.tokens


class BadCheckin(ValueError):
    pass


def normalize_reported_mac(raw: str) -> Optional[str]:
    mac = str(raw or "").strip().upper().replace("-", ":")
    return mac if _MAC_RE.match(mac) else None


def parse_checkin_body(raw: bytes) -> CheckinReport:
    """Parse ``v=1&id=<identity>&n=<count>&macs=A,B,C[&q=A,B]``.

    Tolerant of field order and a trailing newline; strict about content. An
    unparseable body raises ``BadCheckin`` (the endpoint answers 400).
    """
    if len(raw) > MAX_BODY_BYTES:
        raise BadCheckin("body too large")
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise BadCheckin("body is not ascii") from exc
    fields: dict[str, str] = {}
    for part in text.split("&"):
        key, sep, value = part.partition("=")
        if sep:
            fields[key.strip()] = value.strip()
    identity = fields.get("id", "")
    if not _IDENTITY_RE.match(identity):
        raise BadCheckin("missing or invalid identity")
    declared: Optional[int] = None
    n_raw = fields.get("n", "")
    if _DIGITS_RE.match(n_raw):
        declared = int(n_raw)
    tokens = [t for t in fields.get("macs", "").split(",") if t.strip()]
    if len(tokens) > MAX_REPORTED_MACS:
        raise BadCheckin("too many macs")
    macs = set()
    invalid = 0
    for token in tokens:
        mac = normalize_reported_mac(token)
        if mac is None:
            invalid += 1
        else:
            macs.add(mac)
    reports_queues = "q" in fields
    queue_missing = set()
    if reports_queues:
        q_tokens = [t for t in fields.get("q", "").split(",") if t.strip()]
        if len(q_tokens) > MAX_REPORTED_MACS:
            raise BadCheckin("too many q macs")
        for token in q_tokens:
            mac = normalize_reported_mac(token)
            # Only MACs the router also listed as bindings; anything else
            # (truncation, garbage) is ignored rather than acted on.
            if mac is not None and mac in macs:
                queue_missing.add(mac)
    return CheckinReport(
        identity=identity,
        declared_count=declared,
        macs=frozenset(macs),
        tokens=len(tokens),
        invalid=invalid,
        queue_missing=frozenset(queue_missing),
        reports_queues=reports_queues,
    )


@dataclass(frozen=True)
class DesiredEntry:
    mac: str
    rate: str
    expiry_epoch: int
    ref: str


def format_add_line(entry: DesiredEntry) -> Optional[str]:
    """Render one ``A`` line, or None if ANY field fails its whitelist."""
    mac = str(entry.mac or "")
    rate = str(entry.rate or "")
    epoch = str(entry.expiry_epoch)
    ref = str(entry.ref or "")
    if not (_MAC_RE.match(mac) and _RATE_RE.match(rate)
            and _EPOCH_RE.match(epoch) and _REF_RE.match(ref)):
        return None
    line = f"A,{mac},{rate},{epoch},{ref}"
    # Belt and braces: the whole line must match the shape the applier parses
    # by fixed offsets (MAC at 2..19, ref = last 12, epoch = 10 before it).
    return line if _ADD_LINE_RE.match(line) else None


def format_queue_line(entry: DesiredEntry) -> Optional[str]:
    """Render one ``Q`` line (``Q,<mac>,<rate>,<ref>``), or None if unsafe."""
    mac = str(entry.mac or "")
    rate = str(entry.rate or "")
    ref = str(entry.ref or "")
    if not (_MAC_RE.match(mac) and _RATE_RE.match(rate) and _REF_RE.match(ref)):
        return None
    line = f"Q,{mac},{rate},{ref}"
    # The applier parses by fixed offsets too: MAC at 2..19, ref = last 12.
    return line if _QUEUE_LINE_RE.match(line) else None


def render_frame(
    seq: int,
    entries: Iterable[DesiredEntry],
    next_s: int,
    queue_entries: Iterable[DesiredEntry] = (),
) -> str:
    """Build the reply. Invalid entries are dropped, never emitted.

    ``A`` lines come first, then ``Q`` lines; the header count covers both.
    """
    lines = []
    for entry in entries:
        line = format_add_line(entry)
        if line is None:
            logger.warning("[CHECKIN] dropped unsafe line for %r", entry)
            continue
        lines.append(line)
    for entry in queue_entries:
        line = format_queue_line(entry)
        if line is None:
            logger.warning("[CHECKIN] dropped unsafe queue line for %r", entry)
            continue
        lines.append(line)
    seq_s = str(int(seq))
    next_i = max(5, min(3600, int(next_s)))
    if not _DIGITS_RE.match(seq_s):
        seq_s = "0"
    out = [f"{FRAME_MAGIC},{seq_s},{len(lines)},{next_i}", *lines, "END"]
    return "\n".join(out) + "\n"


def idle_frame(next_s: int = IDLE_POLL_SECONDS) -> str:
    return render_frame(_seq(), [], next_s)


def _seq() -> int:
    return int(time.time())


def desired_entry(mac_address: str, speed: str, expiry: datetime) -> Optional[DesiredEntry]:
    """Build the entry the applier needs to replicate the API push.

    ``ref`` is the push's hotspot username (MAC without colons), so the
    applier writes ``USER:<ref>|...`` and ``plan_<ref>`` exactly as
    ``MikroTikAPI.add_customer_bypass_mode`` does.
    """
    mac = normalize_reported_mac(mac_address or "")
    if mac is None or expiry is None:
        return None
    rate = parse_speed_to_mikrotik(speed or "")
    if not rate or not _RATE_RE.match(rate):
        return None
    epoch = calendar.timegm(expiry.utctimetuple())
    if not _EPOCH_RE.match(str(epoch)):
        return None
    return DesiredEntry(mac=mac, rate=rate, expiry_epoch=epoch, ref=mac.replace(":", ""))


def compute_diff(
    desired: Iterable[DesiredEntry], reported: Iterable[str]
) -> tuple[list[DesiredEntry], set[str]]:
    """Return (paid MACs the router is missing, reported MACs nobody paid for)."""
    reported_set = set(reported)
    by_mac: dict[str, DesiredEntry] = {}
    for entry in desired:
        # Duplicate customer rows for one MAC (one per reseller) — keep the
        # latest expiry; the router needs the MAC once.
        prev = by_mac.get(entry.mac)
        if prev is None or entry.expiry_epoch > prev.expiry_epoch:
            by_mac[entry.mac] = entry
    missing = sorted(
        (e for mac, e in by_mac.items() if mac not in reported_set),
        key=lambda e: (-e.expiry_epoch, e.mac),
    )
    unknown = reported_set - set(by_mac)
    return missing, unknown


def next_poll_seconds(
    *,
    lines_sent: int,
    payment_hot: bool,
    router_id: int | None = None,
    rng: random.Random | None = None,
) -> int:
    if lines_sent > 0:
        return CONFIRM_POLL_SECONDS
    if payment_hot:
        return FAST_POLL_SECONDS
    span = 2 * NORMAL_POLL_JITTER_SECONDS + 1
    if router_id is not None and rng is None:
        # Stable per router: the applier rewrites its scheduler whenever next_s changes, and
        # every scheduler change is a config write to the router's flash. A fresh random value
        # on each check-in rewrote it every minute; a fixed per-router offset still spreads the
        # fleet across the window but only changes when the cadence really changes.
        return NORMAL_POLL_SECONDS + (int(router_id) * 7919) % span - NORMAL_POLL_JITTER_SECONDS
    r = rng or random
    return NORMAL_POLL_SECONDS + r.randint(-NORMAL_POLL_JITTER_SECONDS, NORMAL_POLL_JITTER_SECONDS)


# ---------------------------------------------------------------------------
# In-memory pilot state (single worker; a restart only loses observations)
# ---------------------------------------------------------------------------

@dataclass
class RouterCheckinStats:
    checkins: int = 0
    last_checkin_at: Optional[datetime] = None
    last_reported: int = 0
    last_desired: int = 0
    last_missing: int = 0
    last_unknown: int = 0
    would_send_total: int = 0
    lines_sent_total: int = 0
    queue_lines_sent_total: int = 0
    would_queue_total: int = 0
    last_queue_missing: int = 0
    held_in_grace_total: int = 0
    deliveries_recorded_total: int = 0
    count_mismatch_total: int = 0
    invalid_macs_total: int = 0
    last_unknown_log_at: float = 0.0
    # (mac, seconds missing, how it resolved) for the last few resolutions —
    # the shadow-mode evidence of how long push misses last.
    resolved: deque = field(default_factory=lambda: deque(maxlen=25))


@dataclass
class _Offer:
    count: int = 0
    suppressed_until: float = 0.0


@dataclass(frozen=True)
class RouterRef:
    id: int
    auth_method: str
    lb_enabled: bool
    fetched_at: float


_stats: dict[int, RouterCheckinStats] = {}
_missing_since: dict[tuple[int, str], float] = {}
_offers: dict[tuple[int, str], _Offer] = {}
_queue_offers: dict[tuple[int, str], _Offer] = {}
# (router, MAC) -> when this process last sent an A line for it; lets the
# delivery record say whether the check-in itself added the binding.
_sent_at: dict[tuple[int, str], float] = {}
_payment_hint: dict[int, float] = {}
_last_checkin: dict[str, float] = {}
_router_cache: dict[str, RouterRef] = {}


def reset_state() -> None:
    """Test hook."""
    _stats.clear()
    _missing_since.clear()
    _offers.clear()
    _queue_offers.clear()
    _sent_at.clear()
    _payment_hint.clear()
    _last_checkin.clear()
    _router_cache.clear()


def note_payment_initiated(router_id: Optional[int]) -> None:
    """Called when an STK push starts for a customer on ``router_id``.

    Pure in-memory and exception-proof: it must never affect the payment path.
    Only pilot routers are remembered, so the dict stays tiny.
    """
    try:
        if router_id is None or not settings.CHECKIN_ENABLED:
            return
        rid = int(router_id)
        if rid in checkin_router_ids():
            _payment_hint[rid] = time.monotonic()
    except Exception:  # pragma: no cover - defensive
        pass


def payment_hint_active(router_id: int, now_mono: Optional[float] = None) -> bool:
    ts = _payment_hint.get(router_id)
    if ts is None:
        return False
    now_mono = time.monotonic() if now_mono is None else now_mono
    return (now_mono - ts) <= PAYMENT_HOT_SECONDS


def rate_limited(identity: str, now_mono: Optional[float] = None) -> bool:
    """True if this identity checked in too recently. Records the call if not."""
    now_mono = time.monotonic() if now_mono is None else now_mono
    last = _last_checkin.get(identity)
    if last is not None and (now_mono - last) < MIN_SECONDS_BETWEEN_CHECKINS:
        return True
    _last_checkin[identity] = now_mono
    return False


def stats_snapshot() -> dict:
    return {
        "enabled": bool(settings.CHECKIN_ENABLED),
        "kill_switch": bool(settings.CHECKIN_KILL_SWITCH),
        "mode": checkin_mode(),
        "missing_grace_seconds": missing_grace_seconds(),
        "router_ids": sorted(checkin_router_ids()),
        "routers": {
            rid: {
                "checkins": s.checkins,
                "last_checkin_at": s.last_checkin_at.isoformat() + "Z" if s.last_checkin_at else None,
                "last_reported": s.last_reported,
                "last_desired": s.last_desired,
                "last_missing": s.last_missing,
                "last_unknown": s.last_unknown,
                "would_send_total": s.would_send_total,
                "lines_sent_total": s.lines_sent_total,
                "queue_lines_sent_total": s.queue_lines_sent_total,
                "would_queue_total": s.would_queue_total,
                "last_queue_missing": s.last_queue_missing,
                "held_in_grace_total": s.held_in_grace_total,
                "deliveries_recorded_total": s.deliveries_recorded_total,
                "count_mismatch_total": s.count_mismatch_total,
                "invalid_macs_total": s.invalid_macs_total,
                "payment_hot": payment_hint_active(rid),
                "currently_missing": sorted(
                    mac for (r, mac) in _missing_since if r == rid
                ),
                "recent_resolutions": list(s.resolved),
            }
            for rid, s in sorted(_stats.items())
        },
    }


# ---------------------------------------------------------------------------
# DB reads — each in its own short session, released before returning
# ---------------------------------------------------------------------------

async def resolve_router(identity: str) -> Optional[RouterRef]:
    now_mono = time.monotonic()
    cached = _router_cache.get(identity)
    if cached is not None and (now_mono - cached.fetched_at) < ROUTER_CACHE_SECONDS:
        return cached
    async with async_session() as db:
        row = (
            await db.execute(
                select(Router.id, Router.auth_method, Router.lb_enabled)
                .where(Router.identity == identity)
            )
        ).first()
        await db.commit()
    if row is None:
        _router_cache.pop(identity, None)
        return None
    auth = row.auth_method.value if hasattr(row.auth_method, "value") else str(row.auth_method or "")
    ref = RouterRef(id=int(row.id), auth_method=auth, lb_enabled=bool(row.lb_enabled), fetched_at=now_mono)
    _router_cache[identity] = ref
    return ref


@dataclass(frozen=True)
class PendingAttempt:
    """An undelivered provisioning attempt of a paid customer on this router."""

    attempt_id: int
    customer_id: int
    mac: str  # the customer's CURRENT MAC, normalized
    state: str
    created_at: datetime


@dataclass(frozen=True)
class CheckinState:
    desired: list[DesiredEntry]
    undelivered_recent: bool
    pending: list[PendingAttempt] = field(default_factory=list)


async def load_checkin_state(router_id: int, now: datetime) -> CheckinState:
    """One short read: paid hotspot MACs on the router, "payment undelivered?",
    and the undelivered attempts a present MAC would settle.

    The customers read rides ``ix_customers_status_expiry_user`` (status,
    expiry) and filters router_id on the few ACTIVE+unexpired rows; the
    attempts reads ride the ``provisioning_attempts.router_id`` index.
    """
    since = now - timedelta(seconds=PAYMENT_HOT_SECONDS)
    newer = aliased(ProvisioningAttempt)
    async with async_session() as db:
        rows = (
            await db.execute(
                select(Customer.mac_address, Customer.expiry, Plan.speed)
                .join(Plan, Plan.id == Customer.plan_id)
                .where(
                    Customer.router_id == router_id,
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.expiry.is_not(None),
                    Customer.expiry > now,
                    Customer.mac_address.is_not(None),
                    Plan.connection_type == ConnectionType.HOTSPOT,
                )
            )
        ).all()
        undelivered = (
            await db.execute(
                select(ProvisioningAttempt.id)
                .where(
                    ProvisioningAttempt.router_id == router_id,
                    ProvisioningAttempt.provisioning_state != ProvisioningState.ROUTER_UPDATED,
                    ProvisioningAttempt.created_at >= since,
                )
                .limit(1)
            )
        ).first() is not None
        pending_rows = (
            await db.execute(
                select(
                    ProvisioningAttempt.id,
                    ProvisioningAttempt.customer_id,
                    ProvisioningAttempt.provisioning_state,
                    ProvisioningAttempt.created_at,
                    Customer.mac_address,
                )
                .join(Customer, Customer.id == ProvisioningAttempt.customer_id)
                .join(Plan, Plan.id == Customer.plan_id)
                .where(
                    ProvisioningAttempt.router_id == router_id,
                    ProvisioningAttempt.provisioning_state.in_(UNDELIVERED_STATES),
                    ProvisioningAttempt.created_at >= now - RECORD_LOOKBACK,
                    Customer.router_id == router_id,
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.expiry.is_not(None),
                    Customer.expiry > now,
                    Customer.mac_address.is_not(None),
                    Plan.connection_type == ConnectionType.HOTSPOT,
                    # An older purchase that failed and was superseded by a
                    # later delivered one is history, not ours to rewrite.
                    ~exists().where(
                        newer.customer_id == ProvisioningAttempt.customer_id,
                        newer.provisioning_state == ProvisioningState.ROUTER_UPDATED,
                        newer.created_at > ProvisioningAttempt.created_at,
                    ),
                )
                .order_by(ProvisioningAttempt.created_at.desc(), ProvisioningAttempt.id.desc())
                .limit(PENDING_READ_LIMIT)
            )
        ).all()
        await db.commit()
    entries = []
    for mac, expiry, speed in rows:
        entry = desired_entry(mac, speed, expiry)
        if entry is None:
            logger.warning(
                "[CHECKIN] router %s: skipped customer mac=%r speed=%r (fails whitelist)",
                router_id, mac, speed,
            )
            continue
        entries.append(entry)
    pending = []
    for attempt_id, customer_id, state, created_at, mac in pending_rows:
        norm = normalize_reported_mac(mac or "")
        if norm is None:
            continue
        pending.append(PendingAttempt(
            attempt_id=int(attempt_id),
            customer_id=int(customer_id),
            mac=norm,
            state=state.value if hasattr(state, "value") else str(state),
            created_at=created_at,
        ))
    return CheckinState(desired=entries, undelivered_recent=undelivered, pending=pending)


async def load_desired_state(router_id: int, now: datetime) -> tuple[list[DesiredEntry], bool]:
    """Back-compat wrapper: (desired entries, "payment undelivered?")."""
    state = await load_checkin_state(router_id, now)
    return state.desired, state.undelivered_recent


# ---------------------------------------------------------------------------
# The decision (pure apart from the in-memory observations above)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    lines: list[DesiredEntry]
    would_send: list[DesiredEntry]
    unknown: set[str]
    next_s: int
    queue_lines: list[DesiredEntry] = field(default_factory=list)
    would_queue: list[DesiredEntry] = field(default_factory=list)
    # Missing paid MACs held back because they have not been missing for the
    # grace period yet (the Reconnect race guard).
    in_grace: list[DesiredEntry] = field(default_factory=list)


def decide(
    *,
    router: RouterRef,
    report: CheckinReport,
    desired: list[DesiredEntry],
    undelivered_recent: bool,
    mode: str,
    now: datetime,
    now_mono: Optional[float] = None,
    rng: random.Random | None = None,
) -> Decision:
    now_mono = time.monotonic() if now_mono is None else now_mono
    rid = router.id
    stats = _stats.setdefault(rid, RouterCheckinStats())
    stats.checkins += 1
    stats.last_checkin_at = now
    stats.last_reported = len(report.macs)
    stats.last_desired = len(desired)
    stats.invalid_macs_total += report.invalid
    _prune_sent(rid, now_mono)

    missing, unknown = compute_diff(desired, report.macs)
    stats.last_missing = len(missing)
    stats.last_unknown = len(unknown)

    payment_hot = undelivered_recent or payment_hint_active(rid, now_mono)

    if not report.count_matches:
        # A truncated or garbled report must not drive any action, and is not
        # an observation of "missing" either (it would start grace clocks).
        stats.count_mismatch_total += 1
        logger.warning(
            "[CHECKIN] router %s: declared n=%s but %d MACs received; replying empty",
            rid, report.declared_count, report.tokens,
        )
        return Decision([], [], unknown, next_poll_seconds(lines_sent=0, payment_hot=payment_hot, router_id=rid, rng=rng))

    # Tracking also forgets any MAC that stopped being desired (e.g. the OLD
    # MAC after a Reconnect), so its grace clock can never mature.
    _track_missing(rid, missing, report.macs, desired, now_mono, stats)

    grace = missing_grace_seconds()
    eligible: list[DesiredEntry] = []
    in_grace: list[DesiredEntry] = []
    for e in missing:
        first_missing = _missing_since.get((rid, e.mac), now_mono)
        (eligible if (now_mono - first_missing) >= grace else in_grace).append(e)
    stats.held_in_grace_total += len(in_grace)

    cap = max_lines_per_reply()
    offerable = [e for e in eligible if _offerable(_offers, rid, e.mac, now_mono)]
    would_send = offerable[:cap]

    stats.last_queue_missing = len(report.queue_missing)
    would_queue: list[DesiredEntry] = []
    if report.reports_queues:
        # Only an applier that reported q= understands Q lines.
        would_queue = _queue_candidates(rid, report, desired, now_mono)[: max(0, cap - len(would_send))]

    effective_mode = mode
    if mode == MODE_ADD and router.auth_method == RouterAuthMethod.RADIUS.value:
        # RADIUS routers do not get bypass bindings from the push path either.
        effective_mode = MODE_SHADOW

    lines: list[DesiredEntry] = []
    queue_lines: list[DesiredEntry] = []
    if effective_mode == MODE_ADD:
        if would_send:
            lines = would_send
            stats.lines_sent_total += len(lines)
            for e in lines:
                _note_offer(_offers, rid, e.mac, now_mono, MAX_OFFERS_BEFORE_BACKOFF, OFFER_BACKOFF_SECONDS)
                _sent_at[(rid, e.mac)] = now_mono
            logger.info(
                "[CHECKIN] router %s: sending %d add line(s): %s%s",
                rid, len(lines), ",".join(e.mac for e in lines),
                " (lb_enabled: LB_PAID not added by pull)" if router.lb_enabled else "",
            )
        if would_queue:
            queue_lines = would_queue
            stats.queue_lines_sent_total += len(queue_lines)
            for e in queue_lines:
                _note_offer(_queue_offers, rid, e.mac, now_mono,
                            MAX_QUEUE_OFFERS_BEFORE_BACKOFF, QUEUE_OFFER_BACKOFF_SECONDS)
            logger.info(
                "[CHECKIN] router %s: sending %d queue line(s): %s",
                rid, len(queue_lines), ",".join(e.mac for e in queue_lines),
            )
    else:
        if would_send:
            stats.would_send_total += len(would_send)
            logger.info(
                "[CHECKIN] shadow router %s: would send %d add line(s): %s",
                rid, len(would_send), ",".join(e.mac for e in would_send),
            )
        if would_queue:
            stats.would_queue_total += len(would_queue)

    if unknown and (now_mono - stats.last_unknown_log_at) >= UNKNOWN_LOG_EVERY_SECONDS:
        stats.last_unknown_log_at = now_mono
        sample = ",".join(sorted(unknown)[:5])
        logger.info(
            "[CHECKIN] router %s: %d tagged binding(s) with no paid customer (never removed by pull): %s%s",
            rid, len(unknown), sample, "..." if len(unknown) > 5 else "",
        )

    return Decision(
        lines=lines,
        would_send=would_send,
        unknown=unknown,
        # A MAC in its grace window keeps the router on the fast cadence so the
        # next report settles it (present, no longer desired, or send).
        next_s=next_poll_seconds(
            lines_sent=len(lines), payment_hot=payment_hot or bool(in_grace), router_id=rid, rng=rng,
        ),
        queue_lines=queue_lines,
        would_queue=would_queue,
        in_grace=in_grace,
    )


def _offerable(offers: dict, rid: int, mac: str, now_mono: float) -> bool:
    offer = offers.get((rid, mac))
    return offer is None or offer.suppressed_until <= now_mono


def _note_offer(offers: dict, rid: int, mac: str, now_mono: float, max_offers: int, backoff: int) -> None:
    offer = offers.setdefault((rid, mac), _Offer())
    offer.count += 1
    if offer.count >= max_offers:
        offer.count = 0
        offer.suppressed_until = now_mono + backoff
        logger.warning(
            "[CHECKIN] router %s: %s offered %d times and still not converged; "
            "pausing it for %ds (foreign binding, no IP yet, or applier error?)",
            rid, mac, max_offers, backoff,
        )


def _queue_candidates(rid: int, report: CheckinReport, desired: list[DesiredEntry], now_mono: float) -> list[DesiredEntry]:
    """Desired MACs the router holds a binding for but no ``plan_`` queue."""
    by_mac: dict[str, DesiredEntry] = {}
    for entry in desired:
        prev = by_mac.get(entry.mac)
        if prev is None or entry.expiry_epoch > prev.expiry_epoch:
            by_mac[entry.mac] = entry
    # A queue that appeared, or a MAC no longer paid for, resets its offers.
    for key in [k for k in _queue_offers
                if k[0] == rid and (k[1] not in report.queue_missing or k[1] not in by_mac)]:
        _queue_offers.pop(key, None)
    return [
        by_mac[mac] for mac in sorted(report.queue_missing)
        if mac in by_mac and _offerable(_queue_offers, rid, mac, now_mono)
    ]


def _prune_sent(rid: int, now_mono: float) -> None:
    for key in [k for k, t in _sent_at.items() if k[0] == rid and now_mono - t > SENT_MEMORY_SECONDS]:
        _sent_at.pop(key, None)


def _track_missing(rid, missing, reported, desired, now_mono, stats) -> None:
    """Remember when each paid MAC was first seen missing; log how it ended.

    An entry is dropped as soon as the MAC is present again OR is no longer
    desired, so its grace clock restarts from zero if it ever goes missing
    again.
    """
    missing_macs = {e.mac for e in missing}
    desired_macs = {e.mac for e in desired}
    for mac in missing_macs:
        _missing_since.setdefault((rid, mac), now_mono)
    for key in [k for k in _missing_since if k[0] == rid and k[1] not in missing_macs]:
        started = _missing_since.pop(key)
        mac = key[1]
        how = "present" if mac in reported else ("not_desired" if mac not in desired_macs else "unknown")
        seconds = int(now_mono - started)
        stats.resolved.append({"mac": mac, "missing_seconds": seconds, "resolved": how})
        _offers.pop(key, None)
        logger.info(
            "[CHECKIN] router %s: %s missing for %ds, resolved (%s)", rid, mac, seconds, how,
        )


# ---------------------------------------------------------------------------
# Recording deliveries the check-in observed (one short write session)
# ---------------------------------------------------------------------------

def delivery_candidates(report: CheckinReport, pending: Iterable[PendingAttempt]) -> list[PendingAttempt]:
    """Undelivered attempts whose customer's current MAC the router reports.

    Pure; the route only opens a write session when this is non-empty. A
    report whose count does not match is not trusted for this either.
    """
    if not report.count_matches:
        return []
    return [p for p in pending if p.mac in report.macs][:MAX_RECORDS_PER_CHECKIN]


def _truncate(value: str, limit: int = 255) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


async def record_checkin_deliveries(
    router_id: int,
    candidates: list[PendingAttempt],
    now: Optional[datetime] = None,
) -> int:
    """Mark attempts delivered because the router's report shows the MAC.

    The attempt ends in the state a successful push leaves it in
    (``router_updated``, ``router_updated_at``, ``last_error`` cleared) plus
    ``delivered_via='checkin'`` and ``access_seen_at``, so every consumer
    keyed on ``provisioning_state`` (retry job, ops health, session monitor,
    overload alerts) sees it delivered. ``online_state`` is ``unknown``: a
    binding in the report is not proof the device is connected, and the push
    only writes ``offline`` after actually polling the router's hosts — the
    session monitor would read ``offline`` as "client still offline".

    Idempotent: the update is conditional on the attempt still being
    undelivered and the customer still ACTIVE, unexpired, on this router with
    the same MAC (re-checked under the row lock; rows a push holds are
    skipped, not waited on). One short session; no I/O inside it.
    """
    if not candidates:
        return 0
    now = now or datetime.utcnow()
    by_id = {p.attempt_id: p for p in candidates[:MAX_RECORDS_PER_CHECKIN]}
    recorded: list[str] = []
    async with async_session() as db:
        rows = (
            await db.execute(
                select(
                    ProvisioningAttempt,
                    Customer.mac_address,
                    Customer.status,
                    Customer.expiry,
                    Customer.router_id,
                )
                .join(Customer, Customer.id == ProvisioningAttempt.customer_id)
                .where(
                    ProvisioningAttempt.id.in_(sorted(by_id)),
                    ProvisioningAttempt.provisioning_state.in_(UNDELIVERED_STATES),
                )
                .with_for_update(of=ProvisioningAttempt, skip_locked=True)
            )
        ).all()
        for attempt, mac, status, expiry, customer_router_id, in rows:
            pending = by_id.get(attempt.id)
            if pending is None:
                continue
            status_value = status.value if hasattr(status, "value") else str(status)
            if (
                status_value != CustomerStatus.ACTIVE.value
                or expiry is None
                or expiry <= now
                or customer_router_id != router_id
                or normalize_reported_mac(mac or "") != pending.mac
            ):
                continue  # changed since the read (Reconnect, expiry...): leave it
            previous = attempt.provisioning_state
            previous = previous.value if hasattr(previous, "value") else str(previous)
            attempt.provisioning_state = ProvisioningState.ROUTER_UPDATED
            attempt.online_state = ProvisioningOnlineState.UNKNOWN
            attempt.router_updated_at = now
            if attempt.delivered_via is None:
                attempt.delivered_via = DELIVERED_VIA_CHECKIN
            if attempt.access_seen_at is None:
                attempt.access_seen_at = now
            attempt.last_error = None
            attempt.updated_at = now
            added_here = (router_id, pending.mac) in _sent_at
            db.add(ProvisioningLog(
                customer_id=attempt.customer_id,
                router_id=router_id,
                attempt_id=attempt.id,
                mac_address=pending.mac,
                action="checkin_delivery",
                status="success",
                details=_truncate(
                    f"delivered via check-in at {now:%Y-%m-%dT%H:%M:%S}Z; "
                    f"router_id={router_id}; previous_state={previous}; "
                    f"binding_added_by_checkin={'yes' if added_here else 'no'}"
                ),
                log_date=now,
            ))
            recorded.append(f"{attempt.id}:{pending.mac}:{previous}")
        await db.commit()
    if recorded:
        stats = _stats.setdefault(router_id, RouterCheckinStats())
        stats.deliveries_recorded_total += len(recorded)
        logger.info(
            "[CHECKIN] router %s: recorded %d delivery(ies) seen by check-in: %s",
            router_id, len(recorded), ",".join(recorded),
        )
    return len(recorded)


# ---------------------------------------------------------------------------
# Admin metrics: which path delivered, and how fast (one short read)
# ---------------------------------------------------------------------------

METRICS_WINDOW = timedelta(hours=24)
METRICS_ROW_LIMIT = 20000


def _percentile(sorted_values: list[float], p: float) -> Optional[float]:
    """Nearest-rank percentile of an already sorted list."""
    if not sorted_values:
        return None
    rank = max(1, math.ceil(p * len(sorted_values)))
    return round(sorted_values[rank - 1], 1)


def _latency_summary(values: list[float]) -> dict:
    values = sorted(values)
    return {"samples": len(values), "p50_seconds": _percentile(values, 0.50),
            "p95_seconds": _percentile(values, 0.95)}


async def delivery_path_metrics(now: Optional[datetime] = None) -> dict:
    """Per-path delivery counts and payment->access latency, pilot vs rest.

    Covers attempts created in the last 24 h. ``other`` = delivered by a path
    that does not record itself (PPPoE, router agent, rows from before
    2026-09-26). Latency = access_seen_at - created_at, delivered rows only.
    """
    now = now or datetime.utcnow()
    start = now - METRICS_WINDOW
    pilot_ids = checkin_router_ids()
    async with async_session() as db:
        rows = (
            await db.execute(
                select(
                    ProvisioningAttempt.router_id,
                    ProvisioningAttempt.provisioning_state,
                    ProvisioningAttempt.delivered_via,
                    ProvisioningAttempt.created_at,
                    ProvisioningAttempt.access_seen_at,
                )
                .where(ProvisioningAttempt.created_at >= start)
                .order_by(ProvisioningAttempt.created_at.desc())
                .limit(METRICS_ROW_LIMIT)
            )
        ).all()
        await db.commit()

    def _empty():
        return {"attempts": 0,
                "counts": {DELIVERED_VIA_PUSH: 0, DELIVERED_VIA_CHECKIN: 0, "other": 0, "undelivered": 0},
                "_lat": {"all": [], DELIVERED_VIA_PUSH: [], DELIVERED_VIA_CHECKIN: []}}

    groups = {"pilot": _empty(), "rest": _empty()}
    for router_id, state, via, created_at, seen_at in rows:
        g = groups["pilot" if router_id in pilot_ids else "rest"]
        g["attempts"] += 1
        state_value = state.value if hasattr(state, "value") else str(state)
        if state_value != ProvisioningState.ROUTER_UPDATED.value:
            g["counts"]["undelivered"] += 1
            continue
        path = via if via in (DELIVERED_VIA_PUSH, DELIVERED_VIA_CHECKIN) else "other"
        g["counts"][path] += 1
        if seen_at is not None and created_at is not None:
            seconds = (seen_at - created_at).total_seconds()
            if seconds >= 0:
                g["_lat"]["all"].append(seconds)
                if path in g["_lat"]:
                    g["_lat"][path].append(seconds)

    out = {
        "window_hours": int(METRICS_WINDOW.total_seconds() // 3600),
        "pilot_router_ids": sorted(pilot_ids),
        "truncated": len(rows) >= METRICS_ROW_LIMIT,
    }
    for name, g in groups.items():
        lat = g.pop("_lat")
        g["payment_to_access"] = _latency_summary(lat["all"])
        g["payment_to_access_by_path"] = {
            DELIVERED_VIA_PUSH: _latency_summary(lat[DELIVERED_VIA_PUSH]),
            DELIVERED_VIA_CHECKIN: _latency_summary(lat[DELIVERED_VIA_CHECKIN]),
        }
        out[name] = g
    return out
