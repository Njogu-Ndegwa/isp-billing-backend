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
                     body: ``v=1&id=<identity>&n=<count>&macs=AA:..,BB:..``
                     (the MACs of its ``USER:``-tagged ip-bindings)

  server -> router   BWE1,<seq>,<count>,<next_s>
                     A,<mac>,<rate-limit>,<expiry-epoch>,<ref>     (x count)
                     END

The router's fixed applier script (``checkin_applier_script.py``) applies
nothing unless the frame is complete and every line validates. ``A`` means
"ensure this MAC is bypassed exactly like the API push would". There is no
remove line in the pilot: expired MACs the router still reports are only
counted and logged ("unknown").

Design rules (see AGENTS.md "Database Session Discipline"):

* Desired state is derived from existing tables — ACTIVE, unexpired hotspot
  customers on the router with a MAC. No schema change.
* One short read per check-in, released before anything else happens. Nothing
  is written per check-in; in particular the hot ``routers`` row is never
  touched. Pilot observations live in process memory (single worker), like
  ``realtime_state``.
* Every emitted field is whitelisted, so no quote, ``$``, ``;`` or bracket can
  ever reach a router, and a server bug can at worst produce a line the router
  rejects.
"""

from __future__ import annotations

import calendar
import logging
import random
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy import select

from app.config import settings
from app.db.database import async_session
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    Plan,
    ProvisioningAttempt,
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

    @property
    def count_matches(self) -> bool:
        return self.declared_count is not None and self.declared_count == self.tokens


class BadCheckin(ValueError):
    pass


def normalize_reported_mac(raw: str) -> Optional[str]:
    mac = str(raw or "").strip().upper().replace("-", ":")
    return mac if _MAC_RE.match(mac) else None


def parse_checkin_body(raw: bytes) -> CheckinReport:
    """Parse ``v=1&id=<identity>&n=<count>&macs=A,B,C``.

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
    return CheckinReport(
        identity=identity,
        declared_count=declared,
        macs=frozenset(macs),
        tokens=len(tokens),
        invalid=invalid,
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


def render_frame(seq: int, entries: Iterable[DesiredEntry], next_s: int) -> str:
    """Build the reply. Invalid entries are dropped, never emitted."""
    lines = []
    for entry in entries:
        line = format_add_line(entry)
        if line is None:
            logger.warning("[CHECKIN] dropped unsafe line for %r", entry)
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


def next_poll_seconds(*, lines_sent: int, payment_hot: bool, rng: random.Random | None = None) -> int:
    if lines_sent > 0:
        return CONFIRM_POLL_SECONDS
    if payment_hot:
        return FAST_POLL_SECONDS
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
_payment_hint: dict[int, float] = {}
_last_checkin: dict[str, float] = {}
_router_cache: dict[str, RouterRef] = {}


def reset_state() -> None:
    """Test hook."""
    _stats.clear()
    _missing_since.clear()
    _offers.clear()
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


async def load_desired_state(router_id: int, now: datetime) -> tuple[list[DesiredEntry], bool]:
    """One short read: paid hotspot MACs on the router + "payment undelivered?".

    The customers read rides ``ix_customers_status_expiry_user`` (status,
    expiry) and filters router_id on the few ACTIVE+unexpired rows; the
    attempts read rides the ``provisioning_attempts.router_id`` index.
    """
    since = now - timedelta(seconds=PAYMENT_HOT_SECONDS)
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
    return entries, undelivered


# ---------------------------------------------------------------------------
# The decision (pure apart from the in-memory observations above)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    lines: list[DesiredEntry]
    would_send: list[DesiredEntry]
    unknown: set[str]
    next_s: int


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

    missing, unknown = compute_diff(desired, report.macs)
    stats.last_missing = len(missing)
    stats.last_unknown = len(unknown)
    _track_missing(rid, missing, report.macs, desired, now_mono, stats)

    payment_hot = undelivered_recent or payment_hint_active(rid, now_mono)

    if not report.count_matches:
        # A truncated or garbled report must not drive any action.
        stats.count_mismatch_total += 1
        logger.warning(
            "[CHECKIN] router %s: declared n=%s but %d MACs received; replying empty",
            rid, report.declared_count, report.tokens,
        )
        return Decision([], [], unknown, next_poll_seconds(lines_sent=0, payment_hot=payment_hot, rng=rng))

    offerable = [e for e in missing if _offerable(rid, e.mac, now_mono)]
    would_send = offerable[: max_lines_per_reply()]

    effective_mode = mode
    if mode == MODE_ADD and router.auth_method == RouterAuthMethod.RADIUS.value:
        # RADIUS routers do not get bypass bindings from the push path either.
        effective_mode = MODE_SHADOW

    lines: list[DesiredEntry] = []
    if would_send:
        if effective_mode == MODE_ADD:
            lines = would_send
            stats.lines_sent_total += len(lines)
            for e in lines:
                _note_offer(rid, e.mac, now_mono)
            logger.info(
                "[CHECKIN] router %s: sending %d add line(s): %s%s",
                rid, len(lines), ",".join(e.mac for e in lines),
                " (lb_enabled: LB_PAID not added by pull)" if router.lb_enabled else "",
            )
        else:
            stats.would_send_total += len(would_send)
            logger.info(
                "[CHECKIN] shadow router %s: would send %d add line(s): %s",
                rid, len(would_send), ",".join(e.mac for e in would_send),
            )

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
        next_s=next_poll_seconds(lines_sent=len(lines), payment_hot=payment_hot, rng=rng),
    )


def _offerable(rid: int, mac: str, now_mono: float) -> bool:
    offer = _offers.get((rid, mac))
    return offer is None or offer.suppressed_until <= now_mono


def _note_offer(rid: int, mac: str, now_mono: float) -> None:
    offer = _offers.setdefault((rid, mac), _Offer())
    offer.count += 1
    if offer.count >= MAX_OFFERS_BEFORE_BACKOFF:
        offer.count = 0
        offer.suppressed_until = now_mono + OFFER_BACKOFF_SECONDS
        logger.warning(
            "[CHECKIN] router %s: %s offered %d times and still not reported; "
            "pausing it for %ds (foreign binding or applier error?)",
            rid, mac, MAX_OFFERS_BEFORE_BACKOFF, OFFER_BACKOFF_SECONDS,
        )


def _track_missing(rid, missing, reported, desired, now_mono, stats) -> None:
    """Remember when each paid MAC was first seen missing; log how it ended."""
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
