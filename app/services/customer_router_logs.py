"""Keep the router's own log lines about a customer, so they outlive the router.

A MikroTik keeps its log in RAM: about a thousand lines, gone on reboot. When a
customer says "my internet kept dropping last night", the PPPoE server's side
of the story ("peer is not responding", "authentication failed") has usually
scrolled away by the time anyone looks. This module reads the log, picks out
the lines that name one of the router's customers (PPPoE username, MAC or
caller-id) and stores them as ``customer_events`` rows (category
``router_log``), de-duplicated so re-reading the same lines is a no-op.

Two callers:

* the per-customer "pull router logs now" button
  (``POST /api/customers/{id}/audit-log/router-logs``), and
* the background collector (``collect_router_logs_background``), off unless
  ``CUSTOMER_LOG_COLLECTOR_ENABLED`` — it walks routers that have PPPoE
  customers a few at a time.

Times: router log stamps are local to the router (EAT on most of the fleet)
and abbreviated ("10:11:12" today, "oct/11 10:11:12" this year on ROS6,
"10-11 10:11:12" on ROS7). They are resolved against the router's own clock,
read in the same connection, and stored as naive UTC like every other column.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Iterable, Optional

from app.services.log_persistence import _classify_entry

logger = logging.getLogger(__name__)

# EAT; used only when the router's clock could not be read.
DEFAULT_GMT_OFFSET_MINUTES = 180

# Topics worth keeping when they name a customer. Firewall logging is left out
# on purpose: a router that logs its filter rules names every MAC every second.
CUSTOMER_TOPICS = ("pppoe", "ppp", "hotspot", "dhcp", "radius", "wireless", "caps", "wifi")

_MONTHS = {
    m: i for i, m in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1
    )
}

_RE_TIME = re.compile(r"^(\d{1,2}):(\d{2}):(\d{2})$")
_RE_MON_DAY = re.compile(r"^([a-z]{3})/(\d{1,2})(?:/(\d{4}))?\s+(\d{1,2}):(\d{2}):(\d{2})$", re.I)
_RE_ISO = re.compile(r"^(?:(\d{4})-)?(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})$")
_RE_OFFSET = re.compile(r"^([+-])?(\d{1,2}):?(\d{2})?$")


# ---------------------------------------------------------------------------
# Router clock and log timestamps
# ---------------------------------------------------------------------------

def parse_gmt_offset(value: Any) -> Optional[int]:
    """'+03:00' / '-01:00' / '+0300' / seconds as int -> minutes east of UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return int(value) // 60
    text = str(value).strip()
    if text.lstrip("+-").isdigit() and ":" not in text and len(text.lstrip("+-")) > 4:
        return int(text) // 60  # seconds, as some builds report it
    m = _RE_OFFSET.match(text)
    if not m:
        return None
    sign = -1 if m.group(1) == "-" else 1
    return sign * (int(m.group(2)) * 60 + int(m.group(3) or 0))


def parse_router_date(value: str) -> Optional[date]:
    """ROS6 'oct/11/2026' or ROS7 '2026-10-11'."""
    text = (value or "").strip().lower()
    try:
        if "/" in text:
            mon, day, year = text.split("/")
            return date(int(year), _MONTHS[mon[:3]], int(day))
        if "-" in text:
            year, mon, day = text.split("-")
            return date(int(year), int(mon), int(day))
    except (KeyError, ValueError):
        return None
    return None


@dataclass
class RouterClock:
    """The router's own idea of 'now', which its log stamps are relative to."""

    local_now: datetime
    offset_minutes: int
    trusted: bool  # False when the router clock is unset (no RTC, no NTP yet)
    # Our UTC clock when the router's clock was read. Stamps are converted by
    # their distance from local_now, so neither the router's time zone setting
    # nor its drift leaks into the stored time.
    fetched_utc: Optional[datetime] = None

    @classmethod
    def from_clock_print(cls, row: Optional[dict], fallback_utc: datetime) -> "RouterClock":
        row = row or {}
        offset = parse_gmt_offset(row.get("gmt-offset"))
        if offset is None:
            offset = DEFAULT_GMT_OFFSET_MINUTES
        local_date = parse_router_date(row.get("date", ""))
        m = _RE_TIME.match((row.get("time") or "").strip())
        if local_date and m:
            local_now = datetime(local_date.year, local_date.month, local_date.day,
                                 int(m.group(1)), int(m.group(2)), int(m.group(3)))
        else:
            local_now = fallback_utc + timedelta(minutes=offset)
        expected = fallback_utc + timedelta(minutes=offset)
        # A clock more than a day off is unset or wrong; its stamps are useless.
        trusted = abs((local_now - expected).total_seconds()) < 86400
        return cls(local_now=local_now, offset_minutes=offset, trusted=trusted, fetched_utc=fallback_utc)

    def to_utc(self, local: datetime) -> datetime:
        if self.fetched_utc is not None:
            return self.fetched_utc - (self.local_now - local)
        return local - timedelta(minutes=self.offset_minutes)


def parse_log_time(raw: str, clock: RouterClock) -> Optional[datetime]:
    """Resolve an abbreviated RouterOS log stamp to the router's local time."""
    text = (raw or "").strip()
    now = clock.local_now
    m = _RE_TIME.match(text)
    if m:
        parsed = now.replace(hour=int(m.group(1)), minute=int(m.group(2)),
                             second=int(m.group(3)), microsecond=0)
        # A time-only stamp is today; one "after" now was yesterday's.
        return parsed - timedelta(days=1) if parsed > now + timedelta(minutes=5) else parsed
    m = _RE_MON_DAY.match(text)
    if m:
        month = _MONTHS.get(m.group(1).lower())
        if not month:
            return None
        year = int(m.group(3)) if m.group(3) else now.year
        try:
            parsed = datetime(year, month, int(m.group(2)),
                              int(m.group(4)), int(m.group(5)), int(m.group(6)))
        except ValueError:
            return None
        if not m.group(3) and parsed > now + timedelta(days=1):
            parsed = parsed.replace(year=year - 1)
        return parsed
    m = _RE_ISO.match(text)
    if m:
        year = int(m.group(1)) if m.group(1) else now.year
        try:
            parsed = datetime(year, int(m.group(2)), int(m.group(3)),
                              int(m.group(4)), int(m.group(5)), int(m.group(6)))
        except ValueError:
            return None
        if not m.group(1) and parsed > now + timedelta(days=1):
            parsed = parsed.replace(year=year - 1)
        return parsed
    return None


# ---------------------------------------------------------------------------
# Matching lines to customers
# ---------------------------------------------------------------------------

def _canonical_mac(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(hexdigits) != 12:
        return None
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)).upper()


_RE_MAC_IN_TEXT = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:])")
# PPPoE usernames are [A-Za-z0-9._@-]; a line is split on everything else.
_RE_TOKEN = re.compile(r"[A-Za-z0-9._@-]+")
# A 1-3 character username would match half the log.
MIN_USERNAME_LENGTH = 4
# Stamps before this year come from a router whose clock was not yet set.
MIN_PLAUSIBLE_YEAR = 2020
# A username is only looked for in lines from the services that log in users;
# a DHCP or Wi-Fi line names devices by MAC, and a common-word username
# ("home") would otherwise match unrelated text there.
USERNAME_TOPICS = ("ppp", "hotspot", "radius")


@dataclass
class CustomerRef:
    customer_id: int
    user_id: Optional[int]


class CustomerIndex:
    """Who a log line is about: PPPoE username or MAC/caller-id -> customer.

    Lookups are by token, so a router with thousands of customers costs the
    same per line as one with a single customer. A username matches only as a
    whole token and only in PPP/hotspot lines, so "john" never matches "john2"
    or "john.doe". RouterOS writes the interface as "<pppoe-john>", so a
    "pppoe-" prefix is peeled off.
    """

    def __init__(self) -> None:
        self.by_username: dict[str, CustomerRef] = {}
        self.by_mac: dict[str, CustomerRef] = {}

    def add(
        self,
        customer_id: int,
        user_id: Optional[int],
        pppoe_username: Optional[str] = None,
        macs: Iterable[Optional[str]] = (),
    ) -> None:
        ref = CustomerRef(customer_id, user_id)
        # RouterOS user names are case-sensitive: "John" and "john" are two
        # accounts, so they are matched exactly.
        username = (pppoe_username or "").strip()
        if len(username) >= MIN_USERNAME_LENGTH:
            self.by_username.setdefault(username, ref)
        for mac in macs:
            canonical = _canonical_mac(mac)
            if canonical:
                self.by_mac.setdefault(canonical, ref)

    def __len__(self) -> int:
        return len(self.by_username) + len(self.by_mac)

    def match(self, message: str, topics: str = "ppp") -> Optional[tuple[CustomerRef, str]]:
        lowered_topics = (topics or "").lower()
        if self.by_username and any(t in lowered_topics for t in USERNAME_TOPICS):
            for token in _RE_TOKEN.findall(message):
                token = token.rstrip(".-")
                ref = self.by_username.get(token)
                if ref is None and token.startswith("pppoe-"):
                    ref = self.by_username.get(token[len("pppoe-"):])
                if ref is not None:
                    return ref, "username"
        if self.by_mac:
            for found in _RE_MAC_IN_TEXT.findall(message):
                ref = self.by_mac.get(found.upper())
                if ref is not None:
                    return ref, "mac"
        return None


# PPPoE trouble that the generic "notable" patterns do not catch.
_RE_WARNING = re.compile(
    r"not responding|terminating|rejected|lcp|duplicate|no response|link down|timeout", re.IGNORECASE
)


def _severity(topics: str, message: str) -> str:
    lowered = (topics or "").lower()
    if "critical" in lowered or "error" in lowered:
        return "error"
    notable = _classify_entry({"message": message})
    if notable is not None:
        return notable.value
    if "warning" in lowered or _RE_WARNING.search(message):
        return "warning"
    return "info"


def _topic_allowed(topics: str) -> bool:
    lowered = (topics or "").lower()
    if "firewall" in lowered:
        return False
    return any(t in lowered for t in CUSTOMER_TOPICS)


def match_log_entries(
    router_id: int,
    entries: list[dict],
    clock: RouterClock,
    index: CustomerIndex,
    fetched_at: datetime,
) -> list[dict]:
    """Turn raw ``/log print`` rows into ``customer_events`` rows (as dicts).

    Each line goes to the first customer it names (username before MAC). The dedup key is built from
    the resolved stamp, so the same line read twice (or once before midnight
    as "23:59:01" and once after as "oct/11 23:59:01") is stored once.
    """
    rows: list[dict] = []
    seen: dict[tuple[str, str], int] = {}
    for entry in entries:
        message = str(entry.get("message") or "")
        topics = str(entry.get("topics") or "")
        raw_time = str(entry.get("time") or "")
        if not message or not _topic_allowed(topics):
            continue
        local = parse_log_time(raw_time, clock) if clock.trusted else None
        if local is not None and local.year < MIN_PLAUSIBLE_YEAR:
            # Written before the router's clock was set (hAP lite after a
            # reboot: "jan/02/1970"). The time is meaningless; skip the line.
            continue
        # Without a usable clock the raw stamp repeats after every reboot, so
        # the read date is part of the key: same day, same line = duplicate.
        stamp = local.isoformat() if local else f"{fetched_at:%Y-%m-%d}|{raw_time}"
        occurrence = seen.get((stamp, message), 0)
        seen[(stamp, message)] = occurrence + 1

        found = index.match(message, topics)
        if found is None:
            continue
        ref, matched_on = found
        digest = hashlib.sha256(
            f"rl|{router_id}|{stamp}|{occurrence}|{message}".encode("utf-8", "replace")
        ).hexdigest()
        rows.append({
            "customer_id": ref.customer_id,
            "user_id": ref.user_id,
            "router_id": router_id,
            "occurred_at": clock.to_utc(local) if local else fetched_at,
            "category": "router_log",
            "event_type": "router_log",
            "severity": _severity(topics, message),
            "source": "router_log",
            "message": message[:1000],
            "details": {
                "topics": topics[:100],
                "router_time": raw_time[:40],
                "matched_on": matched_on,
                "time_estimated": local is None,
            },
            "dedup_key": digest,
        })
    return rows


# ---------------------------------------------------------------------------
# RouterOS read (sync, runs in the router guard's thread)
# ---------------------------------------------------------------------------

def fetch_router_log_sync(router_info: dict, ppp_username: Optional[str] = None) -> dict:
    """One connection: the router clock, the whole in-memory log and, for one
    PPPoE user, the secret's record of its last disconnect (RouterOS 7)."""
    from app.services.mikrotik_api import MikroTikAPI

    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=20, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        clock_row = None
        try:
            clock = api.send_command("/system/clock/print")
            if clock.get("success") and clock.get("data"):
                clock_row = clock["data"][0]
        except Exception as exc:  # the log is still worth having
            logger.debug("router clock read failed: %s", exc)
        logs = api.send_command_optimized("/log/print", proplist=["time", "topics", "message"])
        if not logs.get("success"):
            return {"error": logs.get("error") or "log_read_failed"}
        secret_row = None
        if ppp_username:
            try:
                secret = api.send_command_optimized(
                    "/ppp/secret/print",
                    proplist=["name", "last-logged-out", "last-caller-id", "last-disconnect-reason"],
                    query=f"?name={ppp_username}",
                )
                if secret.get("success") and secret.get("data"):
                    secret_row = secret["data"][0]
            except Exception as exc:  # RouterOS 6 has no such fields; not fatal
                logger.debug("ppp secret read failed: %s", exc)
        return {"success": True, "clock": clock_row, "entries": logs.get("data", []), "secret": secret_row}
    except Exception as exc:
        logger.warning("router log read failed: %s", exc)
        return {"error": str(exc)}
    finally:
        api.disconnect()


# RouterOS 7 /ppp secret last-disconnect-reason values, in a reseller's words.
DISCONNECT_REASONS = {
    "peer-request": "the customer's router asked to disconnect (restart or reconfiguration)",
    "hung-up": "the customer's router hung up",
    "idle-timeout": "the session was idle too long",
    "session-timeout": "the session reached its time limit",
    "reset": "the session was reset",
    "reboot": "the MikroTik rebooted",
    "port-error": "the link to the customer failed (power, cable or radio)",
    "nas-error": "the MikroTik had an internal error",
    "nas-request": "the MikroTik or billing system disconnected it (for example on expiry)",
}


def last_disconnect_row(router_id: int, secret: Optional[dict], clock: RouterClock,
                        customer_id: int, user_id: Optional[int], fetched_at: datetime) -> Optional[dict]:
    """The secret's own record of the last disconnect, as one router_log row."""
    if not secret:
        return None
    reason = (secret.get("last-disconnect-reason") or "").strip()
    logged_out = (secret.get("last-logged-out") or "").strip()
    if not reason or not logged_out or logged_out.startswith("1970") or logged_out.lower().startswith("jan/01/1970"):
        return None
    local = parse_log_time(logged_out, clock) if clock.trusted else None
    if local is not None and local.year < MIN_PLAUSIBLE_YEAR:
        return None
    caller = (secret.get("last-caller-id") or "").strip()
    plain = DISCONNECT_REASONS.get(reason, reason.replace("-", " "))
    severity = "warning" if reason in ("port-error", "nas-error", "hung-up") else "info"
    return {
        "customer_id": customer_id, "user_id": user_id, "router_id": router_id,
        "occurred_at": clock.to_utc(local) if local else fetched_at,
        "category": "router_log", "event_type": "last_disconnect", "severity": severity,
        "source": "router_log",
        "message": f"Router's record of the last disconnect: {reason} ({plain})"
                   + (f", device {caller}" if caller else ""),
        "details": {"router_time": logged_out[:40], "reason": reason, "caller_id": caller,
                    "time_estimated": local is None},
        "dedup_key": hashlib.sha256(
            f"ld|{router_id}|{customer_id}|{logged_out}|{reason}".encode()).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Capture (async; call with no DB session open)
# ---------------------------------------------------------------------------

def router_info_of(router) -> dict:
    return {
        "ip": router.ip_address, "username": router.username,
        "password": router.password, "port": router.port,
    }


async def capture_router_logs(
    router_id: int,
    router_info: dict,
    index: CustomerIndex,
    *,
    acquire_timeout_seconds: Optional[float] = None,
    ppp_customer: Optional[tuple[int, Optional[int], str]] = None,
) -> dict:
    """Read one router's log, keep the lines that name a customer in ``index``.

    ``ppp_customer`` = (customer_id, owner id, PPPoE username) also reads that
    user's last-disconnect record. RouterOS I/O first, then one short write
    session — never both at once.
    """
    from app.services.customer_events import store_event_rows
    from app.services.router_concurrency import run_with_guard

    fetched_at = datetime.utcnow()
    raw = await run_with_guard(
        router_id, fetch_router_log_sync, router_info,
        ppp_customer[2] if ppp_customer else None,
        acquire_timeout_seconds=acquire_timeout_seconds,
    )
    if raw.get("error"):
        return {"error": raw["error"], "detail": raw.get("detail")}
    entries = raw.get("entries") or []
    clock = RouterClock.from_clock_print(raw.get("clock"), fetched_at)
    rows = match_log_entries(router_id, entries, clock, index, fetched_at)
    matched = len(rows)
    if ppp_customer:
        last = last_disconnect_row(router_id, raw.get("secret"), clock,
                                   ppp_customer[0], ppp_customer[1], fetched_at)
        if last:
            rows.append(last)
    stored = await store_event_rows(rows) if rows else 0
    oldest = None
    for entry in entries[:1]:
        local = parse_log_time(str(entry.get("time") or ""), clock) if clock.trusted else None
        oldest = clock.to_utc(local) if local else None
    return {
        "success": True,
        "lines_read": len(entries),
        "matched": matched,
        "stored": stored,
        # How far back the router's log reaches right now; anything older
        # is only here if it was captured earlier.
        "router_log_starts_at": oldest.isoformat() if oldest else None,
        "router_clock_trusted": clock.trusted,
        "router_gmt_offset_minutes": clock.offset_minutes,
    }


_last_visit: dict[int, datetime] = {}
# Kept well under the 120 s tick so a slow router read cannot push the job
# into its next run.
COLLECTOR_TIME_BUDGET_SECONDS = 60
# Hotspot customers whose time ran out longer ago than this are left out of
# the collector's index; their devices are not ours to follow any more.
HOTSPOT_LOOKBACK = timedelta(days=7)


async def collect_router_logs_background() -> dict:
    """Scheduler job: capture customer log lines from a few PPPoE routers.

    Picks the routers least recently visited, never one visited within
    CUSTOMER_LOG_COLLECTOR_MIN_REVISIT_SECONDS, skips recently-offline ones,
    sheds when the DB pool is busy, and stops when its time budget is spent.
    """
    import time

    from sqlalchemy import or_, select

    from app.config import settings
    from app.db import database as db_module
    from app.db.models import Customer, Router, SubscriptionStatus, User, UserRole

    PAYING_STATUSES = (SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL)
    from app.services.customer_events import _pool_busy
    from app.services.router_availability import router_recently_offline

    if not getattr(settings, "CUSTOMER_LOG_COLLECTOR_ENABLED", False) or _pool_busy():
        return {"skipped": True}
    now = datetime.utcnow()
    per_tick = max(1, int(getattr(settings, "CUSTOMER_LOG_COLLECTOR_ROUTERS_PER_TICK", 4)))
    revisit = timedelta(seconds=int(getattr(settings, "CUSTOMER_LOG_COLLECTOR_MIN_REVISIT_SECONDS", 900)))

    async with db_module.async_session() as db:
        pppoe_router_ids = (
            select(Customer.router_id)
            .where(Customer.pppoe_username.isnot(None), Customer.router_id.isnot(None))
            .distinct()
        )
        # Like the push path, do no router work for resellers who stopped paying.
        routers = (await db.execute(
            select(Router)
            .join(User, Router.user_id == User.id)
            .where(
                Router.id.in_(pppoe_router_ids),
                or_(User.role == UserRole.ADMIN, User.subscription_status.in_(PAYING_STATUSES)),
            )
        )).scalars().all()
        due = [
            r for r in routers
            if not router_recently_offline(r, now)
            and now - _last_visit.get(r.id, datetime.min) >= revisit
        ]
        due.sort(key=lambda r: _last_visit.get(r.id, datetime.min))
        picked = due[:per_tick]
        jobs = []
        if picked:
            customers = (await db.execute(
                select(Customer.id, Customer.user_id, Customer.router_id,
                       Customer.pppoe_username, Customer.mac_address)
                .where(
                    Customer.router_id.in_([r.id for r in picked]),
                    or_(Customer.pppoe_username.isnot(None), Customer.expiry >= now - HOTSPOT_LOOKBACK),
                )
            )).all()
            indexes: dict[int, CustomerIndex] = {r.id: CustomerIndex() for r in picked}
            for cid, uid, rid, username, mac in customers:
                indexes[rid].add(cid, uid, username, [mac])
            jobs = [(r.id, router_info_of(r), indexes[r.id]) for r in picked]
        await db.commit()

    started = time.monotonic()
    summary = {"routers": 0, "stored": 0, "errors": 0}
    for router_id, info, index in jobs:
        if time.monotonic() - started > COLLECTOR_TIME_BUDGET_SECONDS:
            break
        _last_visit[router_id] = datetime.utcnow()
        if not len(index):
            continue
        try:
            result = await capture_router_logs(router_id, info, index, acquire_timeout_seconds=2.0)
        except Exception as exc:
            logger.warning("[AUDIT] log collection failed for router %s: %s", router_id, exc)
            summary["errors"] += 1
            continue
        summary["routers"] += 1
        if result.get("error"):
            summary["errors"] += 1
        else:
            summary["stored"] += result.get("stored", 0)
    if summary["stored"] or summary["errors"]:
        logger.info("[AUDIT] router log collector: %s", summary)
    return summary
