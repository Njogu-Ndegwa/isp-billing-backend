"""Write side of the customer audit log (``customer_events``).

Three producers, three rules:

* **Admin/system actions** (customer edited, PPPoE password regenerated, ...)
  call ``record_customer_event`` after their own commit. It opens its OWN short
  session and never raises: an audit write must not fail or hold up the action
  it describes (Database Session Discipline, rule 2).
* **Session transitions** come from the router push reports, which arrive
  every few seconds from every real-time router. That path must stay
  DB-free, so ``observe_push`` only diffs in memory and queues the events;
  ``flush_customer_events`` (a scheduler job) writes them in one batch and
  skips a tick when the pool is busy.
* **Router log lines** are written by ``store_event_rows`` with an
  ON CONFLICT DO NOTHING on ``dedup_key``.

A session event says what the router reported, not why: "ended" means the
session left ``/ppp active``. The matching router log line (pulled on demand or
by the collector) usually says why.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from sqlalchemy import delete, select

from app.db import database as db_module
from app.db.database import db_pool_snapshot
from app.db.models import Customer, CustomerEvent

logger = logging.getLogger(__name__)

# Bounded so a long DB outage costs memory we chose, not memory we ran out of.
_MAX_BUFFERED = 20_000
_buffer: deque[dict] = deque(maxlen=_MAX_BUFFERED)

FLUSH_BATCH = 2_000
POOL_PRESSURE_PERCENT = 60

# High-volume categories are pruned; record changes are kept.
PRUNED_CATEGORIES = ("session", "router_log")
RETENTION_DAYS = 60
PRUNE_CHUNK = 5_000

# A session or host can be missing from one report without having gone: the
# RouterOS 6 push script stops its /ppp active walk at the first session that
# vanishes mid-loop, and hotspot idle sweeps race the report. Only call it
# gone once it has been missing from this many reports in a row.
OFFLINE_AFTER_MISSES = 2


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def _clean(value: Any) -> Any:
    """Postgres text cannot hold NUL; router-supplied strings sometimes do."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _row(**kwargs: Any) -> dict:
    row = {
        "customer_id": None, "user_id": None, "router_id": None,
        "occurred_at": datetime.utcnow(), "category": "change", "event_type": "note",
        "severity": "info", "source": "system", "actor_user_id": None,
        "actor_label": None, "message": "", "details": None, "dedup_key": None,
    }
    row.update(kwargs)
    row["message"] = _clean(str(row["message"] or ""))[:1000]
    row["details"] = _clean(row["details"])
    if row["actor_label"]:
        row["actor_label"] = _clean(str(row["actor_label"]))[:120]
    return row


async def _insert_rows(session, rows: list[dict]) -> int:
    """Insert, skipping rows whose dedup_key is already stored. Returns inserted count."""
    if not rows:
        return 0
    dialect = session.bind.dialect.name if session.bind is not None else ""
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:  # pragma: no cover - production is Postgres, tests SQLite/Postgres
        session.add_all(CustomerEvent(**r) for r in rows)
        return len(rows)
    now = datetime.utcnow()
    for r in rows:
        r.setdefault("created_at", now)
    stmt = insert(CustomerEvent).values(rows).on_conflict_do_nothing(index_elements=["dedup_key"])
    result = await session.execute(stmt)
    return result.rowcount if result.rowcount is not None and result.rowcount >= 0 else len(rows)


async def _fill_owner(session, rows: list[dict]) -> None:
    missing = {r["customer_id"] for r in rows if r.get("customer_id") and not r.get("user_id")}
    if not missing:
        return
    owners = dict((await session.execute(
        select(Customer.id, Customer.user_id).where(Customer.id.in_(missing))
    )).all())
    for r in rows:
        if r.get("customer_id") in owners and not r.get("user_id"):
            r["user_id"] = owners[r["customer_id"]]


async def store_event_rows(rows: list[dict]) -> int:
    """Write rows in one short session of their own. Returns rows inserted."""
    rows = [_row(**r) for r in rows]
    if not rows:
        return 0
    inserted = 0
    # Looked up at call time so a rebound engine (tests, failover) is used.
    async with db_module.async_session() as session:
        await _fill_owner(session, rows)
        for start in range(0, len(rows), 500):
            inserted += await _insert_rows(session, rows[start:start + 500])
        await session.commit()
    return inserted


async def record_customer_event(
    customer_id: Optional[int],
    event_type: str,
    message: str,
    *,
    category: str = "change",
    severity: str = "info",
    source: str = "admin",
    actor=None,
    user_id: Optional[int] = None,
    router_id: Optional[int] = None,
    details: Optional[dict] = None,
) -> None:
    """Best-effort audit write for an action that has already committed."""
    try:
        await store_event_rows([{
            "customer_id": customer_id,
            "user_id": user_id,
            "router_id": router_id,
            "category": category,
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "actor_user_id": getattr(actor, "id", None),
            "actor_label": actor_label(actor),
            "message": message,
            "details": details,
        }])
    except Exception as exc:
        logger.warning("[AUDIT] could not record %s for customer %s: %s", event_type, customer_id, exc)


def actor_label(actor) -> Optional[str]:
    if actor is None:
        return None
    if getattr(getattr(actor, "role", None), "value", None) == "admin":
        return "Platform admin"
    return getattr(actor, "organization_name", None) or getattr(actor, "email", None) or f"user {actor.id}"


def enqueue_events(rows: Iterable[dict]) -> None:
    # An instance without the scheduler never flushes; queuing there would
    # only fill memory with events nobody writes.
    from app.core.runtime_mode import scheduler_enabled

    if not scheduler_enabled():
        return
    for r in rows:
        _buffer.append(r)


def buffered_count() -> int:
    return len(_buffer)


def _pool_busy() -> bool:
    try:
        percent = db_pool_snapshot().get("checked_out_percent")
        return percent is not None and float(percent) >= POOL_PRESSURE_PERCENT
    except Exception:
        return False


async def flush_customer_events() -> int:
    """Scheduler job: write queued session events. Skips while the pool is busy.

    A batch that fails is retried row by row, and a row that still fails is
    dropped: one bad row must not block every event behind it.
    """
    if not _buffer or _pool_busy():
        return 0
    batch = []
    while _buffer and len(batch) < FLUSH_BATCH:
        batch.append(_buffer.popleft())
    try:
        return await store_event_rows(batch)
    except Exception as exc:
        logger.warning("[AUDIT] flush of %d customer events failed, retrying one by one: %s", len(batch), exc)
    written = 0
    for row in batch:
        try:
            written += await store_event_rows([row])
        except Exception as exc:
            logger.warning("[AUDIT] dropped customer event %s for customer %s: %s",
                           row.get("event_type"), row.get("customer_id"), exc)
    return written


async def prune_customer_events(retention_days: int = RETENTION_DAYS) -> int:
    """Delete old session/router-log rows in chunks, one short transaction each."""
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    removed = 0
    while True:
        async with db_module.async_session() as session:
            ids = (await session.execute(
                select(CustomerEvent.id).where(
                    CustomerEvent.category.in_(PRUNED_CATEGORIES),
                    CustomerEvent.occurred_at < cutoff,
                ).limit(PRUNE_CHUNK)
            )).scalars().all()
            if ids:
                await session.execute(delete(CustomerEvent).where(CustomerEvent.id.in_(ids)))
            await session.commit()
        removed += len(ids)
        if len(ids) < PRUNE_CHUNK:
            return removed


# ---------------------------------------------------------------------------
# Session transitions from push reports
# ---------------------------------------------------------------------------

_RE_UPTIME_PART = re.compile(r"(\d+)([wdhms])")
_UNIT_SECONDS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}


def parse_uptime(value: Optional[str]) -> Optional[int]:
    """RouterOS '1w2d03:04:05' / '3h12m5s' / '00:04:05' -> seconds."""
    text = (value or "").strip()
    if not text:
        return None
    total = 0
    clock = re.search(r"(\d+):(\d{2}):(\d{2})$", text)
    if clock:
        total += int(clock.group(1)) * 3600 + int(clock.group(2)) * 60 + int(clock.group(3))
        text = text[:clock.start()]
    for amount, unit in _RE_UPTIME_PART.findall(text):
        total += int(amount) * _UNIT_SECONDS[unit]
    return total


def format_bytes(value: Optional[int]) -> str:
    if value is None:
        return "?"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit in ("B", "KB") else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"  # pragma: no cover


def format_duration(seconds: Optional[int]) -> str:
    if seconds is None:
        return "unknown time"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, _ = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


@dataclass
class _Seen:
    customer_id: int
    online: bool
    ip: str = ""
    uptime_s: Optional[int] = None
    caller_id: str = ""
    seen_at: Optional[datetime] = None
    misses: int = 0
    up_bytes: Optional[int] = None    # session counters at the last report
    down_bytes: Optional[int] = None
    missing_since: Optional[datetime] = None  # first report it was absent from


def _usage_text(seen: _Seen) -> str:
    if seen.down_bytes is None and seen.up_bytes is None:
        return ""
    return f", used {format_bytes(seen.down_bytes)} down / {format_bytes(seen.up_bytes)} up"


def _session_summary(seen: _Seen) -> dict:
    return {
        "ip": seen.ip, "caller_id": seen.caller_id, "uptime_seconds": seen.uptime_s,
        "download_bytes": seen.down_bytes, "upload_bytes": seen.up_bytes,
        "last_seen_at": _iso(seen.seen_at),
        "started_at": _iso(seen.seen_at - timedelta(seconds=seen.uptime_s))
        if seen.seen_at and seen.uptime_s is not None else None,
    }


# router_id -> key ("pppoe:<user>" or MAC) -> last known state
_sessions: dict[int, dict[str, _Seen]] = {}


def reset_session_tracker() -> None:
    _sessions.clear()
    _buffer.clear()


def _session_event(router_id, customer_id, at, event_type, severity, message, details) -> dict:
    return {
        "customer_id": customer_id, "router_id": router_id, "occurred_at": at,
        "category": "session", "event_type": event_type, "severity": severity,
        "source": "router_push", "message": message, "details": details,
    }


def observe_push(
    router_id: int,
    now: datetime,
    *,
    ppp: Optional[list[dict]] = None,
    pppoe_customers: Optional[dict[str, int]] = None,
    pppoe_queue_bytes: Optional[dict[str, tuple[int, int]]] = None,
    ppp_complete: bool = True,
    hosts: Optional[list[dict]] = None,
    live_hotspot_customers: Optional[dict[str, int]] = None,
) -> list[dict]:
    """Diff one push report against the last one; queue and return the events.

    ``ppp``/``hosts`` are None when the report did not carry that list — then
    nothing is concluded about those customers (absence of a list is not
    absence of the sessions). ``ppp_complete=False`` says the list is known to
    be short (the router counted more sessions than it listed): sessions in it
    are believed, missing ones are not. The first report a router sends after
    a restart only seeds the state, because there is nothing to compare it with.

    ``pppoe_customers`` maps "pppoe:<user>" to the customer id for EVERY PPPoE
    customer on the router, live or not, so the session that is cut when a
    customer expires is recorded too.

    ``pppoe_queue_bytes`` maps "pppoe:<user>" to the (upload, download) counters
    of the session's dynamic queue, which RouterOS creates with the session and
    removes with it — so the last value seen is that session's usage.
    """
    known = _sessions.get(router_id)
    first_report = known is None
    current: dict[str, _Seen] = {} if known is None else dict(known)
    events: list[dict] = []

    if ppp is not None:
        sessions = {f"pppoe:{p.get('name', '')}": p for p in ppp if p.get("name")}
        for key, customer_id in (pppoe_customers or {}).items():
            before = current.get(key)
            session = sessions.get(key)
            if session is None:
                if before is None or not before.online:
                    current[key] = before or _Seen(customer_id, False)
                    continue
                if not ppp_complete:
                    continue  # a short list proves nothing about who is missing
                misses = before.misses + 1
                missing_since = before.missing_since or now
                if misses < OFFLINE_AFTER_MISSES or first_report:
                    current[key] = _replace(before, misses=misses, missing_since=missing_since)
                    continue
                events.append(_session_event(
                    router_id, customer_id, missing_since, "session_disconnected", "warning",
                    f"PPPoE session ended after {format_duration(before.uptime_s)}"
                    f"{_usage_text(before)} (IP {before.ip or '-'})",
                    {"kind": "pppoe", **_session_summary(before)},
                ))
                current[key] = _Seen(customer_id, False, before.ip, None, before.caller_id, before.seen_at)
                continue

            uptime_s = parse_uptime(session.get("uptime"))
            ip = session.get("address", "") or ""
            caller_id = session.get("caller_id", "") or ""
            up, down = (pppoe_queue_bytes or {}).get(key, (None, None))
            details = {"kind": "pppoe", "ip": ip, "caller_id": caller_id, "uptime_seconds": uptime_s}
            # The session began uptime seconds ago, not when we noticed it.
            started = now - timedelta(seconds=uptime_s) if uptime_s is not None else now
            if not first_report:
                if before is None or not before.online:
                    events.append(_session_event(
                        router_id, customer_id, started, "session_connected", "info",
                        f"PPPoE session connected (IP {ip or '-'}{', from ' + caller_id if caller_id else ''})",
                        details,
                    ))
                elif _restarted(before, uptime_s):
                    events.append(_session_event(
                        router_id, customer_id, started, "session_reconnected", "warning",
                        f"PPPoE session dropped and came back between two reports; the previous session "
                        f"lasted at least {format_duration(before.uptime_s)}{_usage_text(before)}. "
                        f"New IP {ip or '-'}",
                        {**details, "previous": _session_summary(before)},
                    ))
                elif before.ip and ip and before.ip != ip:
                    events.append(_session_event(
                        router_id, customer_id, now, "session_ip_changed", "info",
                        f"PPPoE address changed {before.ip} -> {ip}", details,
                    ))
            current[key] = _Seen(customer_id, True, ip, uptime_s, caller_id, now, 0, up, down)

    if hosts is not None:
        best: dict[str, dict] = {}
        for h in hosts:
            mac = _mac(h.get("mac"))
            if mac and (mac not in best or _bytes(h) > _bytes(best[mac])):
                best[mac] = h
        for mac, customer_id in (live_hotspot_customers or {}).items():
            before = current.get(mac)
            host = best.get(mac)
            if host is None:
                if before is not None and before.online:
                    misses = before.misses + 1
                    if misses >= OFFLINE_AFTER_MISSES and not first_report:
                        events.append(_session_event(
                            router_id, customer_id, before.seen_at or now, "device_offline", "info",
                            f"Device left the hotspot after {format_duration(before.uptime_s)}"
                            f"{_usage_text(before)} (IP {before.ip or '-'})",
                            {"kind": "hotspot", "mac": mac, **_session_summary(before)},
                        ))
                        current[mac] = _Seen(customer_id, False, before.ip, None, "", before.seen_at)
                    else:
                        current[mac] = _replace(before, misses=misses)
                elif before is None:
                    current[mac] = _Seen(customer_id, False)
                continue
            ip = host.get("ip", "") or ""
            uptime_s = parse_uptime(host.get("uptime"))
            if not first_report and (before is None or not before.online):
                events.append(_session_event(
                    router_id, customer_id, now, "device_online", "info",
                    f"Device came online on the hotspot (IP {ip or '-'})",
                    {"kind": "hotspot", "mac": mac, "ip": ip, "bypassed": bool(host.get("bypassed"))},
                ))
            current[mac] = _Seen(customer_id, True, ip, uptime_s, "", now, 0,
                                 int(host.get("bytes_in") or 0), int(host.get("bytes_out") or 0))

    # Forget customers who are no longer on this router (deleted, moved) or,
    # for hotspot, no longer paid, so a later return reads as a fresh connect.
    if ppp is not None:
        current = {k: v for k, v in current.items()
                   if not k.startswith("pppoe:") or k in (pppoe_customers or {})}
    if hosts is not None:
        current = {k: v for k, v in current.items()
                   if k.startswith("pppoe:") or k in (live_hotspot_customers or {})}
    _sessions[router_id] = current
    enqueue_events(events)
    return events


def _replace(seen: _Seen, **changes) -> _Seen:
    return _Seen(**{**seen.__dict__, **changes})


def _restarted(before: _Seen, uptime_s: Optional[int]) -> bool:
    """True when the session's uptime went backwards: a new session replaced it.

    Compared with the router's own uptime only, never with our clock: a report
    that waited in our ingest queue would otherwise look like a restart.
    """
    if uptime_s is None or before.uptime_s is None:
        return False
    # 5 s of slack for RouterOS rounding.
    return uptime_s + 5 < before.uptime_s


def _mac(value: Optional[str]) -> Optional[str]:
    digits = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(digits) != 12:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()


def _bytes(host: dict) -> int:
    return int(host.get("bytes_in") or 0) + int(host.get("bytes_out") or 0)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None
