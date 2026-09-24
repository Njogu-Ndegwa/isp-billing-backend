"""Latest router health, one row per router (``router_health``).

Sources: the push agent (``source='push'``, every ~2 min, over the router's own
internet) and the SNMP pilot poller (``source='snmp'``). Whatever arrives most
recently wins; the dashboard dial and the CPU overload alerts read from here,
so every surface shows the same number.

Why a separate table and not columns on ``routers``: the ``routers`` row is the
hot shared summary row written by ~40 availability paths. A health write every
two minutes per router must not contend for its lock (AGENTS.md, Database
Session Discipline rule 2). This table is written in its own short session,
after the push ingest has committed, and never on a customer-facing path.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.db import database
from app.db.models import Router, RouterHealth

logger = logging.getLogger(__name__)

SOURCE_PUSH = "push"
SOURCE_SNMP = "snmp"

_MAX_BYTES = 1 << 42           # 4 TiB — far beyond any MikroTik
_MAX_UPTIME = 10 * 365 * 86400
_TEXT_LIMITS = {"routeros_version": 40, "board_name": 60}


@dataclass
class HealthSample:
    cpu_load: Optional[int] = None
    memory_free_bytes: Optional[int] = None
    memory_total_bytes: Optional[int] = None
    storage_free_bytes: Optional[int] = None
    storage_total_bytes: Optional[int] = None
    uptime_seconds: Optional[int] = None
    routeros_version: Optional[str] = None
    board_name: Optional[str] = None
    wan_link_downs: Optional[int] = None

    def is_empty(self) -> bool:
        return all(v is None for v in self.__dict__.values())


_UPTIME_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}


def parse_uptime(raw) -> Optional[int]:
    """RouterOS uptime -> seconds. Accepts ``1w2d3h4m5s`` (both ROS 6 and 7
    print this) and ``1w2d03:04:05`` (some ROS 7 builds). None if unparseable."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return int(raw) if 0 <= raw <= _MAX_UPTIME else None
    text = str(raw).strip().lower()
    if not text:
        return None
    total = 0
    clock = re.search(r"(\d+):(\d{2}):(\d{2})$", text)
    if clock:
        total += int(clock.group(1)) * 3600 + int(clock.group(2)) * 60 + int(clock.group(3))
        text = text[:clock.start()]
    consumed = "".join(m.group(0) for m in re.finditer(r"(\d+)([wdhms])", text))
    if consumed != text:
        return None
    for num, unit in re.findall(r"(\d+)([wdhms])", text):
        total += int(num) * _UPTIME_UNITS[unit]
    return total if 0 <= total <= _MAX_UPTIME else None


def _int_in(value, lo: int, hi: int) -> Optional[int]:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def sanitize(sample: HealthSample) -> HealthSample:
    """Drop (not reject) any implausible field; the rest of the sample stands."""
    clean = HealthSample(
        cpu_load=_int_in(sample.cpu_load, 0, 100),
        memory_free_bytes=_int_in(sample.memory_free_bytes, 0, _MAX_BYTES),
        memory_total_bytes=_int_in(sample.memory_total_bytes, 1, _MAX_BYTES),
        storage_free_bytes=_int_in(sample.storage_free_bytes, 0, _MAX_BYTES),
        storage_total_bytes=_int_in(sample.storage_total_bytes, 1, _MAX_BYTES),
        uptime_seconds=parse_uptime(sample.uptime_seconds),
        wan_link_downs=_int_in(sample.wan_link_downs, 0, 1 << 40),
    )
    for name, limit in _TEXT_LIMITS.items():
        raw = getattr(sample, name)
        if raw is not None:
            text = "".join(ch for ch in str(raw) if ch.isprintable()).strip()[:limit]
            setattr(clean, name, text or None)
    if (clean.memory_free_bytes is not None and clean.memory_total_bytes is not None
            and clean.memory_free_bytes > clean.memory_total_bytes):
        clean.memory_free_bytes = clean.memory_total_bytes = None
    if (clean.storage_free_bytes is not None and clean.storage_total_bytes is not None
            and clean.storage_free_bytes > clean.storage_total_bytes):
        clean.storage_free_bytes = clean.storage_total_bytes = None
    return clean


async def record(router_id: int, sample: HealthSample, *, source: str,
                 now: Optional[datetime] = None) -> Optional[str]:
    """Upsert the router's latest health in its own short session. Never raises.

    Only fields present in the sample overwrite the stored row, so an SNMP
    reading (CPU only) does not erase memory figures from the last push.
    Returns the router name when a CPU value was stored (for alert copy),
    otherwise None.
    """
    now = now or datetime.utcnow()
    clean = sanitize(sample)
    if clean.is_empty():
        return None
    values = {k: v for k, v in clean.__dict__.items() if v is not None}
    values.update(source=source, sampled_at=now)
    try:
        for _attempt in range(2):
            async with database.async_session() as db:
                row = await db.get(RouterHealth, router_id)
                if row is None:
                    db.add(RouterHealth(router_id=router_id, **values))
                else:
                    for key, value in values.items():
                        setattr(row, key, value)
                try:
                    name = None
                    if clean.cpu_load is not None:
                        name = (await db.execute(
                            select(Router.name).where(Router.id == router_id))).scalar()
                    await db.commit()
                    return name if clean.cpu_load is not None else None
                except IntegrityError:
                    await db.rollback()   # lost an insert race; retry as update
        return None
    except Exception:
        logger.exception("router_health: could not record sample for router %s", router_id)
        return None


async def record_and_evaluate(router_id: int, sample: HealthSample, *, source: str,
                              now: Optional[datetime] = None) -> None:
    """Record a sample and, for CPU, feed the overload rules. Never raises.

    Alert delivery is fire-and-forget: the caller (a router-facing push
    request) never waits on it.
    """
    now = now or datetime.utcnow()
    try:
        name = await record(router_id, sample, source=source, now=now)
        cpu = sanitize(sample).cpu_load
        if cpu is None or name is None or not settings.ROUTER_OVERLOAD_ALERTS_ENABLED:
            return
        from app.services import router_overload_alerts as oa
        oa.record_cpu_sample(router_id, cpu, now)
        level = oa.evaluate_cpu_level(router_id)
        if level is None or not oa.should_attempt(router_id, level, now):
            return
        subject, body = oa.render_cpu_alert(name, level, cpu)
        _spawn(oa.send_overload_alert(router_id, level, subject, body, now=now))
    except Exception:
        logger.exception("router_health: evaluation failed for router %s", router_id)


_tasks: set = set()


def _spawn(coro) -> None:
    try:
        task = asyncio.create_task(coro)
    except RuntimeError:
        coro.close()
        return
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def latest(router_id: int, db) -> Optional[RouterHealth]:
    return await db.get(RouterHealth, router_id)
