"""Bounded router health history for graphs (``router_metric_buckets``).

``router_health`` holds one row per router, the latest reading. It can say what
the CPU is now, but not whether it has been pinned all evening. This module
folds every health sample (push agent and SNMP, via ``router_health.record``)
into two fixed tiers of buckets:

    tier     bucket    kept      rows per router
    fine     5 min     26 h      <= 312
    coarse   1 hour    8 days    <= 192

The 24-hour graph reads the 5-minute tier, the 7-day graph the hourly one.
Storage is bounded by the number of reporting routers, not by time or push
cadence: about 500 narrow rows per router at most. That was ~5 MB for the ~110
routers reporting in Nov 2026, and would be ~20 MB if all 427 did. Raw samples
are never kept.

Each bucket holds CPU load and memory in use as (sum, samples, max). The average
shows the trend, and the max keeps a short spike that the average would flatten.
It also holds reboots and WAN link drops.

Session discipline: pure DB, no I/O. ``fold`` rides ``router_health.record``'s
short session inside a savepoint, so a failure here costs one bucket increment,
never the latest reading the dial and the overload alerts depend on.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import delete, select

from app.db.models import RouterMetricBucket

logger = logging.getLogger(__name__)

FINE_STEP_SECONDS = 300
COARSE_STEP_SECONDS = 3600

# (bucket size, how long buckets of that size are kept). Each tier keeps a
# little more than the longest range drawn from it, so that range is full.
TIERS: tuple[tuple[int, timedelta], ...] = (
    (FINE_STEP_SECONDS, timedelta(hours=26)),
    (COARSE_STEP_SECONDS, timedelta(days=8)),
)

# What the API can draw: range key -> (bucket size, span).
RANGES: dict[str, tuple[int, timedelta]] = {
    "24h": (FINE_STEP_SECONDS, timedelta(hours=24)),
    "7d": (COARSE_STEP_SECONDS, timedelta(days=7)),
}

# Only the push agent reports uptime. A row whose last writer was SNMP (CPU
# only) has a sampled_at that does not belong to its uptime.
SOURCE_WITH_UPTIME = "push"

# A report reaches us a few seconds after the router read its uptime. Real
# reboots move the boot time by at least the previous uptime, so a few minutes
# of slack rules out delivery delay without hiding real reboots.
BOOT_SHIFT_SLACK = timedelta(minutes=5)
UPTIME_BACKWARDS_SLACK_SECONDS = 60

# One report cannot plausibly count more WAN link drops than this. A bigger jump
# means the counter belongs to another interface now (a WAN change, say).
MAX_LINK_DROPS_PER_REPORT = 500


@dataclass(frozen=True)
class PrevReading:
    """The ``router_health`` fields a new sample is compared with, read before it
    is overwritten."""
    uptime_seconds: Optional[int] = None
    wan_link_downs: Optional[int] = None
    sampled_at: Optional[datetime] = None
    source: Optional[str] = None

    @classmethod
    def of(cls, row) -> Optional["PrevReading"]:
        if row is None:
            return None
        return cls(row.uptime_seconds, row.wan_link_downs, row.sampled_at, row.source)


def bucket_floor(ts: datetime, step_seconds: int) -> datetime:
    """Start of the bucket ``ts`` falls in. Steps divide a day, so buckets line
    up on UTC midnight."""
    midnight = ts.replace(hour=0, minute=0, second=0, microsecond=0)
    seconds = ts.hour * 3600 + ts.minute * 60 + ts.second
    return midnight + timedelta(seconds=seconds - seconds % step_seconds)


def memory_used_percent(free_bytes: Optional[int], total_bytes: Optional[int]) -> Optional[int]:
    if free_bytes is None or not total_bytes:
        return None
    return max(0, min(100, round((total_bytes - free_bytes) * 100 / total_bytes)))


def detect_reboot(prev: Optional[PrevReading], new_uptime: Optional[int],
                  now: datetime) -> Optional[datetime]:
    """When the router booted, if it rebooted since ``prev``; otherwise None.

    Two signs, either is enough: the uptime counter went backwards, or the boot
    time it implies moved later than the one ``prev`` implied. The second sign
    also catches a reboot during an outage long enough for the new uptime to pass
    the old one. The first sample a router ever sends is never a reboot.
    """
    if prev is None or prev.uptime_seconds is None or new_uptime is None:
        return None
    booted_at = now - timedelta(seconds=new_uptime)
    if new_uptime + UPTIME_BACKWARDS_SLACK_SECONDS < prev.uptime_seconds:
        return booted_at
    if prev.source == SOURCE_WITH_UPTIME and prev.sampled_at is not None:
        prev_booted_at = prev.sampled_at - timedelta(seconds=prev.uptime_seconds)
        if booted_at - prev_booted_at > BOOT_SHIFT_SLACK:
            return booted_at
    return None


def link_drop_delta(prev_downs: Optional[int], new_downs: Optional[int], rebooted: bool) -> int:
    """WAN link drops since the previous report. The RouterOS counter restarts at
    boot, so after a reboot (or any decrease) the new value is the count."""
    if prev_downs is None or new_downs is None:
        return 0
    delta = new_downs if rebooted or new_downs < prev_downs else new_downs - prev_downs
    return delta if 0 <= delta <= MAX_LINK_DROPS_PER_REPORT else 0


async def _bucket(db, router_id: int, step: int, start: datetime) -> RouterMetricBucket:
    bucket = await db.get(RouterMetricBucket, (router_id, step, start))
    if bucket is None:
        bucket = RouterMetricBucket(
            router_id=router_id, step_seconds=step, bucket_start=start,
            cpu_samples=0, cpu_sum=0, mem_samples=0, mem_sum=0, reboots=0, link_drops=0,
        )
        db.add(bucket)
        # Sessions run with autoflush off: flush so a second lookup of the same
        # bucket in this session (a reboot in the current bucket) finds it.
        await db.flush()
    return bucket


async def fold(db, router_id: int, sample, prev: Optional[PrevReading],
               now: datetime) -> None:
    """Add one sanitized ``HealthSample`` to the router's buckets. Never raises.

    Runs in the caller's session, inside a savepoint; the caller commits.
    """
    cpu = sample.cpu_load
    mem = memory_used_percent(sample.memory_free_bytes, sample.memory_total_bytes)
    booted_at = detect_reboot(prev, sample.uptime_seconds, now)
    drops = link_drop_delta(prev.wan_link_downs if prev else None,
                            sample.wan_link_downs, booted_at is not None)
    if cpu is None and mem is None and booted_at is None and not drops:
        return
    try:
        async with db.begin_nested():
            for step, keep in TIERS:
                if cpu is not None or mem is not None or drops:
                    b = await _bucket(db, router_id, step, bucket_floor(now, step))
                    if cpu is not None:
                        b.cpu_samples += 1
                        b.cpu_sum += cpu
                        b.cpu_max = cpu if b.cpu_max is None else max(b.cpu_max, cpu)
                    if mem is not None:
                        b.mem_samples += 1
                        b.mem_sum += mem
                        b.mem_max = mem if b.mem_max is None else max(b.mem_max, mem)
                    b.link_drops += drops
                if booted_at is not None and now - booted_at <= keep:
                    rb = await _bucket(db, router_id, step, bucket_floor(booted_at, step))
                    rb.reboots += 1
    except Exception:
        logger.exception("router_metric_history: could not fold sample for router %s", router_id)


def _avg(total: int, samples: int) -> Optional[float]:
    return round(total / samples, 1) if samples else None


async def history(db, router_id: int, range_key: str,
                  now: Optional[datetime] = None) -> dict:
    """Dense, column-wise series for one range: one slot per bucket from the
    oldest to the current one, None where the router sent nothing."""
    step, span = RANGES[range_key]
    now = now or datetime.utcnow()
    last = bucket_floor(now, step)
    slots = int(span.total_seconds() // step)
    first = last - timedelta(seconds=step * (slots - 1))
    rows = (await db.execute(
        select(RouterMetricBucket)
        .where(
            RouterMetricBucket.router_id == router_id,
            RouterMetricBucket.step_seconds == step,
            RouterMetricBucket.bucket_start >= first,
            RouterMetricBucket.bucket_start <= last,
        )
        .order_by(RouterMetricBucket.bucket_start)
    )).scalars().all()

    series = {key: [None] * slots for key in ("cpu_avg", "cpu_max", "mem_avg", "mem_max")}
    reboots = [0] * slots
    link_drops = [0] * slots
    cpu_sum = cpu_n = mem_sum = mem_n = 0
    cpu_peak = mem_peak = None
    filled = 0
    for r in rows:
        i = int((r.bucket_start - first).total_seconds() // step)
        if not 0 <= i < slots:
            continue
        series["cpu_avg"][i] = _avg(r.cpu_sum, r.cpu_samples)
        series["cpu_max"][i] = r.cpu_max
        series["mem_avg"][i] = _avg(r.mem_sum, r.mem_samples)
        series["mem_max"][i] = r.mem_max
        reboots[i] = r.reboots
        link_drops[i] = r.link_drops
        cpu_sum += r.cpu_sum
        cpu_n += r.cpu_samples
        mem_sum += r.mem_sum
        mem_n += r.mem_samples
        if r.cpu_max is not None:
            cpu_peak = r.cpu_max if cpu_peak is None else max(cpu_peak, r.cpu_max)
        if r.mem_max is not None:
            mem_peak = r.mem_max if mem_peak is None else max(mem_peak, r.mem_max)
        if r.cpu_samples or r.mem_samples:
            filled += 1

    return {
        "router_id": router_id,
        "range": range_key,
        "step_seconds": step,
        "start": first,
        "slots": slots,
        **series,
        "reboots": reboots,
        "link_drops": link_drops,
        "summary": {
            "cpu_avg": _avg(cpu_sum, cpu_n),
            "cpu_max": cpu_peak,
            "mem_avg": _avg(mem_sum, mem_n),
            "mem_max": mem_peak,
            "reboots": sum(reboots),
            "link_drops": sum(link_drops),
            "buckets_with_data": filled,
        },
    }


async def prune(db, now: datetime) -> None:
    """Drop buckets past their tier's retention. The caller commits."""
    for step, keep in TIERS:
        await db.execute(delete(RouterMetricBucket).where(
            RouterMetricBucket.step_seconds == step,
            RouterMetricBucket.bucket_start < now - keep,
        ))
