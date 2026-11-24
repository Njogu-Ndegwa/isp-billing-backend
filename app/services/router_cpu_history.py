"""Fleet CPU history per router model (``router_cpu_buckets``).

Why: ``router_health`` keeps only the latest sample per router, so there was no
way to see whether a release or a fleet-wide router script change moved CPU on,
say, every RB951 (incidents 2026-10-10 script stacking, 2026-11-23 firewall
depth). This keeps a 5-minute rollup per (board model, RouterOS major) for the
admin "CPU by router model" chart.

How: ``router_health.record`` calls :func:`note` for every sample that carried
CPU. Samples are tallied in memory per router per bucket. When a bucket has
closed (``CLOSE_GRACE`` after its end), one row per model is written in a
single short session: each router counts once, with its mean over the bucket,
so a router pushing every minute weighs the same as one pushing every two.

Costs nothing on the routers (it reuses samples they already send) and nothing
on the hot ``routers`` row. A restart loses at most the open bucket. Writes are
additive, so a bucket written twice (two app instances) still adds up; the
``routers`` column then over-counts, which the chart tolerates.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import delete, select

from app.db import database
from app.db.models import AppInstanceHeartbeat, RouterCpuBucket, RouterHealth

logger = logging.getLogger(__name__)

BUCKET_SECONDS = 300
CLOSE_GRACE = timedelta(seconds=30)
RETENTION = timedelta(days=90)
HIST_BINS = 10
GE80 = 80
GE95 = 95
# A misbehaving router could send a new board name every sample; never let the
# in-memory tally or the table grow without bound.
MAX_KEYS_PER_BUCKET = 300
MAX_OPEN_BUCKETS = 4
UNKNOWN_BOARD = "unknown"

Key = Tuple[str, str]  # (board_name, ros_major)


@dataclass
class _RouterTally:
    n: int = 0
    total: int = 0
    peak: int = 0


@dataclass
class _Bucket:
    routers: Dict[Key, Dict[int, _RouterTally]] = field(default_factory=dict)


_open: Dict[datetime, _Bucket] = {}
_flush_lock: Optional[asyncio.Lock] = None
_last_prune: Optional[datetime] = None
_tasks: set = set()


def bucket_start(ts: datetime) -> datetime:
    epoch = int((ts - datetime(1970, 1, 1)).total_seconds())
    return datetime(1970, 1, 1) + timedelta(seconds=epoch - epoch % BUCKET_SECONDS)


def ros_major(version: Optional[str]) -> str:
    m = re.match(r"\s*(\d+)\.", str(version or ""))
    return m.group(1) if m else "?"


def model_key(board_name: Optional[str], version: Optional[str]) -> Key:
    board = (board_name or "").strip()[:60] or UNKNOWN_BOARD
    return board, ros_major(version)


def note(router_id: int, cpu: int, board_name: Optional[str], version: Optional[str],
         now: Optional[datetime] = None) -> None:
    """Tally one CPU sample. Never raises, never touches the DB itself."""
    try:
        now = now or datetime.utcnow()
        cpu = int(cpu)
        if not 0 <= cpu <= 100:
            return
        start = bucket_start(now)
        bucket = _open.get(start)
        if bucket is None:
            if len(_open) >= MAX_OPEN_BUCKETS:      # samples with odd clocks; drop the oldest
                _open.pop(min(_open))
            bucket = _open[start] = _Bucket()
        key = model_key(board_name, version)
        per_router = bucket.routers.get(key)
        if per_router is None:
            if len(bucket.routers) >= MAX_KEYS_PER_BUCKET:
                return
            per_router = bucket.routers[key] = {}
        tally = per_router.setdefault(int(router_id), _RouterTally())
        tally.n += 1
        tally.total += cpu
        tally.peak = max(tally.peak, cpu)
        if any(s + timedelta(seconds=BUCKET_SECONDS) + CLOSE_GRACE <= now for s in _open):
            _spawn(flush(now))
    except Exception:
        logger.exception("router_cpu_history: could not tally a sample")


def _summarise(per_router: Dict[int, _RouterTally]) -> dict:
    hist = [0] * HIST_BINS
    mean_sum = 0.0
    ge80 = ge95 = samples = peak = 0
    for t in per_router.values():
        if not t.n:
            continue
        mean = t.total / t.n
        mean_sum += mean
        hist[min(int(mean // 10), HIST_BINS - 1)] += 1
        ge80 += mean >= GE80
        ge95 += t.peak >= GE95
        samples += t.n
        peak = max(peak, t.peak)
    return {"routers": sum(hist), "samples": samples, "cpu_mean_sum": round(mean_sum, 2),
            "cpu_peak": peak, "routers_ge80": ge80, "routers_peak_ge95": ge95, "hist": hist}


async def flush(now: Optional[datetime] = None, *, include_open: bool = False) -> int:
    """Write every closed bucket (or every bucket, with ``include_open``) in one
    short session. Returns rows written. Never raises."""
    global _flush_lock, _last_prune
    now = now or datetime.utcnow()
    if _flush_lock is None:
        _flush_lock = asyncio.Lock()
    async with _flush_lock:
        ready = sorted(s for s in _open
                       if include_open or s + timedelta(seconds=BUCKET_SECONDS) + CLOSE_GRACE <= now)
        if not ready:
            return 0
        taken = {s: _open.pop(s) for s in ready}
        written = 0
        try:
            async with database.async_session() as db:
                for start, bucket in taken.items():
                    for (board, major), per_router in bucket.routers.items():
                        s = _summarise(per_router)
                        if not s["routers"]:
                            continue
                        row = await db.get(RouterCpuBucket, (start, board, major))
                        if row is None:
                            db.add(RouterCpuBucket(bucket_start=start, board_name=board, ros_major=major, **s))
                        else:
                            row.routers += s["routers"]
                            row.samples += s["samples"]
                            row.cpu_mean_sum += s["cpu_mean_sum"]
                            row.cpu_peak = max(row.cpu_peak, s["cpu_peak"])
                            row.routers_ge80 += s["routers_ge80"]
                            row.routers_peak_ge95 += s["routers_peak_ge95"]
                            row.hist = [a + b for a, b in zip(row.hist or [0] * HIST_BINS, s["hist"])]
                        written += 1
                if _last_prune is None or now - _last_prune > timedelta(hours=6):
                    await db.execute(delete(RouterCpuBucket).where(RouterCpuBucket.bucket_start < now - RETENTION))
                    _last_prune = now
                await db.commit()
        except Exception:
            logger.exception("router_cpu_history: could not write %d bucket(s)", len(taken))
            return 0
        return written


def _spawn(coro) -> None:
    try:
        task = asyncio.get_running_loop().create_task(coro)
    except RuntimeError:
        coro.close()
        return
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


# --- reading -------------------------------------------------------------------------------

STEPS = {300: "5m", 900: "15m", 3600: "1h", 21600: "6h", 86400: "1d"}


def default_step(hours: int) -> int:
    if hours <= 12:
        return 300
    if hours <= 72:
        return 900
    if hours <= 24 * 14:
        return 3600
    return 21600


def _percentile(hist: List[int], q: float) -> Optional[float]:
    """Upper edge of the bin holding the q-quantile (so p90 = 70 means 'under 70%')."""
    total = sum(hist)
    if not total:
        return None
    rank = q * total
    seen = 0
    for i, n in enumerate(hist):
        seen += n
        if seen >= rank:
            return float(min((i + 1) * 10, 100))
    return 100.0


async def history(db, *, hours: int = 24, step: Optional[int] = None, split_version: bool = False,
                  board: Optional[str] = None, now: Optional[datetime] = None) -> dict:
    now = now or datetime.utcnow()
    hours = max(1, min(int(hours), 24 * 90))
    step = int(step) if step in STEPS else default_step(hours)
    since = bucket_start(now - timedelta(hours=hours))

    q = select(RouterCpuBucket).where(RouterCpuBucket.bucket_start >= since)
    if board:
        q = q.where(RouterCpuBucket.board_name == board)
    rows = (await db.execute(q.order_by(RouterCpuBucket.bucket_start))).scalars().all()

    series: Dict[Key, Dict[datetime, dict]] = {}
    epoch0 = datetime(1970, 1, 1)
    for r in rows:
        key = (r.board_name, r.ros_major if split_version else "*")
        secs = int((r.bucket_start - epoch0).total_seconds())
        t = epoch0 + timedelta(seconds=secs - secs % step)
        pt = series.setdefault(key, {}).setdefault(t, {
            "router_buckets": 0, "buckets": set(), "samples": 0, "mean_sum": 0.0, "peak": 0,
            "ge80": 0, "ge95": 0, "hist": [0] * HIST_BINS})
        pt["router_buckets"] += r.routers
        pt["buckets"].add(r.bucket_start)
        pt["samples"] += r.samples
        pt["mean_sum"] += r.cpu_mean_sum
        pt["peak"] = max(pt["peak"], r.cpu_peak)
        pt["ge80"] += r.routers_ge80
        pt["ge95"] += r.routers_peak_ge95
        pt["hist"] = [a + b for a, b in zip(pt["hist"], r.hist or [0] * HIST_BINS)]

    # Routers reporting now, per model, from the latest-health table.
    now_rows = (await db.execute(select(RouterHealth.board_name, RouterHealth.routeros_version,
                                        RouterHealth.cpu_load, RouterHealth.sampled_at)
                                 .where(RouterHealth.sampled_at >= now - timedelta(minutes=15))
                                 .where(RouterHealth.cpu_load.isnot(None)))).all()
    current: Dict[Key, List[int]] = {}
    for b, v, cpu, _ in now_rows:
        k = model_key(b, v)
        current.setdefault((k[0], k[1] if split_version else "*"), []).append(cpu)

    models = []
    for key in sorted(set(series) | set(current), key=lambda k: -len(current.get(k, []))):
        if board and key[0] != board:
            continue
        points = []
        for t, pt in sorted(series.get(key, {}).items()):
            rb = pt["router_buckets"] or 1
            points.append({
                "t": t.isoformat() + "Z",
                "routers": round(pt["router_buckets"] / max(len(pt["buckets"]), 1), 1),
                "avg": round(pt["mean_sum"] / rb, 1),
                "p50": _percentile(pt["hist"], 0.5),
                "p90": _percentile(pt["hist"], 0.9),
                "max": pt["peak"],
                "pct_over_80": round(100 * pt["ge80"] / rb, 1),
                "pct_peaked_95": round(100 * pt["ge95"] / rb, 1),
                "samples": pt["samples"],
            })
        cur = current.get(key, [])
        models.append({
            "board_name": key[0],
            "ros_major": None if key[1] == "*" else key[1],
            "routers_now": len(cur),
            "avg_now": round(sum(cur) / len(cur), 1) if cur else None,
            "points": points,
        })

    deploys = (await db.execute(
        select(AppInstanceHeartbeat.started_at, AppInstanceHeartbeat.app_version, AppInstanceHeartbeat.runtime_mode)
        .where(AppInstanceHeartbeat.started_at >= since)
        .order_by(AppInstanceHeartbeat.started_at))).all()
    return {
        "from": since.isoformat() + "Z",
        "to": now.isoformat() + "Z",
        "step_seconds": step,
        "bucket_seconds": BUCKET_SECONDS,
        "split_version": split_version,
        "models": models,
        "deploys": [{"at": s.isoformat() + "Z", "version": v, "runtime_mode": m}
                    for s, v, m in deploys if s is not None],
    }
