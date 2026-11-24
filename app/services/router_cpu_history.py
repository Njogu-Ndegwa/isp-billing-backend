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
on the hot ``routers`` row. Writes are additive.

Restarts: a restart splits a bucket between two processes, and neither one's
in-memory tally holds the whole bucket. Adding both halves counted most
routers twice (24 Nov 2026: 210 routers in a bucket that had 105); keeping
only the first half dropped most of them when the restart came early (94 of
106 after the 08:21 deploy, averages off by up to 14 points). The per-router
history (``router_metric_buckets``, router_metric_history.py) is written to
the database with every sample, so it holds those buckets whole. The bucket a
process starts in, and the one before it, are therefore rebuilt from it
instead of from the tally.
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
from app.db.models import AppDeploy, AppInstanceHeartbeat, RouterCpuBucket, RouterHealth, RouterMetricBucket

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


# The bucket this process started in; see "Restarts" above.
_start_bucket: datetime = bucket_start(datetime.utcnow())
_previous_rebuilt = False


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
    global _flush_lock, _last_prune, _previous_rebuilt
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
                restart_buckets = {_start_bucket - timedelta(seconds=BUCKET_SECONDS), _start_bucket}
                if not _previous_rebuilt and _start_bucket in taken and not include_open:
                    # First close of the start bucket: the one before it was cut by the
                    # restart too, and is complete in the per-router history by now.
                    written += await _rebuild_from_per_router(db, _start_bucket - timedelta(seconds=BUCKET_SECONDS))
                    _previous_rebuilt = True
                for start, bucket in taken.items():
                    if start in restart_buckets:
                        rebuilt = await _rebuild_from_per_router(db, start)
                        if rebuilt:
                            written += rebuilt
                            continue
                        # No per-router history (its write failed): fall back to the tally.
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


async def _rebuild_from_per_router(db, start: datetime) -> int:
    """Replace one bucket's rows with a fold of ``router_metric_buckets`` (each
    router's sample count, sum and peak for that 5-minute bucket), filed under
    the model each router reports now. Returns rows written; 0 when there is no
    per-router history for it, in which case nothing is changed."""
    try:
        async with db.begin_nested():
            rows = (await db.execute(
                select(RouterMetricBucket.router_id, RouterMetricBucket.cpu_samples,
                       RouterMetricBucket.cpu_sum, RouterMetricBucket.cpu_max,
                       RouterHealth.board_name, RouterHealth.routeros_version)
                .join(RouterHealth, RouterHealth.router_id == RouterMetricBucket.router_id, isouter=True)
                .where(RouterMetricBucket.step_seconds == BUCKET_SECONDS,
                       RouterMetricBucket.bucket_start == start,
                       RouterMetricBucket.cpu_samples > 0))).all()
            if not rows:
                return 0
            per_key: Dict[Key, Dict[int, _RouterTally]] = {}
            for rid, n, total, peak, board, version in rows:
                per_key.setdefault(model_key(board, version), {})[int(rid)] = _RouterTally(
                    n=int(n), total=int(total), peak=int(peak if peak is not None else total / n))
            await db.execute(delete(RouterCpuBucket).where(RouterCpuBucket.bucket_start == start))
            written = 0
            for (board, major), per_router in per_key.items():
                s = _summarise(per_router)
                if s["routers"]:
                    db.add(RouterCpuBucket(bucket_start=start, board_name=board, ros_major=major, **s))
                    written += 1
            return written
    except Exception:  # noqa: BLE001 - the tally is the fallback
        logger.exception("router_cpu_history: could not rebuild bucket %s from per-router history", start)
        return 0


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
    """The q-quantile of per-router means, placed linearly inside its 10%-wide bin.

    Routers are spread evenly through the bin they fall in, so with 7 routers
    in [40, 50) and the quantile landing on the 5th, the answer is 40 + 10*5/7.
    (It used to be the bin's upper edge, which read up to 10 points high: on
    24 Nov 2026 RB951 p90 showed 50 when the routers' own value was 47, and p50
    showed 20 for 12.)
    """
    total = sum(hist)
    if not total:
        return None
    rank = q * total
    seen = 0
    for i, n in enumerate(hist):
        if n and seen + n >= rank:
            return round(min(i * 10 + 10 * (rank - seen) / n, 100.0), 1)
        seen += n
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

    return {
        "from": since.isoformat() + "Z",
        "to": now.isoformat() + "Z",
        "step_seconds": step,
        "bucket_seconds": BUCKET_SECONDS,
        "split_version": split_version,
        "models": models,
        "deploys": await _deploys(db, since),
    }


async def _deploys(db, since: datetime) -> List[dict]:
    """Every process start since ``since``: the deploy history table, plus any
    live process missing from it (its first-heartbeat insert failed)."""
    seen: Dict[str, tuple] = {}
    try:
        async with db.begin_nested():
            for iid, s, v, m in (await db.execute(
                    select(AppDeploy.instance_id, AppDeploy.started_at, AppDeploy.app_version,
                           AppDeploy.runtime_mode).where(AppDeploy.started_at >= since))).all():
                seen[iid] = (s, v, m)
    except Exception:  # noqa: BLE001 - table not migrated yet: live heartbeats still mark the latest
        logger.warning("router_cpu_history: app_deploys unreadable; using live heartbeats only")
    for iid, s, v, m in (await db.execute(
            select(AppInstanceHeartbeat.instance_id, AppInstanceHeartbeat.started_at,
                   AppInstanceHeartbeat.app_version, AppInstanceHeartbeat.runtime_mode)
            .where(AppInstanceHeartbeat.started_at >= since))).all():
        seen.setdefault(iid, (s, v, m))
    rows = sorted((v for v in seen.values() if v[0] is not None), key=lambda r: r[0])
    return [{"at": s.isoformat() + "Z", "version": v, "runtime_mode": m} for s, v, m in rows]
