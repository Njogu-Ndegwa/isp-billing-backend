"""In-process registry of APScheduler job outcomes (no DB).

Populated by an APScheduler event listener installed from ``main.py`` and read
by the ops-health snapshot (``app/services/ops_health.py``). Everything here is
plain module memory: it costs nothing on the hot path and is deliberately lost
on restart, because a restart resets the scheduler too.

APScheduler 3.10 event flow per run:

* ``EVENT_JOB_SUBMITTED``  -> the job was handed to the executor (started)
* ``EVENT_JOB_EXECUTED``   -> the coroutine returned (finished OK)
* ``EVENT_JOB_ERROR``      -> the coroutine raised
* ``EVENT_JOB_MISSED``     -> the fire time was skipped (misfire grace exceeded)
* ``EVENT_JOB_MAX_INSTANCES`` -> a run was skipped because the previous one is
  still going (this is what "skipped_runs_last_hour" counts for the cleanup job)
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Optional

logger = logging.getLogger(__name__)

SKIP_HISTORY_WINDOW = timedelta(hours=1)
# A job is stale when nothing has finished for this many intervals
# (minimum STALE_MIN_AGE). Thresholds live in ops_health_rules; these are the
# defaults the registry uses to flag ``stale`` on its own snapshot.
STALE_INTERVAL_MULTIPLIER = 3
STALE_MIN_AGE = timedelta(minutes=5)


@dataclass
class JobRecord:
    job_id: str
    name: Optional[str] = None
    interval_seconds: Optional[float] = None
    first_seen_at: Optional[datetime] = None
    last_started_at: Optional[datetime] = None
    last_finished_at: Optional[datetime] = None
    last_duration_seconds: Optional[float] = None
    last_error: Optional[str] = None
    missed_or_skipped: Deque[datetime] = field(default_factory=deque)


_lock = threading.Lock()
_registry: dict[str, JobRecord] = {}
_listener_installed_on: set[int] = set()


def _get(job_id: str, now: datetime) -> JobRecord:
    rec = _registry.get(job_id)
    if rec is None:
        rec = JobRecord(job_id=job_id, first_seen_at=now)
        _registry[job_id] = rec
    return rec


def _prune_skips(rec: JobRecord, now: datetime) -> None:
    cutoff = now - SKIP_HISTORY_WINDOW
    while rec.missed_or_skipped and rec.missed_or_skipped[0] < cutoff:
        rec.missed_or_skipped.popleft()


# --- recording API (also used directly by tests) -----------------------------

def set_interval(job_id: str, interval_seconds: Optional[float], *,
                 name: Optional[str] = None, now: Optional[datetime] = None) -> None:
    now = now or datetime.utcnow()
    with _lock:
        rec = _get(job_id, now)
        rec.interval_seconds = interval_seconds
        if name:
            rec.name = name


def record_started(job_id: str, now: Optional[datetime] = None) -> None:
    now = now or datetime.utcnow()
    with _lock:
        rec = _get(job_id, now)
        rec.last_started_at = now


def record_finished(job_id: str, now: Optional[datetime] = None,
                    error: Optional[str] = None) -> None:
    now = now or datetime.utcnow()
    with _lock:
        rec = _get(job_id, now)
        rec.last_finished_at = now
        if rec.last_started_at is not None and rec.last_started_at <= now:
            rec.last_duration_seconds = round((now - rec.last_started_at).total_seconds(), 3)
        rec.last_error = (str(error)[:255] if error else None)


def record_skipped(job_id: str, now: Optional[datetime] = None) -> None:
    now = now or datetime.utcnow()
    with _lock:
        rec = _get(job_id, now)
        rec.missed_or_skipped.append(now)
        _prune_skips(rec, now)


def reset() -> None:
    """Test hook."""
    with _lock:
        _registry.clear()


# --- reading API --------------------------------------------------------------

def stale_after(rec_interval: Optional[float], multiplier: float = STALE_INTERVAL_MULTIPLIER) -> Optional[timedelta]:
    if not rec_interval:
        return None
    return max(STALE_MIN_AGE, timedelta(seconds=rec_interval * multiplier))


def snapshot(now: Optional[datetime] = None) -> list[dict]:
    """Serializable view of every known job, sorted by id."""
    now = now or datetime.utcnow()
    items = []
    with _lock:
        for job_id in sorted(_registry):
            rec = _registry[job_id]
            _prune_skips(rec, now)
            reference = rec.last_finished_at or rec.first_seen_at
            limit = stale_after(rec.interval_seconds)
            stale = bool(limit and reference and (now - reference) > limit)
            items.append({
                "id": job_id,
                "name": rec.name,
                "interval_seconds": rec.interval_seconds,
                "last_started_at": _iso(rec.last_started_at),
                "last_finished_at": _iso(rec.last_finished_at),
                "last_duration_seconds": rec.last_duration_seconds,
                "last_error": rec.last_error,
                "missed_or_skipped_last_hour": len(rec.missed_or_skipped),
                "seconds_since_finish": (
                    round((now - rec.last_finished_at).total_seconds(), 1)
                    if rec.last_finished_at else None
                ),
                "stale": stale,
            })
    return items


def get(job_id: str, now: Optional[datetime] = None) -> Optional[dict]:
    for item in snapshot(now):
        if item["id"] == job_id:
            return item
    return None


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value else None


# --- APScheduler wiring -------------------------------------------------------

def _interval_of(trigger) -> Optional[float]:
    interval = getattr(trigger, "interval", None)
    if isinstance(interval, timedelta):
        return interval.total_seconds()
    return None


def sync_jobs(scheduler) -> None:
    """Read every job's interval from its trigger (cron jobs get None)."""
    now = datetime.utcnow()
    try:
        jobs = scheduler.get_jobs()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[JOBS] Could not list scheduler jobs: %s", exc)
        return
    for job in jobs:
        set_interval(job.id, _interval_of(job.trigger), name=getattr(job, "name", None), now=now)


def install(scheduler) -> None:
    """Attach the listener once per scheduler and seed intervals."""
    if id(scheduler) in _listener_installed_on:
        sync_jobs(scheduler)
        return
    from apscheduler.events import (
        EVENT_JOB_ERROR,
        EVENT_JOB_EXECUTED,
        EVENT_JOB_MAX_INSTANCES,
        EVENT_JOB_MISSED,
        EVENT_JOB_SUBMITTED,
    )

    def _listener(event) -> None:
        try:
            code = event.code
            job_id = getattr(event, "job_id", None)
            if not job_id:
                return
            if code == EVENT_JOB_SUBMITTED:
                record_started(job_id)
            elif code == EVENT_JOB_EXECUTED:
                record_finished(job_id)
            elif code == EVENT_JOB_ERROR:
                record_finished(job_id, error=getattr(event, "exception", None) or "error")
            elif code in (EVENT_JOB_MISSED, EVENT_JOB_MAX_INSTANCES):
                record_skipped(job_id)
        except Exception:  # noqa: BLE001 - a listener must never break the scheduler
            logger.exception("[JOBS] registry listener failed")

    scheduler.add_listener(
        _listener,
        EVENT_JOB_SUBMITTED | EVENT_JOB_EXECUTED | EVENT_JOB_ERROR
        | EVENT_JOB_MISSED | EVENT_JOB_MAX_INSTANCES,
    )
    _listener_installed_on.add(id(scheduler))
    sync_jobs(scheduler)
