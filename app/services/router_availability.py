from bisect import bisect_left, bisect_right
from datetime import datetime, timedelta
from typing import Dict, Any, Iterable, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import database
from app.db.models import Router, RouterAvailabilityCheck
from app.services.router_status_alerts import (
    send_router_recovery_notification,
    should_consider_recovery_notification,
)


ROUTER_OFFLINE_SKIP_PERIOD = timedelta(minutes=30)
ROUTER_STATUS_STALE_AFTER_SECONDS = 600
ROUTER_AVAILABILITY_RETENTION_DAYS = 30
ROUTER_OFFLINE_CONFIRMATION_WINDOW = timedelta(minutes=5)

# These jobs only emit an availability row when their RouterOS connection
# fails.  A successful run emits no matching positive row, so allowing one of
# these failure-only samples to own the shared router summary creates a strong
# false-offline bias.  Keep the sample for diagnostics/uptime analysis, but do
# not let it suppress customer-facing work.
ADVISORY_OFFLINE_SOURCES = frozenset({"expired_cleanup"})

# Routers that run the usage-push script stamp a success about every five
# minutes. For them a missed report, not a failed server-side connection, is
# what means "down": the RouterOS API from here can fail (busy diagnostic
# slots, slow transit tunnel) while the router and its customers are fine.
PUSH_SOURCE = "usage_push"
PUSH_SILENCE = timedelta(minutes=15)
PUSH_GRACE = timedelta(minutes=8)


def _check_value(check: Any, field: str) -> Any:
    if isinstance(check, dict):
        return check.get(field)
    return getattr(check, field, None)


def summarize_router_flaps(
    checks: Iterable[Any],
    *,
    now: Optional[datetime] = None,
    confirmation_window: timedelta = ROUTER_OFFLINE_CONFIRMATION_WINDOW,
    limit: Optional[int] = 20,
) -> Dict[str, Any]:
    """Turn raw reachability samples into debounced state transitions.

    A single failed connection is not an outage: the production summary already
    requires two negative samples within five minutes, so the history view uses
    the same rule.  One successful sample immediately confirms recovery.

    A router that sends usage-push reports is judged by those reports instead
    (see ``_summarize_pushing_router``): the server failing to open a RouterOS
    connection while the router keeps reporting is a management-path problem,
    not the router or its customers being offline.
    """
    now = now or datetime.utcnow()
    ordered = sorted(
        (
            check
            for check in checks
            if _check_value(check, "checked_at") is not None
            and _check_value(check, "source") not in ADVISORY_OFFLINE_SOURCES
        ),
        key=lambda check: _check_value(check, "checked_at"),
    )
    first_report = next(
        (
            _check_value(check, "checked_at") for check in ordered
            if _check_value(check, "source") == PUSH_SOURCE and _check_value(check, "is_online")
        ),
        None,
    )
    if first_report is not None:
        # Reports are only evidence from the day the router started sending
        # them; before that it is judged by our checks as before. (Router 316
        # started reporting on 2026-09-26: applying the silence rule to the two
        # weeks before turned sparse sampling into 300 phantom outages.)
        before = [c for c in ordered if _check_value(c, "checked_at") < first_report]
        after = [c for c in ordered if _check_value(c, "checked_at") >= first_report]
        reported = _summarize_pushing_router(after, now=now, limit=None)
        if not before:
            return _limit_summary(reported, limit)
        earlier = summarize_router_flaps(
            before, now=first_report, confirmation_window=confirmation_window, limit=None,
        )
        earlier_outages = [
            {**o, "ended_at": o["ended_at"] or first_report.isoformat(),
             "duration_seconds": o["duration_seconds"] if o["ended_at"] else max(
                 0, round((first_report - datetime.fromisoformat(o["started_at"])).total_seconds()))}
            for o in earlier["outages"]
        ]
        earlier_transitions = list(earlier["transitions"])
        if earlier["status"] == "offline":
            earlier_transitions.append({
                "at": first_report.isoformat(), "from": "offline", "to": "online", "source": PUSH_SOURCE,
            })
        transitions = earlier_transitions + reported["transitions"]
        outage_count = sum(1 for t in transitions if t["to"] == "offline")
        merged = {
            **reported,
            "sample_count": len(ordered),
            "transition_count": len(transitions),
            "outage_count": outage_count,
            "recovery_count": sum(1 for t in transitions if t["to"] == "online"),
            "is_flapping": len(transitions) >= 4 or outage_count >= 2,
            "last_transition_at": transitions[-1]["at"] if transitions else None,
            "transitions": transitions,
            "outages": earlier_outages + reported["outages"],
        }
        return _limit_summary(merged, limit)

    state: Optional[bool] = None
    pending_offline_at: Optional[datetime] = None
    transitions = []
    outages = []
    outage_started_at: Optional[datetime] = None

    for check in ordered:
        checked_at = _check_value(check, "checked_at")
        is_online = bool(_check_value(check, "is_online"))
        source = str(_check_value(check, "source") or "unknown")

        if is_online:
            pending_offline_at = None
            if state is False:
                transitions.append({
                    "at": checked_at.isoformat(),
                    "from": "offline",
                    "to": "online",
                    "source": source,
                })
                started = outage_started_at or checked_at
                outages.append({
                    "started_at": started.isoformat(),
                    "ended_at": checked_at.isoformat(),
                    "duration_seconds": max(0, round((checked_at - started).total_seconds())),
                })
                outage_started_at = None
            state = True
            continue

        if state is False:
            continue

        if (
            pending_offline_at is None
            or checked_at - pending_offline_at > confirmation_window
        ):
            pending_offline_at = checked_at
            continue

        # A second recent negative confirms the management path is unavailable.
        previous_state = state
        state = False
        outage_started_at = checked_at
        pending_offline_at = None
        if previous_state is True:
            transitions.append({
                "at": checked_at.isoformat(),
                "from": "online",
                "to": "offline",
                "source": source,
            })

    if state is False and outage_started_at is not None:
        outages.append({
            "started_at": outage_started_at.isoformat(),
            "ended_at": None,
            "duration_seconds": max(0, round((now - outage_started_at).total_seconds())),
        })

    outage_transitions = sum(1 for item in transitions if item["to"] == "offline")
    recovery_transitions = sum(1 for item in transitions if item["to"] == "online")
    transition_count = len(transitions)
    last_sample = ordered[-1] if ordered else None
    last_sample_at = _check_value(last_sample, "checked_at") if last_sample else None
    return {
        "status": "online" if state is True else "offline" if state is False else "unknown",
        "sample_count": len(ordered),
        "last_sample_at": last_sample_at.isoformat() if last_sample_at else None,
        "last_sample_online": (
            bool(_check_value(last_sample, "is_online")) if last_sample else None
        ),
        "pending_outage": pending_offline_at is not None,
        "pending_outage_since": (
            pending_offline_at.isoformat() if pending_offline_at else None
        ),
        "transition_count": transition_count,
        "outage_count": outage_transitions,
        "recovery_count": recovery_transitions,
        "is_flapping": transition_count >= 4 or outage_transitions >= 2,
        "last_transition_at": transitions[-1]["at"] if transitions else None,
        "transitions": transitions[-limit:] if limit else transitions,
        "outages": outages[-limit:] if limit else outages,
        "judged_by": "server_checks",
    }


def _limit_summary(summary: Dict[str, Any], limit: Optional[int]) -> Dict[str, Any]:
    if not limit:
        return summary
    return {**summary, "transitions": summary["transitions"][-limit:], "outages": summary["outages"][-limit:]}


def _summarize_pushing_router(ordered: list, *, now: datetime, limit: Optional[int] = 20) -> Dict[str, Any]:
    """Outages of a router that reports to us, from its reports.

    Its usage-push reports are stamped about every five minutes, so silence is
    the signal: an outage is a gap of more than PUSH_SILENCE with no successful
    sample of any kind. A failed server-side check within PUSH_GRACE of a
    report is ignored outright (the router was demonstrably up); failures
    inside a real gap date its start. Same output shape as the probe path.
    """
    pushes = [
        _check_value(c, "checked_at") for c in ordered
        if _check_value(c, "source") == PUSH_SOURCE and _check_value(c, "is_online")
    ]
    successes = [_check_value(c, "checked_at") for c in ordered if _check_value(c, "is_online")]

    def near_report(at: datetime) -> bool:
        i = bisect_left(pushes, at - PUSH_GRACE)
        return i < len(pushes) and pushes[i] <= at + PUSH_GRACE

    failures = [
        _check_value(c, "checked_at") for c in ordered
        if not _check_value(c, "is_online") and not near_report(_check_value(c, "checked_at"))
    ]

    outages = []
    transitions = []

    def first_failure_between(start: datetime, end: Optional[datetime]) -> Optional[datetime]:
        i = bisect_right(failures, start)
        if i < len(failures) and (end is None or failures[i] < end):
            return failures[i]
        return None

    for prev, nxt in zip(successes, successes[1:]):
        if nxt - prev <= PUSH_SILENCE:
            continue
        started = first_failure_between(prev, nxt) or prev
        outages.append({
            "started_at": started.isoformat(),
            "ended_at": nxt.isoformat(),
            "duration_seconds": max(0, round((nxt - started).total_seconds())),
        })
        transitions.append({"at": started.isoformat(), "from": "online", "to": "offline", "source": PUSH_SOURCE})
        transitions.append({"at": nxt.isoformat(), "from": "offline", "to": "online", "source": PUSH_SOURCE})

    last_success = successes[-1] if successes else None
    silent = last_success is not None and now - last_success > PUSH_SILENCE
    if silent:
        started = first_failure_between(last_success, None) or last_success
        outages.append({
            "started_at": started.isoformat(),
            "ended_at": None,
            "duration_seconds": max(0, round((now - started).total_seconds())),
        })
        transitions.append({"at": started.isoformat(), "from": "online", "to": "offline", "source": PUSH_SOURCE})

    last_sample = ordered[-1] if ordered else None
    last_sample_at = _check_value(last_sample, "checked_at") if last_sample else None
    trailing_failure = failures[-1] if failures and (last_success is None or failures[-1] > last_success) else None
    outage_count = sum(1 for t in transitions if t["to"] == "offline")
    return {
        "status": "offline" if silent else "online",
        "sample_count": len(ordered),
        "last_sample_at": last_sample_at.isoformat() if last_sample_at else None,
        "last_sample_online": bool(_check_value(last_sample, "is_online")) if last_sample else None,
        "pending_outage": bool(trailing_failure) and not silent,
        "pending_outage_since": trailing_failure.isoformat() if trailing_failure and not silent else None,
        "transition_count": len(transitions),
        "outage_count": outage_count,
        "recovery_count": sum(1 for t in transitions if t["to"] == "online"),
        "is_flapping": len(transitions) >= 4 or outage_count >= 2,
        "last_transition_at": transitions[-1]["at"] if transitions else None,
        "transitions": transitions[-limit:] if limit else transitions,
        "outages": outages[-limit:] if limit else outages,
        "judged_by": "router_reports",
    }


def _parse_outage(outage: Dict[str, Any], now: datetime) -> tuple[datetime, datetime]:
    start = datetime.fromisoformat(outage["started_at"])
    end = datetime.fromisoformat(outage["ended_at"]) if outage.get("ended_at") else now
    return start, end


# What a reseller sees as an outage. Shorter "outages" are a failed
# connection followed straight away by a successful one (2026-10-12, router
# 316 before it sent reports: 376 of them, 13 hours in all, while provisioning
# connections alternately failed and succeeded). Flap detection still sees them.
MIN_REPORTED_OUTAGE = timedelta(minutes=5)


def significant_outages(outages: Iterable[Dict[str, Any]], now: datetime) -> list[Dict[str, Any]]:
    """Outages long enough to show a reseller (an ongoing one always counts)."""
    out = []
    for outage in outages:
        if outage.get("ended_at") is None:
            out.append(outage)
            continue
        start, end = _parse_outage(outage, now)
        if end - start >= MIN_REPORTED_OUTAGE:
            out.append(outage)
    return out


def _failure_run_outages(ordered: list, *, close_at: Optional[datetime]) -> list[Dict[str, Any]]:
    """Down from the first failed check after a success until the next success.

    The confirmation rule in summarize_router_flaps (two failures within five
    minutes) suits flap detection but never confirms a router that is simply
    dead and checked less often than that: 202 routers on 2026-10-12, never
    reached all week, read as 100% up.
    """
    outages = []
    started: Optional[datetime] = None
    for check in ordered:
        at = _check_value(check, "checked_at")
        if _check_value(check, "is_online"):
            if started is not None:
                outages.append({
                    "started_at": started.isoformat(),
                    "ended_at": at.isoformat(),
                    "duration_seconds": max(0, round((at - started).total_seconds())),
                })
                started = None
        elif started is None:
            started = at
    if started is not None:
        outages.append({
            "started_at": started.isoformat(),
            "ended_at": close_at.isoformat() if close_at else None,
            "duration_seconds": max(0, round(((close_at or datetime.utcnow()) - started).total_seconds())),
        })
    return outages


def uptime_outages(checks: Iterable[Any], *, now: datetime) -> Dict[str, Any]:
    """The outages a reseller sees in uptime figures, outage lists and the
    activity log.

    From the router's first usage report onward, the report rule of
    summarize_router_flaps; before it (or for a router that never reports),
    down from a failed check to the next success. Advisory samples are
    ignored, and anything shorter than MIN_REPORTED_OUTAGE is dropped.
    Returns the outages plus when usable data starts and how it was judged.
    """
    ordered = sorted(
        (
            c for c in checks
            if _check_value(c, "checked_at") is not None
            and _check_value(c, "source") not in ADVISORY_OFFLINE_SOURCES
        ),
        key=lambda c: _check_value(c, "checked_at"),
    )
    first_report = next(
        (
            _check_value(c, "checked_at") for c in ordered
            if _check_value(c, "source") == PUSH_SOURCE and _check_value(c, "is_online")
        ),
        None,
    )
    before = [c for c in ordered if first_report is None or _check_value(c, "checked_at") < first_report]
    outages = _failure_run_outages(before, close_at=first_report)
    if first_report is not None:
        after = [c for c in ordered if _check_value(c, "checked_at") >= first_report]
        outages += _summarize_pushing_router(after, now=now, limit=None)["outages"]
    return {
        "outages": significant_outages(outages, now),
        "first_data_at": _check_value(ordered[0], "checked_at") if ordered else None,
        "judged_by": "router_reports" if first_report is not None else "server_checks",
    }


def downtime_seconds(outages: Iterable[Dict[str, Any]], start: datetime, end: datetime, now: datetime) -> int:
    """Seconds of the outages that fall inside [start, end)."""
    total = 0.0
    for outage in outages:
        o_start, o_end = _parse_outage(outage, now)
        overlap = (min(o_end, end) - max(o_start, start)).total_seconds()
        if overlap > 0:
            total += overlap
    return int(round(total))


def time_based_uptime(
    outages: Iterable[Dict[str, Any]],
    *,
    start: datetime,
    end: datetime,
    first_data_at: Optional[datetime],
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Uptime as a share of time, over the part of the window we have data for.

    Counting samples (the old method) weighed every failed connection attempt
    as much as five minutes of the router reporting, and over-weighted busy
    periods; time is what a reseller means by "up 99%".
    """
    now = now or end
    outages = list(outages)
    measured_from = max(start, first_data_at) if first_data_at else None
    if measured_from is None or measured_from >= end:
        return {"uptime_percentage": None, "measured_seconds": 0, "downtime_seconds": 0, "outage_count": 0}
    measured = (end - measured_from).total_seconds()
    down = downtime_seconds(outages, measured_from, end, now)
    count = sum(
        1 for o in outages
        if _parse_outage(o, now)[1] > measured_from and _parse_outage(o, now)[0] < end
    )
    return {
        "uptime_percentage": round(max(0.0, 100.0 * (1 - down / measured)), 2) if measured > 0 else None,
        "measured_seconds": int(measured),
        "downtime_seconds": down,
        "outage_count": count,
    }


def uptime_timeline(
    outages: Iterable[Dict[str, Any]],
    *,
    start: datetime,
    end: datetime,
    first_data_at: Optional[datetime],
    buckets: int,
    now: Optional[datetime] = None,
) -> list[Dict[str, Any]]:
    """Equal time slices of the window: up, partly down, down, or no data."""
    now = now or end
    outages = list(outages)
    step = (end - start) / buckets
    out = []
    for i in range(buckets):
        b_start = start + step * i
        b_end = start + step * (i + 1)
        if first_data_at is None or b_end <= first_data_at:
            status, down = "no_data", 0
        else:
            down = downtime_seconds(outages, max(b_start, first_data_at), b_end, now)
            span = (b_end - max(b_start, first_data_at)).total_seconds()
            status = "up" if down == 0 else ("down" if span and down >= span - 1 else "partial")
        out.append({
            "from": b_start.isoformat(),
            "to": b_end.isoformat(),
            "status": status,
            "downtime_seconds": down,
        })
    return out


def router_recently_offline(
    router,
    now: Optional[datetime] = None,
    threshold: timedelta = ROUTER_OFFLINE_SKIP_PERIOD,
) -> bool:
    """True when the router's persisted status is offline and the failure is recent."""
    now = now or datetime.utcnow()
    last_checked = getattr(router, "last_checked_at", None)
    return (
        getattr(router, "last_status", None) is False
        and last_checked is not None
        and (now - last_checked) < threshold
    )


def derive_router_status(
    router: Router,
    now: Optional[datetime] = None,
    stale_after_seconds: int = ROUTER_STATUS_STALE_AFTER_SECONDS,
) -> str:
    """Return online/offline/unknown from the persisted router summary fields."""
    now = now or datetime.utcnow()
    last_checked = getattr(router, "last_checked_at", None)
    last_status = getattr(router, "last_status", None)

    if not last_checked or last_status is None:
        return "unknown"

    age_seconds = (now - last_checked).total_seconds()
    if age_seconds > stale_after_seconds:
        return "unknown"

    return "online" if last_status else "offline"


def build_router_status(router: Router, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Serialize the current persisted router status for API responses."""
    now = now or datetime.utcnow()
    last_checked = getattr(router, "last_checked_at", None)
    age_seconds = (now - last_checked).total_seconds() if last_checked else None
    status = derive_router_status(router, now=now)

    return {
        "status": status,
        "status_is_stale": status == "unknown" and last_checked is not None,
        "status_age_seconds": round(age_seconds, 1) if age_seconds is not None else None,
        "status_last_checked_at": last_checked.isoformat() if last_checked else None,
        "last_online_at": router.last_online_at.isoformat() if getattr(router, "last_online_at", None) else None,
        "status_source": getattr(router, "last_status_source", None),
        "availability_checks": int(getattr(router, "availability_checks", 0) or 0),
        "availability_successes": int(getattr(router, "availability_successes", 0) or 0),
    }


async def record_router_availability(
    db: AsyncSession,
    router_id: int,
    is_online: bool,
    source: str,
    checked_at: Optional[datetime] = None,
    *,
    confirm_offline: bool = False,
) -> None:
    """Persist a single availability check and update the router summary columns.

    This telemetry write runs in its OWN short, immediately-committed session and
    deliberately does NOT use the caller's ``db``/transaction. Router availability
    is recorded from ~40 request and background paths, all targeting the same hot
    ``routers`` row. When the write rode the caller's transaction (previous
    behaviour: mutate + ``flush()`` only), any caller that stalled after the flush
    (e.g. while waiting on slow RouterOS I/O, or one that was cancelled mid-flight)
    held the ``routers`` row lock open until it eventually committed. Concurrent
    availability writers then queued behind that lock, each pinning a pooled DB
    connection while it waited — a lock convoy that drained the connection pool
    (see docs/agent-memory/incidents/2026-06-05-db-pool-lock-convoy.md).

    Committing in a dedicated session bounds the row lock to milliseconds. The
    ``db`` parameter is retained for call-site compatibility and is intentionally
    unused.
    """
    checked_at = checked_at or datetime.utcnow()
    notify_transition = False
    offline_since: Optional[datetime] = None
    async with database.async_session() as adb:
        router = await adb.get(Router, router_id)
        if not router:
            return

        # Historical telemetry accepts every observation.  The shared summary
        # is deliberately stricter: it must never move backwards in time, weak
        # failure-only jobs cannot declare an outage, and an ordinary negative
        # sample needs a second recent negative with no intervening success.
        summary_is_current = (
            router.last_checked_at is None or checked_at >= router.last_checked_at
        )
        update_summary = summary_is_current and is_online

        if summary_is_current and not is_online and source not in ADVISORY_OFFLINE_SOURCES:
            if confirm_offline:
                update_summary = True
            else:
                confirmation_cutoff = checked_at - ROUTER_OFFLINE_CONFIRMATION_WINDOW
                previous_signal = (
                    await adb.execute(
                        select(RouterAvailabilityCheck)
                        .where(
                            RouterAvailabilityCheck.router_id == router_id,
                            RouterAvailabilityCheck.checked_at >= confirmation_cutoff,
                            RouterAvailabilityCheck.checked_at <= checked_at,
                            RouterAvailabilityCheck.source.notin_(ADVISORY_OFFLINE_SOURCES),
                        )
                        .order_by(
                            RouterAvailabilityCheck.checked_at.desc(),
                            RouterAvailabilityCheck.id.desc(),
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none()
                update_summary = bool(previous_signal and not previous_signal.is_online)

            if update_summary:
                # A router that reported to us moments ago is up: our failing to
                # open a RouterOS connection to it is a management-path problem.
                # Recording it as offline here would flip its badge, skip it in
                # background jobs and text the reseller "router offline".
                recent_report = (
                    await adb.execute(
                        select(RouterAvailabilityCheck.id)
                        .where(
                            RouterAvailabilityCheck.router_id == router_id,
                            RouterAvailabilityCheck.source == PUSH_SOURCE,
                            RouterAvailabilityCheck.is_online.is_(True),
                            RouterAvailabilityCheck.checked_at >= checked_at - PUSH_GRACE,
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if recent_report is not None:
                    update_summary = False

        if update_summary and is_online:
            # Capture the offline->online transition BEFORE overwriting the
            # summary columns; the message itself is sent after this commit.
            notify_transition = should_consider_recovery_notification(router, checked_at)
            if notify_transition:
                offline_since = router.last_online_at

        if update_summary:
            router.last_status = is_online
            router.last_checked_at = checked_at
            router.last_status_source = source

        router.availability_checks = int(router.availability_checks or 0) + 1
        if is_online:
            router.availability_successes = int(router.availability_successes or 0) + 1
            if router.last_online_at is None or checked_at >= router.last_online_at:
                router.last_online_at = checked_at

        adb.add(
            RouterAvailabilityCheck(
                router_id=router_id,
                checked_at=checked_at,
                is_online=is_online,
                source=source,
            )
        )
        await adb.commit()

    if notify_transition:
        # DB-only, own short session, never raises (see router_status_alerts).
        await send_router_recovery_notification(
            router_id, offline_since=offline_since, now=checked_at
        )


async def prune_router_availability_history(
    db: AsyncSession,
    retention_days: int = ROUTER_AVAILABILITY_RETENTION_DAYS,
    now: Optional[datetime] = None,
) -> None:
    """Delete old availability samples so the table stays bounded."""
    now = now or datetime.utcnow()
    cutoff = now - timedelta(days=retention_days)
    await db.execute(
        delete(RouterAvailabilityCheck).where(RouterAvailabilityCheck.checked_at < cutoff)
    )
