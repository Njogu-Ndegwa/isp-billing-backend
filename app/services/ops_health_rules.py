"""Alert rules for the operations health monitor.

Pure functions over the ``sections`` dict built by ``ops_health.compute_snapshot``.
Every threshold lives here (and only here) so a tuning change is one line and
one test. Table (warning / critical):

    provisioning.retry_backlog     retry_pending >= 25 in 60 min          / >= 50
    provisioning.success_ratio     < 0.7 with >= 10 samples               / < 0.4
    provisioning.latency_p95       ratio vs baseline >= 2 (>= 5 samples)  / ratio >= 4 or p95 >= 60 s
    payments.pending_over_5m       >= 5                                   / >= 15
    payments.callback_silence      no completed txn for 30 min (06-23 EAT, >= 1 created) / 60 min
    payments.latency_p95           ratio >= 2                             / ratio >= 4
    expiry.hot_backlog             expired_active_hot >= 100              / >= 300
    expiry.oldest_hot              >= 15 min                              / >= 60 min
    expiry.removal_p95             ratio >= 2                             / ratio >= 4
    expiry.cleanup_stale           cleanup job not finished > 10 min      / > 30 min
    tunnels.platform_event         recent_drops_10m >= 5                  / >= 15
    tunnels.transit_fallback       transit_fallback >= 10 (when available)/ >= 30
    control_plane.multiple_writers -                                      / active_writers > 1 OR db_identity_mismatch
    control_plane.no_writer        no scheduler-enabled heartbeat 3 min   / 10 min
    safety_net.spike               removals > max(20, 5 x baseline)       / > max(100, 10 x baseline)
    jobs.stale                     no finish for 3 x interval (min 5 min) / > 6 x interval
    db_pool.pressure               pressure warning                       / pressure critical
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

# --- thresholds ---------------------------------------------------------------

PROVISIONING_RETRY_BACKLOG_WARN = 25
PROVISIONING_RETRY_BACKLOG_CRIT = 50
PROVISIONING_SUCCESS_RATIO_MIN_SAMPLES = 10
PROVISIONING_SUCCESS_RATIO_WARN = 0.7
PROVISIONING_SUCCESS_RATIO_CRIT = 0.4
PROVISIONING_LATENCY_MIN_SAMPLES = 5
PROVISIONING_LATENCY_RATIO_WARN = 2.0
PROVISIONING_LATENCY_RATIO_CRIT = 4.0
PROVISIONING_LATENCY_P95_CRIT_SECONDS = 60.0

PAYMENTS_PENDING_OVER_5M_WARN = 5
PAYMENTS_PENDING_OVER_5M_CRIT = 15
PAYMENTS_SILENCE_WARN_MINUTES = 30
PAYMENTS_SILENCE_CRIT_MINUTES = 60
PAYMENTS_SILENCE_HOURS_EAT = (6, 23)   # inclusive start, exclusive end, local hour
PAYMENTS_LATENCY_RATIO_WARN = 2.0
PAYMENTS_LATENCY_RATIO_CRIT = 4.0

EXPIRY_HOT_BACKLOG_WARN = 100
EXPIRY_HOT_BACKLOG_CRIT = 300
EXPIRY_OLDEST_HOT_WARN_MINUTES = 15
EXPIRY_OLDEST_HOT_CRIT_MINUTES = 60
EXPIRY_REMOVAL_RATIO_WARN = 2.0
EXPIRY_REMOVAL_RATIO_CRIT = 4.0
EXPIRY_CLEANUP_STALE_WARN_MINUTES = 10
EXPIRY_CLEANUP_STALE_CRIT_MINUTES = 30

TUNNELS_PLATFORM_EVENT_WARN = 5
TUNNELS_PLATFORM_EVENT_CRIT = 15
TUNNELS_TRANSIT_FALLBACK_WARN = 10
TUNNELS_TRANSIT_FALLBACK_CRIT = 30

CONTROL_PLANE_NO_WRITER_WARN_MINUTES = 3
CONTROL_PLANE_NO_WRITER_CRIT_MINUTES = 10

SAFETY_NET_SPIKE_WARN_FLOOR = 20
SAFETY_NET_SPIKE_WARN_MULTIPLIER = 5
SAFETY_NET_SPIKE_CRIT_FLOOR = 100
SAFETY_NET_SPIKE_CRIT_MULTIPLIER = 10

JOBS_STALE_WARN_MULTIPLIER = 3
JOBS_STALE_CRIT_MULTIPLIER = 6
JOBS_STALE_MIN_MINUTES = 5

LOCAL_UTC_OFFSET_HOURS = 3   # EAT; mirrors settings.LOCAL_UTC_OFFSET_HOURS

SEVERITY_ORDER = {"critical": 3, "warning": 2, "watch": 1, "healthy": 0, "unknown": -1}
STATUS_ORDER = {"critical": 4, "warning": 3, "watch": 2, "unknown": 1, "healthy": 0}


# --- helpers ------------------------------------------------------------------

def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _alert(key: str, severity: str, title: str, message: str,
           value: Any, threshold: Any) -> dict:
    return {
        "key": key,
        "severity": severity,
        "title": title,
        "message": message,
        "value": value,
        "threshold": threshold,
    }


def _two_level(key, title, value, warn, crit, fmt, *, higher_is_worse=True) -> Optional[dict]:
    """Common shape: one metric, two thresholds."""
    v = _num(value)
    if v is None:
        return None
    if higher_is_worse:
        if v >= crit:
            return _alert(key, "critical", title, fmt(v, crit), value, crit)
        if v >= warn:
            return _alert(key, "warning", title, fmt(v, warn), value, warn)
    else:
        if v < crit:
            return _alert(key, "critical", title, fmt(v, crit), value, crit)
        if v < warn:
            return _alert(key, "warning", title, fmt(v, warn), value, warn)
    return None


def _latency_ratio_alert(key, title, latency: Optional[dict], warn, crit,
                         *, min_samples=1, p95_crit_seconds=None) -> Optional[dict]:
    if not isinstance(latency, dict):
        return None
    samples = int(latency.get("samples") or 0)
    p95 = _num(latency.get("p95"))
    ratio = _num(latency.get("ratio"))
    if samples < min_samples or p95 is None:
        return None
    baseline = latency.get("baseline_p95")
    if p95_crit_seconds is not None and p95 >= p95_crit_seconds:
        return _alert(
            key, "critical", title,
            f"p95 {p95:.1f}s over {samples} samples (critical at {p95_crit_seconds:.0f}s"
            + (f", baseline {baseline:.1f}s" if _num(baseline) is not None else "") + ").",
            p95, p95_crit_seconds,
        )
    if ratio is None:
        return None
    if ratio >= crit:
        return _alert(key, "critical", title,
                      f"p95 {p95:.1f}s is {ratio:.1f}x the 7-day baseline "
                      f"({baseline:.1f}s) over {samples} samples.", ratio, crit)
    if ratio >= warn:
        return _alert(key, "warning", title,
                      f"p95 {p95:.1f}s is {ratio:.1f}x the 7-day baseline "
                      f"({baseline:.1f}s) over {samples} samples.", ratio, warn)
    return None


def within_payment_hours(now: datetime) -> bool:
    local_hour = (now + timedelta(hours=LOCAL_UTC_OFFSET_HOURS)).hour
    start, end = PAYMENTS_SILENCE_HOURS_EAT
    return start <= local_hour < end


# --- rule set -----------------------------------------------------------------

def evaluate(sections: dict, now: Optional[datetime] = None) -> list[dict]:
    """Return active alerts, most severe first. Pure: no I/O, no clock reads."""
    now = now or datetime.utcnow()
    alerts: list[dict] = []
    s = sections or {}

    # provisioning ------------------------------------------------------------
    prov = s.get("provisioning") or {}
    counts = prov.get("counts") or {}
    a = _two_level(
        "provisioning.retry_backlog", "Provisioning retry backlog",
        counts.get("retry_pending"),
        PROVISIONING_RETRY_BACKLOG_WARN, PROVISIONING_RETRY_BACKLOG_CRIT,
        lambda v, t: (f"{int(v)} attempts waiting for retry in the last "
                      f"{prov.get('window_minutes', 60)} min across "
                      f"{prov.get('routers_with_backlog', 0)} routers (threshold {int(t)})."),
    )
    if a:
        alerts.append(a)
    ratio = prov.get("success_ratio")
    ratio_samples = int(prov.get("success_ratio_samples") or 0)
    if _num(ratio) is not None and ratio_samples >= PROVISIONING_SUCCESS_RATIO_MIN_SAMPLES:
        a = _two_level(
            "provisioning.success_ratio", "Provisioning success ratio",
            ratio, PROVISIONING_SUCCESS_RATIO_WARN, PROVISIONING_SUCCESS_RATIO_CRIT,
            lambda v, t: (f"Only {v:.0%} of {ratio_samples} settled attempts reached the "
                          f"router in the last hour (threshold {t:.0%})."),
            higher_is_worse=False,
        )
        if a:
            alerts.append(a)
    latency = (prov.get("latency") or {}).get("end_to_end")
    a = _latency_ratio_alert(
        "provisioning.latency_p95", "Provisioning latency p95", latency,
        PROVISIONING_LATENCY_RATIO_WARN, PROVISIONING_LATENCY_RATIO_CRIT,
        min_samples=PROVISIONING_LATENCY_MIN_SAMPLES,
        p95_crit_seconds=PROVISIONING_LATENCY_P95_CRIT_SECONDS,
    )
    if a:
        alerts.append(a)

    # payments ----------------------------------------------------------------
    pay = s.get("payments") or {}
    pcounts = pay.get("counts") or {}
    a = _two_level(
        "payments.pending_over_5m", "Payments stuck pending",
        pcounts.get("pending_over_5m"),
        PAYMENTS_PENDING_OVER_5M_WARN, PAYMENTS_PENDING_OVER_5M_CRIT,
        lambda v, t: f"{int(v)} M-Pesa transactions pending for over 5 minutes (threshold {int(t)}).",
    )
    if a:
        alerts.append(a)
    silence = _num(pay.get("minutes_since_last_completed"))
    created = int(pcounts.get("created") or 0)
    if silence is not None and created >= 1 and within_payment_hours(now):
        a = _two_level(
            "payments.callback_silence", "No completed payments",
            silence, PAYMENTS_SILENCE_WARN_MINUTES, PAYMENTS_SILENCE_CRIT_MINUTES,
            lambda v, t: (f"No M-Pesa transaction has completed for {v:.0f} min while "
                          f"{created} were created in the last hour (threshold {int(t)} min)."),
        )
        if a:
            alerts.append(a)
    a = _latency_ratio_alert(
        "payments.latency_p95", "Payment callback latency p95",
        pay.get("callback_latency"),
        PAYMENTS_LATENCY_RATIO_WARN, PAYMENTS_LATENCY_RATIO_CRIT,
    )
    if a:
        alerts.append(a)

    # expiry ------------------------------------------------------------------
    exp = s.get("expiry") or {}
    a = _two_level(
        "expiry.hot_backlog", "Expired customers still active",
        exp.get("expired_active_hot"),
        EXPIRY_HOT_BACKLOG_WARN, EXPIRY_HOT_BACKLOG_CRIT,
        lambda v, t: (f"{int(v)} expired customers are still ACTIVE on reachable routers "
                      f"({int(exp.get('expired_active_quarantined') or 0)} more quarantined on "
                      f"routers offline 3+ days; threshold {int(t)})."),
    )
    if a:
        alerts.append(a)
    a = _two_level(
        "expiry.oldest_hot", "Oldest un-removed expiry",
        exp.get("oldest_hot_expired_minutes"),
        EXPIRY_OLDEST_HOT_WARN_MINUTES, EXPIRY_OLDEST_HOT_CRIT_MINUTES,
        lambda v, t: (f"The oldest expired-but-active customer on a reachable router expired "
                      f"{v:.0f} min ago (threshold {int(t)} min)."),
    )
    if a:
        alerts.append(a)
    a = _latency_ratio_alert(
        "expiry.removal_p95", "Expiry removal latency p95",
        exp.get("removal_latency"),
        EXPIRY_REMOVAL_RATIO_WARN, EXPIRY_REMOVAL_RATIO_CRIT,
    )
    if a:
        alerts.append(a)
    cleanup = exp.get("cleanup_job") or {}
    since_finish = _num(cleanup.get("minutes_since_finished"))
    if since_finish is not None and since_finish > EXPIRY_CLEANUP_STALE_WARN_MINUTES:
        sev = "critical" if since_finish > EXPIRY_CLEANUP_STALE_CRIT_MINUTES else "warning"
        thr = (EXPIRY_CLEANUP_STALE_CRIT_MINUTES if sev == "critical"
               else EXPIRY_CLEANUP_STALE_WARN_MINUTES)
        alerts.append(_alert(
            "expiry.cleanup_stale", sev, "Expiry cleanup job stale",
            (f"cleanup_expired_users has not finished for {since_finish:.0f} min "
             f"(threshold {thr} min; last error: {cleanup.get('last_error') or 'none'})."),
            round(since_finish, 1), thr,
        ))

    # tunnels -----------------------------------------------------------------
    tun = s.get("tunnels") or {}
    a = _two_level(
        "tunnels.platform_event", "Fleet-wide tunnel drops",
        tun.get("recent_drops_10m"),
        TUNNELS_PLATFORM_EVENT_WARN, TUNNELS_PLATFORM_EVENT_CRIT,
        lambda v, t: (f"{int(v)} routers went online -> offline in the last 10 min "
                      f"(threshold {int(t)}); a fleet-wide drop points at the tunnel host, not the sites."),
    )
    if a:
        alerts.append(a)
    control_path = tun.get("control_path") or {}
    if control_path.get("available"):
        a = _two_level(
            "tunnels.transit_fallback", "Routers on AWS transit fallback",
            control_path.get("transit_fallback"),
            TUNNELS_TRANSIT_FALLBACK_WARN, TUNNELS_TRANSIT_FALLBACK_CRIT,
            lambda v, t: (f"{int(v)} routers are reached through the AWS transit path instead of "
                          f"the native Hetzner tunnel (threshold {int(t)}); expect ~2x RouterOS latency."),
        )
        if a:
            alerts.append(a)

    # control plane -----------------------------------------------------------
    cp = s.get("control_plane") or {}
    writers = int(cp.get("active_writers") or 0)
    mismatch = bool(cp.get("db_identity_mismatch"))
    if writers > 1 or mismatch:
        detail = (f"{writers} active scheduler writers" if writers > 1
                  else "instances disagree on which database they are attached to")
        instances = ", ".join(
            f"{i.get('hostname') or i.get('instance_id')} ({i.get('runtime_mode')}, "
            f"db {str(i.get('db_identity') or '?')[:8]})"
            for i in (cp.get("instances") or [])[:5]
        )
        alerts.append(_alert(
            "control_plane.multiple_writers", "critical", "Multiple active writers",
            f"{detail}: {instances}. Only ONE app may run the scheduler against this database.",
            writers, 1,
        ))
    no_writer = _num(cp.get("minutes_since_writer_heartbeat"))
    if no_writer is None:
        no_writer = float("inf")
    if no_writer >= CONTROL_PLANE_NO_WRITER_WARN_MINUTES:
        sev = "critical" if no_writer >= CONTROL_PLANE_NO_WRITER_CRIT_MINUTES else "warning"
        thr = (CONTROL_PLANE_NO_WRITER_CRIT_MINUTES if sev == "critical"
               else CONTROL_PLANE_NO_WRITER_WARN_MINUTES)
        shown = None if no_writer == float("inf") else round(no_writer, 1)
        alerts.append(_alert(
            "control_plane.no_writer", sev, "No scheduler heartbeat",
            ("No app instance with the scheduler enabled has written a heartbeat"
             + (f" for {shown:.0f} min" if shown is not None else " yet")
             + f" (threshold {thr} min)."),
            shown, thr,
        ))

    # safety net --------------------------------------------------------------
    sn = s.get("safety_net") or {}
    removals = _num(sn.get("removals_last_hour"))
    baseline = _num(sn.get("baseline_per_hour")) or 0.0
    if removals is not None:
        warn_t = max(SAFETY_NET_SPIKE_WARN_FLOOR, SAFETY_NET_SPIKE_WARN_MULTIPLIER * baseline)
        crit_t = max(SAFETY_NET_SPIKE_CRIT_FLOOR, SAFETY_NET_SPIKE_CRIT_MULTIPLIER * baseline)
        if removals > crit_t or removals > warn_t:
            sev = "critical" if removals > crit_t else "warning"
            thr = crit_t if sev == "critical" else warn_t
            alerts.append(_alert(
                "safety_net.spike", sev, "Safety-net binding removals spike",
                (f"The safety net removed {int(removals)} IP bindings in the last hour "
                 f"(7-day baseline {baseline:.1f}/h, threshold {thr:.0f}). A spike means paid "
                 f"clients are being kicked: check for a second writer or a stale database."),
                removals, round(thr, 1),
            ))

    # jobs --------------------------------------------------------------------
    jobs = s.get("jobs") or {}
    worst = None
    for item in jobs.get("items") or []:
        interval = _num(item.get("interval_seconds"))
        since = _num(item.get("seconds_since_finish"))
        if not interval:
            continue
        if since is None:
            # Never finished: measure from when the registry first saw it.
            since = _num(item.get("seconds_since_first_seen"))
            if since is None:
                continue
        floor = JOBS_STALE_MIN_MINUTES * 60
        warn_t = max(floor, interval * JOBS_STALE_WARN_MULTIPLIER)
        crit_t = max(floor, interval * JOBS_STALE_CRIT_MULTIPLIER)
        if since > crit_t:
            candidate = ("critical", item, since, crit_t)
        elif since > warn_t:
            candidate = ("warning", item, since, warn_t)
        else:
            continue
        if worst is None or SEVERITY_ORDER[candidate[0]] > SEVERITY_ORDER[worst[0]] \
                or (candidate[0] == worst[0] and candidate[2] / candidate[3] > worst[2] / worst[3]):
            worst = candidate
    if worst:
        sev, item, since, thr = worst
        alerts.append(_alert(
            "jobs.stale", sev, "Scheduler job stale",
            (f"Job '{item.get('id')}' has not finished for {since / 60:.0f} min "
             f"(interval {int(item.get('interval_seconds'))}s, threshold {thr / 60:.0f} min"
             + (f"; last error: {item.get('last_error')}" if item.get("last_error") else "")
             + ")."),
            round(since, 1), round(thr, 1),
        ))

    # db pool -----------------------------------------------------------------
    pool = s.get("db_pool") or {}
    level = pool.get("pressure_level")
    if level in ("warning", "critical"):
        alerts.append(_alert(
            "db_pool.pressure", level, "DB pool pressure",
            (f"DB pool pressure is {level}: {pool.get('checked_out')} of "
             f"{(pool.get('pool_size') or 0) + (pool.get('max_overflow') or 0)} connections checked out"
             + (f" ({', '.join(pool.get('patterns') or [])})" if pool.get("patterns") else "") + "."),
            pool.get("checked_out"), level,
        ))

    alerts.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), x["key"]))
    return alerts


# --- section / overall status --------------------------------------------------

_WATCH_RULES = {
    "provisioning": lambda sec: int((sec.get("counts") or {}).get("retry_pending") or 0) >= 10,
    "payments": lambda sec: int((sec.get("counts") or {}).get("pending_over_5m") or 0) >= 2,
    "expiry": lambda sec: int(sec.get("expired_active_hot") or 0) >= 50,
    "tunnels": lambda sec: int(sec.get("recent_drops_10m") or 0) >= 1,
    "safety_net": lambda sec: int(sec.get("removals_last_hour") or 0) > 0,
    "db_pool": lambda sec: sec.get("pressure_level") == "watch",
    "jobs": lambda sec: any(i.get("last_error") for i in (sec.get("items") or [])),
    "control_plane": lambda sec: False,
}


def section_status(name: str, section: dict, alerts: list[dict]) -> str:
    if not isinstance(section, dict) or section.get("available") is False:
        return "unknown"
    worst = "healthy"
    for alert in alerts:
        if alert["key"].split(".", 1)[0] != name:
            continue
        if SEVERITY_ORDER.get(alert["severity"], 0) > SEVERITY_ORDER[worst]:
            worst = alert["severity"]
    if worst == "healthy":
        try:
            if _WATCH_RULES.get(name, lambda _s: False)(section):
                worst = "watch"
        except Exception:  # noqa: BLE001 - a status hint must never fail the snapshot
            pass
    return worst


def overall_status(sections: dict) -> str:
    worst = "healthy"
    for section in (sections or {}).values():
        status = (section or {}).get("status", "unknown") if isinstance(section, dict) else "unknown"
        if STATUS_ORDER.get(status, 1) > STATUS_ORDER[worst]:
            worst = status
    return worst
