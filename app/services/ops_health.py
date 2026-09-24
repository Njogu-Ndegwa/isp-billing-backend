"""Operations health monitor: DB-only snapshot builder, heartbeat, alert delivery.

Contract: see the ops-health spec (JSON served by ``GET /api/admin/ops-health``)
and the alert table in ``app/services/ops_health_rules.py``.

Session discipline (AGENTS.md): every section is built in its OWN short
session -- open, query, commit, close -- then assembled in pure Python. The job
does no network I/O at all; the one optional outbound action (critical SMS) is
fired after every session is closed. Percentiles are computed in Python from
bounded row fetches so the same code runs on SQLite (tests) and Postgres.

Only ONE active writer should ever run the snapshot job. The heartbeat table is
what detects when that is violated (control_plane.multiple_writers).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import socket
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from sqlalchemy import delete, func, or_, select

from app.config import settings
from app.db import database
from app.db.database import db_pool_snapshot
from app.db.models import (
    AppInstanceHeartbeat,
    Customer,
    CustomerStatus,
    MpesaTransaction,
    MpesaTransactionStatus,
    OpsHealthSnapshot,
    ProvisioningAttempt,
    ProvisioningLog,
    ProvisioningState,
    ResellerInboxMessage,
    Router,
    RouterAvailabilityCheck,
    SubscriptionStatus,
    User,
    UserRole,
)
from app.core.runtime_mode import runtime_mode_name, scheduler_enabled
from app.services import job_registry
from app.services import ops_health_rules as rules
from app.services.management_tunnel_health import classify_primary_tunnel
from app.services.router_availability import ROUTER_STATUS_STALE_AFTER_SECONDS
from app.services.ops_health_problem_routers import build_problem_routers_section

logger = logging.getLogger(__name__)

WINDOW = timedelta(minutes=60)
BASELINE_WINDOW = timedelta(days=7)
BASELINE_MIN_SNAPSHOTS = 100
BASELINE_MIN_SAMPLES = 20
ROW_FETCH_LIMIT = 5000
SNAPSHOT_FETCH_LIMIT = 20000
SNAPSHOT_RETENTION = timedelta(days=7)
HEARTBEAT_RETENTION = timedelta(days=7)
HEARTBEAT_LIVE_WINDOW = timedelta(minutes=3)
DROP_WINDOW = timedelta(minutes=10)
ALERT_DEDUPE = timedelta(minutes=30)
HISTORY_BUCKET = timedelta(minutes=5)
HISTORY_MAX_HOURS = 168
EXPIRY_QUARANTINE_AFTER = timedelta(days=3)   # same rule as mikrotik_background
DEACTIVATION_ACTIONS = ("hotspot_deactivation", "pppoe_deactivation")
SAFETY_NET_ACTION = "safety_net_binding_removed"
CLEANUP_JOB_ID = "cleanup_expired_users"
OPS_ALERT_SMS_CATEGORY = "ops_alert"

# Pool-busy threshold shared with the other optional background jobs.
from app.services.mikrotik_background import BACKGROUND_DB_BUSY_THRESHOLD_PERCENT  # noqa: E402


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------

def percentile(values: Iterable[float], pct: float) -> Optional[float]:
    """Linear-interpolated percentile (pct in 0..100) over a finite sample."""
    data = sorted(float(v) for v in values)
    if not data:
        return None
    if len(data) == 1:
        return round(data[0], 3)
    rank = (pct / 100.0) * (len(data) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(data) - 1)
    frac = rank - lo
    return round(data[lo] + (data[hi] - data[lo]) * frac, 3)


def _median(values: list[float]) -> Optional[float]:
    return percentile(values, 50)


def latency_block(samples: list[float], baseline_p95: Optional[float],
                  baseline_samples: int) -> dict:
    """{p50, p95, samples, baseline_p95, ratio}; ratio null below BASELINE_MIN_SAMPLES."""
    p50 = percentile(samples, 50)
    p95 = percentile(samples, 95)
    ratio = None
    if (
        p95 is not None and baseline_p95 is not None and baseline_p95 > 0
        and baseline_samples >= BASELINE_MIN_SAMPLES
    ):
        ratio = round(p95 / baseline_p95, 2)
    return {
        "p50": p50,
        "p95": p95,
        "samples": len(samples),
        "baseline_p95": baseline_p95,
        "baseline_samples": baseline_samples,
        "ratio": ratio,
    }


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"


def _seconds(later: Optional[datetime], earlier: Optional[datetime]) -> Optional[float]:
    if later is None or earlier is None:
        return None
    return (later - earlier).total_seconds()


CUT_OFF_OWNER_STATUSES = (SubscriptionStatus.SUSPENDED, SubscriptionStatus.INACTIVE)


def is_owner_cut_off(owner_status) -> bool:
    """A suspended or inactive reseller's routers serve 503 at the platform
    level, so nothing on them is a live backlog."""
    if owner_status is None:
        return False
    value = owner_status.value if hasattr(owner_status, "value") else str(owner_status)
    return value in {s.value for s in CUT_OFF_OWNER_STATUSES}


def is_router_quarantined(last_status, last_online_at, created_at, now: datetime,
                          last_cleanup_failure_at: Optional[datetime] = None) -> bool:
    """Same rule as ``mikrotik_background._router_long_offline``: the last
    successful online signal (or creation, if never online) is >= 3 days old,
    AND either the router is marked offline or expiry cleanup has itself failed
    to reach it since that signal (a silent router keeps a stale
    ``last_status = true``). Cleanup keeps that evidence in memory; here it
    comes from its ``expired_cleanup`` availability rows."""
    reference = last_online_at or created_at
    if reference is None or (now - reference) < EXPIRY_QUARANTINE_AFTER:
        return False
    if last_status is False:
        return True
    return last_cleanup_failure_at is not None and last_cleanup_failure_at > reference


async def load_cleanup_failures_since_online(db, now: datetime) -> dict[int, datetime]:
    """Latest ``expired_cleanup`` failure per router that happened after the
    router's last online signal, for routers silent long enough to quarantine."""
    reference = func.coalesce(Router.last_online_at, Router.created_at)
    rows = (await db.execute(
        select(RouterAvailabilityCheck.router_id, func.max(RouterAvailabilityCheck.checked_at))
        .join(Router, Router.id == RouterAvailabilityCheck.router_id)
        .where(RouterAvailabilityCheck.source == "expired_cleanup",
               RouterAvailabilityCheck.is_online.is_(False),
               reference <= now - EXPIRY_QUARANTINE_AFTER,
               RouterAvailabilityCheck.checked_at > reference)
        .group_by(RouterAvailabilityCheck.router_id)
    )).all()
    return {router_id: failed_at for router_id, failed_at in rows}


def sample_history_points(rows: list[tuple[datetime, dict]], bucket: timedelta = HISTORY_BUCKET) -> list[dict]:
    """One point per bucket (the first snapshot in it), oldest first."""
    points: list[dict] = []
    seen: set[int] = set()
    bucket_seconds = int(bucket.total_seconds())
    for generated_at, metrics in sorted(rows, key=lambda r: r[0]):
        key = int(generated_at.timestamp()) // bucket_seconds
        if key in seen:
            continue
        seen.add(key)
        point = {"t": _iso(generated_at)}
        point.update(metrics or {})
        points.append(point)
    return points


def read_route_state_file(path: str) -> dict:
    """{"available": bool, native, transit_fallback, unrouted, checked_at}."""
    unavailable = {"available": False, "native": None, "transit_fallback": None,
                   "unrouted": None, "checked_at": None}
    if not path:
        return unavailable
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return unavailable
        return {
            "available": True,
            "native": int(data.get("native") or 0),
            "transit_fallback": int(data.get("transit_fallback") or 0),
            "unrouted": int(data.get("unrouted") or 0),
            "checked_at": data.get("checked_at"),
        }
    except Exception as exc:  # noqa: BLE001 - a missing/bad file is "unavailable", not an error
        logger.debug("[OPS-HEALTH] route state file unreadable (%s): %s", path, exc)
        return unavailable


# Display order for per-tunnel breakdowns. Primary planes first, then the
# insurance planes, then anything the classifier cannot place.
TUNNEL_TYPES = ("wireguard", "l2tp", "sstp", "wg2_insurance", "aws_insurance", "other")
# Values of routers.management_tunnel that override the ip_address range.
MANAGEMENT_TUNNEL_OVERRIDES = frozenset({"sstp"})


def tunnel_type_for_ip(ip_address: Optional[str]) -> str:
    """Which management tunnel a router is reached over, from its stored IP.

    Primary planes follow ``management_tunnel_health.classify_primary_tunnel``
    (10.0.0-99.x WireGuard, 10.0.100-199.x L2TP/IPsec). The Hetzner wg2
    insurance plane is 10.251/16 and the retired-AWS one 10.250/16.
    """
    primary = classify_primary_tunnel(ip_address)
    if primary:
        return primary
    try:
        octets = str(ipaddress.ip_address(ip_address or "")).split(".")
    except ValueError:
        return "other"
    if octets[:2] == ["10", "251"]:
        return "wg2_insurance"
    if octets[:2] == ["10", "250"]:
        return "aws_insurance"
    return "other"


def tunnel_type_for_router(ip_address: Optional[str], management_tunnel: Optional[str] = None) -> str:
    """Like ``tunnel_type_for_ip``, but a router moved onto another management
    tunnel (routers.management_tunnel, e.g. SSTP) keeps its original address
    range, so the explicit flag wins."""
    if management_tunnel in MANAGEMENT_TUNNEL_OVERRIDES:
        return management_tunnel
    return tunnel_type_for_ip(ip_address)


async def load_management_tunnel_overrides(db) -> dict[int, str]:
    """{router_id: management_tunnel} for the few routers that set it."""
    rows = (await db.execute(
        select(Router.id, Router.management_tunnel)
        .where(Router.management_tunnel.isnot(None))
    )).all()
    return {rid: tunnel for rid, tunnel in rows}


def _by_tunnel_latency(samples_by_tunnel: dict[str, list[float]],
                       baselines_by_tunnel: dict[str, tuple[Optional[float], int]]) -> dict:
    """{tunnel: latency_block} for every tunnel that has samples or a known
    baseline, in TUNNEL_TYPES order."""
    out: dict[str, dict] = {}
    for tunnel in TUNNEL_TYPES:
        if tunnel not in samples_by_tunnel and tunnel not in baselines_by_tunnel:
            continue
        base = baselines_by_tunnel.get(tunnel) or (None, 0)
        out[tunnel] = latency_block(samples_by_tunnel.get(tunnel, []), base[0], base[1])
    return out


def _parse_count(details: Optional[str]) -> int:
    if not details:
        return 0
    for part in str(details).split(";"):
        part = part.strip()
        if part.startswith("count="):
            try:
                return int(part[6:])
            except ValueError:
                return 0
    return 0


# ---------------------------------------------------------------------------
# baselines (7 days of stored snapshot metrics, else raw tables)
# ---------------------------------------------------------------------------

async def load_snapshot_baselines(now: datetime) -> dict:
    """{"count": n, "<metric>": [values...]} from the previous 7 days of snapshots.

    Only the flat ``metrics`` column is read, never ``payload``.
    """
    start = now - BASELINE_WINDOW
    series: dict[str, list[float]] = defaultdict(list)
    count = 0
    async with database.async_session() as db:
        rows = (await db.execute(
            select(OpsHealthSnapshot.metrics)
            .where(OpsHealthSnapshot.generated_at >= start,
                   OpsHealthSnapshot.generated_at < now)
            .order_by(OpsHealthSnapshot.generated_at.desc())
            .limit(SNAPSHOT_FETCH_LIMIT)
        )).scalars().all()
        await db.commit()
    for metrics in rows:
        count += 1
        if not isinstance(metrics, dict):
            continue
        for key, value in metrics.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                series[key].append(float(value))
    result: dict[str, Any] = dict(series)
    result["count"] = count
    return result


def _baseline_from_snapshots(baselines: dict, p95_key: str, samples_key: str) -> Optional[tuple[Optional[float], int]]:
    """Median of stored p95s (snapshots with samples > 0). None = use raw tables."""
    if not baselines or baselines.get("count", 0) < BASELINE_MIN_SNAPSHOTS:
        return None
    p95s = baselines.get(p95_key) or []
    samples = baselines.get(samples_key) or []
    values = [p for p, n in zip(p95s, samples) if n and n > 0] if samples else list(p95s)
    return (_median(values), len(values))


# ---------------------------------------------------------------------------
# section builders (one short session each)
# ---------------------------------------------------------------------------

async def build_provisioning_section(now: datetime, baselines: Optional[dict] = None) -> dict:
    window_start = now - WINDOW
    async with database.async_session() as db:
        state_rows = (await db.execute(
            select(ProvisioningAttempt.provisioning_state, func.count())
            .where(ProvisioningAttempt.updated_at >= window_start)
            .group_by(ProvisioningAttempt.provisioning_state)
        )).all()
        per_router_rows = (await db.execute(
            select(ProvisioningAttempt.router_id, func.count())
            .where(ProvisioningAttempt.updated_at >= window_start,
                   ProvisioningAttempt.provisioning_state == ProvisioningState.RETRY_PENDING)
            .group_by(ProvisioningAttempt.router_id)
        )).all()
        pending_by_router = sorted(
            ((rid, n) for rid, n in per_router_rows if rid is not None),
            key=lambda r: (-r[1], r[0]),
        )
        top_ids = [rid for rid, _ in pending_by_router[:10]]
        # id -> (name, tunnel type) for the whole fleet: the per-tunnel split
        # needs every router an attempt touched, not just the top ten.
        router_rows = (await db.execute(select(Router.id, Router.name, Router.ip_address))).all()
        overrides = await load_management_tunnel_overrides(db)
        names: dict[int, str] = {rid: name for rid, name, _ in router_rows}
        tunnel_of: dict[int, str] = {
            rid: tunnel_type_for_router(ip, overrides.get(rid)) for rid, _, ip in router_rows
        }
        errors: dict[int, str] = {}
        if top_ids:
            err_rows = (await db.execute(
                select(ProvisioningAttempt.router_id, ProvisioningAttempt.last_error)
                .where(ProvisioningAttempt.router_id.in_(top_ids),
                       ProvisioningAttempt.provisioning_state == ProvisioningState.RETRY_PENDING,
                       ProvisioningAttempt.updated_at >= window_start)
                .order_by(ProvisioningAttempt.updated_at.desc())
                .limit(200)
            )).all()
            for rid, err in err_rows:
                if rid not in errors and err:
                    errors[rid] = str(err)[:120]
        lat_rows = (await db.execute(
            select(ProvisioningAttempt.created_at, ProvisioningAttempt.last_attempt_at,
                   ProvisioningAttempt.router_updated_at, ProvisioningAttempt.router_id)
            .where(ProvisioningAttempt.router_updated_at >= window_start)
            .order_by(ProvisioningAttempt.router_updated_at.desc())
            .limit(ROW_FETCH_LIMIT)
        )).all()
        raw_baseline_rows = []
        snap_e2e = _baseline_from_snapshots(baselines or {}, "provisioning_p95_end_to_end",
                                            "provisioning_samples_end_to_end")
        snap_call = _baseline_from_snapshots(baselines or {}, "provisioning_p95_router_call",
                                             "provisioning_samples_router_call")
        if snap_e2e is None or snap_call is None:
            raw_baseline_rows = (await db.execute(
                select(ProvisioningAttempt.created_at, ProvisioningAttempt.last_attempt_at,
                       ProvisioningAttempt.router_updated_at, ProvisioningAttempt.router_id)
                .where(ProvisioningAttempt.router_updated_at >= now - BASELINE_WINDOW,
                       ProvisioningAttempt.router_updated_at < window_start)
                .order_by(ProvisioningAttempt.router_updated_at.desc())
                .limit(ROW_FETCH_LIMIT)
            )).all()
        await db.commit()

    counts = {s.value: 0 for s in ProvisioningState}
    for state, n in state_rows:
        key = state.value if hasattr(state, "value") else str(state)
        counts[key] = int(n)
    settled = counts["router_updated"] + counts["retry_pending"] + counts["failed"]
    success_ratio = round(counts["router_updated"] / settled, 3) if settled else None

    def _split(rows):
        """Fleet lists plus per-tunnel lists for both latencies."""
        e2e, call = [], []
        e2e_t: dict[str, list[float]] = defaultdict(list)
        call_t: dict[str, list[float]] = defaultdict(list)
        for created, attempted, updated, router_id in rows:
            tunnel = tunnel_of.get(router_id, "other")
            v = _seconds(updated, created)
            if v is not None and v >= 0:
                e2e.append(v)
                e2e_t[tunnel].append(v)
            v = _seconds(updated, attempted)
            if v is not None and v >= 0:
                call.append(v)
                call_t[tunnel].append(v)
        return e2e, call, e2e_t, call_t

    e2e, call, e2e_by_tunnel, call_by_tunnel = _split(lat_rows)

    # Baselines: fleet + per tunnel, from stored snapshots when there are
    # enough, else from the raw 7-day rows fetched above.
    base_e2e_t: dict[str, tuple[Optional[float], int]] = {}
    base_call_t: dict[str, tuple[Optional[float], int]] = {}
    if snap_e2e is None or snap_call is None:
        base_e2e, base_call, raw_e2e_t, raw_call_t = _split(raw_baseline_rows)
        snap_e2e = snap_e2e or (percentile(base_e2e, 95), len(base_e2e))
        snap_call = snap_call or (percentile(base_call, 95), len(base_call))
        for tunnel, values in raw_e2e_t.items():
            base_e2e_t[tunnel] = (percentile(values, 95), len(values))
        for tunnel, values in raw_call_t.items():
            base_call_t[tunnel] = (percentile(values, 95), len(values))
    else:
        for tunnel in TUNNEL_TYPES:
            e2e_b = _baseline_from_snapshots(
                baselines or {}, f"provisioning_p95_end_to_end__{tunnel}",
                f"provisioning_samples_end_to_end__{tunnel}")
            call_b = _baseline_from_snapshots(
                baselines or {}, f"provisioning_p95_router_call__{tunnel}",
                f"provisioning_samples_router_call__{tunnel}")
            if e2e_b and e2e_b[1]:
                base_e2e_t[tunnel] = e2e_b
            if call_b and call_b[1]:
                base_call_t[tunnel] = call_b

    # Backlog split by tunnel so a problem plane is obvious at a glance.
    backlog_by_tunnel: dict[str, dict] = {}
    for rid, n in pending_by_router:
        tunnel = tunnel_of.get(rid, "other")
        entry = backlog_by_tunnel.setdefault(tunnel, {"routers": 0, "pending": 0,
                                                       "routers_with_backlog": 0})
        entry["routers"] += 1
        entry["pending"] += int(n)
        if n >= 3:
            entry["routers_with_backlog"] += 1
    backlog_by_tunnel = {t: backlog_by_tunnel[t] for t in TUNNEL_TYPES if t in backlog_by_tunnel}

    e2e_blocks = _by_tunnel_latency(e2e_by_tunnel, base_e2e_t)
    call_blocks = _by_tunnel_latency(call_by_tunnel, base_call_t)
    routers_per_tunnel: dict[str, int] = defaultdict(int)
    for tunnel in tunnel_of.values():
        routers_per_tunnel[tunnel] += 1
    by_tunnel = {
        tunnel: {
            "end_to_end": e2e_blocks.get(tunnel),
            "router_call": call_blocks.get(tunnel),
            "routers": routers_per_tunnel.get(tunnel, 0),
        }
        for tunnel in TUNNEL_TYPES if tunnel in e2e_blocks or tunnel in call_blocks
    }

    return {
        "status": "unknown",
        "window_minutes": int(WINDOW.total_seconds() // 60),
        "counts": counts,
        "success_ratio": success_ratio,
        "success_ratio_samples": settled,
        "routers_with_backlog": sum(1 for _, n in pending_by_router if n >= 3),
        "backlog_by_tunnel": backlog_by_tunnel,
        "top_routers": [
            {"router_id": rid, "router_name": names.get(rid), "pending": int(n),
             "last_error": errors.get(rid), "tunnel": tunnel_of.get(rid, "other")}
            for rid, n in pending_by_router[:10]
        ],
        "latency": {
            "end_to_end": latency_block(e2e, snap_e2e[0], snap_e2e[1]),
            "router_call": latency_block(call, snap_call[0], snap_call[1]),
            "by_tunnel": by_tunnel,
        },
    }


async def build_payments_section(now: datetime, baselines: Optional[dict] = None) -> dict:
    window_start = now - WINDOW
    async with database.async_session() as db:
        status_rows = (await db.execute(
            select(MpesaTransaction.status, func.count())
            .where(MpesaTransaction.created_at >= window_start)
            .group_by(MpesaTransaction.status)
        )).all()
        pending_over_5m = (await db.execute(
            select(func.count()).select_from(MpesaTransaction)
            .where(MpesaTransaction.created_at >= window_start,
                   MpesaTransaction.created_at <= now - timedelta(minutes=5),
                   MpesaTransaction.status == MpesaTransactionStatus.pending)
        )).scalar_one()
        lat_rows = (await db.execute(
            select(MpesaTransaction.created_at, MpesaTransaction.updated_at)
            .where(MpesaTransaction.created_at >= window_start,
                   MpesaTransaction.status == MpesaTransactionStatus.completed)
            .order_by(MpesaTransaction.created_at.desc())
            .limit(ROW_FETCH_LIMIT)
        )).all()
        last_completed = (await db.execute(
            select(func.max(MpesaTransaction.updated_at))
            .where(MpesaTransaction.status == MpesaTransactionStatus.completed)
        )).scalar_one()
        snap = _baseline_from_snapshots(baselines or {}, "payments_p95_callback",
                                        "payments_samples_callback")
        raw_rows = []
        if snap is None:
            raw_rows = (await db.execute(
                select(MpesaTransaction.created_at, MpesaTransaction.updated_at)
                .where(MpesaTransaction.created_at >= now - BASELINE_WINDOW,
                       MpesaTransaction.created_at < window_start,
                       MpesaTransaction.status == MpesaTransactionStatus.completed)
                .order_by(MpesaTransaction.created_at.desc())
                .limit(ROW_FETCH_LIMIT)
            )).all()
        await db.commit()

    by_status: dict[str, int] = defaultdict(int)
    for status, n in status_rows:
        key = status.value if hasattr(status, "value") else str(status)
        by_status[key] += int(n)
    counts = {
        "created": sum(by_status.values()),
        "completed": by_status.get("completed", 0),
        "failed": by_status.get("failed", 0) + by_status.get("expired", 0),
        "pending": by_status.get("pending", 0),
        "pending_over_5m": int(pending_over_5m or 0),
    }
    samples = [v for c, u in lat_rows if (v := _seconds(u, c)) is not None and v >= 0]
    if snap is None:
        base = [v for c, u in raw_rows if (v := _seconds(u, c)) is not None and v >= 0]
        snap = (percentile(base, 95), len(base))
    since = _seconds(now, last_completed)
    return {
        "status": "unknown",
        "window_minutes": int(WINDOW.total_seconds() // 60),
        "counts": counts,
        "callback_latency": latency_block(samples, snap[0], snap[1]),
        "minutes_since_last_completed": round(since / 60, 1) if since is not None else None,
        "last_completed_at": _iso(last_completed),
    }


async def build_expiry_section(now: datetime, baselines: Optional[dict] = None) -> dict:
    window_start = now - WINDOW
    async with database.async_session() as db:
        router_rows = (await db.execute(
            select(Router.id, Router.last_status, Router.last_online_at, Router.created_at,
                   Router.ip_address, User.subscription_status)
            .outerjoin(User, User.id == Router.user_id)
        )).all()
        cleanup_failures = await load_cleanup_failures_since_online(db, now)
        overrides = await load_management_tunnel_overrides(db)
        group_rows = (await db.execute(
            select(Customer.router_id, func.count(), func.min(Customer.expiry))
            .where(Customer.status == CustomerStatus.ACTIVE,
                   Customer.expiry.isnot(None),
                   Customer.expiry <= now,
                   or_(Customer.mac_address.isnot(None), Customer.pppoe_username.isnot(None)))
            .group_by(Customer.router_id)
        )).all()
        removal_rows = (await db.execute(
            select(ProvisioningLog.log_date, Customer.expiry, Customer.router_id)
            .join(Customer, Customer.id == ProvisioningLog.customer_id)
            .where(ProvisioningLog.action.in_(DEACTIVATION_ACTIONS),
                   ProvisioningLog.status == "success",
                   ProvisioningLog.log_date >= window_start)
            .order_by(ProvisioningLog.log_date.desc())
            .limit(ROW_FETCH_LIMIT)
        )).all()
        snap = _baseline_from_snapshots(baselines or {}, "expiry_p95_removal",
                                        "expiry_samples_removal")
        raw_rows = []
        if snap is None:
            raw_rows = (await db.execute(
                select(ProvisioningLog.log_date, Customer.expiry, Customer.router_id)
                .join(Customer, Customer.id == ProvisioningLog.customer_id)
                .where(ProvisioningLog.action.in_(DEACTIVATION_ACTIONS),
                       ProvisioningLog.status == "success",
                       ProvisioningLog.log_date >= now - BASELINE_WINDOW,
                       ProvisioningLog.log_date < window_start)
                .order_by(ProvisioningLog.log_date.desc())
                .limit(ROW_FETCH_LIMIT)
            )).all()
        await db.commit()

    tunnel_of = {rid: tunnel_type_for_router(ip, overrides.get(rid))
                 for rid, _, _, _, ip, _ in router_rows}
    quarantined_routers = {
        rid for rid, last_status, last_online, created, _, _ in router_rows
        if is_router_quarantined(last_status, last_online, created, now,
                                 cleanup_failures.get(rid))
    }
    # Routers of suspended/inactive resellers are cut off at the platform level
    # (their customers cannot be online), so their expired customers are not a
    # backlog the cleanup can drain. First live alert (2026-09-23) was 12
    # customers on 4 such routers, 16 days old, hiding the real 4-day backlog.
    suspended_owner_routers = {
        rid for rid, _, _, _, _, owner_status in router_rows
        if is_owner_cut_off(owner_status)
    }
    total = hot = quarantined = suspended_owner = 0
    oldest_hot: Optional[datetime] = None
    hot_by_tunnel: dict[str, dict] = {}
    for router_id, n, oldest in group_rows:
        n = int(n)
        total += n
        # Owner first: a suspended reseller's routers usually go silent too, and
        # "reseller suspended" is the more useful reason than "quarantined".
        if router_id in suspended_owner_routers:
            suspended_owner += n
            continue
        if router_id in quarantined_routers:
            quarantined += n
            continue
        hot += n
        entry = hot_by_tunnel.setdefault(tunnel_of.get(router_id, "other"),
                                         {"routers": 0, "customers": 0})
        entry["routers"] += 1
        entry["customers"] += n
        if oldest is not None and (oldest_hot is None or oldest < oldest_hot):
            oldest_hot = oldest
    hot_by_tunnel = {t: hot_by_tunnel[t] for t in TUNNEL_TYPES if t in hot_by_tunnel}

    def _latencies(rows):
        out = []
        by_tunnel: dict[str, list[float]] = defaultdict(list)
        for log_date, expiry, router_id in rows:
            v = _seconds(log_date, expiry)
            if v is not None and v >= 0:
                out.append(v)
                by_tunnel[tunnel_of.get(router_id, "other")].append(v)
        return out, by_tunnel

    samples, samples_by_tunnel = _latencies(removal_rows)
    base_by_tunnel: dict[str, tuple[Optional[float], int]] = {}
    if snap is None:
        base, raw_by_tunnel = _latencies(raw_rows)
        snap = (percentile(base, 95), len(base))
        for tunnel, values in raw_by_tunnel.items():
            base_by_tunnel[tunnel] = (percentile(values, 95), len(values))
    else:
        for tunnel in TUNNEL_TYPES:
            b = _baseline_from_snapshots(baselines or {}, f"expiry_p95_removal__{tunnel}",
                                         f"expiry_samples_removal__{tunnel}")
            if b and b[1]:
                base_by_tunnel[tunnel] = b

    job = job_registry.get(CLEANUP_JOB_ID, now) or {}
    since_finish = job.get("seconds_since_finish")
    return {
        "status": "unknown",
        "expired_active_total": total,
        "expired_active_hot": hot,
        "expired_active_quarantined": quarantined,
        "expired_active_suspended_owner": suspended_owner,
        "hot_by_tunnel": hot_by_tunnel,
        "oldest_hot_expired_minutes": (
            round(_seconds(now, oldest_hot) / 60, 1) if oldest_hot else None
        ),
        "removal_latency": latency_block(samples, snap[0], snap[1]),
        "removal_latency_by_tunnel": _by_tunnel_latency(samples_by_tunnel, base_by_tunnel),
        "cleanup_job": {
            "last_finished_at": job.get("last_finished_at"),
            "last_duration_seconds": job.get("last_duration_seconds"),
            "skipped_runs_last_hour": job.get("missed_or_skipped_last_hour", 0),
            "last_error": job.get("last_error"),
            "minutes_since_finished": (
                round(since_finish / 60, 1) if since_finish is not None else None
            ),
        },
    }


def count_recent_drops(checks: Iterable[tuple[int, datetime, bool]], now: datetime,
                       window: timedelta = DROP_WINDOW) -> int:
    """Routers with an online -> offline transition whose offline check is in the window."""
    by_router: dict[int, list[tuple[datetime, bool]]] = defaultdict(list)
    for router_id, checked_at, is_online in checks:
        by_router[router_id].append((checked_at, bool(is_online)))
    cutoff = now - window
    drops = 0
    for seq in by_router.values():
        seq.sort(key=lambda r: r[0])
        previous = None
        dropped = False
        for checked_at, online in seq:
            if previous is True and online is False and checked_at >= cutoff:
                dropped = True
                break
            previous = online
        if dropped:
            drops += 1
    return drops


async def build_tunnels_section(now: datetime, baselines: Optional[dict] = None) -> dict:
    async with database.async_session() as db:
        router_rows = (await db.execute(
            select(Router.last_status, Router.last_checked_at, Router.ip_address,
                   Router.management_tunnel, Router.last_online_at, User.subscription_status)
            .outerjoin(User, User.id == Router.user_id)
        )).all()
        check_rows = (await db.execute(
            select(RouterAvailabilityCheck.router_id, RouterAvailabilityCheck.checked_at,
                   RouterAvailabilityCheck.is_online)
            .where(RouterAvailabilityCheck.checked_at >= now - (DROP_WINDOW * 2))
            .order_by(RouterAvailabilityCheck.checked_at.desc())
            .limit(SNAPSHOT_FETCH_LIMIT)
        )).all()
        await db.commit()

    online = offline = stale = silent_24h = 0
    by_tunnel: dict[str, dict] = {}
    stale_after = timedelta(seconds=ROUTER_STATUS_STALE_AFTER_SECONDS)
    for last_status, last_checked, ip, management_tunnel, last_online, owner_status in router_rows:
        # "Stale" only means nobody checked in 10 minutes; a quiet healthy router
        # lands there too. Not heard from for a day is what "probably down" means.
        # Suspended resellers' routers are cut off on purpose, so not counted.
        if not is_owner_cut_off(owner_status) and (last_online is None or now - last_online > timedelta(hours=24)):
            silent_24h += 1
        bucket = by_tunnel.setdefault(tunnel_type_for_router(ip, management_tunnel),
                                      {"online": 0, "offline": 0, "stale": 0, "total": 0})
        bucket["total"] += 1
        if last_checked is None or (now - last_checked) > stale_after:
            stale += 1
            bucket["stale"] += 1
        elif last_status:
            online += 1
            bucket["online"] += 1
        else:
            offline += 1
            bucket["offline"] += 1
    drops = count_recent_drops(check_rows, now)
    return {
        "status": "unknown",
        "counts": {"online": online, "offline": offline, "stale": stale,
                   "total": len(router_rows), "silent_24h": silent_24h},
        "by_tunnel": {t: by_tunnel[t] for t in TUNNEL_TYPES if t in by_tunnel},
        "recent_drops_10m": drops,
        "platform_event": drops >= rules.TUNNELS_PLATFORM_EVENT_WARN,
        "control_path": read_route_state_file(getattr(settings, "OPS_ROUTE_STATE_FILE", "")),
    }


async def build_control_plane_section(now: datetime, baselines: Optional[dict] = None) -> dict:
    async with database.async_session() as db:
        live = (await db.execute(
            select(AppInstanceHeartbeat)
            .where(AppInstanceHeartbeat.last_seen_at >= now - HEARTBEAT_LIVE_WINDOW)
            .order_by(AppInstanceHeartbeat.last_seen_at.desc())
            .limit(50)
        )).scalars().all()
        last_writer = (await db.execute(
            select(func.max(AppInstanceHeartbeat.last_seen_at))
            .where(AppInstanceHeartbeat.scheduler_enabled.is_(True),
                   AppInstanceHeartbeat.runtime_mode == "active")
        )).scalar_one()
        await db.commit()

    instances = [{
        "instance_id": row.instance_id,
        "hostname": row.hostname,
        "runtime_mode": row.runtime_mode,
        "scheduler_enabled": bool(row.scheduler_enabled),
        "db_identity": row.db_identity,
        "app_version": row.app_version,
        "started_at": _iso(row.started_at),
        "last_seen_at": _iso(row.last_seen_at),
    } for row in live]
    # A deploy recreates the container: the old process's heartbeat row stays
    # inside the 3-minute live window while the new process is already
    # running, which looked like two writers after every deploy on
    # 2026-09-23. An instance that has NOT heartbeated since the newest
    # instance started is superseded, not concurrent; a genuine second writer
    # keeps heartbeating and is counted again within a minute.
    newest_started = max((r.started_at for r in live if r.started_at), default=None)
    superseded_ids = {
        r.instance_id for r in live
        if newest_started is not None and r.started_at != newest_started
        and r.last_seen_at is not None and r.last_seen_at < newest_started
    }
    for inst in instances:
        inst["superseded"] = inst["instance_id"] in superseded_ids
    concurrent = [i for i in instances if not i["superseded"]]
    writers = sum(1 for i in concurrent if i["runtime_mode"] == "active" and i["scheduler_enabled"])
    identities = {i["db_identity"] for i in concurrent if i["db_identity"]}
    since_writer = _seconds(now, last_writer)
    return {
        "status": "unknown",
        "active_writers": writers,
        "instances": instances,
        "db_identity_mismatch": len(identities) > 1,
        "minutes_since_writer_heartbeat": (
            round(since_writer / 60, 1) if since_writer is not None else None
        ),
    }


async def build_safety_net_section(now: datetime, baselines: Optional[dict] = None) -> dict:
    window_start = now - WINDOW
    async with database.async_session() as db:
        recent = (await db.execute(
            select(ProvisioningLog.details, ProvisioningLog.log_date)
            .where(ProvisioningLog.action == SAFETY_NET_ACTION,
                   ProvisioningLog.log_date >= window_start)
            .order_by(ProvisioningLog.log_date.desc())
            .limit(ROW_FETCH_LIMIT)
        )).all()
        baseline_rows = (await db.execute(
            select(ProvisioningLog.details)
            .where(ProvisioningLog.action == SAFETY_NET_ACTION,
                   ProvisioningLog.log_date >= now - BASELINE_WINDOW,
                   ProvisioningLog.log_date < window_start)
            .limit(SNAPSHOT_FETCH_LIMIT)
        )).scalars().all()
        last_any = (await db.execute(
            select(func.max(ProvisioningLog.log_date))
            .where(ProvisioningLog.action == SAFETY_NET_ACTION)
        )).scalar_one()
        await db.commit()

    removals = sum(_parse_count(d) for d, _ in recent)
    baseline_total = sum(_parse_count(d) for d in baseline_rows)
    hours = BASELINE_WINDOW.total_seconds() / 3600 - WINDOW.total_seconds() / 3600
    return {
        "status": "unknown",
        "removals_last_hour": removals,
        "baseline_per_hour": round(baseline_total / hours, 2) if hours > 0 else 0.0,
        "last_removal_at": _iso(last_any),
    }


def build_jobs_section(now: datetime) -> dict:
    items = job_registry.snapshot(now)
    return {"status": "unknown", "items": items}


def build_db_pool_section() -> dict:
    snap = db_pool_snapshot()
    pressure = snap.get("pressure") or {}
    return {
        "status": "unknown",
        "pressure_level": pressure.get("level", "unknown"),
        "patterns": pressure.get("patterns") or [],
        "checked_out": snap.get("checked_out"),
        "checked_out_percent": snap.get("checked_out_percent"),
        "pool_size": snap.get("configured_pool_size"),
        "max_overflow": snap.get("configured_max_overflow"),
    }


# ---------------------------------------------------------------------------
# assembly
# ---------------------------------------------------------------------------

def metrics_from_sections(sections: dict) -> dict:
    """Flat numbers stored per snapshot for sparklines and 7-day baselines."""
    prov = sections.get("provisioning") or {}
    pay = sections.get("payments") or {}
    exp = sections.get("expiry") or {}
    tun = sections.get("tunnels") or {}
    sn = sections.get("safety_net") or {}
    cp = sections.get("control_plane") or {}
    lat = prov.get("latency") or {}
    metrics: dict[str, Any] = {}
    # Per-tunnel p95/sample pairs feed the per-tunnel 7-day baselines.
    for tunnel, block in (lat.get("by_tunnel") or {}).items():
        for kind in ("end_to_end", "router_call"):
            sub = (block or {}).get(kind) or {}
            metrics[f"provisioning_p95_{kind}__{tunnel}"] = sub.get("p95")
            metrics[f"provisioning_samples_{kind}__{tunnel}"] = sub.get("samples", 0)
    for tunnel, block in (exp.get("removal_latency_by_tunnel") or {}).items():
        metrics[f"expiry_p95_removal__{tunnel}"] = (block or {}).get("p95")
        metrics[f"expiry_samples_removal__{tunnel}"] = (block or {}).get("samples", 0)
    return {
        **metrics,
        "provisioning_retry_pending": (prov.get("counts") or {}).get("retry_pending", 0),
        "provisioning_p95_end_to_end": (lat.get("end_to_end") or {}).get("p95"),
        "provisioning_samples_end_to_end": (lat.get("end_to_end") or {}).get("samples", 0),
        "provisioning_p95_router_call": (lat.get("router_call") or {}).get("p95"),
        "provisioning_samples_router_call": (lat.get("router_call") or {}).get("samples", 0),
        "payments_p95_callback": (pay.get("callback_latency") or {}).get("p95"),
        "payments_samples_callback": (pay.get("callback_latency") or {}).get("samples", 0),
        "expiry_active_hot": exp.get("expired_active_hot", 0),
        "expiry_p95_removal": (exp.get("removal_latency") or {}).get("p95"),
        "expiry_samples_removal": (exp.get("removal_latency") or {}).get("samples", 0),
        "tunnels_offline": (tun.get("counts") or {}).get("offline", 0),
        "tunnels_silent_24h": (tun.get("counts") or {}).get("silent_24h", 0),
        "paid_not_connected_24h": (sections.get("problem_routers") or {}).get("paid_not_connected_24h"),
        "problem_routers_attention": ((sections.get("problem_routers") or {}).get("counts") or {}).get("attention"),
        "safety_net_removals": sn.get("removals_last_hour", 0),
        "active_writers": cp.get("active_writers", 0),
    }


def _carry_alert_history(alerts: list[dict], previous_alerts: Optional[list[dict]],
                         now: datetime) -> list[dict]:
    previous = {a.get("key"): a for a in (previous_alerts or []) if isinstance(a, dict)}
    for alert in alerts:
        prev = previous.get(alert["key"])
        alert["since"] = (prev or {}).get("since") or _iso(now)
        alert["notified_at"] = (prev or {}).get("notified_at")
        alert["notified_severity"] = (prev or {}).get("notified_severity")
    return alerts


async def compute_snapshot(now: Optional[datetime] = None,
                           previous_alerts: Optional[list[dict]] = None) -> dict:
    """Build sections (own short session each), evaluate rules, assemble."""
    now = now or datetime.utcnow()
    baselines = await load_snapshot_baselines(now)
    sections: dict[str, dict] = {}
    builders = [
        ("provisioning", build_provisioning_section),
        ("payments", build_payments_section),
        ("expiry", build_expiry_section),
        ("tunnels", build_tunnels_section),
        ("control_plane", build_control_plane_section),
        ("safety_net", build_safety_net_section),
        ("problem_routers", build_problem_routers_section),
    ]
    for name, builder in builders:
        try:
            sections[name] = await builder(now, baselines)
        except Exception as exc:  # noqa: BLE001 - one broken section must not hide the rest
            logger.exception("[OPS-HEALTH] section %s failed", name)
            sections[name] = {"status": "unknown", "available": False, "error": str(exc)[:200]}
    sections["jobs"] = build_jobs_section(now)
    sections["db_pool"] = build_db_pool_section()

    alerts = rules.evaluate(sections, now)
    alerts = _carry_alert_history(alerts, previous_alerts, now)
    for name, section in sections.items():
        section["status"] = rules.section_status(name, section, alerts)
    return {
        "generated_at": _iso(now),
        # Problem routers carry their own colours; some router is nearly always
        # struggling, so they must not hold the whole dashboard amber.
        "overall_status": rules.overall_status(
            {k: v for k, v in sections.items() if k != "problem_routers"}),
        "sections": sections,
        "alerts": alerts,
        "metrics": metrics_from_sections(sections),
        "baseline_source": "snapshots" if baselines.get("count", 0) >= BASELINE_MIN_SNAPSHOTS else "raw",
    }


# ---------------------------------------------------------------------------
# heartbeat
# ---------------------------------------------------------------------------

_PROCESS_STARTED_AT = datetime.utcnow()
_HOSTNAME = (socket.gethostname() or "unknown")[:255]
_INSTANCE_ID = "{}-{}".format(
    _HOSTNAME[:100],
    hashlib.sha1(f"{_HOSTNAME}|{_PROCESS_STARTED_AT.isoformat()}|{os.getpid()}".encode()).hexdigest()[:12],
)[:128]
_DB_IDENTITY: Optional[str] = None


def instance_id() -> str:
    return _INSTANCE_ID


def app_version() -> str:
    return (os.environ.get("GIT_SHA") or os.environ.get("APP_VERSION") or "unknown")[:64]


async def _resolve_db_identity(db) -> str:
    global _DB_IDENTITY
    if _DB_IDENTITY:
        return _DB_IDENTITY
    try:
        dialect = db.get_bind().dialect.name
    except Exception:  # noqa: BLE001
        dialect = "unknown"
    if dialect == "sqlite":
        _DB_IDENTITY = "sqlite"
        return _DB_IDENTITY
    if dialect in ("postgresql", "postgres"):
        from sqlalchemy import text
        try:
            value = (await db.execute(text("SELECT system_identifier FROM pg_control_system()"))).scalar_one()
            _DB_IDENTITY = str(value)[:64]
            return _DB_IDENTITY
        except Exception as exc:  # noqa: BLE001 - permission or old PG: fall back, do not cache
            logger.warning("[OPS-HEALTH] pg_control_system() unavailable: %s", exc)
            return "postgres-unknown"
    return dialect[:64]


async def write_heartbeat(now: Optional[datetime] = None) -> dict:
    """Upsert this process's heartbeat row in its own short session."""
    now = now or datetime.utcnow()
    async with database.async_session() as db:
        identity = await _resolve_db_identity(db)
        row = await db.get(AppInstanceHeartbeat, _INSTANCE_ID)
        fields = dict(
            hostname=_HOSTNAME,
            runtime_mode=runtime_mode_name()[:16],
            scheduler_enabled=bool(scheduler_enabled()),
            db_identity=identity,
            app_version=app_version(),
            started_at=_PROCESS_STARTED_AT,
            last_seen_at=now,
        )
        if row is None:
            row = AppInstanceHeartbeat(instance_id=_INSTANCE_ID, **fields)
            db.add(row)
        else:
            for key, value in fields.items():
                setattr(row, key, value)
        await db.commit()
    return {"instance_id": _INSTANCE_ID, **fields}


async def retire_heartbeat() -> bool:
    """Delete this process's heartbeat row on graceful shutdown (best effort).

    Called from the FastAPI shutdown hook so a deploy's outgoing container
    never lingers as a "live" instance. Returns True if a row was removed.
    """
    try:
        async with database.async_session() as db:
            result = await db.execute(delete(AppInstanceHeartbeat).where(
                AppInstanceHeartbeat.instance_id == _INSTANCE_ID
            ))
            await db.commit()
            return bool(result.rowcount)
    except Exception:  # noqa: BLE001 - shutdown must never fail on this
        logger.warning("[OPS-HEALTH] could not retire heartbeat %s", _INSTANCE_ID)
        return False


# ---------------------------------------------------------------------------
# alert delivery
# ---------------------------------------------------------------------------

# key -> (severity, sent_at). Module memory is the fast path; the previous
# snapshot's ``notified_at`` is the restart-safe fallback.
_alert_last_sent: dict[str, tuple[str, datetime]] = {}


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", ""))
    except ValueError:
        return None


def select_alerts_to_notify(alerts: list[dict], now: datetime,
                            memory: Optional[dict] = None) -> list[dict]:
    """Alerts due for delivery: never sent, sent >= 30 min ago, or escalated."""
    memory = _alert_last_sent if memory is None else memory
    due = []
    for alert in alerts:
        key, severity = alert["key"], alert["severity"]
        last = memory.get(key)
        if last is None:
            sent_at = _parse_iso(alert.get("notified_at"))
            last = (alert.get("notified_severity") or severity, sent_at) if sent_at else None
        if last is None:
            due.append(alert)
            continue
        last_severity, sent_at = last
        escalated = rules.SEVERITY_ORDER.get(severity, 0) > rules.SEVERITY_ORDER.get(last_severity, 0)
        if escalated or (now - sent_at) >= ALERT_DEDUPE:
            due.append(alert)
    return due


def _format_alert_body(alerts: list[dict]) -> str:
    lines = []
    for alert in alerts:
        lines.append(f"[{alert['severity'].upper()}] {alert['title']}: {alert['message']}")
    lines.append("")
    lines.append("Open Admin > Dashboard > Operations health for live detail.")
    return "\n".join(lines)[:2000]


async def deliver_alerts(alerts: list[dict], now: Optional[datetime] = None,
                         memory: Optional[dict] = None) -> dict:
    """Inbox message to every admin (own short session); optional critical SMS
    queued in the same session and dispatched AFTER it closes."""
    now = now or datetime.utcnow()
    memory = _alert_last_sent if memory is None else memory
    due = select_alerts_to_notify(alerts, now, memory)
    if not due:
        return {"delivered": 0, "sms_queued": 0}

    critical = [a for a in due if a["severity"] == "critical"]
    worst = due[0]["severity"]
    subject = (f"[Ops {worst.upper()}] {len(due)} alert(s): "
               + ", ".join(a["title"] for a in due[:3]))[:200]
    body = _format_alert_body(due)
    sms_phone = (getattr(settings, "OPS_ALERT_SMS_PHONE", "") or "").strip()
    sms_ids: list[int] = []
    delivered = 0

    async with database.async_session() as db:
        admin_ids = (await db.execute(
            select(User.id).where(User.role == UserRole.ADMIN).order_by(User.id)
        )).scalars().all()
        if not admin_ids:
            logger.warning("[OPS-HEALTH] No admin users; alerts not delivered: %s",
                           [a["key"] for a in due])
        for admin_id in admin_ids:
            db.add(ResellerInboxMessage(
                recipient_user_id=admin_id,
                sender_user_id=admin_ids[0],
                subject=subject,
                body=body,
                sent_sms=False,
            ))
            delivered += 1
        if critical and sms_phone and admin_ids:
            from app.db.models import SmsMessage, SmsMessageKind, SmsMessageStatus
            from app.services.messaging.segments import count_segments

            sms_body = ("OPS CRITICAL: " + "; ".join(
                f"{a['title']} ({a['message']})" for a in critical[:2]
            ))[:300]
            row = SmsMessage(
                user_id=admin_ids[0],
                recipient_phone=sms_phone[:20],
                body=sms_body,
                segments=count_segments(sms_body),
                credits_charged=0,
                kind=SmsMessageKind.ADMIN_TO_RESELLER,
                category=OPS_ALERT_SMS_CATEGORY,
                status=SmsMessageStatus.QUEUED,
            )
            db.add(row)
            await db.flush()
            sms_ids.append(row.id)
        await db.commit()
    # --- session closed; only now may anything leave the process ---

    for alert in due:
        memory[alert["key"]] = (alert["severity"], now)
        alert["notified_at"] = _iso(now)
        alert["notified_severity"] = alert["severity"]

    if sms_ids:
        try:
            from app.services.sms_dispatch import dispatch_admin_sms_messages
            asyncio.create_task(dispatch_admin_sms_messages(
                sms_ids, settings.SMS_SENDER_ID, owner_user_id=None,
            ))
        except Exception:  # noqa: BLE001 - SMS is best effort
            logger.exception("[OPS-HEALTH] could not schedule ops alert SMS")
    logger.warning("[OPS-HEALTH] delivered %d alert(s) to %d admin(s): %s",
                   len(due), delivered, [a["key"] for a in due])
    return {"delivered": delivered, "sms_queued": len(sms_ids)}


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------

async def load_previous_alerts() -> list[dict]:
    async with database.async_session() as db:
        payload = (await db.execute(
            select(OpsHealthSnapshot.payload)
            .order_by(OpsHealthSnapshot.generated_at.desc(), OpsHealthSnapshot.id.desc())
            .limit(1)
        )).scalar_one_or_none()
        await db.commit()
    if isinstance(payload, dict):
        alerts = payload.get("alerts")
        return alerts if isinstance(alerts, list) else []
    return []


async def store_snapshot(snapshot: dict, now: datetime) -> int:
    async with database.async_session() as db:
        row = OpsHealthSnapshot(
            generated_at=now,
            overall_status=str(snapshot.get("overall_status", "unknown"))[:16],
            payload={"sections": snapshot["sections"], "alerts": snapshot["alerts"],
                     "baseline_source": snapshot.get("baseline_source")},
            metrics=snapshot.get("metrics") or {},
        )
        db.add(row)
        await db.commit()
        return row.id


async def prune(now: datetime) -> None:
    async with database.async_session() as db:
        await db.execute(delete(OpsHealthSnapshot).where(
            OpsHealthSnapshot.generated_at < now - SNAPSHOT_RETENTION
        ))
        await db.execute(delete(AppInstanceHeartbeat).where(
            AppInstanceHeartbeat.last_seen_at < now - HEARTBEAT_RETENTION
        ))
        await db.commit()


async def load_history_points(now: datetime, hours: int) -> list[dict]:
    hours = max(1, min(int(hours), HISTORY_MAX_HOURS))
    async with database.async_session() as db:
        rows = (await db.execute(
            select(OpsHealthSnapshot.generated_at, OpsHealthSnapshot.metrics)
            .where(OpsHealthSnapshot.generated_at >= now - timedelta(hours=hours))
            .order_by(OpsHealthSnapshot.generated_at.asc())
            .limit(SNAPSHOT_FETCH_LIMIT)
        )).all()
        await db.commit()
    return sample_history_points([(g, m) for g, m in rows])


async def load_latest_snapshot() -> Optional[dict]:
    async with database.async_session() as db:
        row = (await db.execute(
            select(OpsHealthSnapshot)
            .order_by(OpsHealthSnapshot.generated_at.desc(), OpsHealthSnapshot.id.desc())
            .limit(1)
        )).scalar_one_or_none()
        await db.commit()
    if row is None:
        return None
    payload = row.payload if isinstance(row.payload, dict) else {}
    return {
        "generated_at": row.generated_at,
        "overall_status": row.overall_status,
        "sections": payload.get("sections") or {},
        "alerts": payload.get("alerts") or [],
    }


# ---------------------------------------------------------------------------
# scheduler entrypoint
# ---------------------------------------------------------------------------

_pool_busy_logged = False


def _db_pool_busy() -> bool:
    global _pool_busy_logged
    snap = db_pool_snapshot()
    pct = snap.get("checked_out_percent")
    level = (snap.get("pressure") or {}).get("level")
    busy = (
        (isinstance(pct, (int, float)) and pct >= BACKGROUND_DB_BUSY_THRESHOLD_PERCENT)
        or level in ("warning", "critical")
    )
    if busy and not _pool_busy_logged:
        logger.warning("[OPS-HEALTH] Skipping snapshot while DB pool is busy: "
                       "checked_out=%s (%s%%), pressure=%s",
                       snap.get("checked_out"), pct, level)
        _pool_busy_logged = True
    elif not busy:
        _pool_busy_logged = False
    return busy


async def run_cycle(now: Optional[datetime] = None) -> dict:
    """One scheduler tick: heartbeat -> (skip if pool busy) -> compute ->
    evaluate -> deliver -> store -> prune. DB only."""
    now = now or datetime.utcnow()
    try:
        await write_heartbeat(now)
    except Exception:  # noqa: BLE001
        logger.exception("[OPS-HEALTH] heartbeat failed")
    if _db_pool_busy():
        return {"skipped": "db_pool_busy"}
    previous = await load_previous_alerts()
    snapshot = await compute_snapshot(now, previous_alerts=previous)
    delivery = await deliver_alerts(snapshot["alerts"], now)
    snapshot_id = await store_snapshot(snapshot, now)
    try:
        await prune(now)
    except Exception:  # noqa: BLE001
        logger.exception("[OPS-HEALTH] prune failed")
    return {"snapshot_id": snapshot_id, "overall_status": snapshot["overall_status"],
            "alerts": len(snapshot["alerts"]), **delivery}
