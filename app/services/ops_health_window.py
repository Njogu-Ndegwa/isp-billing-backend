"""Look-back report for the operations health panel.

Answers "was there a problem between T1 and T2, and on which router?" by
computing provisioning, expiry-removal and payment figures live for an
arbitrary time slice, optionally filtered to one router. Nothing here uses
the stored snapshots or the 7-day baseline, so old incident days cannot
pollute the answer.

Session discipline (AGENTS.md): one short read-only session per call, bounded
row fetches, no network I/O.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import func, select

from app.db import database
from app.db.models import (
    Customer,
    CustomerStatus,
    MpesaTransaction,
    MpesaTransactionStatus,
    ProvisioningAttempt,
    ProvisioningLog,
    ProvisioningState,
    Router,
    User,
)
from app.services.ops_health import (
    DEACTIVATION_ACTIONS,
    TUNNEL_TYPES,
    _iso,
    _seconds,
    is_owner_cut_off,
    is_router_quarantined,
    percentile,
    tunnel_type_for_ip,
)

MAX_WINDOW = timedelta(days=14)
ROW_LIMIT = 20000
TOP_ROUTERS = 15


def clamp_window(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    """Order the bounds and cap the slice at MAX_WINDOW (measured from ``end``)."""
    if end < start:
        start, end = end, start
    if end - start > MAX_WINDOW:
        start = end - MAX_WINDOW
    return start, end


def _stats(samples: list[float]) -> dict:
    return {
        "p50": percentile(samples, 50),
        "p95": percentile(samples, 95),
        "max": round(max(samples), 3) if samples else None,
        "samples": len(samples),
    }


def summarize_attempts(rows: list[tuple], tunnel_of: dict[int, str],
                       names: dict[int, str]) -> dict:
    """Pure aggregation of (router_id, state, created, attempted, updated, tries, error).

    Counts are by the attempt's CURRENT state for attempts created in the
    window; latencies use attempts confirmed (router_updated) in the window.
    """
    counts: dict[str, int] = {s.value: 0 for s in ProvisioningState}
    e2e: list[float] = []
    call: list[float] = []
    tries: list[float] = []
    per_tunnel: dict[str, dict] = defaultdict(lambda: {"attempts": 0, "delivered": 0,
                                                       "not_delivered": 0, "e2e": [], "call": []})
    per_router: dict[int, dict] = defaultdict(lambda: {"attempts": 0, "delivered": 0,
                                                       "not_delivered": 0, "e2e": [], "call": [],
                                                       "last_error": None})
    for router_id, state, created, attempted, updated, attempt_count, error in rows:
        key = state.value if hasattr(state, "value") else str(state)
        counts[key] = counts.get(key, 0) + 1
        tunnel = tunnel_of.get(router_id, "other")
        t = per_tunnel[tunnel]
        r = per_router[router_id] if router_id is not None else None
        t["attempts"] += 1
        if r is not None:
            r["attempts"] += 1
        if key == "router_updated":
            t["delivered"] += 1
            if r is not None:
                r["delivered"] += 1
            v = _seconds(updated, created)
            if v is not None and v >= 0:
                e2e.append(v)
                t["e2e"].append(v)
                if r is not None:
                    r["e2e"].append(v)
            v = _seconds(updated, attempted)
            if v is not None and v >= 0:
                call.append(v)
                t["call"].append(v)
                if r is not None:
                    r["call"].append(v)
            if attempt_count:
                tries.append(float(attempt_count))
        elif key in ("retry_pending", "failed"):
            t["not_delivered"] += 1
            if r is not None:
                r["not_delivered"] += 1
                if error:
                    r["last_error"] = str(error)[:120]

    settled = counts.get("router_updated", 0) + counts.get("retry_pending", 0) + counts.get("failed", 0)
    by_tunnel = {
        tunnel: {
            "attempts": t["attempts"], "delivered": t["delivered"], "not_delivered": t["not_delivered"],
            "end_to_end": _stats(t["e2e"]), "router_call": _stats(t["call"]),
        }
        for tunnel, t in per_tunnel.items()
    }
    by_tunnel = {k: by_tunnel[k] for k in TUNNEL_TYPES if k in by_tunnel}

    routers = []
    for router_id, r in per_router.items():
        routers.append({
            "router_id": router_id,
            "router_name": names.get(router_id),
            "tunnel": tunnel_of.get(router_id, "other"),
            "attempts": r["attempts"],
            "delivered": r["delivered"],
            "not_delivered": r["not_delivered"],
            "end_to_end_p95": percentile(r["e2e"], 95),
            "router_call_p95": percentile(r["call"], 95),
            "last_error": r["last_error"],
        })
    # Worst first: undelivered payments, then slowest router call.
    routers.sort(key=lambda x: (-x["not_delivered"], -(x["router_call_p95"] or 0), x["router_id"]))

    return {
        "counts": counts,
        "success_ratio": round(counts.get("router_updated", 0) / settled, 3) if settled else None,
        "end_to_end": _stats(e2e),
        "router_call": _stats(call),
        "retries_per_delivery": {"p50": percentile(tries, 50), "max": max(tries) if tries else None},
        "by_tunnel": by_tunnel,
        "routers": routers[:TOP_ROUTERS],
        "routers_total": len(routers),
    }


def classify_unenforced(router_state, now: datetime) -> str:
    """Why an expired customer is still ACTIVE, from what we know about the router."""
    if router_state is None:
        return "no_router"
    if is_owner_cut_off(router_state.get("owner_status")):
        return "owner_suspended"
    if is_router_quarantined(router_state.get("last_status"), router_state.get("last_online_at"),
                             router_state.get("created_at"), now):
        return "router_offline_3d_plus"
    if router_state.get("last_status") is False:
        return "router_offline"
    checked = router_state.get("last_checked_at")
    if checked is None or (now - checked) > timedelta(hours=6):
        return "router_status_stale"
    if router_state.get("router_agent_enabled"):
        return "agent_managed_pending"
    return "router_online_not_removed"


REASON_LABELS = {
    "owner_suspended": "reseller suspended (router cut off at platform level)",
    "router_offline_3d_plus": "router offline 3+ days (quarantined)",
    "router_offline": "router offline (recent)",
    "router_status_stale": "router marked online but not reached for 6h+",
    "agent_managed_pending": "router agent has not executed the removal",
    "router_online_not_removed": "router online, cleanup has not removed it",
    "no_router": "customer has no router",
}


def summarize_enforcement(rows, router_state, tunnel_of, names, now: datetime) -> dict:
    """rows: (customer_id, router_id, expiry, status, removed_at_or_None)."""
    expired = removed = still_active = 0
    per_router: dict = {}
    for _cid, rid, expiry, status, removed_at in rows:
        expired += 1
        status_value = status.value if hasattr(status, "value") else str(status)
        enforced = removed_at is not None or status_value != CustomerStatus.ACTIVE.value
        if enforced:
            removed += 1
            continue
        still_active += 1
        entry = per_router.setdefault(rid, {"count": 0, "oldest_expiry": expiry})
        entry["count"] += 1
        if expiry is not None and (entry["oldest_expiry"] is None or expiry < entry["oldest_expiry"]):
            entry["oldest_expiry"] = expiry
    routers = []
    for rid, e in per_router.items():
        reason = classify_unenforced(router_state.get(rid), now)
        state = router_state.get(rid) or {}
        oldest = e["oldest_expiry"]
        owner = state.get("owner_status")
        routers.append({
            "router_id": rid,
            "router_name": names.get(rid),
            "tunnel": tunnel_of.get(rid, "other"),
            "still_active": e["count"],
            "oldest_expired_minutes": round(_seconds(now, oldest) / 60, 1) if oldest else None,
            "reason": reason,
            "reason_label": REASON_LABELS.get(reason, reason),
            "router_last_status": state.get("last_status"),
            "router_last_online_at": _iso(state.get("last_online_at")),
            "owner_status": owner.value if hasattr(owner, "value") else owner,
        })
    routers.sort(key=lambda x: (-x["still_active"], x["router_id"]))
    by_reason: dict = defaultdict(int)
    for r in routers:
        by_reason[r["reason"]] += r["still_active"]
    return {
        "expired": expired,
        "removed": removed,
        "still_active": still_active,
        "pct_removed": round(100.0 * removed / expired, 1) if expired else None,
        "by_reason": dict(by_reason),
        "routers": routers[:TOP_ROUTERS],
        "routers_total": len(routers),
    }


async def build_window_report(start: datetime, end: datetime,
                              router_id: Optional[int] = None) -> dict[str, Any]:
    start, end = clamp_window(start, end)
    async with database.async_session() as db:
        router_rows = (await db.execute(
            select(Router.id, Router.name, Router.ip_address, Router.last_status,
                   Router.last_online_at, Router.last_checked_at, Router.created_at,
                   Router.router_agent_enabled, User.subscription_status)
            .outerjoin(User, User.id == Router.user_id)
        )).all()
        names = {r[0]: r[1] for r in router_rows}
        tunnel_of = {r[0]: tunnel_type_for_ip(r[2]) for r in router_rows}
        router_state = {
            r[0]: {"last_status": r[3], "last_online_at": r[4], "last_checked_at": r[5],
                   "created_at": r[6], "router_agent_enabled": bool(r[7]), "owner_status": r[8]}
            for r in router_rows
        }

        attempt_q = (
            select(ProvisioningAttempt.router_id, ProvisioningAttempt.provisioning_state,
                   ProvisioningAttempt.created_at, ProvisioningAttempt.last_attempt_at,
                   ProvisioningAttempt.router_updated_at, ProvisioningAttempt.attempt_count,
                   ProvisioningAttempt.last_error)
            .where(ProvisioningAttempt.created_at >= start, ProvisioningAttempt.created_at < end)
            .order_by(ProvisioningAttempt.created_at.desc())
            .limit(ROW_LIMIT)
        )
        if router_id is not None:
            attempt_q = attempt_q.where(ProvisioningAttempt.router_id == router_id)
        attempt_rows = (await db.execute(attempt_q)).all()

        removal_q = (
            select(ProvisioningLog.log_date, Customer.expiry, Customer.router_id)
            .join(Customer, Customer.id == ProvisioningLog.customer_id)
            .where(ProvisioningLog.action.in_(DEACTIVATION_ACTIONS),
                   ProvisioningLog.status == "success",
                   ProvisioningLog.log_date >= start, ProvisioningLog.log_date < end)
            .order_by(ProvisioningLog.log_date.desc())
            .limit(ROW_LIMIT)
        )
        if router_id is not None:
            removal_q = removal_q.where(Customer.router_id == router_id)
        removal_rows = (await db.execute(removal_q)).all()

        # Enforcement: customers whose (current) expiry fell inside the slice.
        # Renewed customers carry a later expiry and are therefore not counted;
        # they are not a problem. "Removed" = a successful deactivation log at
        # or after the expiry, or the row is no longer ACTIVE.
        removed_sub = (
            select(func.min(ProvisioningLog.log_date))
            .where(ProvisioningLog.customer_id == Customer.id,
                   ProvisioningLog.action.in_(DEACTIVATION_ACTIONS),
                   ProvisioningLog.status == "success",
                   ProvisioningLog.log_date >= Customer.expiry)
            .correlate(Customer)
            .scalar_subquery()
        )
        exp_q = (
            select(Customer.id, Customer.router_id, Customer.expiry, Customer.status, removed_sub)
            .where(Customer.expiry >= start, Customer.expiry < end,
                   (Customer.mac_address.isnot(None)) | (Customer.pppoe_username.isnot(None)))
            .order_by(Customer.expiry.asc())
            .limit(ROW_LIMIT)
        )
        if router_id is not None:
            exp_q = exp_q.where(Customer.router_id == router_id)
        expiry_rows = (await db.execute(exp_q)).all()

        payments: Optional[dict] = None
        if router_id is None:
            status_rows = (await db.execute(
                select(MpesaTransaction.status, func.count())
                .where(MpesaTransaction.created_at >= start, MpesaTransaction.created_at < end)
                .group_by(MpesaTransaction.status)
            )).all()
            pay_rows = (await db.execute(
                select(MpesaTransaction.created_at, MpesaTransaction.updated_at)
                .where(MpesaTransaction.created_at >= start, MpesaTransaction.created_at < end,
                       MpesaTransaction.status == MpesaTransactionStatus.completed)
                .order_by(MpesaTransaction.created_at.desc())
                .limit(ROW_LIMIT)
            )).all()
            by_status: dict[str, int] = defaultdict(int)
            for status, n in status_rows:
                by_status[status.value if hasattr(status, "value") else str(status)] += int(n)
            payments = {
                "counts": {
                    "created": sum(by_status.values()),
                    "completed": by_status.get("completed", 0),
                    "failed": by_status.get("failed", 0) + by_status.get("expired", 0),
                    "pending": by_status.get("pending", 0),
                },
                "callback_latency": _stats(
                    [v for c, u in pay_rows if (v := _seconds(u, c)) is not None and v >= 0]
                ),
            }
        await db.commit()

    removal_samples: list[float] = []
    removal_by_tunnel: dict[str, list[float]] = defaultdict(list)
    for log_date, expiry, rid in removal_rows:
        v = _seconds(log_date, expiry)
        if v is not None and v >= 0:
            removal_samples.append(v)
            removal_by_tunnel[tunnel_of.get(rid, "other")].append(v)

    return {
        "window": {"start": _iso(start), "end": _iso(end),
                   "hours": round((end - start).total_seconds() / 3600, 2)},
        "router": (
            {"router_id": router_id, "router_name": names.get(router_id),
             "tunnel": tunnel_of.get(router_id, "other")}
            if router_id is not None else None
        ),
        "provisioning": summarize_attempts(attempt_rows, tunnel_of, names),
        "expiry": {
            "enforcement": summarize_enforcement(expiry_rows, router_state, tunnel_of, names, datetime.utcnow()),
            "removals": len(removal_samples),
            "removal_latency": _stats(removal_samples),
            "by_tunnel": {
                t: _stats(removal_by_tunnel[t]) for t in TUNNEL_TYPES if t in removal_by_tunnel
            },
        },
        "payments": payments,
        "truncated": max(len(attempt_rows), len(removal_rows), len(expiry_rows)) >= ROW_LIMIT,
    }
