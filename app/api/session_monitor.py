"""
Session Integrity Monitor (DB-Only, Unified, Batched)
======================================================

Monitors all active customers to detect session anomalies — customers being
cut off before their purchased time expires, failed provisioning, or time
discrepancies.

**Unified interface** — same endpoints, same anomaly codes, same response
shape regardless of whether routers use DIRECT_API or RADIUS.

**Performance** — uses bulk queries (not per-customer queries).  The total
query count is fixed at ~8 regardless of how many customers you have:
  1  Load routers
  2  Load customers + plans (one JOIN)
  3  Load last payment per customer (window function)
  4  Load last provisioning per customer (window function)
  5  Load RADIUS latest session per username (window function, RADIUS only)
  6  Load RADIUS credentials per username (RADIUS only)
  7  Load RADIUS timeouts per username (RADIUS only)
  8  Count recently-cut-off customers
Total: ~8 queries for the overview, ~5 for single-customer deep-dive.

Anomaly codes (same for every router type):
  CUT_OFF_EARLY          Customer lost paid time
  PAYMENT_NOT_ACTIVATED  Payment recorded but customer is still not active
  PROVISIONING_FAILED    Most recent provisioning attempt failed
  CREDENTIALS_MISSING    Active customer but auth credentials are broken
  TIME_MISMATCH          Configured session time doesn't match plan duration
  SESSION_SHORTCHANGED   Customer got less time than they paid for

Endpoints:
  GET /api/session-monitor                           All routers overview
  GET /api/session-monitor/router/{router_id}        Single router
  GET /api/session-monitor/customer/{customer_id}    Single customer deep-dive
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Set

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from pydantic import BaseModel, Field

from app.db.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Session Monitor"])


# ============================================================================
# Response models
# ============================================================================

class SessionAnomaly(BaseModel):
    code: str
    severity: str
    message: str
    details: Optional[Dict[str, Any]] = None


class PaymentInfo(BaseModel):
    payment_id: Optional[int] = None
    amount: Optional[float] = None
    payment_date: Optional[str] = None
    days_paid_for: Optional[int] = None
    payment_method: Optional[str] = None


class ProvisioningInfo(BaseModel):
    action: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    log_date: Optional[str] = None


class SessionInfo(BaseModel):
    is_online: bool = False
    start_time: Optional[str] = None
    stop_time: Optional[str] = None
    uptime_seconds: int = 0
    uptime_human: str = ""
    disconnect_cause: Optional[str] = None
    bytes_in: int = 0
    bytes_out: int = 0


class CustomerSessionHealth(BaseModel):
    customer_id: int
    customer_name: Optional[str] = None
    phone: Optional[str] = None
    mac_address: Optional[str] = None
    plan_name: Optional[str] = None
    plan_speed: Optional[str] = None
    plan_duration: Optional[str] = None
    status: str
    expiry: Optional[str] = None
    time_remaining_seconds: Optional[int] = None
    time_remaining_human: Optional[str] = None
    router_id: Optional[int] = None
    router_name: Optional[str] = None
    health: str = Field(..., description="HEALTHY, WARNING, or CRITICAL")
    anomaly_count: int = 0
    anomalies: List[SessionAnomaly] = []
    last_payment: Optional[PaymentInfo] = None
    last_provisioning: Optional[ProvisioningInfo] = None
    session: Optional[SessionInfo] = None


class RouterMonitorSummary(BaseModel):
    router_id: int
    router_name: str
    router_ip: str
    total_active_customers: int = 0
    healthy: int = 0
    warnings: int = 0
    critical: int = 0
    customers: List[CustomerSessionHealth] = []


class SessionMonitorOverview(BaseModel):
    timestamp: str
    total_routers: int = 0
    total_active_customers: int = 0
    total_healthy: int = 0
    total_warnings: int = 0
    total_critical: int = 0
    recently_cut_off_early: int = 0
    routers: List[RouterMonitorSummary] = []


# ============================================================================
# Helpers
# ============================================================================

def _s2h(seconds: Optional[int]) -> str:
    if seconds is None or seconds < 0:
        return "N/A"
    if seconds == 0:
        return "0s"
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def _dur_human(value: int, unit: str) -> str:
    labels = {"MINUTES": "minute", "HOURS": "hour", "DAYS": "day"}
    lbl = labels.get(unit.upper(), unit)
    return f"{value} {lbl}{'s' if value != 1 else ''}"


def _plan_secs(dur_val: int, dur_unit: str) -> int:
    mult = {"MINUTES": 60, "HOURS": 3600, "DAYS": 86400}
    return dur_val * mult.get(dur_unit.upper(), 3600)


# ============================================================================
# Bulk data loaders — one query per table, not per customer
# ============================================================================

async def _bulk_load_customers(
    db: AsyncSession, router_ids: List[int], cutoff: datetime
) -> List[Dict]:
    """Load all relevant customers with their plan info in one shot."""
    if not router_ids:
        return []
    placeholders = ", ".join(f":rid_{i}" for i in range(len(router_ids)))
    params: Dict[str, Any] = {f"rid_{i}": rid for i, rid in enumerate(router_ids)}
    params['cutoff'] = cutoff

    r = await db.execute(text(f"""
        SELECT
            c.id, c.name, c.phone, c.mac_address, c.status, c.expiry,
            c.plan_id, c.router_id,
            p.name as plan_name, p.speed as plan_speed,
            p.duration_value as plan_duration_value,
            p.duration_unit as plan_duration_unit
        FROM customers c
        LEFT JOIN plans p ON c.plan_id = p.id
        WHERE c.router_id IN ({placeholders})
          AND c.status IN ('active', 'inactive', 'pending')
          AND (c.expiry IS NULL OR c.expiry > :cutoff)
        ORDER BY c.router_id, c.expiry ASC
    """), params)
    return [dict(row._mapping) for row in r.fetchall()]


async def _bulk_load_last_payments(
    db: AsyncSession, customer_ids: List[int]
) -> Dict[int, PaymentInfo]:
    """Last payment per customer using a window function."""
    if not customer_ids:
        return {}
    placeholders = ", ".join(f":cid_{i}" for i in range(len(customer_ids)))
    params = {f"cid_{i}": cid for i, cid in enumerate(customer_ids)}

    r = await db.execute(text(f"""
        SELECT * FROM (
            SELECT
                customer_id, id, amount, payment_date, days_paid_for, payment_method,
                ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY payment_date DESC) as rn
            FROM customer_payments
            WHERE customer_id IN ({placeholders})
        ) sub WHERE rn = 1
    """), params)

    result: Dict[int, PaymentInfo] = {}
    for row in r.fetchall():
        result[row.customer_id] = PaymentInfo(
            payment_id=row.id,
            amount=float(row.amount) if row.amount else None,
            payment_date=row.payment_date.isoformat() if row.payment_date else None,
            days_paid_for=row.days_paid_for,
            payment_method=str(row.payment_method) if row.payment_method else None,
        )
    return result


async def _bulk_load_last_provisioning(
    db: AsyncSession, customer_ids: List[int]
) -> Dict[int, ProvisioningInfo]:
    """Last provisioning log per customer."""
    if not customer_ids:
        return {}
    placeholders = ", ".join(f":cid_{i}" for i in range(len(customer_ids)))
    params = {f"cid_{i}": cid for i, cid in enumerate(customer_ids)}

    r = await db.execute(text(f"""
        SELECT * FROM (
            SELECT
                customer_id, action, status, error, log_date,
                ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY log_date DESC) as rn
            FROM provisioning_logs
            WHERE customer_id IN ({placeholders})
        ) sub WHERE rn = 1
    """), params)

    result: Dict[int, ProvisioningInfo] = {}
    for row in r.fetchall():
        result[row.customer_id] = ProvisioningInfo(
            action=row.action,
            status=row.status,
            error=row.error,
            log_date=row.log_date.isoformat() if row.log_date else None,
        )
    return result


async def _bulk_load_radius_sessions(
    db: AsyncSession, usernames: List[str]
) -> Dict[str, SessionInfo]:
    """Latest RADIUS accounting record per username."""
    if not usernames:
        return {}
    placeholders = ", ".join(f":u_{i}" for i in range(len(usernames)))
    params = {f"u_{i}": u for i, u in enumerate(usernames)}

    r = await db.execute(text(f"""
        SELECT * FROM (
            SELECT
                username, acctsessionid, acctstarttime, acctstoptime,
                acctsessiontime, acctterminatecause,
                acctinputoctets, acctoutputoctets,
                ROW_NUMBER() OVER (PARTITION BY username ORDER BY acctstarttime DESC) as rn
            FROM radius_accounting
            WHERE username IN ({placeholders})
        ) sub WHERE rn = 1
    """), params)

    result: Dict[str, SessionInfo] = {}
    for row in r.fetchall():
        is_online = row.acctstoptime is None
        st = row.acctsessiontime or 0
        result[row.username] = SessionInfo(
            is_online=is_online,
            start_time=row.acctstarttime.isoformat() if row.acctstarttime else None,
            stop_time=row.acctstoptime.isoformat() if row.acctstoptime else None,
            uptime_seconds=st,
            uptime_human=_s2h(st),
            disconnect_cause=row.acctterminatecause if not is_online else None,
            bytes_in=row.acctinputoctets or 0,
            bytes_out=row.acctoutputoctets or 0,
        )
    return result


async def _bulk_load_radius_credentials(
    db: AsyncSession, usernames: List[str]
) -> Set[str]:
    """Which usernames have valid credentials. Returns the set of OK usernames."""
    if not usernames:
        return set()
    placeholders = ", ".join(f":u_{i}" for i in range(len(usernames)))
    params = {f"u_{i}": u for i, u in enumerate(usernames)}

    r = await db.execute(text(f"""
        SELECT DISTINCT username FROM radius_check
        WHERE username IN ({placeholders})
          AND attribute = 'Cleartext-Password'
          AND (expiry IS NULL OR expiry > NOW())
    """), params)
    return {row.username for row in r.fetchall()}


async def _bulk_load_radius_timeouts(
    db: AsyncSession, usernames: List[str]
) -> Dict[str, int]:
    """Session-Timeout value per username."""
    if not usernames:
        return {}
    placeholders = ", ".join(f":u_{i}" for i in range(len(usernames)))
    params = {f"u_{i}": u for i, u in enumerate(usernames)}

    r = await db.execute(text(f"""
        SELECT username, value FROM radius_reply
        WHERE username IN ({placeholders})
          AND attribute = 'Session-Timeout'
    """), params)

    result: Dict[str, int] = {}
    for row in r.fetchall():
        try:
            result[row.username] = int(row.value)
        except (ValueError, TypeError):
            pass
    return result


async def _bulk_load_radius_expiries(
    db: AsyncSession, usernames: List[str]
) -> Dict[str, datetime]:
    """Expiry from radius_check per username."""
    if not usernames:
        return {}
    placeholders = ", ".join(f":u_{i}" for i in range(len(usernames)))
    params = {f"u_{i}": u for i, u in enumerate(usernames)}

    r = await db.execute(text(f"""
        SELECT * FROM (
            SELECT username, expiry,
                   ROW_NUMBER() OVER (PARTITION BY username ORDER BY id DESC) as rn
            FROM radius_check
            WHERE username IN ({placeholders}) AND expiry IS NOT NULL
        ) sub WHERE rn = 1
    """), params)

    result: Dict[str, datetime] = {}
    for row in r.fetchall():
        if row.expiry:
            result[row.username] = row.expiry
    return result


# ============================================================================
# Anomaly analysis (operates on pre-loaded data, zero extra queries)
# ============================================================================

def _analyze(
    cust: Dict,
    now: datetime,
    payment: Optional[PaymentInfo],
    prov: Optional[ProvisioningInfo],
    session: Optional[SessionInfo],
    creds_ok: bool,
    radius_timeout: Optional[int],
    radius_expiry: Optional[datetime],
    is_radius: bool,
) -> CustomerSessionHealth:
    """Pure analysis — no DB calls, just comparisons."""
    anomalies: List[SessionAnomaly] = []

    mac = cust.get('mac_address') or ''
    expiry = cust.get('expiry')
    time_left = int((expiry - now).total_seconds()) if expiry else None
    is_active = cust.get('status') == 'active'
    has_time = time_left is not None and time_left > 0

    dur_val = cust.get('plan_duration_value')
    dur_unit = cust.get('plan_duration_unit')
    plan_seconds = _plan_secs(dur_val, dur_unit) if dur_val and dur_unit else None
    dur_str = _dur_human(dur_val, dur_unit) if dur_val and dur_unit else None
    radius_username = mac.replace(':', '').replace('-', '').upper() if mac else None

    # ================================================================
    # 1. CUT_OFF_EARLY — customer lost paid time
    # ================================================================

    # Case A: DB says inactive but expiry is still in the future
    if not is_active and has_time and cust.get('status') == 'inactive':
        anomalies.append(SessionAnomaly(
            code="CUT_OFF_EARLY",
            severity="CRITICAL",
            message=f"Customer was deactivated with {_s2h(time_left)} of paid time still remaining.",
            details={
                "time_remaining_seconds": time_left,
                "time_remaining_human": _s2h(time_left),
                "expiry": expiry.isoformat() if expiry else None,
            }
        ))

    # Case B (RADIUS): session ended before expiry while customer is still active
    if is_radius and is_active and has_time and session and not session.is_online:
        if session.stop_time and expiry:
            stop_dt = datetime.fromisoformat(session.stop_time)
            if stop_dt < (expiry - timedelta(minutes=5)):
                lost = int((expiry - stop_dt).total_seconds())
                anomalies.append(SessionAnomaly(
                    code="CUT_OFF_EARLY",
                    severity="CRITICAL",
                    message=f"Session ended {_s2h(lost)} before expiry. Cause: {session.disconnect_cause or 'Unknown'}.",
                    details={
                        "session_ended_at": session.stop_time,
                        "expiry": expiry.isoformat(),
                        "time_lost_seconds": lost,
                        "time_lost_human": _s2h(lost),
                        "disconnect_cause": session.disconnect_cause,
                    }
                ))

    # ================================================================
    # 2. PAYMENT_NOT_ACTIVATED
    # ================================================================
    if payment and cust.get('status') in ('inactive', 'pending') and payment.payment_date:
        pay_dt = datetime.fromisoformat(payment.payment_date)
        ago = int((now - pay_dt).total_seconds())

        payment_not_reflected = expiry is None or pay_dt > expiry

        if ago > 300 and payment_not_reflected:
            anomalies.append(SessionAnomaly(
                code="PAYMENT_NOT_ACTIVATED",
                severity="CRITICAL",
                message=f"Payment of {payment.amount} was recorded {_s2h(ago)} ago but customer is still {cust.get('status', 'unknown').upper()}.",
                details={
                    "payment_id": payment.payment_id,
                    "payment_date": payment.payment_date,
                    "amount": payment.amount,
                    "current_status": cust.get('status'),
                    "seconds_since_payment": ago,
                }
            ))

    # ================================================================
    # 3. PROVISIONING_FAILED
    # ================================================================
    if prov and prov.status and prov.status.upper() == 'FAILED':
        if is_active:
            anomalies.append(SessionAnomaly(
                code="PROVISIONING_FAILED",
                severity="WARNING",
                message=f"Last provisioning logged a failure ({prov.error or 'no details'}), but customer is currently active. May have been retried successfully.",
                details={"action": prov.action, "error": prov.error, "log_date": prov.log_date}
            ))
        else:
            anomalies.append(SessionAnomaly(
                code="PROVISIONING_FAILED",
                severity="CRITICAL",
                message=f"Last provisioning failed: {prov.error or 'No error details recorded.'}",
                details={"action": prov.action, "error": prov.error, "log_date": prov.log_date}
            ))

    # ================================================================
    # 4. CREDENTIALS_MISSING (RADIUS only)
    # ================================================================
    if is_radius and is_active and has_time and radius_username and not creds_ok:
        anomalies.append(SessionAnomaly(
            code="CREDENTIALS_MISSING",
            severity="CRITICAL",
            message="Customer is active but their authentication credentials are missing or expired. They cannot reconnect if disconnected.",
            details={"username": radius_username}
        ))

    # ================================================================
    # 5. TIME_MISMATCH (RADIUS only)
    # ================================================================
    if is_radius and is_active and radius_username and plan_seconds:
        if radius_timeout is not None:
            diff = abs(radius_timeout - plan_seconds)
            tol = max(60, plan_seconds * 0.10)
            if diff > tol:
                anomalies.append(SessionAnomaly(
                    code="TIME_MISMATCH",
                    severity="WARNING",
                    message=f"Configured session timeout ({_s2h(radius_timeout)}) differs from plan duration ({_s2h(plan_seconds)}) by {_s2h(int(diff))}.",
                    details={
                        "configured_timeout_seconds": radius_timeout,
                        "plan_duration_seconds": plan_seconds,
                        "difference_seconds": int(diff),
                    }
                ))

        if radius_expiry and expiry:
            diff_sec = abs((radius_expiry - expiry).total_seconds())
            if diff_sec > 300:
                anomalies.append(SessionAnomaly(
                    code="TIME_MISMATCH",
                    severity="WARNING",
                    message=f"Authentication expiry is {_s2h(int(diff_sec))} out of sync with billing expiry.",
                    details={
                        "auth_expiry": radius_expiry.isoformat(),
                        "billing_expiry": expiry.isoformat(),
                        "difference_seconds": int(diff_sec),
                    }
                ))

    # ================================================================
    # 6. SESSION_SHORTCHANGED (both router types)
    # ================================================================
    if is_active and payment and payment.payment_date and expiry and plan_seconds:
        pay_dt = datetime.fromisoformat(payment.payment_date)
        actual_dur = (expiry - pay_dt).total_seconds()
        if actual_dur > 0 and actual_dur < plan_seconds * 0.85:
            shortfall = plan_seconds - int(actual_dur)
            anomalies.append(SessionAnomaly(
                code="SESSION_SHORTCHANGED",
                severity="WARNING",
                message=f"Customer's session is {_s2h(shortfall)} shorter than the plan duration of {dur_str}.",
                details={
                    "payment_date": payment.payment_date,
                    "actual_expiry": expiry.isoformat(),
                    "plan_duration_seconds": plan_seconds,
                    "actual_duration_seconds": int(actual_dur),
                    "shortfall_seconds": shortfall,
                    "shortfall_human": _s2h(shortfall),
                }
            ))

    # ---- Verdict ----
    crit = sum(1 for a in anomalies if a.severity == "CRITICAL")
    health = "CRITICAL" if crit else ("WARNING" if anomalies else "HEALTHY")

    return CustomerSessionHealth(
        customer_id=cust['id'],
        customer_name=cust.get('name'),
        phone=cust.get('phone'),
        mac_address=mac,
        plan_name=cust.get('plan_name'),
        plan_speed=cust.get('plan_speed'),
        plan_duration=dur_str,
        status=cust.get('status', 'unknown'),
        expiry=expiry.isoformat() if expiry else None,
        time_remaining_seconds=time_left,
        time_remaining_human=_s2h(time_left) if time_left is not None else None,
        router_id=cust.get('router_id'),
        router_name=cust.get('router_name'),
        health=health,
        anomaly_count=len(anomalies),
        anomalies=anomalies,
        last_payment=payment,
        last_provisioning=prov,
        session=session,
    )


# ============================================================================
# Batch analyze — loads all data upfront, then loops in Python
# ============================================================================

async def _batch_analyze(
    db: AsyncSession,
    router_map: Dict[int, Any],
    customers: List[Dict],
    now: datetime,
    include_healthy: bool,
) -> Dict[int, RouterMonitorSummary]:
    if not customers:
        return {
            rid: RouterMonitorSummary(
                router_id=rtr.id, router_name=rtr.name, router_ip=rtr.ip_address,
            )
            for rid, rtr in router_map.items()
        }

    customer_ids = [c['id'] for c in customers]

    payments = await _bulk_load_last_payments(db, customer_ids)
    provs = await _bulk_load_last_provisioning(db, customer_ids)

    radius_usernames: List[str] = []
    for c in customers:
        rtr = router_map.get(c.get('router_id'))
        if rtr and (rtr.auth_method or 'DIRECT_API') == 'RADIUS':
            mac = c.get('mac_address') or ''
            uname = mac.replace(':', '').replace('-', '').upper()
            if uname:
                radius_usernames.append(uname)

    radius_sessions: Dict[str, SessionInfo] = {}
    radius_creds_ok: Set[str] = set()
    radius_timeouts: Dict[str, int] = {}
    radius_expiries: Dict[str, datetime] = {}

    if radius_usernames:
        unique_unames = list(set(radius_usernames))
        radius_sessions = await _bulk_load_radius_sessions(db, unique_unames)
        radius_creds_ok = await _bulk_load_radius_credentials(db, unique_unames)
        radius_timeouts = await _bulk_load_radius_timeouts(db, unique_unames)
        radius_expiries = await _bulk_load_radius_expiries(db, unique_unames)

    summaries: Dict[int, RouterMonitorSummary] = {}
    for rid, rtr in router_map.items():
        summaries[rid] = RouterMonitorSummary(
            router_id=rtr.id, router_name=rtr.name, router_ip=rtr.ip_address,
        )

    for cust in customers:
        rid = cust.get('router_id')
        rtr = router_map.get(rid)
        if not rtr or rid not in summaries:
            continue

        is_radius = (rtr.auth_method or 'DIRECT_API') == 'RADIUS'
        mac = cust.get('mac_address') or ''
        uname = mac.replace(':', '').replace('-', '').upper() if mac else ''
        cust['router_name'] = rtr.name

        report = _analyze(
            cust=cust,
            now=now,
            payment=payments.get(cust['id']),
            prov=provs.get(cust['id']),
            session=radius_sessions.get(uname) if is_radius else None,
            creds_ok=uname in radius_creds_ok if is_radius else True,
            radius_timeout=radius_timeouts.get(uname) if is_radius else None,
            radius_expiry=radius_expiries.get(uname) if is_radius else None,
            is_radius=is_radius,
        )

        summary = summaries[rid]
        if cust.get('status') == 'active':
            summary.total_active_customers += 1

        if report.health == "CRITICAL":
            summary.critical += 1
        elif report.health == "WARNING":
            summary.warnings += 1
        else:
            summary.healthy += 1

        if include_healthy or report.health != "HEALTHY":
            summary.customers.append(report)

    return summaries


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/session-monitor", response_model=SessionMonitorOverview)
async def session_monitor_overview(
    user_id: int = Query(1, description="User / reseller ID"),
    include_healthy: bool = Query(True, description="Include healthy customers"),
    db: AsyncSession = Depends(get_db),
):
    """
    Session integrity overview across all routers.

    Uses ~8 total DB queries regardless of customer count.

    Key metric: **recently_cut_off_early** — customers currently INACTIVE
    but with paid time remaining.  If > 0, something went wrong.
    """
    now = datetime.utcnow()

    routers_result = await db.execute(text("""
        SELECT id, name, ip_address, auth_method
        FROM routers WHERE user_id = :uid ORDER BY name
    """), {'uid': user_id})
    all_routers = routers_result.fetchall()
    router_map = {r.id: r for r in all_routers}

    router_ids = [r.id for r in all_routers]
    customers = await _bulk_load_customers(db, router_ids, now - timedelta(hours=24))

    summaries = await _batch_analyze(db, router_map, customers, now, include_healthy)

    cut_off = await db.execute(text("""
        SELECT COUNT(*) as cnt FROM customers
        WHERE user_id = :uid AND status = 'inactive' AND expiry > NOW()
    """), {'uid': user_id})
    early_count = cut_off.fetchone().cnt

    total_h = total_w = total_c = total_active = 0
    ordered_summaries: List[RouterMonitorSummary] = []
    for rtr in all_routers:
        s = summaries.get(rtr.id)
        if s:
            total_h += s.healthy
            total_w += s.warnings
            total_c += s.critical
            total_active += s.total_active_customers
            ordered_summaries.append(s)

    return SessionMonitorOverview(
        timestamp=now.isoformat(),
        total_routers=len(all_routers),
        total_active_customers=total_active,
        total_healthy=total_h,
        total_warnings=total_w,
        total_critical=total_c,
        recently_cut_off_early=early_count,
        routers=ordered_summaries,
    )


@router.get("/session-monitor/router/{router_id}", response_model=RouterMonitorSummary)
async def session_monitor_router(
    router_id: int,
    include_healthy: bool = Query(True),
    db: AsyncSession = Depends(get_db),
):
    """Session integrity for a specific router. ~7 queries total."""
    now = datetime.utcnow()

    r = await db.execute(text(
        "SELECT id, name, ip_address, auth_method FROM routers WHERE id = :rid"
    ), {'rid': router_id})
    rtr = r.fetchone()
    if not rtr:
        raise HTTPException(status_code=404, detail="Router not found")

    customers = await _bulk_load_customers(db, [rtr.id], now - timedelta(hours=24))
    summaries = await _batch_analyze(db, {rtr.id: rtr}, customers, now, include_healthy)
    return summaries.get(rtr.id, RouterMonitorSummary(
        router_id=rtr.id, router_name=rtr.name, router_ip=rtr.ip_address,
    ))


@router.get("/session-monitor/customer/{customer_id}", response_model=CustomerSessionHealth)
async def session_monitor_customer(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Deep-dive for a single customer.  ~5 queries total:
    customer+plan, payment, provisioning, and RADIUS data if applicable.
    """
    now = datetime.utcnow()

    r = await db.execute(text("""
        SELECT
            c.id, c.name, c.phone, c.mac_address, c.status, c.expiry,
            c.plan_id, c.router_id,
            p.name as plan_name, p.speed as plan_speed,
            p.duration_value as plan_duration_value,
            p.duration_unit as plan_duration_unit,
            r.name as router_name, r.ip_address as router_ip, r.auth_method
        FROM customers c
        LEFT JOIN plans p ON c.plan_id = p.id
        LEFT JOIN routers r ON c.router_id = r.id
        WHERE c.id = :cid
    """), {'cid': customer_id})
    row = r.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Customer not found")

    cust = dict(row._mapping)
    is_radius = (cust.get('auth_method') or 'DIRECT_API') == 'RADIUS'
    mac = cust.get('mac_address') or ''
    uname = mac.replace(':', '').replace('-', '').upper() if mac else ''

    payments = await _bulk_load_last_payments(db, [cust['id']])
    provs = await _bulk_load_last_provisioning(db, [cust['id']])

    session = None
    creds_ok = True
    r_timeout = None
    r_expiry = None

    if is_radius and uname:
        sessions = await _bulk_load_radius_sessions(db, [uname])
        session = sessions.get(uname)
        creds_set = await _bulk_load_radius_credentials(db, [uname])
        creds_ok = uname in creds_set
        timeouts = await _bulk_load_radius_timeouts(db, [uname])
        r_timeout = timeouts.get(uname)
        expiries = await _bulk_load_radius_expiries(db, [uname])
        r_expiry = expiries.get(uname)

    return _analyze(
        cust=cust,
        now=now,
        payment=payments.get(cust['id']),
        prov=provs.get(cust['id']),
        session=session,
        creds_ok=creds_ok,
        radius_timeout=r_timeout,
        radius_expiry=r_expiry,
        is_radius=is_radius,
    )
