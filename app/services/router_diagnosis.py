"""What is ailing a problem router: a small live probe for the routers the
problem-routers card lists as ``attention``.

Every few minutes this job takes those routers (at most ``MAX_ROUTERS``) and,
for each one, opens a handful of plain TCP connections to its API port and
tries ONE RouterOS API login. Together with the router's own latest health
reading (``router_health``: push agent / SNMP) that tells apart the problems we
kept confusing on 2026-09-25:

* overloaded  - the line is clean (TCP connects every time) but the API login
                times out, or the router itself reports CPU >= 90%. A different
                tunnel does not help; a reboot or better hardware does.
* lossy_line  - TCP connects only some of the time. Tunnel handshakes stay
                fresh, so the tunnel looks "up"; SSTP (TCP) rides it out better
                than a UDP tunnel.
* udp_blocked - nothing reaches the router over its (UDP) tunnel, yet its own
                HTTPS push still arrives: the site blocks or mangles UDP.
* offline     - nothing gets through and no push either: power or internet.
* healthy_now - it answered; waiting payments will be retried.

Database Session Discipline: the inputs are read in ONE short session which is
closed before any socket is opened; nothing is written to the database (the
result is kept in memory and attached to the problem-routers section when the
ops-health snapshot builds it). The probes run on a dedicated 4-thread pool so
they never occupy the event loop's default executor, the API login uses the
``background`` circuit-breaker lane (it stands down while paid deliveries are
struggling on the same router), and the whole tick is skipped while the DB pool
is under pressure.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Callable, Optional

from sqlalchemy import select

from app.db import database
from app.db.database import db_pool_snapshot
from app.db.models import Router, RouterHealth

logger = logging.getLogger(__name__)

INTERVAL = timedelta(minutes=5)
MAX_ROUTERS = 15
CONCURRENCY = 4
TCP_ATTEMPTS = 5
TCP_TIMEOUT_SECONDS = 3.0
TCP_GAP_SECONDS = 1.0
LOGIN_CONNECT_TIMEOUT = 5
LOGIN_TIMEOUT = 10
CPU_OVERLOADED = 90
CPU_FRESH = timedelta(minutes=10)
PUSH_FRESH = timedelta(minutes=5)
# Do not probe off a problem-routers section older than this (snapshot job dead).
SECTION_MAX_AGE = timedelta(minutes=15)
# A diagnosis older than this is dropped rather than shown as current.
RESULT_MAX_AGE = timedelta(minutes=20)

# Management tunnels that ride on UDP (WireGuard; L2TP/IPsec is IKE/NAT-T on
# UDP 500/4500). A router whose push arrives while one of these is dead is
# behind a site that blocks or mangles UDP.
UDP_TUNNELS = frozenset({"wireguard", "l2tp", "wg2_insurance", "aws_insurance"})

AILMENTS = ("overloaded", "lossy_line", "udp_blocked", "tunnel_down", "offline",
            "healthy_now", "login_rejected", "inconclusive")
LOGIN_RESULTS = ("ok", "timeout", "rejected", "error", "skipped")

ACTION_REBOOT = "Reboot the router; if it recurs, upgrade hardware or RouterOS"
ACTION_SSTP = "Move management to SSTP"
ACTION_UPLINK = "Site line losing packets — reseller should check the uplink"
ACTION_OFFLINE = "Site power or internet is down — contact reseller"
ACTION_HEALTHY = "Reachable again — waiting payments will retry"
ACTION_TUNNEL_DOWN = "Router is online but its management tunnel is down — check the tunnel"
ACTION_LOGIN_REJECTED = "API login rejected — check the router's API username/password"
ACTION_INCONCLUSIVE = "Probe inconclusive — will retry next round"

# router_id -> {ailment, evidence, action, sstp_candidate, tcp_ok, login, probed_at}
_RESULTS: dict[int, dict] = {}
_EXECUTOR: Optional[ThreadPoolExecutor] = None
_pool_busy_logged = False


def reset() -> None:
    _RESULTS.clear()


# ---------------------------------------------------------------------------
# pure classifier
# ---------------------------------------------------------------------------

def _ago(delta: timedelta) -> str:
    minutes = max(0, int(delta.total_seconds() // 60))
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    return f"{hours // 24} days ago"


_LOGIN_TEXT = {
    "ok": "API login ok",
    "timeout": "API login timed out",
    "rejected": "API login rejected",
    "error": "API login dropped",
    "skipped": "API login skipped (circuit breaker)",
}


def build_evidence(tcp_ok: int, tcp_attempts: int, login: str,
                   health: Optional[dict], now: datetime) -> str:
    """Short human evidence line, e.g. "TCP 5/5, API login timed out, CPU 100% (push 3 min ago)"."""
    parts = [f"TCP {tcp_ok}/{tcp_attempts}"]
    if tcp_ok > 0 and login in _LOGIN_TEXT:
        parts.append(_LOGIN_TEXT[login])
    if health and health.get("sampled_at"):
        source = health.get("source") or "push"
        age = now - health["sampled_at"]
        cpu = health.get("cpu_load")
        if age <= CPU_FRESH and cpu is not None:
            parts.append(f"CPU {cpu}% ({source} {_ago(age)})")
        elif age <= CPU_FRESH:
            parts.append(f"{source} {_ago(age)}")
        else:
            parts.append(f"last {source} {_ago(age)}")
    else:
        parts.append("no push")
    return ", ".join(parts)


def classify(tcp_ok: int, tcp_attempts: int, login: str, tunnel: Optional[str],
             health: Optional[dict], now: datetime) -> dict:
    """Pure: probe results + latest router_health row -> ailment, action, SSTP hint.

    ``health`` is ``{"source", "sampled_at", "cpu_load"}`` or None. Order matters:
    a router reporting CPU >= 90% is overloaded whatever the probe saw; a line that
    drops some TCP connects is lossy even if the one login got through.
    """
    age = (now - health["sampled_at"]) if health and health.get("sampled_at") else None
    cpu = health.get("cpu_load") if health else None
    cpu_hot = age is not None and age <= CPU_FRESH and cpu is not None and cpu >= CPU_OVERLOADED
    push_recent = (age is not None and age <= PUSH_FRESH
                   and (health.get("source") or "push") == "push")
    is_sstp = tunnel == "sstp"

    if cpu_hot or (tcp_ok >= 4 and login == "timeout"):
        ailment, action, sstp = "overloaded", ACTION_REBOOT, False
    elif 1 <= tcp_ok <= 3:
        ailment = "lossy_line"
        action = ACTION_UPLINK if is_sstp else ACTION_SSTP
        sstp = not is_sstp
    elif login == "ok":
        ailment, action, sstp = "healthy_now", ACTION_HEALTHY, False
    elif tcp_ok == 0 and push_recent and tunnel in UDP_TUNNELS:
        ailment, action, sstp = "udp_blocked", ACTION_SSTP, True
    elif tcp_ok == 0 and push_recent:
        ailment, action, sstp = "tunnel_down", ACTION_TUNNEL_DOWN, False
    elif tcp_ok == 0:
        ailment, action, sstp = "offline", ACTION_OFFLINE, False
    elif login == "rejected":
        ailment, action, sstp = "login_rejected", ACTION_LOGIN_REJECTED, False
    else:  # line clean but the login was skipped or dropped: no verdict this round
        ailment, action, sstp = "inconclusive", ACTION_INCONCLUSIVE, False
    return {
        "ailment": ailment,
        "evidence": build_evidence(tcp_ok, tcp_attempts, login, health, now),
        "action": action,
        "sstp_candidate": sstp,
    }


# ---------------------------------------------------------------------------
# probes (blocking; run on the dedicated thread pool)
# ---------------------------------------------------------------------------

def tcp_probe(host: str, port: int, attempts: int = TCP_ATTEMPTS,
              timeout: float = TCP_TIMEOUT_SECONDS, gap: float = TCP_GAP_SECONDS,
              connect: Callable = socket.create_connection,
              sleep: Callable[[float], None] = time.sleep) -> int:
    """Plain TCP connects to the API port (no login, no circuit breaker)."""
    ok = 0
    for i in range(attempts):
        if i:
            sleep(gap)
        try:
            conn = connect((host, port), timeout=timeout)
        except OSError:
            continue
        ok += 1
        try:
            conn.close()
        except OSError:
            pass
    return ok


def login_probe(host: str, username: str, password: str, port: int,
                api_factory: Optional[Callable] = None,
                clock: Callable[[], float] = time.monotonic) -> str:
    """ONE RouterOS API login on the background lane -> ok|timeout|rejected|error|skipped."""
    if api_factory is None:
        from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI

        def api_factory():
            return MikroTikAPI(host, username, password, port, timeout=LOGIN_TIMEOUT,
                               connect_timeout=LOGIN_CONNECT_TIMEOUT, lane=LANE_BACKGROUND)
    api = api_factory()
    started = clock()
    try:
        if api.connect():
            return "ok"
        elapsed = clock() - started
        err = (getattr(api, "last_connect_error", None) or "").lower()
        if "circuit breaker" in err:
            return "skipped"
        if "timed out" in err or elapsed >= LOGIN_TIMEOUT * 0.8:
            return "timeout"
        # RouterOS answered with a !trap (e.g. "invalid user name or password").
        if "api login rejected" in err and "check the router's api username/password" not in err:
            return "rejected"
        return "error"
    except Exception:  # noqa: BLE001 - a probe must never kill the tick
        return "error"
    finally:
        try:
            api.disconnect()
        except Exception:  # noqa: BLE001
            pass


def probe_router(target: dict) -> dict:
    tcp_ok = tcp_probe(target["ip"], target["port"])
    login = "skipped"
    if tcp_ok >= 1:
        login = login_probe(target["ip"], target["username"], target["password"], target["port"])
    return {"tcp_ok": tcp_ok, "login": login}


def _executor() -> ThreadPoolExecutor:
    global _EXECUTOR
    if _EXECUTOR is None:
        _EXECUTOR = ThreadPoolExecutor(max_workers=CONCURRENCY, thread_name_prefix="router-diagnosis")
    return _EXECUTOR


# ---------------------------------------------------------------------------
# job
# ---------------------------------------------------------------------------

def _db_pool_busy() -> bool:
    global _pool_busy_logged
    from app.services.mikrotik_background import BACKGROUND_DB_BUSY_THRESHOLD_PERCENT
    try:
        snap = db_pool_snapshot()
    except Exception as exc:  # noqa: BLE001 - optional job: skip if we cannot tell
        logger.warning("[ROUTER-DIAGNOSIS] could not read DB pool pressure: %s", exc)
        return True
    pct = snap.get("checked_out_percent")
    level = (snap.get("pressure") or {}).get("level")
    busy = ((isinstance(pct, (int, float)) and pct >= BACKGROUND_DB_BUSY_THRESHOLD_PERCENT)
            or level in ("warning", "critical"))
    if busy and not _pool_busy_logged:
        logger.warning("[ROUTER-DIAGNOSIS] skipping while DB pool is busy: checked_out=%s (%s%%), "
                       "pressure=%s", snap.get("checked_out"), pct, level)
    _pool_busy_logged = busy
    return busy


def attention_router_ids(now: datetime) -> list[int]:
    """Routers in ``attention`` on the latest in-process problem-routers section."""
    from app.services import ops_health_problem_routers as pr

    value, at = pr.latest_section()
    if value is None or at is None or now - at > SECTION_MAX_AGE:
        return []
    ids = [r["router_id"] for r in value.get("routers") or [] if r.get("state") == "attention"]
    return ids[:MAX_ROUTERS]


async def load_targets(router_ids: list[int]) -> list[dict]:
    """ONE short session: router address/creds/tunnel + latest health row."""
    from app.services.ops_health import tunnel_type_for_router

    if not router_ids:
        return []
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, Router.ip_address, Router.port, Router.username, Router.password,
                   Router.management_tunnel, RouterHealth.source, RouterHealth.sampled_at,
                   RouterHealth.cpu_load)
            .outerjoin(RouterHealth, RouterHealth.router_id == Router.id)
            .where(Router.id.in_(router_ids))
        )).all()
        await db.commit()
    order = {rid: i for i, rid in enumerate(router_ids)}
    targets = [
        {"id": rid, "ip": ip, "port": port or 8728, "username": user, "password": pw,
         "tunnel": tunnel_type_for_router(ip, mt),
         "health": ({"source": src, "sampled_at": sampled, "cpu_load": cpu} if sampled else None)}
        for rid, ip, port, user, pw, mt, src, sampled, cpu in rows
        if ip
    ]
    targets.sort(key=lambda t: order.get(t["id"], 0))
    return targets


def _prune(now: datetime) -> None:
    for rid in [rid for rid, d in _RESULTS.items() if now - d["_probed_at"] > RESULT_MAX_AGE]:
        _RESULTS.pop(rid, None)


def _public(d: dict) -> dict:
    return {k: v for k, v in d.items() if not k.startswith("_")}


def diagnosis_for(router_id: int, now: Optional[datetime] = None) -> Optional[dict]:
    d = _RESULTS.get(router_id)
    if d is None:
        return None
    if now is not None and now - d["_probed_at"] > RESULT_MAX_AGE:
        return None
    return _public(d)


def attach_diagnoses(rows: list[dict], now: Optional[datetime] = None) -> list[dict]:
    """Copies of the problem-router rows with ``diagnosis`` (dict or None). Pure memory."""
    return [{**row, "diagnosis": diagnosis_for(row.get("router_id"), now)} for row in rows]


async def run_diagnosis_cycle(now: Optional[datetime] = None,
                              probe: Callable[[dict], dict] = probe_router) -> dict:
    now = now or datetime.utcnow()
    _prune(now)
    if _db_pool_busy():
        return {"skipped": "db_pool_busy"}
    ids = attention_router_ids(now)
    if not ids:
        return {"probed": 0}
    targets = await load_targets(ids)  # session is closed before any probe starts

    loop = asyncio.get_running_loop()
    started = time.monotonic()
    results = await asyncio.gather(
        *(loop.run_in_executor(_executor(), probe, t) for t in targets),
        return_exceptions=True,
    )
    elapsed = time.monotonic() - started
    probed_at = now + timedelta(seconds=elapsed)
    counts: dict[str, int] = {}
    for target, result in zip(targets, results):
        if isinstance(result, BaseException):
            logger.warning("[ROUTER-DIAGNOSIS] probe of router %s failed: %s", target["id"], result)
            continue
        diag = classify(result["tcp_ok"], TCP_ATTEMPTS, result["login"], target["tunnel"],
                        target["health"], now)
        _RESULTS[target["id"]] = {
            **diag, "tcp_ok": result["tcp_ok"], "login": result["login"],
            "probed_at": probed_at.replace(microsecond=0).isoformat() + "Z", "_probed_at": probed_at,
        }
        counts[diag["ailment"]] = counts.get(diag["ailment"], 0) + 1
    summary = {"probed": len(targets), "seconds": round(elapsed, 1), "ailments": counts}
    logger.info("[ROUTER-DIAGNOSIS] %s", summary)
    return summary
