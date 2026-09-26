"""What is ailing a problem router: a small live probe for the routers the
problem-routers card lists as ``attention``.

Every few minutes this job takes those routers (at most ``MAX_ROUTERS``) and,
for each one, opens a handful of plain TCP connections to its API port (timing
each one) and, when that is cheap enough for the router, tries ONE RouterOS API
login during which it reads a few small tables. Together with data we already
hold (``router_health`` from the push agent / SNMP, the check-in pilot's
last-seen time, the command agent's last-seen time, and payments) it labels the
router with what is wrong. Labels, as confirmed in production on 2026-09-25/26:

* overloaded        - the router itself is the bottleneck: CPU >= 90% or under
                      ~10 MB free (router_health or the login's own read), or the
                      API login times out on a clean, fast line. Hints say why:
                      a 32 MB board (hAP lite / hAP mini / smips), RouterOS 7 on
                      such a board, or script jobs piling up.
                      Powernet #3 (483), Pamoja #3 (486), lee net #1 (371).
* isp_blocks_server - the router's tunnel to our Hetzner server never handshakes
                      while its AWS tunnel does: the site's ISP drops Hetzner's
                      replies. RONGAI (448), HOME951 (351), LEADERS APLITE (426).
* replaced_router   - no payments for a day while a sibling router of the same
                      reseller started taking them at about that time.
                      Powernet #8 (182) -> Powernet #3 (483).
* congested_line    - TCP connects mostly succeed, but slowly or erratically:
                      the site's internet line is saturated (bufferbloat).
                      Lux #2 (210). SSTP will not fix this.
* lossy_line        - TCP connects only some of the time.
* healthy_now       - it answered; waiting payments will be retried.
* udp_blocked /     - nothing reaches the router over its tunnel, yet the site
  tunnel_down         shows life (HTTPS push, check-in, command agent, or
                      payments still arriving). udp_blocked when the dead tunnel
                      rides UDP (WireGuard / L2TP-IPsec).
* offline           - "site dark": no tunnel, no push, no check-in, no payments.
* login_rejected / inconclusive.

Not built: an L2TP NAT-collision label (two routers dialling from one public
IP). The app never learns a router's public source IP without new router I/O.

Router I/O budget: the TCP connects are raw SYNs (no login, no circuit
breaker). The API login is skipped for a router that already reports CPU >= 90%
or low memory, and for LOGIN_BACKOFF after a login timed out (the earlier
result is reused, with its age) -- a login costs a hAP lite real CPU. A login
that does happen reads at most five small tables.

Database Session Discipline: the inputs are read in ONE short session which is
closed before any socket is opened; nothing is written to the database (the
result is kept in memory and attached to the problem-routers section when the
ops-health snapshot builds it). The probes run on a dedicated 4-thread pool so
they never occupy the event loop's default executor, the API login uses the
``background`` circuit-breaker lane (it stands down while paid deliveries are
struggling on the same router), and the whole tick is skipped while the DB pool
is under pressure.

Admin only: these are inferences, so they are attached only to the admin
ops-health sections; the reseller UI shows facts, not verdicts.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Callable, Optional

from sqlalchemy import select

from app.db import database
from app.db.database import db_pool_snapshot
from app.db.models import ProvisioningAttempt, Router, RouterHealth

logger = logging.getLogger(__name__)

INTERVAL = timedelta(minutes=5)
MAX_ROUTERS = 15
CONCURRENCY = 4
TCP_ATTEMPTS = 5
TCP_TIMEOUT_SECONDS = 4.0
TCP_GAP_SECONDS = 1.0
LOGIN_CONNECT_TIMEOUT = 5
LOGIN_TIMEOUT = 10
CPU_OVERLOADED = 90
MEMORY_LOW_BYTES = 10 * 1024 * 1024
CPU_FRESH = timedelta(minutes=10)
PUSH_FRESH = timedelta(minutes=5)
# A check-in (every ~60 s) or command-agent poll this recent means the site has internet.
LIFE_FRESH = timedelta(minutes=10)
# A payment attempt on the router this recent means customers reach the portal.
PAYMENT_LIFE = timedelta(hours=1)
# After an API login timed out, do not log in again for this long (reuse that result).
LOGIN_BACKOFF = timedelta(minutes=15)
# Board / RouterOS version learnt from a login stay useful for this long.
FACTS_MAX_AGE = timedelta(hours=24)
# Congested line: connects get through but slowly or erratically (seconds).
CONGESTED_MEDIAN_SECONDS = 1.5
CONGESTED_SPREAD_SECONDS = 2.0
# WireGuard: a peer with keepalive re-handshakes every ~2 min.
HANDSHAKE_ALIVE_SECONDS = 5 * 60
HANDSHAKE_DEAD_SECONDS = 15 * 60
SCRIPT_JOBS_PILING = 5
# Stop starting new prints once a login's reads have taken this long (worst case
# per router stays ~1 min, so 15 routers at 4-way concurrency fit in 5 minutes).
READ_BUDGET_SECONDS = 8.0
# Replaced router: silent this long while a sibling took over.
REPLACED_SILENCE = timedelta(hours=24)
REPLACED_MIN_PAYMENTS_BEFORE = 5   # the silent router was really in use
REPLACED_MIN_PAYMENTS_TAKEN = 5    # the sibling took a real share since
REPLACED_BEFORE_SPAN = timedelta(days=3)
REPLACED_SLACK = timedelta(hours=6)
PAYMENTS_LOOKBACK = timedelta(days=7)
# Do not probe off a problem-routers section older than this (snapshot job dead).
SECTION_MAX_AGE = timedelta(minutes=15)
# A diagnosis older than this is dropped rather than shown as current.
RESULT_MAX_AGE = timedelta(minutes=20)

# Management tunnels that ride on UDP (WireGuard; L2TP/IPsec is IKE/NAT-T on
# UDP 500/4500). A router showing life while one of these is dead is behind a
# site that blocks or mangles UDP.
UDP_TUNNELS = frozenset({"wireguard", "l2tp", "wg2_insurance", "aws_insurance"})

# Which of our servers a router-side tunnel points at (endpoint first, then name).
HETZNER_ENDPOINTS = frozenset({"91.98.238.12"})
AWS_ENDPOINTS = frozenset({"54.91.202.229", "35.170.199.141"})

_SMALL_BOARD_RE = re.compile(r"hap\s*(lite|mini)|rb9[34]1", re.IGNORECASE)

AILMENTS = ("overloaded", "isp_blocks_server", "replaced_router", "congested_line", "lossy_line",
            "udp_blocked", "tunnel_down", "offline", "healthy_now", "login_rejected",
            "inconclusive")
LOGIN_RESULTS = ("ok", "timeout", "rejected", "error", "skipped", "spared")

TITLES = {
    "overloaded": "Router overloaded",
    "isp_blocks_server": "ISP blocks our server",
    "replaced_router": "Probably replaced",
    "congested_line": "Internet line congested",
    "lossy_line": "Line dropping packets",
    "udp_blocked": "Tunnel blocked, site online",
    "tunnel_down": "Tunnel down, site online",
    "offline": "Site dark",
    "healthy_now": "Reachable now",
    "login_rejected": "API login rejected",
    "inconclusive": "Inconclusive",
}

ACTION_REBOOT = "Reboot the router; if it recurs, upgrade hardware or RouterOS"
ACTION_SMALL_BOARD = "Hardware too small (32 MB) — replace with a bigger board"
ACTION_ROS7_SMALL = "RouterOS 7 is too heavy for this board — downgrade to v6 or replace it"
ACTION_SCRIPTS = "Clear the stuck script jobs and check the schedulers, then reboot if needed"
ACTION_ISP_BLOCKS = ("The site's ISP drops our Hetzner server's replies — use the alternate "
                     "server IP, or ask the reseller to contact the ISP")
ACTION_REPLACED = "Owner probably replaced this router — confirm and retire it"
ACTION_CONGESTED = ("Site's internet line is saturated or poor — ask the reseller about uplink "
                    "capacity / their ISP (SSTP won't fix this)")
ACTION_SSTP = "Move management to SSTP"
ACTION_UPLINK = "Site line losing packets — reseller should check the uplink"
ACTION_OFFLINE = "Site power or internet is down — contact reseller"
ACTION_HEALTHY = "Reachable again — waiting payments will retry"
ACTION_TUNNEL_DOWN = "Router is online but its management tunnel is down — check the tunnel"
ACTION_TUNNEL_DOWN_CHECKIN = ("Management tunnel is down; payments still deliver via check-in — "
                              "fix the tunnel")
ACTION_LOGIN_REJECTED = "API login rejected — check the router's API username/password"
ACTION_INCONCLUSIVE = "Probe inconclusive — will retry next round"

# router_id -> public diagnosis + private "_probed_at"
_RESULTS: dict[int, dict] = {}
# router_id -> {"login": "timeout", "at": datetime}: last timed-out login (backoff)
_LOGIN_MEMO: dict[int, dict] = {}
# router_id -> {"board", "arch", "version", "at"} learnt at a login
_FACTS: dict[int, dict] = {}
_EXECUTOR: Optional[ThreadPoolExecutor] = None
_pool_busy_logged = False


def reset() -> None:
    _RESULTS.clear()
    _LOGIN_MEMO.clear()
    _FACTS.clear()


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------

def _ago(delta: timedelta) -> str:
    minutes = max(0, int(delta.total_seconds() // 60))
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    return f"{hours // 24} days ago"


def _mb(n: Optional[int]) -> str:
    return f"{n / (1024 * 1024):.0f} MB" if n is not None else "?"


def is_small_board(board: Optional[str], arch: Optional[str] = None) -> bool:
    """hAP lite / hAP mini / RB941 / RB931 or any smips board (32 MB RAM)."""
    return bool((board and _SMALL_BOARD_RE.search(board)) or (arch and arch.lower() == "smips"))


def ros_major(version: Optional[str]) -> Optional[int]:
    m = re.match(r"\s*(\d+)\.", version or "")
    return int(m.group(1)) if m else None


_DURATION_RE = re.compile(r"(\d+)(ms|w|d|h|m|s)")
_DURATION_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}


def parse_ros_duration(value: Optional[str]) -> Optional[float]:
    """RouterOS durations -> seconds: "4m36s", "1d2h", "9h47m12s", "00:04:36". None if empty."""
    if not value:
        return None
    value = str(value).strip()
    if ":" in value:
        days = 0
        if "d" in value:  # "1d 02:03:04"
            d, _, value = value.partition("d")
            try:
                days = int(d.strip() or 0)
            except ValueError:
                return None
        try:
            parts = [float(p) for p in value.strip().split(":")]
        except ValueError:
            return None
        secs = 0.0
        for p in parts:
            secs = secs * 60 + p
        return days * 86400 + secs
    matches = _DURATION_RE.findall(value)
    if not matches:
        return None
    return float(sum(int(n) * _DURATION_UNITS[u] for n, u in matches))


def _fmt_age(seconds: Optional[float]) -> str:
    if seconds is None:
        return "never"
    s = int(seconds)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 172800:
        return f"{s // 3600}h{(s % 3600) // 60:02d}m ago"
    return f"{s // 86400} days ago"


def tunnel_side(name: Optional[str], endpoint: Optional[str]) -> Optional[str]:
    """"hetzner" / "aws" / None for a router-side tunnel, by endpoint first, then name."""
    ep = (endpoint or "").strip()
    if ep in HETZNER_ENDPOINTS:
        return "hetzner"
    if ep in AWS_ENDPOINTS:
        return "aws"
    n = (name or "").lower()
    if "hz" in n or "hetzner" in n:
        return "hetzner"
    if "aws" in n:
        return "aws"
    return None


def summarize_tunnels(wg_peers: list[dict], l2tp: list[dict], sstp: list[dict]) -> list[dict]:
    """Router tables -> [{name, kind, side, state: alive|dead|unknown, age_s}], enabled only."""
    out = []
    for p in wg_peers or []:
        if str(p.get("disabled")).lower() == "true":
            continue
        age = parse_ros_duration(p.get("last-handshake"))
        if age is not None and age <= HANDSHAKE_ALIVE_SECONDS:
            state = "alive"
        elif age is None or age >= HANDSHAKE_DEAD_SECONDS:
            state = "dead"
        else:
            state = "unknown"
        out.append({"name": p.get("interface"), "kind": "wireguard",
                    "side": tunnel_side(p.get("interface"), p.get("endpoint-address")),
                    "state": state, "age_s": age})
    for kind, rows in (("l2tp", l2tp), ("sstp", sstp)):
        for c in rows or []:
            if str(c.get("disabled")).lower() == "true":
                continue
            running = str(c.get("running")).lower() == "true"
            out.append({"name": c.get("name"), "kind": kind,
                        "side": tunnel_side(c.get("name"), c.get("connect-to")),
                        "state": "alive" if running else "dead", "age_s": None})
    return out


def _tunnel_fact(t: dict) -> str:
    if t["kind"] == "wireguard":
        return f"{t['name']} handshake {_fmt_age(t['age_s'])}"
    return f"{t['name']} {'running' if t['state'] == 'alive' else 'not running'}"


def hetzner_blocked(tunnels: Optional[list[dict]]) -> Optional[list[str]]:
    """Facts when every enabled Hetzner tunnel is dead while an AWS one is alive, else None."""
    if not tunnels:
        return None
    hz = [t for t in tunnels if t["side"] == "hetzner"]
    aws_alive = [t for t in tunnels if t["side"] == "aws" and t["state"] == "alive"]
    if not hz or not aws_alive or any(t["state"] != "dead" for t in hz):
        return None
    return [_tunnel_fact(t) for t in hz] + [_tunnel_fact(aws_alive[0])]


def line_is_congested(tcp_times: Optional[list]) -> Optional[str]:
    """Evidence text when the successful connects were slow or erratic, else None."""
    times = [t for t in (tcp_times or []) if t is not None]
    if len(times) < 3:
        return None
    med = statistics.median(times)
    spread = max(times) - min(times)
    if med >= CONGESTED_MEDIAN_SECONDS or spread >= CONGESTED_SPREAD_SECONDS:
        return f"connects took {min(times):.1f}–{max(times):.1f} s (median {med:.1f} s)"
    return None


def detect_replacement(router_id: int, owner_routers: dict[int, str],
                       payments: dict[int, list[datetime]], now: datetime) -> Optional[dict]:
    """Pure: did a sibling router of the same owner take over this router's payments?

    ``owner_routers``: {router_id: name} for every router of the owner (this one
    included). ``payments``: {router_id: [created_at, ...]} within the lookback.
    The router must have been in use (>= 5 payments), silent for 24 h, and a
    sibling must have taken >= 5 payments since about then, at least doubling
    its earlier daily rate.
    """
    mine = sorted(payments.get(router_id) or [])
    if len(mine) < REPLACED_MIN_PAYMENTS_BEFORE:
        return None
    last = mine[-1]
    if now - last < REPLACED_SILENCE:
        return None
    pivot = last - REPLACED_SLACK
    before_start = max(now - PAYMENTS_LOOKBACK, pivot - REPLACED_BEFORE_SPAN)
    before_days = max((pivot - before_start).total_seconds() / 86400, 0.0)
    after_days = max((now - pivot).total_seconds() / 86400, 1e-6)
    best = None
    for rid, name in owner_routers.items():
        if rid == router_id:
            continue
        times = payments.get(rid) or []
        after = sum(1 for t in times if t >= pivot)
        before = sum(1 for t in times if before_start <= t < pivot)
        if after < REPLACED_MIN_PAYMENTS_TAKEN:
            continue
        rate_before = before / before_days if before_days else 0.0
        if after / after_days < 2 * rate_before:
            continue
        if best is None or after > best["taken"]:
            best = {"router_id": rid, "router_name": name, "taken": after, "last_payment_at": last}
    return best


# ---------------------------------------------------------------------------
# pure classifier
# ---------------------------------------------------------------------------

_LOGIN_TEXT = {
    "ok": "API login ok",
    "timeout": "API login timed out",
    "rejected": "API login rejected",
    "error": "API login dropped",
    "skipped": "API login skipped (circuit breaker)",
    "spared": "API login not tried (router busy)",
}


def _base_facts(tcp_ok: int, tcp_attempts: int, login: str, health: Optional[dict],
                now: datetime, login_age: Optional[timedelta] = None) -> list[str]:
    parts = [f"TCP {tcp_ok}/{tcp_attempts}"]
    if login == "spared":
        parts.append(_LOGIN_TEXT[login])
    elif tcp_ok > 0 and login in _LOGIN_TEXT:
        text = _LOGIN_TEXT[login]
        if login_age is not None:
            text += f" {_ago(login_age)} (not retried)"
        parts.append(text)
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
    return parts


def build_evidence(tcp_ok: int, tcp_attempts: int, login: str,
                   health: Optional[dict], now: datetime,
                   login_age: Optional[timedelta] = None) -> str:
    """Short human evidence line, e.g. "TCP 5/5, API login timed out, CPU 100% (push 3 min ago)"."""
    return ", ".join(_base_facts(tcp_ok, tcp_attempts, login, health, now, login_age))


def _load_reading(health: Optional[dict], resource: Optional[dict], now: datetime) -> dict:
    """Current CPU / free memory from this round's login, else a fresh router_health row."""
    if resource and (resource.get("cpu") is not None or resource.get("free_memory") is not None):
        return {"cpu": resource.get("cpu"), "free": resource.get("free_memory"), "source": "login"}
    if health and health.get("sampled_at") and now - health["sampled_at"] <= CPU_FRESH:
        return {"cpu": health.get("cpu_load"), "free": health.get("memory_free_bytes"),
                "source": health.get("source") or "push"}
    return {"cpu": None, "free": None, "source": None}


def is_router_busy(health: Optional[dict], now: datetime) -> bool:
    """A fresh router_health row says CPU >= 90% or memory nearly gone."""
    reading = _load_reading(health, None, now)
    return ((reading["cpu"] is not None and reading["cpu"] >= CPU_OVERLOADED)
            or (reading["free"] is not None and reading["free"] < MEMORY_LOW_BYTES))


def _overload_advice(board: Optional[str], arch: Optional[str], version: Optional[str],
                     script_jobs: Optional[int]) -> tuple[str, list[str]]:
    hints = []
    action = ACTION_REBOOT
    if script_jobs is not None and script_jobs >= SCRIPT_JOBS_PILING:
        hints.append(f"Scripts piling up ({script_jobs} running jobs)")
        action = ACTION_SCRIPTS
    if is_small_board(board, arch):
        label = board or arch
        if ros_major(version) == 7:
            hints.append(f"RouterOS 7 too heavy for this board ({label}, {version})")
            action = ACTION_ROS7_SMALL
        else:
            hints.append(f"Hardware too small ({label}, 32 MB RAM)")
            if action == ACTION_REBOOT:
                action = ACTION_SMALL_BOARD
    return action, hints


def classify(tcp_ok: int, tcp_attempts: int, login: str, tunnel: Optional[str],
             health: Optional[dict], now: datetime, *,
             tcp_times: Optional[list] = None,
             login_age: Optional[timedelta] = None,
             readings: Optional[dict] = None,
             facts: Optional[dict] = None,
             life: Optional[dict] = None,
             replacement: Optional[dict] = None) -> dict:
    """Pure: probe results + what we already know -> ailment, title, evidence, action.

    ``health``: latest router_health ``{"source", "sampled_at", "cpu_load",
    "memory_free_bytes", "board_name", "routeros_version"}`` or None.
    ``readings``: from this round's login ``{"resource": {...}, "script_jobs": n,
    "tunnels": [...]}``. ``facts``: board/arch/version learnt at an earlier login.
    ``life``: ``{"checkin_at", "agent_at", "last_payment_at"}``.
    ``replacement``: from ``detect_replacement``. ``login_age`` is set when
    ``login`` was reused from an earlier round instead of tried now.

    Order matters: a router reporting overload is overloaded whatever the probe
    saw; Hetzner-blocked evidence read off the router itself beats line
    statistics; a slow line explains a login timeout better than the router.
    """
    readings = readings or {}
    facts = facts or {}
    life = life or {}
    resource = readings.get("resource") or {}
    age = (now - health["sampled_at"]) if health and health.get("sampled_at") else None
    push_recent = (age is not None and age <= PUSH_FRESH
                   and (health.get("source") or "push") == "push")
    is_sstp = tunnel == "sstp"
    load = _load_reading(health, resource, now)
    cpu_hot = load["cpu"] is not None and load["cpu"] >= CPU_OVERLOADED
    mem_low = load["free"] is not None and load["free"] < MEMORY_LOW_BYTES
    board = resource.get("board") or (health or {}).get("board_name") or facts.get("board")
    arch = resource.get("arch") or facts.get("arch")
    version = resource.get("version") or (health or {}).get("routeros_version") or facts.get("version")

    base = _base_facts(tcp_ok, tcp_attempts, login, health, now, login_age)
    extra: list[str] = []
    hints: list[str] = []
    sstp = False

    congested = line_is_congested(tcp_times) if tcp_ok >= 3 else None
    blocked = hetzner_blocked(readings.get("tunnels")) if login == "ok" else None
    checkin_at, agent_at = life.get("checkin_at"), life.get("agent_at")
    paid_at = life.get("last_payment_at")
    checkin_recent = checkin_at is not None and now - checkin_at <= LIFE_FRESH
    agent_recent = agent_at is not None and now - agent_at <= LIFE_FRESH
    paying = paid_at is not None and now - paid_at <= PAYMENT_LIFE
    router_answered = login == "ok" and tcp_ok >= 4

    if cpu_hot or mem_low or (tcp_ok >= 4 and login == "timeout" and not congested):
        ailment = "overloaded"
        if load["source"] == "login" and load["cpu"] is not None:
            extra.append(f"CPU {load['cpu']}% (at login)")
        if load["free"] is not None and (mem_low or load["source"] == "login"):
            extra.append(f"{_mb(load['free'])} free")
        action, hints = _overload_advice(board, arch, version, readings.get("script_jobs"))
    elif blocked:
        ailment, action = "isp_blocks_server", ACTION_ISP_BLOCKS
        extra.extend(blocked)
        hints.append("Reachable only through the AWS fallback")
    elif replacement and not router_answered:
        ailment, action = "replaced_router", ACTION_REPLACED
        extra.append("no payments since "
                     + replacement["last_payment_at"].strftime("%d %b %H:%M UTC"))
        extra.append(f"{replacement['router_name']} took {replacement['taken']} payments since")
        hints.append(f"Owner probably replaced this router with {replacement['router_name']}")
    elif congested:
        ailment, action = "congested_line", ACTION_CONGESTED
        extra.append(congested)
    elif 1 <= tcp_ok <= 3:
        ailment = "lossy_line"
        action = ACTION_UPLINK if is_sstp else ACTION_SSTP
        sstp = not is_sstp
    elif login == "ok":
        ailment, action = "healthy_now", ACTION_HEALTHY
    elif tcp_ok == 0:
        signs = []
        if checkin_recent:
            signs.append(f"check-in {_ago(now - checkin_at)}")
        if agent_recent:
            signs.append(f"command agent {_ago(now - agent_at)}")
        if paying:
            signs.append(f"payment {_ago(now - paid_at)}")
        if push_recent or signs:
            extra.extend(signs)
            if checkin_recent:
                hints.append("Check-in still delivering")
            if tunnel in UDP_TUNNELS:
                ailment, action, sstp = "udp_blocked", ACTION_SSTP, True
            else:
                ailment = "tunnel_down"
                action = ACTION_TUNNEL_DOWN_CHECKIN if checkin_recent else ACTION_TUNNEL_DOWN
        else:
            ailment, action = "offline", ACTION_OFFLINE
            extra.append("no check-in")
            extra.append(f"last payment {_ago(now - paid_at)}" if paid_at else "no payments in 7 days")
    elif login == "rejected":
        ailment, action = "login_rejected", ACTION_LOGIN_REJECTED
    else:  # line clean but the login was skipped or dropped: no verdict this round
        ailment, action = "inconclusive", ACTION_INCONCLUSIVE

    facts_out = base + extra
    return {
        "ailment": ailment,
        "title": TITLES[ailment],
        "evidence": ", ".join(facts_out),
        "facts": facts_out,
        "action": action,
        "hints": hints,
        "sstp_candidate": sstp,
    }


# ---------------------------------------------------------------------------
# probes (blocking; run on the dedicated thread pool)
# ---------------------------------------------------------------------------

def tcp_probe_timed(host: str, port: int, attempts: int = TCP_ATTEMPTS,
                    timeout: float = TCP_TIMEOUT_SECONDS, gap: float = TCP_GAP_SECONDS,
                    connect: Callable = socket.create_connection,
                    sleep: Callable[[float], None] = time.sleep,
                    clock: Callable[[], float] = time.monotonic) -> list[Optional[float]]:
    """Plain TCP connects to the API port (no login, no circuit breaker).

    One entry per attempt: seconds the connect took, or None if it failed.
    """
    out: list[Optional[float]] = []
    for i in range(attempts):
        if i:
            sleep(gap)
        started = clock()
        try:
            conn = connect((host, port), timeout=timeout)
        except OSError:
            out.append(None)
            continue
        out.append(round(clock() - started, 3))
        try:
            conn.close()
        except OSError:
            pass
    return out


def tcp_probe(host: str, port: int, attempts: int = TCP_ATTEMPTS,
              timeout: float = TCP_TIMEOUT_SECONDS, gap: float = TCP_GAP_SECONDS,
              connect: Callable = socket.create_connection,
              sleep: Callable[[float], None] = time.sleep) -> int:
    """Number of successful plain TCP connects."""
    return sum(1 for t in tcp_probe_timed(host, port, attempts, timeout, gap, connect, sleep)
               if t is not None)


def login_probe(host: str, username: str, password: str, port: int,
                api_factory: Optional[Callable] = None,
                clock: Callable[[], float] = time.monotonic,
                on_login: Optional[Callable] = None) -> str:
    """ONE RouterOS API login on the background lane -> ok|timeout|rejected|error|skipped.

    ``on_login(api)`` runs while logged in (a few small prints); its errors are ignored.
    """
    if api_factory is None:
        from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI

        def api_factory():
            return MikroTikAPI(host, username, password, port, timeout=LOGIN_TIMEOUT,
                               connect_timeout=LOGIN_CONNECT_TIMEOUT, lane=LANE_BACKGROUND)
    api = api_factory()
    started = clock()
    try:
        if api.connect():
            if on_login is not None:
                try:
                    on_login(api)
                except Exception as exc:  # noqa: BLE001 - the reads are a bonus
                    logger.debug("[ROUTER-DIAGNOSIS] reads on %s failed: %s", host, exc)
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


def _print(api, cmd: str, proplist: list[str]) -> list[dict]:
    try:
        r = api.send_command_optimized(cmd, proplist=proplist)
    except Exception:  # noqa: BLE001
        return []
    return (r.get("data") or []) if isinstance(r, dict) and r.get("success") else []


def _int(value) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def read_router_state(api, clock: Callable[[], float] = time.monotonic) -> dict:
    """While logged in: resource, running script jobs, management tunnels (small prints).

    Stops starting new prints after READ_BUDGET_SECONDS so a slow router is not held.
    """
    started = clock()

    def rd(cmd: str, props: list[str]) -> list[dict]:
        if clock() - started > READ_BUDGET_SECONDS:
            return []
        return _print(api, cmd, props)

    res = (rd("/system/resource/print",
              ["cpu-load", "free-memory", "total-memory", "board-name",
               "architecture-name", "version"]) or [{}])[0]
    jobs = rd("/system/script/job/print", [".id"])
    jobs_read = clock() - started <= READ_BUDGET_SECONDS
    wg = rd("/interface/wireguard/peers/print",
            ["interface", "endpoint-address", "last-handshake", "disabled"])
    l2tp: list[dict] = []
    sstp: list[dict] = []
    if not wg:  # RouterOS 6 (no WireGuard) or no peers: the dial-out clients instead
        l2tp = rd("/interface/l2tp-client/print", ["name", "connect-to", "running", "disabled"])
        sstp = rd("/interface/sstp-client/print", ["name", "connect-to", "running", "disabled"])
    resource = {
        "cpu": _int(res.get("cpu-load")),
        "free_memory": _int(res.get("free-memory")),
        "total_memory": _int(res.get("total-memory")),
        "board": res.get("board-name"),
        "arch": res.get("architecture-name"),
        "version": res.get("version"),
    } if res else {}
    return {"resource": resource, "script_jobs": len(jobs) if jobs_read else None,
            "tunnels": summarize_tunnels(wg, l2tp, sstp)}


def probe_router(target: dict) -> dict:
    """TCP connects, then (unless ``target["skip_login"]``) one login with small reads."""
    times = tcp_probe_timed(target["ip"], target["port"])
    tcp_ok = sum(1 for t in times if t is not None)
    login, readings = "skipped", None
    if tcp_ok >= 1 and not target.get("skip_login"):
        box: dict = {}
        login = login_probe(target["ip"], target["username"], target["password"], target["port"],
                            on_login=lambda api: box.update(read_router_state(api)))
        readings = box or None
    return {"tcp_ok": tcp_ok, "tcp_times": times, "login": login, "readings": readings}


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


def last_checkin_at(router_id: int) -> Optional[datetime]:
    """When this process last got a check-in from the router (pilot only; memory)."""
    try:
        from app.services import checkin_delivery
        return getattr(checkin_delivery._stats.get(router_id), "last_checkin_at", None)
    except Exception:  # noqa: BLE001 - optional signal
        return None


def login_skip_reason(router_id: int, health: Optional[dict], now: datetime) -> Optional[str]:
    """Spare the router an API login: already reporting overload, or a login just timed out."""
    if is_router_busy(health, now):
        return "busy"
    memo = _LOGIN_MEMO.get(router_id)
    if memo and memo.get("login") == "timeout" and now - memo["at"] < LOGIN_BACKOFF:
        return "recent_timeout"
    return None


async def load_targets(router_ids: list[int], now: Optional[datetime] = None) -> list[dict]:
    """ONE short session: address/creds/tunnel, latest health row, the owners' payments."""
    from app.services.ops_health import tunnel_type_for_router

    if not router_ids:
        return []
    now = now or datetime.utcnow()
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, Router.ip_address, Router.port, Router.username, Router.password,
                   Router.management_tunnel, Router.user_id, Router.agent_last_seen_at,
                   RouterHealth.source, RouterHealth.sampled_at, RouterHealth.cpu_load,
                   RouterHealth.memory_free_bytes, RouterHealth.board_name,
                   RouterHealth.routeros_version)
            .outerjoin(RouterHealth, RouterHealth.router_id == Router.id)
            .where(Router.id.in_(router_ids))
        )).all()
        owner_ids = sorted({r[6] for r in rows if r[6] is not None})
        siblings = (await db.execute(
            select(Router.id, Router.name, Router.user_id).where(Router.user_id.in_(owner_ids))
        )).all() if owner_ids else []
        sibling_ids = [s[0] for s in siblings]
        paid = (await db.execute(
            select(ProvisioningAttempt.router_id, ProvisioningAttempt.created_at)
            .where(ProvisioningAttempt.router_id.in_(sibling_ids),
                   ProvisioningAttempt.created_at >= now - PAYMENTS_LOOKBACK)
        )).all() if sibling_ids else []
        await db.commit()

    by_owner: dict[int, dict[int, str]] = {}
    for rid, name, uid in siblings:
        by_owner.setdefault(uid, {})[rid] = name
    payments: dict[int, list[datetime]] = {}
    for rid, created in paid:
        payments.setdefault(rid, []).append(created)

    order = {rid: i for i, rid in enumerate(router_ids)}
    targets = []
    for (rid, ip, port, user, pw, mt, uid, agent_at, src, sampled, cpu, mem_free, board,
         version) in rows:
        if not ip:
            continue
        mine = payments.get(rid) or []
        targets.append({
            "id": rid, "ip": ip, "port": port or 8728, "username": user, "password": pw,
            "tunnel": tunnel_type_for_router(ip, mt),
            "health": ({"source": src, "sampled_at": sampled, "cpu_load": cpu,
                        "memory_free_bytes": mem_free, "board_name": board,
                        "routeros_version": version} if sampled else None),
            "life": {"checkin_at": last_checkin_at(rid), "agent_at": agent_at,
                     "last_payment_at": max(mine) if mine else None},
            "replacement": detect_replacement(rid, by_owner.get(uid, {}), payments, now),
        })
    targets.sort(key=lambda t: order.get(t["id"], 0))
    return targets


def _prune(now: datetime) -> None:
    for rid in [rid for rid, d in _RESULTS.items() if now - d["_probed_at"] > RESULT_MAX_AGE]:
        _RESULTS.pop(rid, None)
    for rid in [rid for rid, m in _LOGIN_MEMO.items() if now - m["at"] >= LOGIN_BACKOFF]:
        _LOGIN_MEMO.pop(rid, None)
    for rid in [rid for rid, f in _FACTS.items() if now - f["at"] > FACTS_MAX_AGE]:
        _FACTS.pop(rid, None)


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


def _remember(target: dict, result: dict, now: datetime) -> tuple[str, Optional[timedelta]]:
    """Update the login backoff and learnt facts; return (login to classify on, age if reused)."""
    rid = target["id"]
    skip = target.get("skip_login")
    if skip == "recent_timeout":
        if result["tcp_ok"] >= 1:
            return "timeout", now - _LOGIN_MEMO[rid]["at"]
        return "skipped", None
    if skip == "busy":
        return "spared", None
    login = result["login"]
    if login == "timeout":
        _LOGIN_MEMO[rid] = {"login": "timeout", "at": now}
    elif login in ("ok", "rejected"):
        _LOGIN_MEMO.pop(rid, None)
    res = (result.get("readings") or {}).get("resource") or {}
    if res.get("board") or res.get("version") or res.get("arch"):
        _FACTS[rid] = {"board": res.get("board"), "arch": res.get("arch"),
                       "version": res.get("version"), "at": now}
    return login, None


async def run_diagnosis_cycle(now: Optional[datetime] = None,
                              probe: Callable[[dict], dict] = probe_router) -> dict:
    now = now or datetime.utcnow()
    _prune(now)
    if _db_pool_busy():
        return {"skipped": "db_pool_busy"}
    ids = attention_router_ids(now)
    if not ids:
        return {"probed": 0}
    targets = await load_targets(ids, now)  # session is closed before any probe starts
    for t in targets:
        t["skip_login"] = login_skip_reason(t["id"], t["health"], now)

    loop = asyncio.get_running_loop()
    started = time.monotonic()
    results = await asyncio.gather(
        *(loop.run_in_executor(_executor(), probe, t) for t in targets),
        return_exceptions=True,
    )
    elapsed = time.monotonic() - started
    probed_at = now + timedelta(seconds=elapsed)
    counts: dict[str, int] = {}
    spared = 0
    for target, result in zip(targets, results):
        if isinstance(result, BaseException):
            logger.warning("[ROUTER-DIAGNOSIS] probe of router %s failed: %s", target["id"], result)
            continue
        login, login_age = _remember(target, result, now)
        spared += bool(target.get("skip_login"))
        diag = classify(result["tcp_ok"], TCP_ATTEMPTS, login, target["tunnel"],
                        target["health"], now,
                        tcp_times=result.get("tcp_times"), login_age=login_age,
                        readings=result.get("readings"), facts=_FACTS.get(target["id"]),
                        life=target.get("life"), replacement=target.get("replacement"))
        _RESULTS[target["id"]] = {
            **diag, "tcp_ok": result["tcp_ok"], "login": login,
            "probed_at": probed_at.replace(microsecond=0).isoformat() + "Z", "_probed_at": probed_at,
        }
        counts[diag["ailment"]] = counts.get(diag["ailment"], 0) + 1
    summary = {"probed": len(targets), "logins_spared": spared, "seconds": round(elapsed, 1),
               "ailments": counts}
    logger.info("[ROUTER-DIAGNOSIS] %s", summary)
    return summary
