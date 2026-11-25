"""Per-WAN health check for load-balanced (PCC) routers: catch a line that
answers ping but drops real traffic, pull it out of the balancing, alert.

Why (KWETU WIFI / ZEUS, router 671, 2026-11-19): line 2 still answered ping
and 1480-byte DF probes, so check-gateway kept its routes active, but 193 of
444 established TCP flows marked for WAN2 had under 1 KB of reply, against 10
of 281 on WAN1 (ISP FUP or a consumer modem's NAT session limit). PCC kept
sending about half of all new connections into it for hours: "some sites
work, some don't", "pays then no internet". RouterOS failover is binary
(gateway answers or not) and cannot see partial loss.

Detector (detector id ``lb_wan_reply_loss``, registry code
``LB_WAN2_SILENT_REPLY_LOSS``): read conntrack, group ESTABLISHED TCP flows by
connection-mark (``WANn_conn``, one per WAN) and compute each WAN's share of
"starved" flows (reply bytes < LB_HEALTH_STARVED_REPLY_BYTES). A WAN is
degraded in one check when its share is at least LB_HEALTH_MIN_STARVED_RATIO
over at least LB_HEALTH_MIN_FLOWS flows AND at least LB_HEALTH_RELATIVE_FACTOR
times the healthiest other WAN's share. Comparing against the other line is
what makes the number meaningful: idle keep-alives and uploads have tiny
replies on every line, a broken line has many more of them.

Mitigation (hysteresis, state persisted in ``routers.lb_config["health"]``):

  active --N degraded checks--> pulled   disable ONLY that WAN's
                                          ISP_BILLING_PCC_MARK_WANn rule; new
                                          connections hash into no mark and
                                          ride the main table's checked WAN1
                                          default. Routes, fallbacks and the
                                          UNAUTH guard are never touched.
  pulled --cooldown elapsed-->    trial   re-enable the MARK rule (only while
                                          the guard and the WAN's ROUTE rule
                                          are enabled)
  trial  --M healthy checks-->    active  restored, cooldown reset
  trial  --N degraded checks-->   pulled  cooldown doubled (capped)

A pulled WAN gets no new flows, so conntrack cannot judge it while it rests,
and ping is exactly the signal that lied. So recovery is proven on real
traffic during a trial instead. (An active HTTP probe would need a router-side
routing rule so /tool/fetch leaves through that WAN's table: a standing config
write this job does not make.)

WAN1 is never pulled: unmarked traffic (unauth/portal, and every hash bucket
whose MARK rule is off) rides WAN1's main-table default, so disabling
MARK_WAN1 moves nothing. A degraded WAN1 is alerted for a human instead.

Every action is a router event (customer_events) and a short ops alert to the
platform admins' inbox (critical ones also go to OPS_ALERT_SMS_PHONE).
LB_HEALTH_AUTO_MITIGATE=false keeps detection and alerts, never writes.

Locks: the per-router lock only (acquire_router_only), never fleet slots. DB
sessions are short and closed before any RouterOS I/O.

The pure part (thresholds, stats, verdicts, the state machine) imports nothing
from the app at module level, so the read-only fleet detector script in the
setup-dual-wan-lb skill can run it inside the production container before this
module is deployed.
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

DETECTOR_ID = "lb_wan_reply_loss"
FINDING_CODE = "LB_WAN2_SILENT_REPLY_LOSS"
PRIMARY_FINDING_CODE = "LB_WAN1_SILENT_REPLY_LOSS"
LOCK_HOLDER = "load-balancing line health check"
MAX_ROUTERS_PER_RUN = 25
READ_TIMEOUT_SECONDS = 90
WRITE_TIMEOUT_SECONDS = 60
PRIMARY_REALERT_AFTER = timedelta(hours=6)

GUARD_COMMENT = "ISP_BILLING_PCC_UNAUTH_GUARD_V2"
_CONN_MARK_RE = re.compile(r"WAN(\d+)_conn")
_MARK_RE = re.compile(r"ISP_BILLING_PCC_MARK_WAN(\d+)")
_ROUTE_RE = re.compile(r"ISP_BILLING_PCC_ROUTE_WAN(\d+)")

CONN_PROPLIST = ["protocol", "tcp-state", "connection-mark", "repl-bytes"]
MANGLE_PROPLIST = [".id", "comment", "disabled"]

STATE_ACTIVE = "active"
STATE_PULLED = "pulled"
STATE_TRIAL = "trial"

VERDICT_DEGRADED = "degraded"
VERDICT_HEALTHY = "healthy"
VERDICT_UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Thresholds:
    starved_reply_bytes: int = 1024
    min_flows: int = 50
    min_baseline_flows: int = 30
    min_starved_ratio: float = 0.25
    relative_factor: float = 4.0
    baseline_floor: float = 0.02
    absolute_only_ratio: float = 0.75
    degraded_checks: int = 3
    healthy_checks: int = 3
    cooldown_minutes: int = 30
    max_cooldown_minutes: int = 240

    @classmethod
    def from_settings(cls) -> "Thresholds":
        from app.config import settings

        d = cls()
        return cls(**{
            name: getattr(settings, "LB_HEALTH_" + name.upper(), getattr(d, name))
            for name in cls.__dataclass_fields__
        })


# ---------------------------------------------------------------------------
# Detector math (pure)
# ---------------------------------------------------------------------------

def _bytes(value: Any) -> int:
    try:
        return int(str(value or "0").strip() or 0)
    except ValueError:
        return 0


def wan_flow_stats(conns: Iterable[dict], starved_reply_bytes: int = 1024) -> Dict[int, dict]:
    """{wan_number: {"flows", "starved", "ratio"}} over established TCP flows,
    keyed by the 1-based WAN number in the ``WANn_conn`` connection mark.
    Unmarked flows (unauth/portal/bypass traffic) are not counted."""
    stats: Dict[int, dict] = {}
    for c in conns:
        proto = c.get("protocol")
        if proto and proto != "tcp":
            continue
        if c.get("tcp-state") != "established":
            continue
        m = _CONN_MARK_RE.fullmatch(c.get("connection-mark") or "")
        if not m:
            continue
        s = stats.setdefault(int(m.group(1)), {"flows": 0, "starved": 0})
        s["flows"] += 1
        if _bytes(c.get("repl-bytes")) < starved_reply_bytes:
            s["starved"] += 1
    for s in stats.values():
        s["ratio"] = round(s["starved"] / s["flows"], 4) if s["flows"] else 0.0
    return stats


def assess_wans(stats: Dict[int, dict], wan_numbers: Iterable[int],
                th: Thresholds = Thresholds()) -> Dict[int, dict]:
    """One check's verdict per WAN: degraded / healthy / unknown.

    unknown = too few flows to judge (dormant, pulled, or a quiet hour)."""
    wans = sorted(set(wan_numbers) | set(stats))
    out: Dict[int, dict] = {}
    for n in wans:
        s = stats.get(n) or {"flows": 0, "starved": 0, "ratio": 0.0}
        others = [stats[o]["ratio"] for o in wans
                  if o != n and o in stats and stats[o]["flows"] >= th.min_baseline_flows]
        baseline = min(others) if others else None
        v = {"flows": s["flows"], "starved": s["starved"], "ratio": s["ratio"],
             "baseline_ratio": baseline, "factor": None}
        if s["flows"] < th.min_flows:
            v["verdict"] = VERDICT_UNKNOWN
            v["reason"] = f"only {s['flows']} established flows (< {th.min_flows})"
        elif baseline is None:
            bad = s["ratio"] >= max(th.absolute_only_ratio, th.min_starved_ratio)
            v["verdict"] = VERDICT_DEGRADED if bad else VERDICT_HEALTHY
            v["reason"] = "no other line to compare; absolute threshold only"
        else:
            factor = s["ratio"] / max(baseline, th.baseline_floor)
            v["factor"] = round(factor, 2)
            bad = s["ratio"] >= th.min_starved_ratio and factor >= th.relative_factor
            v["verdict"] = VERDICT_DEGRADED if bad else VERDICT_HEALTHY
            v["reason"] = (f"{s['starved']}/{s['flows']} starved = {s['ratio']:.0%}, "
                           f"{factor:.1f}x the best other line ({baseline:.0%})")
        out[n] = v
    return out


def _disabled(row: dict) -> bool:
    """RouterOS prints true/false; writes (and some fakes) use yes/no."""
    return str(row.get("disabled") or "").strip().lower() in ("true", "yes")


def mark_rule_state(mangle_rows: Iterable[dict]) -> dict:
    """Which managed MARK / ROUTE rules are enabled, and the guard's state."""
    marks: Dict[int, bool] = {}
    routes: Dict[int, bool] = {}
    guard: Optional[bool] = None
    for r in mangle_rows:
        comment = r.get("comment") or ""
        enabled = not _disabled(r)
        m = _MARK_RE.fullmatch(comment)
        if m:
            marks[int(m.group(1))] = marks.get(int(m.group(1)), False) or enabled
            continue
        m = _ROUTE_RE.fullmatch(comment)
        if m:
            routes[int(m.group(1))] = routes.get(int(m.group(1)), False) or enabled
            continue
        if comment == GUARD_COMMENT:
            guard = bool(guard) or enabled
    return {"marks": marks, "routes": routes, "guard": guard}


def contract_record(router_id: int, name: str, verdicts: Dict[int, dict],
                    wan_ports: List[str], rules: Optional[dict] = None) -> dict:
    """The incident-to-detector JSON line for one router (read-only)."""
    degraded = [n for n, v in verdicts.items() if v["verdict"] == VERDICT_DEGRADED]
    record = {
        "router_id": router_id, "name": name, "detector": DETECTOR_ID,
        "status": "hit" if degraded else "clean",
        "severity": "blocker" if degraded else None,
        "code": None,
        "evidence": {"wans": {f"WAN{n}": {**v, "port": _port_for(wan_ports, n)}
                              for n, v in sorted(verdicts.items())},
                     "mark_rules": (rules or {}).get("marks"),
                     "guard_enabled": (rules or {}).get("guard")},
        "reseller_message": None,
        "fix_ref": "skill:setup-dual-wan-lb",
    }
    if degraded:
        primary = 1 in degraded
        record["code"] = PRIMARY_FINDING_CODE if primary else FINDING_CODE
        lines = ", ".join(f"line {n} ({_port_for(wan_ports, n) or 'WAN' + str(n)})"
                          for n in degraded)
        record["reseller_message"] = (
            f"Internet {lines} is connected but is not answering many websites: "
            f"{verdicts[degraded[0]]['ratio']:.0%} of its connections get almost no "
            "reply, while the other line is fine. Customers on it see some sites load "
            "and others not. Ask that line's provider to check the bundle / speed "
            "limit, or restart its modem; we move customers to the working line "
            "meanwhile."
        )
    marks = (rules or {}).get("marks") or {}
    if marks and not any(marks.values()):
        record["evidence"]["note"] = ("all MARK rules disabled (load balancing rolled "
                                      "back on the router); flows reflect old marks only")
    return record


def _port_for(wan_ports: List[str], n: int) -> Optional[str]:
    return wan_ports[n - 1] if 0 < n <= len(wan_ports) else None


# ---------------------------------------------------------------------------
# Hysteresis (pure)
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def step_wan(entry: Optional[dict], streak: Optional[dict], verdict: str, *,
             mark_enabled: bool, can_pull: bool, now: datetime,
             th: Thresholds = Thresholds()) -> Tuple[dict, dict, Optional[str]]:
    """Advance one WAN by one check.

    *entry* is the persisted state ({"state", "since", "cooldown_minutes",
    "pulls", "alerted_at"}); *streak* the in-memory consecutive counters
    ({"degraded", "healthy"}). Returns (entry, streak, action) where action is
    None or one of: "pull", "alert", "trial", "repull", "restore",
    "external_reenable", "external_disable".
      * can_pull False (WAN1, or mitigation switched off) turns "pull" into
        "alert" (at most once per PRIMARY_REALERT_AFTER).
      * mark_enabled is the live state of this WAN's MARK rule.
    """
    entry = dict(entry or {"state": STATE_ACTIVE})
    streak = dict(streak or {"degraded": 0, "healthy": 0})
    state = entry.get("state") or STATE_ACTIVE

    def count() -> None:
        if verdict == VERDICT_DEGRADED:
            streak["degraded"] += 1
            streak["healthy"] = 0
        elif verdict == VERDICT_HEALTHY:
            streak["healthy"] += 1
            streak["degraded"] = 0

    def pulled(cooldown: int) -> dict:
        return {"state": STATE_PULLED, "since": _iso(now), "cooldown_minutes": cooldown,
                "pulls": int(entry.get("pulls") or 0) + 1}

    if state == STATE_PULLED:
        if mark_enabled:
            # Someone (dashboard re-apply, auto-activation) put it back: judge it.
            entry = {**entry, "state": STATE_TRIAL, "since": _iso(now)}
            return entry, {"degraded": 0, "healthy": 0}, "external_reenable"
        since = _parse(entry.get("since")) or now
        cooldown = int(entry.get("cooldown_minutes") or th.cooldown_minutes)
        if now - since >= timedelta(minutes=cooldown):
            entry = {**entry, "state": STATE_TRIAL, "since": _iso(now)}
            return entry, {"degraded": 0, "healthy": 0}, "trial"
        return entry, {"degraded": 0, "healthy": 0}, None

    if state == STATE_TRIAL:
        if not mark_enabled:
            entry = {**entry, "state": STATE_PULLED, "since": _iso(now)}
            return entry, {"degraded": 0, "healthy": 0}, "external_disable"
        count()
        if streak["degraded"] >= th.degraded_checks:
            cooldown = min(int(entry.get("cooldown_minutes") or th.cooldown_minutes) * 2,
                           th.max_cooldown_minutes)
            return pulled(cooldown), {"degraded": 0, "healthy": 0}, "repull"
        if streak["healthy"] >= th.healthy_checks:
            return {"state": STATE_ACTIVE}, {"degraded": 0, "healthy": 0}, "restore"
        return entry, streak, None

    # active
    if not mark_enabled:
        # Not ours (a manual rollback or a staged line): nothing to judge.
        return entry, {"degraded": 0, "healthy": 0}, None
    count()
    if streak["healthy"] >= th.healthy_checks and entry.get("alerted_at"):
        entry.pop("alerted_at", None)
    if streak["degraded"] < th.degraded_checks:
        return entry, streak, None
    if can_pull:
        return pulled(th.cooldown_minutes), {"degraded": 0, "healthy": 0}, "pull"
    last = _parse(entry.get("alerted_at"))
    if last is None or now - last >= PRIMARY_REALERT_AFTER:
        entry["alerted_at"] = _iso(now)
        return entry, streak, "alert"
    return entry, streak, None


# ---------------------------------------------------------------------------
# RouterOS side (sync, worker thread)
# ---------------------------------------------------------------------------

def _connect(router_info: dict):
    from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI

    return MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"],
        router_info["port"], timeout=45, connect_timeout=8, lane=LANE_BACKGROUND,
    )


def read_router(api) -> dict:
    """Read-only: established TCP conntrack (trimmed) + managed mangle state."""
    from app.services.mikrotik_lb import _rd

    r = api.send_command_optimized("/ip/firewall/connection/print",
                                   proplist=CONN_PROPLIST, query="?tcp-state=established")
    if not r.get("success"):
        return {"error": "conntrack_read_failed", "detail": r.get("error")}
    mangle = _rd(api, "/ip/firewall/mangle/print", MANGLE_PROPLIST)
    return {"conns": r.get("data") or [], "mangle": mangle}


def _read_sync(router_info: dict) -> dict:
    api = _connect(router_info)
    if not api.connect():
        return {"error": "connect_failed", "detail": api.last_connect_error}
    try:
        return read_router(api)
    finally:
        api.disconnect()


def set_mark_rule(api, wan_number: int, enable: bool) -> dict:
    """Disable or re-enable ONLY ISP_BILLING_PCC_MARK_WAN<n>.

    Disabling is always the safe direction (fewer marked connections). Enabling
    refuses unless the UNAUTH guard and this WAN's ROUTE rule are enabled: a
    live MARK rule without the guard kills the portal, and one without its
    ROUTE rule marks connections nobody routes. WAN1's rule is never touched.
    """
    from app.services.mikrotik_lb import _rd

    if wan_number <= 1:
        return {"ok": False, "error": "never_touch_wan1"}
    comment = f"ISP_BILLING_PCC_MARK_WAN{wan_number}"
    rows = _rd(api, "/ip/firewall/mangle/print", MANGLE_PROPLIST)
    state = mark_rule_state(rows)
    targets = [r for r in rows if (r.get("comment") or "") == comment]
    if not targets:
        return {"ok": False, "error": "mark_rule_missing"}
    if enable:
        if not state["guard"]:
            return {"ok": False, "error": "guard_not_enabled"}
        if not state["routes"].get(wan_number):
            return {"ok": False, "error": "route_rule_not_enabled"}
    changed = []
    for row in targets:
        if _disabled(row) is not enable:
            continue  # already in the wanted state
        r = api.send_command("/ip/firewall/mangle/set",
                             {".id": row[".id"], "disabled": "no" if enable else "yes"})
        if not r.get("success"):
            return {"ok": False, "error": "set_failed", "detail": r.get("error"),
                    "changed": changed}
        changed.append(row[".id"])
    after = mark_rule_state(_rd(api, "/ip/firewall/mangle/print", MANGLE_PROPLIST))
    ok = after["marks"].get(wan_number) is enable
    return {"ok": ok, "changed": changed, "rule": comment,
            "error": None if ok else "verify_failed"}


def _set_mark_sync(router_info: dict, wan_number: int, enable: bool) -> dict:
    api = _connect(router_info)
    if not api.connect():
        return {"ok": False, "error": "connect_failed", "detail": api.last_connect_error}
    try:
        return set_mark_rule(api, wan_number, enable)
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

_running = False
# (router_id, wan_number) -> {"degraded": int, "healthy": int}
_streaks: Dict[Tuple[int, int], dict] = {}
_alert_memory: Dict[str, tuple] = {}


def reset_state() -> None:
    global _running
    _running = False
    _streaks.clear()
    _alert_memory.clear()


_WRITES = {"pull": False, "repull": False, "trial": True}


def _messages(action: str, label: str, v: dict, entry: dict, name: str) -> Tuple[str, str]:
    """(event message, short alert line)."""
    stat = (f"{v.get('starved')}/{v.get('flows')} flows starved ({v.get('ratio', 0):.0%})"
            if v.get("flows") else "no flows yet")
    base = v.get("baseline_ratio")
    vs = f" vs {base:.0%} on the best other line" if base is not None else ""
    cooldown = entry.get("cooldown_minutes")
    msgs = {
        "pull": (f"Load balancing: {label} answers ping but is dropping replies "
                 f"({stat}{vs}). Took it out of the balancing; new connections use the "
                 f"other line(s). Retry in {cooldown} min.",
                 f"{name}: {label} pulled from LB, {stat}{vs}"),
        "repull": (f"Load balancing: {label} is still dropping replies on trial "
                   f"({stat}{vs}); taken out again, next retry in {cooldown} min.",
                   f"{name}: {label} failed its trial, out again ({cooldown} min)"),
        "trial": (f"Load balancing: putting {label} back into the balancing on trial "
                  "after its rest; watching its connections.", ""),
        "restore": (f"Load balancing: {label} has been healthy on trial ({stat}{vs}); "
                    "it is balancing normally again.",
                    f"{name}: {label} healthy again, back in LB"),
        "alert": (f"Load balancing: {label} answers ping but is dropping replies "
                  f"({stat}{vs}). Not moved automatically (the main line, or automatic "
                  "action is off); check that line.",
                  f"{name}: {label} dropping replies ({stat}{vs}), needs a human"),
        "external_reenable": (f"Load balancing: {label} was switched back on outside the "
                              "health check; watching it on trial.", ""),
        "external_disable": (f"Load balancing: {label} was switched off outside the "
                             "health check during its trial.", ""),
    }
    return msgs[action]


_ALERT_SEVERITY = {"pull": "critical", "alert": "critical", "repull": "warning",
                   "restore": "watch"}
_EVENT_SEVERITY = {"pull": "warning", "repull": "warning", "alert": "warning",
                   "trial": "info", "restore": "info", "external_reenable": "info",
                   "external_disable": "info"}


async def _record(bundle: dict, wan: int, action: str, v: dict, entry: dict,
                  write: Optional[dict]) -> None:
    from app.services.customer_events import record_customer_event

    label = f"line {wan} ({_port_for(bundle['wan_ports'], wan) or 'WAN' + str(wan)})"
    event_msg, alert_line = _messages(action, label, v, entry, bundle["name"])
    failed = write is not None and not write.get("ok")
    if failed:
        event_msg += f" [router change FAILED: {write.get('error')}]"
        alert_line = alert_line or f"{bundle['name']}: {label} {action} failed"
        alert_line += f" (router change failed: {write.get('error')})"
    await record_customer_event(
        None, f"lb_wan_health_{action}", event_msg, category="change",
        severity="warning" if failed else _EVENT_SEVERITY[action], source="system",
        user_id=bundle.get("user_id"), router_id=bundle["id"],
        details={"wan": wan, "port": _port_for(bundle["wan_ports"], wan), "verdict": v,
                 "state": entry, "write": write, "detector": DETECTOR_ID},
    )
    if alert_line:
        try:
            from app.services.ops_health import deliver_alerts

            await deliver_alerts([{
                "key": f"lb_wan_health:{bundle['id']}:WAN{wan}:{action}",
                "severity": "warning" if failed else _ALERT_SEVERITY.get(action, "warning"),
                "title": f"LB line health, router {bundle['id']}",
                "message": alert_line,
            }], memory=_alert_memory)
        except Exception:  # noqa: BLE001 - alerts are best effort
            logger.exception("[LB-HEALTH] alert delivery failed for router %s", bundle["id"])


async def _persist(router_id: int, health: dict) -> None:
    from app.db import database as db_module
    from app.db.models import Router

    async with db_module.async_session() as db:
        router = await db.get(Router, router_id)
        if router is None or not router.lb_enabled:
            return
        config = dict(router.lb_config or {})
        config["health"] = health
        router.lb_config = config
        await db.commit()


async def check_router(bundle: dict, th: Optional[Thresholds] = None,
                       now: Optional[datetime] = None,
                       mitigate: Optional[bool] = None) -> dict:
    """One health check of one router; returns a summary (also for tests)."""
    from app.config import settings
    from app.services.mikrotik_background import router_locks

    th = th or Thresholds.from_settings()
    now = now or datetime.utcnow()
    mitigate = settings.LB_HEALTH_AUTO_MITIGATE if mitigate is None else mitigate
    rid = bundle["id"]
    wan_numbers = list(range(1, len(bundle["wan_ports"]) + 1))

    async with router_locks.acquire_router_only(bundle["router_key"], holder=LOCK_HOLDER):
        state = await asyncio.wait_for(asyncio.to_thread(_read_sync, bundle["router_info"]),
                                       READ_TIMEOUT_SECONDS)
    if state.get("error"):
        return {"router_id": rid, "status": "unreachable", "error": state["error"]}

    rules = mark_rule_state(state["mangle"])
    health = dict(bundle.get("health") or {})
    entries = dict(health.get("wans") or {})
    ours = any((e or {}).get("state") in (STATE_PULLED, STATE_TRIAL) for e in entries.values())
    if not rules["guard"] or (not any(rules["marks"].values()) and not ours):
        # Rolled back on the router (ZEUS after rollback_lb.py) or half-built:
        # there is no balancing to protect, and never write near a missing guard.
        return {"router_id": rid, "status": "skipped", "reason": "lb_not_live_on_router",
                "rules": rules}

    stats = wan_flow_stats(state["conns"], th.starved_reply_bytes)
    verdicts = assess_wans(stats, wan_numbers, th)
    actions = []
    changed = False
    for n in wan_numbers:
        key = str(n)
        entry, streak, action = step_wan(
            entries.get(key), _streaks.get((rid, n)), verdicts[n]["verdict"],
            mark_enabled=bool(rules["marks"].get(n)),
            can_pull=bool(mitigate) and n > 1, now=now, th=th,
        )
        _streaks[(rid, n)] = streak
        write = None
        if action in _WRITES:
            async with router_locks.acquire_router_only(bundle["router_key"],
                                                        holder=LOCK_HOLDER):
                write = await asyncio.wait_for(
                    asyncio.to_thread(_set_mark_sync, bundle["router_info"], n,
                                      _WRITES[action]),
                    WRITE_TIMEOUT_SECONDS)
            if not write.get("ok"):
                # Leave the state as it was; the next check retries.
                entry = entries.get(key) or {"state": STATE_ACTIVE}
                if action in ("pull", "repull"):
                    _streaks[(rid, n)] = {"degraded": th.degraded_checks - 1, "healthy": 0}
                if action == "trial":
                    # e.g. guard off: stay pulled, push the next try out.
                    entry = {**entry, "since": _iso(now)}
        if entry != (entries.get(key) or {"state": STATE_ACTIVE}):
            changed = True
        if entry.get("state") == STATE_ACTIVE and len(entry) == 1:
            entries.pop(key, None)
        else:
            entries[key] = entry
        if action:
            actions.append({"wan": n, "action": action, "write": write})
            await _record(bundle, n, action, verdicts[n], entry, write)
    if changed:
        health = {"wans": entries, "updated_at": _iso(now)}
        await _persist(rid, health)
    hit = any(v["verdict"] == VERDICT_DEGRADED for v in verdicts.values())
    return {"router_id": rid, "status": "hit" if hit else "clean",
            "verdicts": verdicts, "actions": actions, "health": entries}


async def check_lb_wan_health_background() -> None:
    """APScheduler job."""
    global _running
    from app.config import settings

    if _running or not settings.LB_HEALTH_CHECK_ENABLED:
        return
    from sqlalchemy import select

    from app.db import database as db_module
    from app.db.models import Router
    from app.services.mikrotik_background import (
        _background_db_pool_is_busy,
        _router_recently_offline,
    )

    if _background_db_pool_is_busy("LB-HEALTH"):
        return
    _running = True
    try:
        now = datetime.utcnow()
        bundles = []
        async with db_module.async_session() as db:
            routers = (await db.execute(
                select(Router).where(Router.lb_enabled == True)  # noqa: E712
                .order_by(Router.id)
            )).scalars().all()
            for r in routers:
                config = r.lb_config or {}
                wan_ports = list(config.get("wan_ports") or [])
                if len(wan_ports) < 2 or _router_recently_offline(r, now):
                    continue
                bundles.append({
                    "id": r.id, "name": r.name or f"router {r.id}", "user_id": r.user_id,
                    "router_key": f"{r.ip_address}:{r.port}",
                    "router_info": {"ip": r.ip_address, "username": r.username,
                                    "password": r.password, "port": r.port},
                    "wan_ports": wan_ports,
                    "health": config.get("health") or {},
                })
                if len(bundles) >= MAX_ROUTERS_PER_RUN:
                    break
            await db.commit()  # release the DB before router I/O
        th = Thresholds.from_settings()
        for bundle in bundles:  # one router at a time: light by design
            try:
                result = await check_router(bundle, th)
                if result.get("actions"):
                    logger.warning("[LB-HEALTH] Router %s: %s", bundle["id"], result["actions"])
            except Exception as exc:  # noqa: BLE001
                logger.warning("[LB-HEALTH] Router %s check failed: %s", bundle["id"], exc)
    finally:
        _running = False
