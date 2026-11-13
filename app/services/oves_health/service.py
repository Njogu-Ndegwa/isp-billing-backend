"""OVES platform health cycle: collect -> evaluate -> alert -> store.

Session discipline (AGENTS.md): every DB touch is its own short session that
is committed and closed BEFORE any network call. Collection (Kubernetes API,
probes, AWS) runs with no session open at all; the critical SMS is dispatched
only after the inbox session closes. The job sheds when the DB pool is busy.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import Text, cast, delete, func, select, update

from app.config import settings
from app.db import database
from app.db.models import OvesHealthSnapshot, ResellerInboxMessage, User, UserRole
from app.services.oves_health import apollo, collectors, parsers, probes, rules
from app.services.oves_health.cloud import AwsReadOnly
from app.services.oves_health.k8s import K8sClient, cluster_configs

logger = logging.getLogger(__name__)

RETENTION = timedelta(days=14)
PAYLOAD_RETENTION = timedelta(hours=3)
RECENT_WINDOW = timedelta(minutes=60)
PRUNE_EVERY = 15
MAX_LATENCY_SAMPLES = 300
OVES_ALERT_SMS_CATEGORY = "oves_alert"

_state: dict[str, Any] = {
    "probe_streaks": {}, "source_streaks": {}, "degraded_streaks": {},
    "alert_memory": {}, "baseline": {"hour": None, "value": None}, "cycles": 0,
}


def enabled() -> bool:
    return bool(getattr(settings, "OVES_HEALTH_ENABLED", False))


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


# ---------------------------------------------------------------------------
# metrics (the small per-minute record) and rolling windows
# ---------------------------------------------------------------------------

def build_metrics(codes: parsers.CodeStats, db_errors: int, probe_results: list[dict],
                  clusters: dict[str, dict], traffic: dict[str, dict],
                  hosts: list[dict]) -> dict:
    k = {}
    for name, cl in clusters.items():
        if "error" in cl:
            continue
        nodes = cl["nodes"]
        k[name] = [
            max((n.get("cpu_pct") or 0) for n in nodes) if nodes else None,
            max((n.get("mem_pct") or 0) for n in nodes) if nodes else None,
            max((n.get("disk_pct") or 0) for n in nodes) if nodes else None,
            cl["workloads"]["total"] - cl["workloads"]["ok"],
            cl["pods"]["restarted_1h"],
            sum(1 for n in nodes if not n["ready"]),
        ]
    return {
        "c_ok": codes.ok, "c_fail": codes.failed, "c_fail_sys": codes.failed_system,
        "c_lat": [int(x) for x in codes.latencies_ms[:MAX_LATENCY_SAMPLES]],
        "c_type": codes.by_type, "c_reason": codes.by_reason,
        "c_idx": codes.index_failures, "c_ot_retry": codes.opentoken_retries,
        "c_integrity": codes.integrity_warnings, "db_err": db_errors,
        "p": {r["id"]: [{"up": 1, "slow": 1, "down": 0}.get(r["status"]), r["latency_ms"]]
              for r in probe_results},
        "k": k,
        "t": {svc: [t["requests"], t["status_5xx"], t["p95_ms"],
                    t.get("real_requests", t["requests"]), t.get("real_5xx", t["status_5xx"])]
              for svc, t in traffic.items()},
        "h": {h["name"]: [h.get("cpu_pct"), h.get("cpu_credits")] for h in hosts},
    }


def code_window(rows: list[tuple[datetime, dict]], since: datetime) -> dict:
    stats = parsers.CodeStats()
    for at, m in rows:
        if at < since or not m:
            continue
        stats.ok += int(m.get("c_ok") or 0)
        stats.failed += int(m.get("c_fail") or 0)
        stats.failed_system += int(m.get("c_fail_sys") or 0)
        stats.index_failures += int(m.get("c_idx") or 0)
        stats.opentoken_retries += int(m.get("c_ot_retry") or 0)
        stats.integrity_warnings += int(m.get("c_integrity") or 0)
        stats.db_errors += int(m.get("db_err") or 0)
        stats.latencies_ms.extend(float(x) for x in (m.get("c_lat") or []))
        for key, src in (("by_type", "c_type"), ("by_reason", "c_reason")):
            target = getattr(stats, key)
            for k2, v in (m.get(src) or {}).items():
                target[k2] = target.get(k2, 0) + int(v or 0)
    out = stats.summary()
    out.pop("recent_failures", None)
    return out


def traffic_window(rows: list[tuple[datetime, dict]], since: datetime) -> dict[str, dict]:
    acc: dict[str, dict] = {}
    for at, m in rows:
        if at < since or not m:
            continue
        for svc, vals in (m.get("t") or {}).items():
            a = acc.setdefault(svc, {"requests": 0, "status_5xx": 0, "real_requests": 0,
                                     "real_5xx": 0, "p95": []})
            a["requests"] += int(vals[0] or 0)
            a["status_5xx"] += int(vals[1] or 0)
            # rows written before bot filtering have 3 fields: treat all as real
            a["real_requests"] += int((vals[3] if len(vals) > 3 else vals[0]) or 0)
            a["real_5xx"] += int((vals[4] if len(vals) > 4 else vals[1]) or 0)
            if vals[2] is not None:
                a["p95"].append(float(vals[2]))
    return {svc: {"requests": a["requests"], "status_5xx": a["status_5xx"],
                  "real_requests": a["real_requests"], "real_5xx": a["real_5xx"],
                  "bot_5xx": a["status_5xx"] - a["real_5xx"],
                  "real_error_rate": (round(a["real_5xx"] / a["real_requests"], 4)
                                      if a["real_requests"] else None),
                  "p95_ms": max(a["p95"]) if a["p95"] else None}
            for svc, a in acc.items()}


# ---------------------------------------------------------------------------
# DB reads/writes (each its own short session)
# ---------------------------------------------------------------------------

async def load_recent(now: datetime) -> tuple[list[tuple[datetime, dict]], list[dict]]:
    async with database.async_session() as db:
        rows = (await db.execute(
            select(OvesHealthSnapshot.generated_at, OvesHealthSnapshot.metrics)
            .where(OvesHealthSnapshot.generated_at >= now - RECENT_WINDOW)
            .order_by(OvesHealthSnapshot.generated_at.asc())
        )).all()
        last_payload = (await db.execute(
            select(OvesHealthSnapshot.payload)
            .where(OvesHealthSnapshot.payload.isnot(None))
            .order_by(OvesHealthSnapshot.generated_at.desc()).limit(1)
        )).scalar_one_or_none()
        await db.commit()
    alerts = (last_payload or {}).get("alerts") if isinstance(last_payload, dict) else None
    return [(g, m or {}) for g, m in rows], alerts or []


async def load_baseline(now: datetime) -> Optional[float]:
    """Average codes per hour for this UTC hour over the previous 7 days."""
    cache = _state["baseline"]
    if cache["hour"] == (now.date(), now.hour):
        return cache["value"]
    async with database.async_session() as db:
        rows = (await db.execute(
            select(OvesHealthSnapshot.generated_at,
                   OvesHealthSnapshot.metrics["c_ok"].as_integer(),
                   OvesHealthSnapshot.metrics["c_fail"].as_integer())
            .where(OvesHealthSnapshot.generated_at >= now - timedelta(days=7),
                   OvesHealthSnapshot.generated_at < now - timedelta(hours=1))
        )).all()
        await db.commit()
    per_day: dict = {}
    for at, ok, fail in rows:
        if at.hour == now.hour:
            per_day[at.date()] = per_day.get(at.date(), 0) + (ok or 0) + (fail or 0)
    value = (sum(per_day.values()) / len(per_day)) if len(per_day) >= 2 else None
    cache.update(hour=(now.date(), now.hour), value=value)
    return value


async def store(now: datetime, status: str, payload: dict, metrics: dict) -> int:
    async with database.async_session() as db:
        row = OvesHealthSnapshot(
            generated_at=now, overall_status=status[:16], payload=payload, metrics=metrics,
            codes_ok=int(metrics.get("c_ok") or 0), codes_failed=int(metrics.get("c_fail") or 0),
            codes_failed_system=int(metrics.get("c_fail_sys") or 0),
            index_failures=int(metrics.get("c_idx") or 0), db_errors=int(metrics.get("db_err") or 0),
        )
        db.add(row)
        await db.commit()
        return row.id


async def prune(now: datetime) -> None:
    async with database.async_session() as db:
        await db.execute(delete(OvesHealthSnapshot).where(
            OvesHealthSnapshot.generated_at < now - RETENTION))
        await db.execute(update(OvesHealthSnapshot)
                         .where(OvesHealthSnapshot.generated_at < now - PAYLOAD_RETENTION,
                                OvesHealthSnapshot.payload.isnot(None))
                         .values(payload=None))
        await db.commit()


# ---------------------------------------------------------------------------
# alert delivery: inbox to every admin, critical SMS, recovery notices
# ---------------------------------------------------------------------------

def _parse_iso(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", ""))
    except ValueError:
        return None


def select_due(alerts: list[dict], previous: list[dict], now: datetime,
               memory: dict) -> list[dict]:
    prev = {a["key"]: a for a in previous}
    due = []
    for a in alerts:
        last = memory.get(a["key"])
        if last is None and a["key"] in prev:
            p = prev[a["key"]]
            sent = _parse_iso(p.get("notified_at"))
            if sent:
                last = (p.get("notified_severity") or p["severity"], sent)
        if last is None:
            due.append(a)
            continue
        sev, sent = last
        escalated = rules.SEVERITY_ORDER[a["severity"]] > rules.SEVERITY_ORDER.get(sev, 0)
        if escalated or now - sent >= timedelta(minutes=rules.repeat_minutes(a["key"])):
            due.append(a)
        else:
            a["notified_at"] = _iso(sent)
            a["notified_severity"] = sev
    return due


def recovered(alerts: list[dict], previous: list[dict]) -> list[dict]:
    live = {a["key"] for a in alerts}
    return [p for p in previous
            if p["key"] not in live and p.get("notified_at")
            and p.get("severity") in ("warning", "critical")]


async def deliver(alerts: list[dict], previous: list[dict], now: datetime) -> dict:
    memory = _state["alert_memory"]
    due = select_due(alerts, previous, now, memory)
    back = recovered(alerts, previous)
    if not due and not back:
        return {"delivered": 0, "recovered": 0, "sms_queued": 0}

    parts = []
    if due:
        parts += [f"[{a['severity'].upper()}] {a['title']}: {a['message']}" for a in due]
    if back:
        parts += [""] + [f"[RECOVERED] {p['title']}" for p in back]
    parts += ["", "Open Admin > Dashboard > OVES platform health for live detail."]
    body = "\n".join(parts)[:2000]
    if due:
        worst = rules.worst(a["severity"] for a in due)
        subject = (f"[OVES {worst.upper()}] " + ", ".join(a["title"] for a in due[:3]))[:200]
    else:
        subject = ("[OVES RECOVERED] " + ", ".join(p["title"] for p in back[:3]))[:200]

    critical = [a for a in due if a["severity"] == "critical"]
    sms_phone = (getattr(settings, "OPS_ALERT_SMS_PHONE", "") or "").strip()
    sms_ids: list[int] = []
    delivered = 0
    async with database.async_session() as db:
        admin_ids = (await db.execute(
            select(User.id).where(User.role == UserRole.ADMIN).order_by(User.id)
        )).scalars().all()
        for admin_id in admin_ids:
            db.add(ResellerInboxMessage(recipient_user_id=admin_id, sender_user_id=admin_ids[0],
                                        subject=subject, body=body, sent_sms=False))
            delivered += 1
        if critical and sms_phone and admin_ids:
            from app.db.models import SmsMessage, SmsMessageKind, SmsMessageStatus
            from app.services.messaging.segments import count_segments

            sms_body = ("OVES CRITICAL: " + "; ".join(a["title"] for a in critical[:3]))[:300]
            row = SmsMessage(user_id=admin_ids[0], recipient_phone=sms_phone[:20], body=sms_body,
                             segments=count_segments(sms_body), credits_charged=0,
                             kind=SmsMessageKind.ADMIN_TO_RESELLER,
                             category=OVES_ALERT_SMS_CATEGORY, status=SmsMessageStatus.QUEUED)
            db.add(row)
            await db.flush()
            sms_ids.append(row.id)
        await db.commit()
    # --- session closed; only now may anything leave the process ---

    for a in due:
        memory[a["key"]] = (a["severity"], now)
        a["notified_at"] = _iso(now)
        a["notified_severity"] = a["severity"]
    for p in back:
        memory.pop(p["key"], None)
    if sms_ids:
        try:
            from app.services.sms_dispatch import dispatch_admin_sms_messages
            asyncio.create_task(dispatch_admin_sms_messages(
                sms_ids, settings.SMS_SENDER_ID, owner_user_id=None))
        except Exception:  # noqa: BLE001
            logger.exception("[OVES-HEALTH] could not schedule alert SMS")
    logger.warning("[OVES-HEALTH] alerts=%s recovered=%s", [a["key"] for a in due],
                   [p["key"] for p in back])
    return {"delivered": delivered, "recovered": len(back), "sms_queued": len(sms_ids)}


# ---------------------------------------------------------------------------
# collection (NO DB session open anywhere in here)
# ---------------------------------------------------------------------------

# AWS dev and Tencent are dependencies, not where codes are made: refreshing
# their full pod/deployment lists every 3 minutes instead of every minute cuts
# most of the bytes and CPU (dev alone is ~1.9 MB of pods per list).
SECONDARY_CLUSTER_REFRESH = timedelta(seconds=170)
_cluster_cache: dict[str, tuple[datetime, dict]] = {}


def _collect_blocking(now: datetime) -> dict:
    return asyncio.run(collect(now))


async def collect_off_loop(now: datetime) -> dict:
    """Run the whole collection on a worker thread with its OWN event loop.

    The app is a single uvicorn worker: anything the collector does on the
    request loop (TLS handshakes, JSON decoding of multi-MB Kubernetes lists,
    regexes over every log line) delays every reseller request. Measured on
    production 2026-10-12: /health p95 went 9 ms -> 162 ms (max 610 ms) during
    the cycle. Here the request loop only awaits a future; the GIL is handed
    back every few ms, so requests keep flowing. No DB session is touched in
    collect(), so nothing async-DB crosses loops.
    """
    return await asyncio.to_thread(_collect_blocking, now)


async def collect(now: datetime) -> dict:
    sources: dict[str, dict] = {}
    clusters: dict[str, dict] = {}
    logs: Optional[dict] = None
    timeout = float(getattr(settings, "OVES_HEALTH_PROBE_TIMEOUT_SECONDS", 10.0))

    async def one_cluster(cfg):
        cached = _cluster_cache.get(cfg.name)
        if cfg.name != "prod" and cached and now - cached[0] < SECONDARY_CLUSTER_REFRESH:
            return cfg.name, cached[1], None
        client = K8sClient(cfg)
        try:
            cl = await collectors.collect_cluster(client, now, cfg.name)
            pod_items = cl.pop("_pod_items")
            lg = None
            if cfg.name == "prod":
                lg = await collectors.collect_logs(client, cfg.name, pod_items, now)
            else:
                _cluster_cache[cfg.name] = (now, cl)
            return cfg.name, cl, lg
        finally:
            await client.aclose()

    cfgs = cluster_configs(settings)
    tasks = [one_cluster(c) for c in cfgs if c.configured]
    probe_task = probes.run_all(probes.registry(), timeout)

    aws_task = None
    instances = collectors.parse_instances(getattr(settings, "OVES_AWS_DB_INSTANCES", ""))
    if settings.OVES_AWS_ACCESS_KEY_ID and settings.OVES_AWS_SECRET_ACCESS_KEY and instances:
        aws = AwsReadOnly(settings.OVES_AWS_ACCESS_KEY_ID, settings.OVES_AWS_SECRET_ACCESS_KEY,
                          settings.OVES_AWS_DB_REGION)

        async def aws_hosts():
            try:
                return await collectors.collect_db_hosts(aws, instances, now)
            finally:
                await aws.aclose()
        aws_task = aws_hosts()

    gathered = await asyncio.gather(probe_task, *tasks,
                                    *( [aws_task] if aws_task else [] ),
                                    return_exceptions=True)
    probe_results = gathered[0] if not isinstance(gathered[0], Exception) else []
    cluster_results = gathered[1:1 + len(tasks)]
    configured = [c for c in cfgs if c.configured]
    for cfg, res in zip(configured, cluster_results):
        if isinstance(res, Exception):
            msg = f"{type(res).__name__}: {str(res)[:160]}"
            sources[f"k8s_{cfg.name}"] = {"state": "error", "error": msg}
            clusters[cfg.name] = {"error": msg}
            continue
        name, cl, lg = res
        clusters[name] = cl
        sources[f"k8s_{name}"] = {"state": "ok"}
        if lg is not None:
            logs = lg
            sources["code_logs"] = ({"state": "ok"} if not lg["errors"]
                                    else {"state": "partial", "error": lg["errors"][0]})
    for cfg in cfgs:
        if not cfg.configured:
            sources[f"k8s_{cfg.name}"] = {"state": "not_configured"}
    if "code_logs" not in sources:
        sources["code_logs"] = {"state": "not_configured" if not cfgs[0].configured else "error",
                                "error": "prod cluster unavailable"}

    hosts: list[dict] = []
    if aws_task is None:
        sources["aws_db_hosts"] = {"state": "not_configured"}
    else:
        res = gathered[-1]
        if isinstance(res, Exception):
            sources["aws_db_hosts"] = {"state": "error", "error": f"{type(res).__name__}: {str(res)[:160]}"}
        else:
            hosts = res
            sources["aws_db_hosts"] = {"state": "ok"}
    sources["probes"] = {"state": "ok" if probe_results else "error"}

    graphql = None
    apollo_keys = apollo.parse_graph_keys(getattr(settings, "OVES_APOLLO_GRAPH_KEYS", ""))
    if not apollo_keys:
        sources["apollo"] = {"state": "not_configured"}
    else:
        try:
            graphql = await apollo.cycle_summary(apollo_keys, now)   # refreshed every 5 min
            failed = (graphql or {}).get("failures") or {}
            sources["apollo"] = ({"state": "ok"} if not failed else
                                 {"state": "partial" if len(failed) < len(apollo_keys) else "error",
                                  "error": f"{len(failed)} graph(s): " + next(iter(failed.values()))})
        except Exception as exc:  # noqa: BLE001
            sources["apollo"] = {"state": "error", "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
    return {"clusters": clusters, "logs": logs, "probes": probe_results, "hosts": hosts,
            "graphql": graphql, "sources": sources}


# The services a code passes through, in order, for the panel's first view.
# (id, label, role, probe id, prod deployment, Apollo graph)
CODE_PATH = [
    ("shadow_api", "Shadow API", "Device OTP / code routes", "shadow_api", "shadow-api", None),
    ("thing_make", "Thing (make)", "Generates codes for shadow + devices", "thing_make_db",
     "thing-microservice-make", "Thing-Microservice-Shadow-A"),
    ("thing", "Thing", "Codes for ERM admin + ble-app", "thing_prod_gql", "thing-microservice",
     "Thing-Microservice-Use"),
    ("opentoken", "OpenToken", "OpenPAYGO algorithm", "opentoken_algo", "oves-open-token", None),
    ("auth", "Auth", "Login + MQTT auth", "login", "auth-microservice", "Auth-Microservice-Prod"),
    ("account", "Account", "Accounts + PAYG", "account_db", "account-microservice",
     "Account-Microservice-Prod"),
    ("mqtt", "MQTT broker", "Delivers codes to devices", "mqtt_broker", None, None),
]
_PROBE_SEV = {"up": "ok", "slow": "warning", "down": "critical", "unknown": "unknown"}
_SERVICE_SEV = {"ok": "ok", "restarting": "warning", "degraded": "warning", "down": "critical"}


def build_code_path(probe_by_id: dict, prod: Optional[dict], graphql: Optional[dict],
                    db_errors_5m: int) -> list[dict]:
    services = {s["name"]: s for s in ((prod or {}).get("services") or [])}
    graphs = {g["graph"]: g for g in ((graphql or {}).get("graphs") or [])}
    out = []
    for sid, label, role, probe_id, deploy, graph in CODE_PATH:
        probe = probe_by_id.get(probe_id) or {}
        svc = services.get(deploy) if deploy else None
        g = graphs.get(graph) if graph else None
        statuses, notes = [], []
        if probe:
            statuses.append(_PROBE_SEV.get(probe.get("status"), "unknown"))
            if probe.get("status") != "up":
                notes.append(probe.get("detail") or probe.get("status"))
        if svc:
            statuses.append(_SERVICE_SEV.get(svc["state"], "unknown"))
            if svc["state"] != "ok":
                notes.append(f"{svc['ready']}/{svc['desired']} pods ready")
        rate = None
        if g and g.get("requests"):
            rate = g.get("system_error_rate") or 0
            statuses.append("critical" if rate >= 0.10 else "warning" if rate >= 0.02 else "ok")
            if rate >= 0.02:
                top = next((e for e in g.get("top_errors") or [] if e.get("kind") == "system"), None)
                if top:
                    notes.append(str(top.get("message", ""))[:100])
        if sid == "auth" and db_errors_5m >= 5:
            statuses.append("critical")
            notes.append(f"{db_errors_5m} MongoDB errors in app logs (5 min)")
        out.append({
            "id": sid, "label": label, "role": role,
            "status": rules.worst(statuses) if statuses else "unknown",
            "pods": f"{svc['ready']}/{svc['desired']}" if svc else None,
            "restarts": svc["restarts"] if svc else None,
            "latency_ms": probe.get("latency_ms"),
            "requests_15m": g.get("requests") if g else None,
            "errors_15m": g.get("errors") if g else None,
            "error_rate": g.get("error_rate") if g else None,
            "platform_error_rate": rate,
            "note": "; ".join(n for n in notes if n)[:200] or None,
        })
    return out


def _bump(streaks: dict, key: str, firing: bool) -> None:
    if firing:
        streaks[key] = streaks.get(key, 0) + 1
    else:
        streaks.pop(key, None)


def assemble(now: datetime, collected: dict, recent: list[tuple[datetime, dict]],
             baseline: Optional[float]) -> tuple[dict, dict, list[dict]]:
    st = _state
    logs = collected["logs"]
    codes = logs["codes"] if logs else parsers.CodeStats()
    db_err_now = sum((logs or {}).get("db_errors", {}).values()) if logs else 0
    traffic_now = (logs or {}).get("traffic", {})
    metrics = build_metrics(codes, db_err_now, collected["probes"], collected["clusters"],
                            traffic_now, collected["hosts"])
    rows = recent + [(now, metrics)]

    for r in collected["probes"]:
        _bump(st["probe_streaks"], r["id"], r["status"] == "down")
        r["streak"] = st["probe_streaks"].get(r["id"], 0)
    for src, info in collected["sources"].items():
        _bump(st["source_streaks"], src, info.get("state") == "error")
    for cname, cl in collected["clusters"].items():
        if "error" in cl:
            continue
        live = {f"{cname}:{w['namespace']}/{w['name']}" for w in cl["workloads"]["problems"]
                if w["state"] == "degraded"}
        for key in list(st["degraded_streaks"]):
            if key.startswith(cname + ":") and key not in live:
                st["degraded_streaks"].pop(key)
        for key in live:
            st["degraded_streaks"][key] = st["degraded_streaks"].get(key, 0) + 1

    win5 = code_window(rows, now - timedelta(minutes=5))
    win15 = code_window(rows, now - timedelta(minutes=15))
    win60 = code_window(rows, now - timedelta(minutes=60))
    traffic5 = traffic_window(rows, now - timedelta(minutes=5))

    alerts: list[dict] = []
    if logs:
        alerts += rules.evaluate_codes(win15, win60, baseline)
    alerts += rules.evaluate_db(win5["db_errors"], collected["hosts"])
    alerts += rules.evaluate_probes(collected["probes"], st["probe_streaks"])
    for cname, cl in collected["clusters"].items():
        if "error" not in cl:
            alerts += rules.evaluate_cluster(cname, cl, st["degraded_streaks"])
    failures5 = (logs or {}).get("failures_5m") or {}
    log_errors5 = (logs or {}).get("log_errors_5m") or {}
    for svc, t in traffic5.items():
        t["top_failures"] = failures5.get(svc, [])
        t["log_errors"] = log_errors5.get(svc, [])
    alerts += rules.evaluate_traffic(traffic5)
    alerts += rules.evaluate_collectors(collected["sources"], st["source_streaks"])
    graphql = collected.get("graphql")
    if graphql:
        alerts += rules.evaluate_graphql(graphql)
    alerts.sort(key=lambda a: -rules.SEVERITY_ORDER[a["severity"]])

    def sev_for(prefix: str) -> str:
        return rules.worst(a["severity"] for a in alerts if a["section"].startswith(prefix))

    probe_by_id = {r["id"]: r for r in collected["probes"]}
    db_probe_ids = ["login", "thing_make_db", "account_db", "client_db", "client_use_db",
                    "event_db", "auth_use_db", "thing_use_db"]
    groups: dict[str, list] = {g: [] for g in probes.GROUP_LABELS}
    for r in collected["probes"]:
        groups.setdefault(r["group"], []).append(r)

    sections = {
        "codes": {
            "status": rules.worst([sev_for("codes") if logs else "unknown",
                                   sev_for("graphql.codes")]),
            # Apollo GraphOS counts every code request (all pods, errors inside
            # HTTP 200 included); preferred over the log-derived numbers.
            "apollo_15m": (graphql or {}).get("codes_15m"),
            "apollo_operations": (graphql or {}).get("code_operations") or [],
            "apollo_errors": (graphql or {}).get("code_errors") or [],
            "apollo_window": {"from": (graphql or {}).get("from"), "to": (graphql or {}).get("to")}
            if graphql else None,
            "path": build_code_path(probe_by_id, collected["clusters"].get("prod"), graphql,
                                    win5["db_errors"]),
            "available": logs is not None,
            "last_5m": win5, "last_15m": win15, "last_60m": win60,
            "baseline_per_hour": round(baseline, 1) if baseline is not None else None,
            "by_service": {svc: s.summary() for svc, s in (logs or {}).get("codes_by_service", {}).items()},
            "recent_failures": codes.samples,
            "opentoken_probe": probe_by_id.get("opentoken_algo"),
            "pods_watched": (logs or {}).get("code_pods", 0),
            "note": ("Successes = 'Request to generate* took N ms' (logged on success only). "
                     "Failures = ERROR lines from CodeEvent*/Codegen*; JWT-guard rejections "
                     "never reach them, so the failure count is a floor."),
        },
        "database": {
            "status": rules.worst([sev_for("database")] + [
                "critical" if probe_by_id.get(i, {}).get("status") == "down"
                and probe_by_id[i].get("streak", 0) >= rules.CRITICAL_PROBE_STREAK else "ok"
                for i in ("login",)]),
            "login": probe_by_id.get("login"),
            "service_checks": [probe_by_id[i] for i in db_probe_ids[1:] if i in probe_by_id],
            "log_errors_5m": win5["db_errors"], "log_errors_60m": win60["db_errors"],
            "log_errors_by_service": (logs or {}).get("db_errors", {}),
            "hosts": collected["hosts"],
            "hosts_available": collected["sources"].get("aws_db_hosts", {}).get("state") == "ok",
            "replica_set": {"available": False,
                            "note": "rs0 is private (eu-central-1). Member state comes from "
                                    "the login probe, /health/db and app-log errors."},
            "tencent_rs": probe_by_id.get("tencent_mongo"),
        },
        "clusters": {
            name: ({"status": "unknown", "error": cl["error"]} if "error" in cl else
                   {"status": sev_for(f"cluster.{name}"), **cl})
            for name, cl in collected["clusters"].items()
        },
        "traffic": {"last_5m": traffic5},
        "graphql": (
            {"available": True, "status": sev_for("graphql"), **graphql}
            if graphql else {"available": False, "status": "unknown"}
        ),
        "dependencies": {
            "status": rules.worst(a["severity"] for a in alerts if a["section"] == "dependencies"),
            "groups": [{"id": g, "label": probes.GROUP_LABELS.get(g, g),
                        "probes": sorted(items, key=lambda r: (r["status"] == "up", r["name"]))}
                       for g, items in groups.items() if items],
        },
    }
    for cfg_name in ("prod", "dev", "tencent"):
        sections["clusters"].setdefault(cfg_name, {"status": "unknown", "not_configured": True})

    overall = rules.worst([alerts[0]["severity"]] if alerts else ["ok"])
    payload = {"generated_at": _iso(now), "overall_status": overall, "sections": sections,
               "alerts": alerts, "sources": collected["sources"]}
    return payload, metrics, alerts


# ---------------------------------------------------------------------------
# scheduler entrypoint
# ---------------------------------------------------------------------------

async def run_cycle(now: Optional[datetime] = None) -> dict:
    if not enabled():
        return {"skipped": "disabled"}
    from app.services.ops_health import _db_pool_busy
    if _db_pool_busy():
        return {"skipped": "db_pool_busy"}
    now = now or datetime.utcnow()
    recent, previous_alerts = await load_recent(now)
    try:
        baseline = await load_baseline(now)
    except Exception:  # noqa: BLE001
        logger.exception("[OVES-HEALTH] baseline failed")
        baseline = None
    collected = await collect_off_loop(now)              # no session open
    payload, metrics, alerts = assemble(now, collected, recent, baseline)
    try:
        delivery = await deliver(alerts, previous_alerts, now)
    except Exception:  # noqa: BLE001
        logger.exception("[OVES-HEALTH] alert delivery failed")
        delivery = {}
    snapshot_id = await store(now, payload["overall_status"], payload, metrics)
    _state["cycles"] += 1
    if _state["cycles"] % PRUNE_EVERY == 1:
        try:
            await prune(now)
        except Exception:  # noqa: BLE001
            logger.exception("[OVES-HEALTH] prune failed")
    return {"snapshot_id": snapshot_id, "overall_status": payload["overall_status"],
            "alerts": len(alerts), **delivery}


# ---------------------------------------------------------------------------
# read side (API)
# ---------------------------------------------------------------------------

async def load_latest() -> Optional[dict]:
    async with database.async_session() as db:
        row = (await db.execute(
            select(OvesHealthSnapshot.generated_at, OvesHealthSnapshot.payload)
            .where(OvesHealthSnapshot.payload.isnot(None))
            .order_by(OvesHealthSnapshot.generated_at.desc()).limit(1)
        )).first()
        await db.commit()
    if row is None:
        return None
    payload = dict(row[1])
    payload["generated_at"] = _iso(row[0])
    return payload


HISTORY_BUCKETS = [(1, 1), (6, 5), (24, 15), (72, 60), (168, 120), (336, 240)]


def bucket_minutes(hours: int) -> int:
    for max_h, minutes in HISTORY_BUCKETS:
        if hours <= max_h:
            return minutes
    return 240


SCALAR_KEYS = ("c_ok", "c_fail", "c_fail_sys", "c_idx", "db_err")
MAX_HEAVY_ROWS = 480
HISTORY_CACHE_SECONDS = 60
_history_cache: dict[tuple, tuple[float, dict]] = {}


def aggregate_history(scalar_rows: list[tuple[datetime, dict]],
                      heavy_rows: list[tuple[datetime, dict]], start: datetime, hours: int,
                      probe_id: Optional[str] = None) -> dict:
    """Bucket per-minute metrics. Counts come from EVERY row (``scalar_rows``);
    latency, probe and cluster gauges from ``heavy_rows``, which may be a
    sample on long ranges -- fine for percentiles and uptime, wrong for sums,
    which is why the two are separate."""
    size = timedelta(minutes=bucket_minutes(hours))
    n_buckets = max(1, int(timedelta(hours=hours) / size))

    def bucketize(rows):
        out: dict[int, list[dict]] = {}
        for at, m in rows:
            idx = int((at - start) / size)
            if 0 <= idx < n_buckets:
                out.setdefault(idx, []).append(m or {})
        return out

    sb, hb = bucketize(scalar_rows), bucketize(heavy_rows)
    points = []
    probe_up: dict[str, list[int]] = {}
    probe_ms: dict[str, list[float]] = {}
    for idx in range(n_buckets):
        at = start + idx * size
        ss, hs = sb.get(idx, []), hb.get(idx, [])
        if not ss and not hs:
            points.append({"t": _iso(at), "samples": 0})
            continue
        ok = sum(int(m.get("c_ok") or 0) for m in ss)
        fail = sum(int(m.get("c_fail") or 0) for m in ss)
        lats = [float(x) for m in hs for x in (m.get("c_lat") or [])]
        point = {
            "t": _iso(at), "samples": len(ss),
            "codes_ok": ok, "codes_failed": fail,
            "codes_failed_system": sum(int(m.get("c_fail_sys") or 0) for m in ss),
            "success_rate": round(ok / (ok + fail), 4) if ok + fail else None,
            "code_p50_ms": parsers.percentile(lats, 50),
            "code_p95_ms": parsers.percentile(lats, 95),
            "index_failures": sum(int(m.get("c_idx") or 0) for m in ss),
            "db_errors": sum(int(m.get("db_err") or 0) for m in ss),
        }
        for cname in ("prod", "dev", "tencent"):
            vals = [m["k"][cname] for m in hs if cname in (m.get("k") or {})]
            if vals:
                point[f"{cname}_cpu_max"] = max((v[0] or 0) for v in vals)
                point[f"{cname}_mem_max"] = max((v[1] or 0) for v in vals)
                point[f"{cname}_disk_max"] = max((v[2] or 0) for v in vals)
                point[f"{cname}_unhealthy"] = max((v[3] or 0) for v in vals)
        up = down = down_any = 0
        lat: list[float] = []
        for m in hs:
            for pid, pair in (m.get("p") or {}).items():
                u, l = (pair + [None, None])[:2] if isinstance(pair, list) else (None, None)
                if u is not None:
                    probe_up.setdefault(pid, []).append(u)
                    if u == 0:
                        down_any += 1
                if l is not None:
                    probe_ms.setdefault(pid, []).append(l)
                if pid == probe_id:
                    up += u == 1
                    down += u == 0
                    if l is not None:
                        lat.append(l)
        point["probes_down"] = down_any
        if probe_id:
            point["probe_uptime"] = round(up / (up + down), 4) if up + down else None
            point["probe_p95_ms"] = parsers.percentile(lat, 95)
        points.append(point)
    total_ok = sum(p.get("codes_ok", 0) for p in points)
    total_fail = sum(p.get("codes_failed", 0) for p in points)
    return {
        "hours": hours, "bucket_minutes": bucket_minutes(hours), "points": points,
        "probe_uptime": {pid: round(sum(v) / len(v), 4) for pid, v in probe_up.items() if v},
        "probe_p95_ms": {pid: parsers.percentile(v, 95) for pid, v in probe_ms.items()},
        "totals": {"codes_ok": total_ok, "codes_failed": total_fail,
                   "success_rate": round(total_ok / (total_ok + total_fail), 4)
                   if total_ok + total_fail else None},
    }


async def load_history(now: datetime, hours: int, probe_id: Optional[str] = None) -> dict:
    hours = max(1, min(int(hours), int(RETENTION.total_seconds() // 3600)))
    key = (hours, probe_id)
    hit = _history_cache.get(key)
    if hit and time.monotonic() - hit[0] < HISTORY_CACHE_SECONDS:
        return hit[1]
    start = now - timedelta(hours=hours)
    stride = max(1, (hours * 60) // MAX_HEAVY_ROWS)
    m = OvesHealthSnapshot.metrics
    T = OvesHealthSnapshot
    # Columns first; the JSON path is only evaluated for rows written before
    # the columns existed (COALESCE stops at the first non-null).
    cols = [func.coalesce(T.codes_ok, m["c_ok"].as_integer()),
            func.coalesce(T.codes_failed, m["c_fail"].as_integer()),
            func.coalesce(T.codes_failed_system, m["c_fail_sys"].as_integer()),
            func.coalesce(T.index_failures, m["c_idx"].as_integer()),
            func.coalesce(T.db_errors, m["db_err"].as_integer())]
    async with database.async_session() as db:
        scalar = (await db.execute(
            select(T.generated_at, *cols).where(T.generated_at >= start)
        )).all()
        # Fetched as TEXT so the JSON is decoded on the worker thread below, not
        # by the driver on the request loop.
        heavy_q = (select(T.generated_at, cast(T.metrics, Text))
                   .where(T.generated_at >= start))
        if stride > 1:
            heavy_q = heavy_q.where(T.id % stride == 0)
        heavy = (await db.execute(heavy_q)).all()
        await db.commit()

    def build() -> dict:
        # Pre-sum the counters per chart bucket (14 days = 20k rows -> ~84 sums)
        # instead of handing aggregate_history one dict per minute.
        size_s = bucket_minutes(hours) * 60
        sums: dict[int, list[int]] = {}
        for r in scalar:
            idx = int((r[0] - start).total_seconds() // size_s)
            acc = sums.get(idx)
            if acc is None:
                acc = sums[idx] = [0] * len(SCALAR_KEYS)
            for i, v in enumerate(r[1:]):
                if v:
                    acc[i] += v
        scalar_rows = [(start + timedelta(seconds=idx * size_s), dict(zip(SCALAR_KEYS, acc)))
                       for idx, acc in sums.items()]
        heavy_rows = [(g, json.loads(txt) if txt else {}) for g, txt in heavy]
        return aggregate_history(scalar_rows, heavy_rows, start, hours, probe_id)

    # 80-145 ms of pure Python for 1-14 days (benchmarked): keep it off the loop.
    out = await asyncio.to_thread(build)
    _history_cache[key] = (time.monotonic(), out)
    if len(_history_cache) > 64:
        _history_cache.clear()
    return out
