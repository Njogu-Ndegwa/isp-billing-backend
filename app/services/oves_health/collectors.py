"""Collectors: Kubernetes (both clusters), code generation, ingress traffic,
MongoDB hosts (AWS). Pure network I/O -- no DB session is ever open here.

Log collection keeps a per-container cursor in process memory, so each cycle
reads only the lines written since the last one (``sinceTime`` + the line's
own timestamp). On the first cycle after a restart, or for a new pod, the
window starts 65 s back -- a restart loses at most one minute of counts,
never double-counts.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from app.services.oves_health import parsers
from app.services.oves_health.k8s import K8sClient

logger = logging.getLogger(__name__)

FIRST_WINDOW = timedelta(seconds=65)
MAX_WINDOW = timedelta(minutes=10)
RECENT_RESTART = timedelta(hours=1)
PENDING_GRACE = timedelta(minutes=5)

# deployment app label -> role in the code pipeline
CODE_DEPLOYMENTS = {
    "thing-microservice-make": "devices + shadow API",
    "thing-microservice": "ERM admin + ble-app",
    "thing-use-microservice": "thing-use",
}
DB_WATCH_DEPLOYMENTS = ("auth-microservice", "client-microservice", "account-microservice")
INGRESS_SELECTOR = "app.kubernetes.io/component=controller"

_cursors: dict[tuple, datetime] = {}


def _cursor_key(cluster: str, ns: str, pod: str, container: str) -> tuple:
    return (cluster, ns, pod, container)


def _since(key: tuple, now: datetime) -> datetime:
    cur = _cursors.get(key)
    if cur is None or now - cur > MAX_WINDOW:
        return now - FIRST_WINDOW
    return cur


def _prune_cursors(live: set[tuple], cluster: str) -> None:
    for key in list(_cursors):
        if key[0] == cluster and key not in live:
            _cursors.pop(key, None)


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


async def read_new_lines(client: K8sClient, cluster: str, pod: dict, now: datetime,
                         live: set[tuple]) -> list[tuple[datetime, str]]:
    meta = pod["metadata"]
    ns, name = meta["namespace"], meta["name"]
    if (pod.get("status") or {}).get("phase") != "Running":
        return []
    container = pod["spec"]["containers"][0]["name"]
    key = _cursor_key(cluster, ns, name, container)
    live.add(key)
    since = _since(key, now)
    text = await client.pod_log(ns, name, container, since)
    lines, newest = parsers.lines_after(text, since)
    if newest is not None:
        _cursors[key] = newest
    elif key not in _cursors:
        _cursors[key] = since
    return lines


# ---------------------------------------------------------------------------
# cluster state
# ---------------------------------------------------------------------------

def summarize_workloads(deployments: list[dict], statefulsets: list[dict]) -> dict:
    items = []
    for kind, rows in (("Deployment", deployments), ("StatefulSet", statefulsets)):
        for d in rows:
            spec, st, meta = d.get("spec", {}), d.get("status", {}), d["metadata"]
            desired = int(spec.get("replicas", 1) or 0)
            ready = int(st.get("readyReplicas", 0) or 0)
            if desired == 0:
                continue
            if ready >= desired:
                state = "ok"
            elif ready == 0:
                state = "down"
            else:
                state = "degraded"
            items.append({"namespace": meta["namespace"], "name": meta["name"], "kind": kind,
                          "desired": desired, "ready": ready, "state": state})
    items.sort(key=lambda w: ({"down": 0, "degraded": 1, "ok": 2}[w["state"]],
                              w["namespace"], w["name"]))
    return {
        "total": len(items),
        "ok": sum(1 for w in items if w["state"] == "ok"),
        "degraded": sum(1 for w in items if w["state"] == "degraded"),
        "down": sum(1 for w in items if w["state"] == "down"),
        "problems": [w for w in items if w["state"] != "ok"][:40],
    }


def summarize_pods(pods: list[dict], now: datetime) -> dict:
    restarts, crashloop, pending, total_restarts_1h = [], [], [], 0
    running = 0
    for p in pods:
        meta, st = p["metadata"], p.get("status", {})
        phase = st.get("phase")
        if phase == "Running":
            running += 1
        if phase == "Succeeded":
            continue
        if phase == "Pending":
            created = _parse_time(meta.get("creationTimestamp"))
            if created and now - created > PENDING_GRACE:
                pending.append({"namespace": meta["namespace"], "pod": meta["name"]})
        for cs in st.get("containerStatuses") or []:
            waiting = (cs.get("state") or {}).get("waiting") or {}
            if waiting.get("reason") in ("CrashLoopBackOff", "ImagePullBackOff",
                                         "ErrImagePull", "CreateContainerConfigError"):
                crashloop.append({"namespace": meta["namespace"], "pod": meta["name"],
                                  "reason": waiting["reason"],
                                  "restarts": cs.get("restartCount", 0)})
            term = (cs.get("lastState") or {}).get("terminated") or {}
            finished = _parse_time(term.get("finishedAt"))
            if finished and now - finished <= RECENT_RESTART:
                total_restarts_1h += 1
                restarts.append({"namespace": meta["namespace"], "pod": meta["name"],
                                 "reason": term.get("reason") or "Error",
                                 "exit_code": term.get("exitCode"),
                                 "at": finished.isoformat() + "Z",
                                 "restarts": cs.get("restartCount", 0)})
    restarts.sort(key=lambda r: r["at"], reverse=True)
    return {"total": len(pods), "running": running, "restarted_1h": total_restarts_1h,
            "oom_1h": sum(1 for r in restarts if r["reason"] == "OOMKilled"),
            "recent_restarts": restarts[:15], "crashloop": crashloop[:15],
            "pending": pending[:15]}


def summarize_nodes(nodes: list[dict]) -> list[dict]:
    out = []
    for n in nodes:
        conds = {c["type"]: c["status"] for c in (n.get("status", {}).get("conditions") or [])}
        pressure = [t for t in ("MemoryPressure", "DiskPressure", "PIDPressure")
                    if conds.get(t) == "True"]
        out.append({
            "name": n["metadata"]["name"],
            "ready": conds.get("Ready") == "True",
            "pressure": pressure,
            "instance_type": n["metadata"].get("labels", {}).get("node.kubernetes.io/instance-type"),
            "ip": next((a["address"] for a in n.get("status", {}).get("addresses", [])
                        if a.get("type") == "InternalIP"), None),
        })
    return sorted(out, key=lambda x: x["name"])


# Named services shown first on each cluster card, most important first.
# (namespace or None for any, name match, label, role). The shadow path leads:
# devices -> shadow-api -> thing-make (codes) -> auth + account.
KEY_SERVICES: dict[str, list[tuple[Optional[str], str, str, str]]] = {
    "prod": [
        ("erm", "shadow-api", "Shadow API", "Device OTP / code routes"),
        ("erm", "thing-microservice-make", "Thing (make)", "Generates codes for shadow + devices"),
        ("erm", "auth-microservice", "Auth", "Login, MQTT auth for shadow"),
        ("erm", "account-microservice", "Account", "Accounts + PAYG for shadow"),
        ("erm", "thing-microservice", "Thing", "Codes for ERM admin + ble-app"),
        ("erm", "oves-open-token", "OpenToken", "OpenPAYGO code algorithm"),
        ("erm", "api-gateway-microservice", "Gateway", "Federated GraphQL"),
        ("erm", "client-microservice", "Client", "Customers, people"),
        ("erm", "event-microservice", "Event", "Events, telemetry"),
        ("ingress-nginx", "ingress-nginx-controller", "Ingress", "Every public request"),
    ],
    "tencent": [
        (None, "emqx", "EMQX broker", "Production MQTT"),
        (None, "wvapp", "wvapp", "Field app web layer"),
        (None, "ble-app", "ble-app", "Field app web layer"),
        (None, "abs-platform", "ABS", "Identify / top-up"),
        (None, "dirac-fed", "DIRAC", "Portal API"),
        (None, "api-gateway-microservice", "Gateway", "Dev federated GraphQL"),
    ],
    "dev": [
        (None, "keycloak", "Keycloak", "Prod signup + SSO"),
        (None, "elasticsearch", "Elasticsearch", "Prod search, code index"),
        (None, "influxdb", "InfluxDB", "Prod fleet buckets"),
        (None, "vault", "Vault", "Secrets"),
    ],
}


def _selector_matches(selector: dict, labels: dict) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def _pod_brief(p: dict, now: datetime) -> dict:
    st = p.get("status", {})
    statuses = st.get("containerStatuses") or []
    ready = sum(1 for c in statuses if c.get("ready"))
    restarts = sum(int(c.get("restartCount") or 0) for c in statuses)
    waiting = next(((c.get("state") or {}).get("waiting", {}).get("reason")
                    for c in statuses if (c.get("state") or {}).get("waiting")), None)
    last = next(((c.get("lastState") or {}).get("terminated") for c in statuses
                 if (c.get("lastState") or {}).get("terminated")), None) or {}
    started = _parse_time(st.get("startTime") or p["metadata"].get("creationTimestamp"))
    finished = _parse_time(last.get("finishedAt"))
    if waiting:
        state = waiting
    elif st.get("phase") == "Running" and statuses and ready == len(statuses):
        state = "Ready"
    else:
        state = st.get("phase") or "Unknown"
    return {
        "name": p["metadata"]["name"],
        "state": state,
        "ok": state == "Ready",
        "restarts": restarts,
        "last_restart_reason": last.get("reason"),
        "last_restart_ago_s": int((now - finished).total_seconds()) if finished else None,
        "age_s": int((now - started).total_seconds()) if started else None,
        "node": p.get("spec", {}).get("nodeName"),
    }


def key_services(cluster: str, workloads: list[dict], pods: list[dict], now: datetime) -> list[dict]:
    out, seen = [], set()
    for ns, match, label, role in KEY_SERVICES.get(cluster, []):
        candidates = [w for w in workloads
                      if (ns is None or w["metadata"]["namespace"] == ns)
                      and (w["metadata"]["name"] == match if ns else match in w["metadata"]["name"])
                      and (w["metadata"]["namespace"], w["metadata"]["name"]) not in seen]
        if not candidates:
            continue
        w = candidates[0]
        meta = w["metadata"]
        seen.add((meta["namespace"], meta["name"]))
        selector = (w.get("spec", {}).get("selector") or {}).get("matchLabels") or {}
        owned = [p for p in pods
                 if p["metadata"]["namespace"] == meta["namespace"]
                 and _selector_matches(selector, p["metadata"].get("labels") or {})]
        # Failed/Succeeded pods are dead leftovers (evictions, old jobs): count, don't list.
        leftovers = sum(1 for p in owned if (p.get("status") or {}).get("phase") in ("Failed", "Succeeded"))
        mine = [_pod_brief(p, now) for p in owned
                if (p.get("status") or {}).get("phase") not in ("Failed", "Succeeded")]
        mine.sort(key=lambda x: (x["ok"], x["name"]))
        desired = int(w.get("spec", {}).get("replicas", 1) or 0)
        ready = int(w.get("status", {}).get("readyReplicas", 0) or 0)
        state = "ok" if ready >= desired else ("down" if ready == 0 else "degraded")
        if state == "ok" and any(x["last_restart_ago_s"] is not None and x["last_restart_ago_s"] < 3600
                                 for x in mine):
            state = "restarting"
        out.append({"label": label, "role": role, "namespace": meta["namespace"],
                    "name": meta["name"], "desired": desired, "ready": ready, "state": state,
                    "restarts": sum(x["restarts"] for x in mine), "dead_pods": leftovers,
                    "pods": mine[:12]})
    return out


_NODE_QUERIES = {
    "cpu_pct": '100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])))',
    "mem_pct": "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)",
    "disk_pct": ('100 * max by (instance) (1 - node_filesystem_avail_bytes{mountpoint="/",'
                 'fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{mountpoint="/",'
                 'fstype!~"tmpfs|overlay"})'),
}


async def node_usage(client: K8sClient) -> dict[str, dict]:
    """Per-node CPU/mem/disk % from the in-cluster Prometheus, keyed by IP."""
    out: dict[str, dict] = {}
    results = await asyncio.gather(*(client.prom_query(q) for q in _NODE_QUERIES.values()),
                                   return_exceptions=True)
    for key, res in zip(_NODE_QUERIES, results):
        if isinstance(res, Exception):
            continue
        for r in res:
            ip = r["metric"].get("instance", "").split(":")[0]
            try:
                out.setdefault(ip, {})[key] = round(float(r["value"][1]), 1)
            except (KeyError, ValueError, IndexError):
                pass
    return out


async def collect_cluster(client: K8sClient, now: datetime, cluster: str = "") -> dict:
    deps, sts, pods, nodes = await asyncio.gather(
        client.list_cached("/apis/apps/v1/deployments"),
        client.list_cached("/apis/apps/v1/statefulsets"),
        client.list_cached("/api/v1/pods"),
        client.list_cached("/api/v1/nodes"),
    )
    nodes = nodes.get("items", [])
    node_list = summarize_nodes(nodes)
    try:
        usage = await node_usage(client)
    except Exception:  # noqa: BLE001
        usage = {}
    for n in node_list:
        n.update(usage.get(n["ip"] or "", {}))
    pod_items = pods.get("items", [])
    ready_nodes = [n for n in node_list if n["ready"]]
    return {
        "services": key_services(cluster, deps.get("items", []) + sts.get("items", []), pod_items, now),
        "node_summary": {
            "total": len(node_list), "ready": len(ready_nodes),
            "cpu_max": max((n.get("cpu_pct") or 0 for n in node_list), default=None),
            "mem_max": max((n.get("mem_pct") or 0 for n in node_list), default=None),
            "disk_max": max((n.get("disk_pct") or 0 for n in node_list), default=None),
            "pressure": sorted({p for n in node_list for p in n["pressure"]}),
        },
        "workloads": summarize_workloads(deps.get("items", []), sts.get("items", [])),
        "pods": summarize_pods(pod_items, now),
        "nodes": node_list,
        "_pod_items": pod_items,     # used by the log collectors, stripped before storage
    }


# ---------------------------------------------------------------------------
# logs: code generation, DB errors, ingress traffic
# ---------------------------------------------------------------------------

def _pods_of(pod_items: list[dict], namespace: str, app: str) -> list[dict]:
    return [p for p in pod_items
            if p["metadata"]["namespace"] == namespace
            and p["metadata"].get("labels", {}).get("app") == app]


async def collect_logs(client: K8sClient, cluster: str, pod_items: list[dict],
                       now: datetime) -> dict:
    live: set[tuple] = set()
    per_service: dict[str, parsers.CodeStats] = {}
    db_errors: dict[str, int] = {}
    errors: list[str] = []

    async def code_pod(app: str, pod: dict):
        lines = await read_new_lines(client, cluster, pod, now, live)
        return app, parsers.parse_code_lines(lines, service=app)

    async def db_pod(app: str, pod: dict):
        lines = await read_new_lines(client, cluster, pod, now, live)
        return app, parsers.count_db_errors(lines)

    async def ingress_pod(pod: dict):
        return await read_new_lines(client, cluster, pod, now, live)

    code_tasks = [code_pod(app, p) for app in CODE_DEPLOYMENTS
                  for p in _pods_of(pod_items, "erm", app)]
    db_tasks = [db_pod(app, p) for app in DB_WATCH_DEPLOYMENTS
                for p in _pods_of(pod_items, "erm", app)]
    ingress_pods = [p for p in pod_items
                    if p["metadata"]["namespace"] == "ingress-nginx"
                    and p["metadata"].get("labels", {}).get("app.kubernetes.io/component") == "controller"]

    results = await asyncio.gather(*code_tasks, *db_tasks,
                                   *(ingress_pod(p) for p in ingress_pods),
                                   return_exceptions=True)
    n_code, n_db = len(code_tasks), len(db_tasks)
    traffic: dict[str, parsers.ServiceTraffic] = {}
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            errors.append(f"{type(res).__name__}: {str(res)[:120]}")
            continue
        if i < n_code:
            app, stats = res
            per_service.setdefault(app, parsers.CodeStats()).merge(stats)
            db_errors[app] = db_errors.get(app, 0) + stats.db_errors
        elif i < n_code + n_db:
            app, n = res
            db_errors[app] = db_errors.get(app, 0) + n
        else:
            parsers.parse_ingress_lines(res, traffic)
    _prune_cursors(live, cluster)

    total = parsers.CodeStats()
    for stats in per_service.values():
        total.merge(stats)
    return {
        "codes": total,
        "codes_by_service": per_service,
        "db_errors": db_errors,
        "traffic": {svc: t.summary() for svc, t in sorted(traffic.items())},
        "errors": errors[:5],
        "code_pods": n_code,
    }


# ---------------------------------------------------------------------------
# MongoDB EC2 members (AWS CloudWatch + EC2 status), cached 5 minutes
# ---------------------------------------------------------------------------

_aws_cache: dict[str, Any] = {"at": None, "data": None}
AWS_REFRESH = timedelta(minutes=5)


def parse_instances(spec: str) -> list[tuple[str, str]]:
    out = []
    for part in (spec or "").split(","):
        if "=" in part:
            name, iid = part.rsplit("=", 1)
            if name.strip() and iid.strip():
                out.append((name.strip(), iid.strip()))
    return out


async def collect_db_hosts(aws, instances: list[tuple[str, str]], now: datetime) -> list[dict]:
    if _aws_cache["at"] and now - _aws_cache["at"] < AWS_REFRESH and _aws_cache["data"]:
        return _aws_cache["data"]
    ids = [iid for _n, iid in instances]
    status = await aws.instance_status(ids)
    try:
        modes = await aws.credit_modes(ids)
    except Exception:  # noqa: BLE001 - optional; non-burstable types have none
        modes = {}

    async def metrics(iid: str):
        cpu, credits, failed = await asyncio.gather(
            aws.metric_latest(iid, "CPUUtilization"),
            aws.metric_latest(iid, "CPUCreditBalance"),
            aws.metric_latest(iid, "StatusCheckFailed", stat="Maximum"),
            return_exceptions=True,
        )
        return [None if isinstance(v, Exception) else v for v in (cpu, credits, failed)]

    rows = await asyncio.gather(*(metrics(iid) for iid in ids))
    out = []
    for (name, iid), (cpu, credits, failed) in zip(instances, rows):
        st = status.get(iid, {})
        out.append({"name": name, "instance_id": iid, "state": st.get("state"),
                    "system_status": st.get("system_status"),
                    "instance_status": st.get("instance_status"),
                    "events": st.get("events") or [],
                    "cpu_pct": cpu, "cpu_credits": credits, "credit_mode": modes.get(iid),
                    "status_check_failed": failed})
    _aws_cache.update(at=now, data=out)
    return out
