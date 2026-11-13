"""Apollo GraphOS insights for the OVES subgraphs: the same numbers Studio's
Insights page shows (requests, errors, error rate per operation, error groups
with their messages), read from the GraphOS Platform API.

Why it is needed on top of the log parser: a GraphQL error is an HTTP 200, and
many failures never reach an ``ERROR [CodeEvent...]`` log line -- e.g. the
E11000 duplicate-code collisions and the 30 s "Server selection timed out"
MongoDB errors were visible here and nowhere in the logs. Every subgraph
already reports usage to GraphOS (APOLLO_KEY / APOLLO_GRAPH_REF in its chart).

Keys: ``OVES_APOLLO_GRAPH_KEYS`` = ``Graph-Id=service:Graph-Id:...,...`` (each
graph's own key). Never called with a DB session open.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

PLATFORM_API = "https://graphql.api.apollographql.com/api/graphql"
VARIANT = "current"

# graph id -> (label, what it serves), most important first.
GRAPHS: dict[str, tuple[str, str]] = {
    "Thing-Microservice-Shadow-A": ("Thing (make) · shadow", "Codes for shadow API + devices"),
    "Thing-Microservice-Use": ("Thing · ERM / ble-app", "Codes for ERM admin + ble-app"),
    "Auth-Microservice-Prod": ("Auth", "Login, MQTT auth"),
    "Account-Microservice-Prod": ("Account", "Accounts, PAYG"),
    "Client-Microservice-Prod": ("Client", "Customers, people"),
    "Event-Microservice-Prod": ("Event", "Events, telemetry"),
    "Auth-Microservice-Shadow-AP": ("Auth (use)", "auth-use-microservice"),
    "Client-Microservice-Shadow": ("Client (use)", "client-use-microservice"),
    "Thing-Micorservice-Make": ("Thing (use)", "thing-use-microservice"),
}
CODE_GRAPHS = ("Thing-Microservice-Shadow-A", "Thing-Microservice-Use", "Thing-Micorservice-Make")
CODE_OPERATION_RE = re.compile(r"^(generate|opentoken|batchcode|createbatchcode)", re.I)

# (hours, Resolution enum, bucket minutes) -- Studio's choices for each range.
RANGES = {1: ("R1M", 1), 6: ("R5M", 5), 24: ("R15M", 15), 72: ("R1H", 60),
          168: ("R6H", 360), 336: ("R6H", 360)}
CACHE_SECONDS = 60

# Error-message classes: caller-caused vs platform. Order matters.
_ERROR_CLASSES = [
    ("rate_limited", "user", re.compile(r"Minimum time lapse", re.I)),
    ("schema_mismatch", "system", re.compile(r"GraphQLValidationFailure|Cannot query field|"
                                             r"Unknown argument|Unknown type", re.I)),
    ("duplicate_code", "system", re.compile(r"E11000 duplicate key", re.I)),
    ("database", "system", re.compile(
        r"Server selection timed out|not primary|secondaryOk|NotWritablePrimary|MongoNetwork|"
        r"connection .* (closed|timed out)", re.I)),
    ("search", "system", re.compile(r"search_phase_execution_exception|query_shard_exception|"
                                    r"index_not_found", re.I)),
    ("not_found", "user", re.compile(r"not (be )?found|could not be found|does not exist", re.I)),
    ("unauthorized", "user", re.compile(r"Unauthori[sz]ed|Forbidden|Invalid Credentials|jwt|"
                                        r"refresh token|token expired", re.I)),
    ("validation", "user", re.compile(r"Bad Request|validation|must be|is required|Variable \"|"
                                      r"got invalid value|does not contain any", re.I)),
    ("not_owner", "user", re.compile(r"does not own|DISTRIBUTOR_DOES_NOT_OWN", re.I)),
    ("limit_reached", "user", re.compile(r"limit|exceed", re.I)),
    ("upstream", "system", re.compile(r"ECONNREFUSED|ETIMEDOUT|ENOTFOUND|socket hang up|timeout|"
                                      r"\b50[234]\b", re.I)),
]
_FEDERATED_SUFFIX = re.compile(r"__[a-z0-9_]+__\d+$", re.I)


# Generated codes are device credentials; never show them, even to admins.
_CODE_VALUE = re.compile(r'(code(?:Dec|Hex)String"?\s*:\s*)"[^"]*"', re.I)


def mask_codes(message: str) -> str:
    return _CODE_VALUE.sub(lambda m: m.group(1) + '"***"', message or "")


def display_name(name: Optional[str]) -> str:
    """Gateway fetches arrive as `Op__thing_microservice_prodomnivoltaiccomgraphql__0`."""
    if not name:
        return "(unnamed)"
    return _FEDERATED_SUFFIX.sub("", name) or name


def classify(message: str) -> tuple[str, str]:
    for reason, kind, rx in _ERROR_CLASSES:
        if rx.search(message or ""):
            return reason, kind
    return "other", "system"


def parse_graph_keys(spec: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (spec or "").split(","):
        if "=" not in part:
            continue
        graph, key = part.split("=", 1)
        graph, key = graph.strip(), key.strip()
        if graph and key.startswith(f"service:{graph}:"):
            out[graph] = key
    return out


def ordered_graphs(keys: dict[str, str]) -> list[str]:
    known = [g for g in GRAPHS if g in keys]
    return known + sorted(g for g in keys if g not in GRAPHS)


def resolution_for(hours: int) -> tuple[int, str, int]:
    for h in sorted(RANGES):
        if hours <= h:
            return h, *RANGES[h]
    return 336, *RANGES[336]


def _ts(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat() + "Z"


INSIGHTS_QUERY = """
query OvesInsights($graph: ID!, $from: Timestamp!, $to: Timestamp!, $resolution: Resolution!) {
  graph(id: $graph) {
    variant(name: "current") {
      operationInsightsList(from: $from, to: $to, first: 60,
                            orderBy: {column: REQUEST_COUNT, direction: DESCENDING}) {
        nodes { id name type requestCount requestCountPerMin errorCount errorPercentage
                serviceTimeP50Ms serviceTimeP95Ms }
      }
      errorInsightsList(from: $from, to: $to, first: 60,
                        groupBy: [OPERATION_NAME, PATH, CODE, SERVICE],
                        orderBy: {column: COUNT, direction: DESCENDING}) {
        nodes { operationName path code service errorCount
                traceRefs(limit: 3) { items { errorMessage timestamp } } }
      }
    }
    statsWindow(from: $from, to: $to, resolution: $resolution) {
      queryStats(filter: {schemaTag: "current"}, limit: 10000) {
        timestamp
        groupBy { queryName }
        metrics { totalRequestCount requestsWithErrorsCount }
      }
    }
  }
}
"""


def _tls():
    from app.services.oves_health.probes import shared_tls
    return shared_tls()


class ApolloError(RuntimeError):
    pass


async def fetch_raw(client: httpx.AsyncClient, graph: str, key: str, start: datetime,
                    end: datetime, resolution: str) -> dict:
    resp = await client.post(PLATFORM_API, json={
        "query": INSIGHTS_QUERY,
        "variables": {"graph": graph, "from": _ts(start), "to": _ts(end), "resolution": resolution},
    }, headers={"X-API-KEY": key, "apollographql-client-name": "bitwave-oves-health",
                "apollographql-client-version": "1"})
    if resp.status_code >= 400:
        raise ApolloError(f"HTTP {resp.status_code}")
    body = resp.json()
    if body.get("errors"):
        raise ApolloError(str(body["errors"][0].get("message", "error"))[:160])
    graph_data = (body.get("data") or {}).get("graph") or {}
    variant = graph_data.get("variant")
    if variant is None:
        raise ApolloError("graph or variant not visible to this key")
    variant["statsWindow"] = graph_data.get("statsWindow") or {}
    return variant


def summarize(graph: str, variant: dict, start: datetime, end: datetime, bucket_minutes: int,
              operation: Optional[str] = None) -> dict:
    """Shape one graph's raw insights into the panel's contract."""
    ops = []
    for n in (variant.get("operationInsightsList") or {}).get("nodes") or []:
        name = n.get("name") or "(unnamed)"
        ops.append({
            "name": name, "label": display_name(name), "type": (n.get("type") or "").lower(),
            "requests": int(n.get("requestCount") or 0),
            "requests_per_min": round(float(n.get("requestCountPerMin") or 0), 2),
            "errors": int(n.get("errorCount") or 0),
            "error_rate": round(float(n.get("errorPercentage") or 0) / 100, 5)
            if n.get("errorPercentage") is not None else None,
            "p50_ms": n.get("serviceTimeP50Ms"), "p95_ms": n.get("serviceTimeP95Ms"),
            "is_code": bool(CODE_OPERATION_RE.match(display_name(name))),
        })

    errors = []
    for n in (variant.get("errorInsightsList") or {}).get("nodes") or []:
        op_name = n.get("operationName") or "(unnamed)"
        if operation and op_name != operation:
            continue
        refs = ((n.get("traceRefs") or {}).get("items") or [])
        messages = [r.get("errorMessage") for r in refs if r.get("errorMessage")]
        message = mask_codes(messages[0]) if messages else (n.get("code") or "(no message reported)")
        reason, kind = classify(message)
        last = max((r.get("timestamp") for r in refs if r.get("timestamp")), default=None)
        errors.append({
            "operation": op_name, "operation_label": display_name(op_name),
            "path": n.get("path"), "code": n.get("code"),
            "service": n.get("service"), "count": int(n.get("errorCount") or 0),
            "message": message[:400], "reason": reason, "kind": kind, "last_seen": last,
            "is_code": bool(CODE_OPERATION_RE.match(display_name(op_name))),
        })

    # Request/error series: Studio buckets, zero-filled so the chart has a real x axis.
    size = timedelta(minutes=bucket_minutes)
    n_buckets = max(1, int((end - start) / size))
    series = [{"t": _ts(start + i * size), "requests": 0, "errors": 0} for i in range(n_buckets)]
    window = (variant.get("statsWindow") or {}).get("queryStats") or []
    for row in window:
        name = ((row.get("groupBy") or {}).get("queryName")) or "(unnamed)"
        if operation and name != operation:
            continue
        try:
            at = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00")).replace(tzinfo=None)
        except (KeyError, ValueError):
            continue
        idx = int((at - start) / size)
        if 0 <= idx < n_buckets:
            m = row.get("metrics") or {}
            series[idx]["requests"] += int(m.get("totalRequestCount") or 0)
            series[idx]["errors"] += int(m.get("requestsWithErrorsCount") or 0)
    for p in series:
        p["error_rate"] = round(p["errors"] / p["requests"], 5) if p["requests"] else None

    shown = [o for o in ops if not operation or o["name"] == operation]
    requests = sum(o["requests"] for o in shown)
    errors_total = sum(o["errors"] for o in shown)
    system_errors = min(sum(e["count"] for e in errors if e["kind"] == "system"), errors_total)
    label, role = GRAPHS.get(graph, (graph, ""))
    return {
        "graph": graph, "label": label, "role": role, "operation": operation,
        "from": _ts(start), "to": _ts(end), "bucket_minutes": bucket_minutes,
        "requests": requests, "errors": errors_total,
        "error_rate": round(errors_total / requests, 5) if requests else None,
        "system_errors": system_errors,
        "operations": ops, "error_groups": errors, "series": series,
        "studio_url": (f"https://studio.apollographql.com/graph/{graph}/variant/{VARIANT}/insights"
                       + (f"?queryName={operation}" if operation else "")),
    }


# ---------------------------------------------------------------------------
# cached reads (API) and the per-cycle summary (alerts)
# ---------------------------------------------------------------------------

_cache: dict[tuple, tuple[float, dict]] = {}
_lock = asyncio.Lock()


async def insights(keys: dict[str, str], graph: str, hours: int,
                   operation: Optional[str] = None, now: Optional[datetime] = None) -> dict:
    if graph not in keys:
        raise ApolloError("graph not configured")
    hours, resolution, bucket = resolution_for(hours)
    cache_key = (graph, hours, operation)
    hit = _cache.get(cache_key)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    async with _lock:
        hit = _cache.get(cache_key)
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            return hit[1]
        end = (now or datetime.utcnow()).replace(second=0, microsecond=0)
        start = end - timedelta(hours=hours)
        async with httpx.AsyncClient(timeout=30, verify=_tls()) as client:
            variant = await fetch_raw(client, graph, keys[graph], start, end, resolution)
        out = summarize(graph, variant, start, end, bucket, operation)
        _cache[cache_key] = (time.monotonic(), out)
        if len(_cache) > 200:
            for k, _v in sorted(_cache.items(), key=lambda kv: kv[1][0])[:100]:
                _cache.pop(k, None)
        return out


def graph_list(keys: dict[str, str]) -> list[dict]:
    return [{"graph": g, "label": GRAPHS.get(g, (g, ""))[0], "role": GRAPHS.get(g, (g, ""))[1]}
            for g in ordered_graphs(keys)]


SUMMARY_EVERY = timedelta(minutes=5)
_summary: dict[str, Any] = {"at": None, "data": None}


async def cycle_summary(keys: dict[str, str], now: datetime) -> Optional[dict]:
    """Last-15-minute picture of every graph, refreshed every 5 minutes, for
    the snapshot (tiles + alerts). Failures per graph are reported, not raised."""
    if _summary["at"] and now - _summary["at"] < SUMMARY_EVERY:
        return _summary["data"]
    end = now.replace(second=0, microsecond=0)
    start = end - timedelta(minutes=15)
    graphs = ordered_graphs(keys)

    async with httpx.AsyncClient(timeout=30, verify=_tls()) as client:
        async def one(g: str):
            try:
                raw = await fetch_raw(client, g, keys[g], start, end, "R5M")
                return g, summarize(g, raw, start, end, 5), None
            except Exception as exc:  # noqa: BLE001
                return g, None, f"{type(exc).__name__}: {str(exc)[:120]}"
        results = await asyncio.gather(*(one(g) for g in graphs))

    per_graph, failures = [], {}
    code_ops: list[dict] = []
    code_errors: list[dict] = []
    code = {"requests": 0, "errors": 0, "system_errors": 0}
    for g, s, err in results:
        if err:
            failures[g] = err
            continue
        top = sorted(s["error_groups"], key=lambda e: -e["count"])[:5]
        if g in CODE_GRAPHS:
            for o in s["operations"]:
                if o["is_code"] and o["requests"]:
                    code_ops.append({**o, "graph": g, "graph_label": s["label"]})
            code_errors.extend({**e, "graph": g, "graph_label": s["label"]}
                               for e in s["error_groups"] if e["is_code"])
        per_graph.append({"graph": g, "label": s["label"], "role": s["role"],
                          "requests": s["requests"], "errors": s["errors"],
                          "error_rate": s["error_rate"], "system_errors": s["system_errors"],
                          "system_error_rate": (round(s["system_errors"] / s["requests"], 5)
                                                if s["requests"] else None),
                          "top_errors": top})
        if g in CODE_GRAPHS:
            code["requests"] += sum(o["requests"] for o in s["operations"] if o["is_code"])
            code["errors"] += sum(o["errors"] for o in s["operations"] if o["is_code"])
            n_code_errors = sum(o["errors"] for o in s["operations"] if o["is_code"])
            code["system_errors"] += min(n_code_errors, sum(
                e["count"] for e in s["error_groups"] if e["is_code"] and e["kind"] == "system"))
    code["success_rate"] = (round(1 - code["errors"] / code["requests"], 5)
                            if code["requests"] else None)
    code["system_success_rate"] = (round(1 - code["system_errors"] / code["requests"], 5)
                                   if code["requests"] else None)
    code["error_rate"] = round(code["errors"] / code["requests"], 5) if code["requests"] else None
    code["system_error_rate"] = (round(code["system_errors"] / code["requests"], 5)
                                 if code["requests"] else None)
    code_ops.sort(key=lambda o: -o["requests"])
    code_errors.sort(key=lambda e: (e["kind"] != "system", -e["count"]))
    data = {"from": _ts(start), "to": _ts(end), "graphs": per_graph, "failures": failures,
            "codes_15m": code, "code_operations": code_ops[:12], "code_errors": code_errors[:10]}
    _summary.update(at=now, data=data)
    return data
