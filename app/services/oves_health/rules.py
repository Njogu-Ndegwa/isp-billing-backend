"""Alert rules for OVES platform health. Pure functions over the assembled
snapshot plus rolling windows built from stored per-minute metrics.

| key                         | fires when                                              | severity |
|-----------------------------|---------------------------------------------------------|----------|
| oves.codes.system_failures  | >= 3 platform-side code failures in 15 min              | warning  |
| oves.codes.success_rate     | system success < 90 % over 15 min (>= 10 attempts)      | critical |
| oves.codes.stalled          | 0 codes in 60 min when this hour normally does >= 20    | warning  |
| oves.codes.slow             | code p95 > 8 s over 15 min (>= 5 codes)                 | warning  |
| oves.codes.index_failures   | >= 25 % of codes failed Elasticsearch indexing (60 min) | info     |
| oves.db.log_errors          | >= 5 "not primary"/selection errors in app logs, 5 min  | critical |
| oves.db.host.<name>         | MongoDB EC2 status check failing / stopped              | critical |
| oves.db.credits.<name>      | standard-mode member < 20 credits (election risk);      | warning  |
|                             | unlimited member at 0 credits (surplus billing)         | info     |
| oves.probe.<id>             | critical probe down 2 cycles / other probe down 3       | crit/warn|
| oves.exposure.<id>          | a port that must be private answers from the internet   | warning  |
| oves.k8s.<c>.workload.<w>   | workload with 0 ready replicas (or < desired 10 min)    | crit/warn|
| oves.k8s.<c>.node.<n>       | node NotReady / disk > 90 % / memory pressure           | crit/warn|
| oves.k8s.<c>.crashloop      | pods in CrashLoopBackOff / ImagePullBackOff             | warning  |
| oves.k8s.<c>.oom            | OOMKilled containers in the last hour                   | warning  |
| oves.ingress.<svc>          | 5xx > 5 % of >= 20 requests in 5 min                    | warning  |
| oves.collector.<source>     | a configured source failed 3 cycles running (blind)     | warning  |
| oves.gql.<graph>            | platform (not caller) errors on >= 2 % / 10 % of >= 50  | warn/crit|
|                             | requests in 15 min (Apollo GraphOS)                     |          |
| oves.gql.codes              | code mutations failing on the platform side >= 2 %      | crit     |
| oves.gql.database           | MongoDB timeouts / "not primary" returned to clients    | critical |
| oves.gql.duplicate_code     | E11000 duplicate code-event collisions                  | warning  |
"""

from __future__ import annotations

from typing import Optional

SEVERITY_ORDER = {"ok": 0, "info": 1, "warning": 2, "critical": 3}

CRITICAL_PROBE_STREAK = 2
PROBE_STREAK = 3
COLLECTOR_STREAK = 3
DEGRADED_GRACE_CYCLES = 10
CREDITS_WARN = 20.0
CRITICAL_NAMESPACES = {"erm", "ingress-nginx", "emqx-ce", "emqx", "data-services", "vault",
                       "elk", "kube-system", "monitoring"}

# repeat interval (minutes) for a still-firing alert, per key prefix
REPEAT_MINUTES = {
    "oves.exposure.": 24 * 60,
    "oves.db.credits.": 6 * 60,
    "oves.codes.index_failures": 12 * 60,
    "oves.collector.": 6 * 60,
    "oves.gql.duplicate_code": 6 * 60,
    "oves.gql.": 2 * 60,
}
DEFAULT_REPEAT_MINUTES = 30


def repeat_minutes(key: str) -> int:
    for prefix, minutes in REPEAT_MINUTES.items():
        if key.startswith(prefix):
            return minutes
    return DEFAULT_REPEAT_MINUTES


def _alert(key: str, severity: str, title: str, message: str, section: str) -> dict:
    return {"key": key, "severity": severity, "title": title, "message": message,
            "section": section}


def worst(statuses) -> str:
    best = "ok"
    for s in statuses:
        if SEVERITY_ORDER.get(s, 0) > SEVERITY_ORDER.get(best, 0):
            best = s
    return best


def evaluate_codes(win15: dict, win60: dict, baseline_hour: Optional[float]) -> list[dict]:
    out = []
    if win15["failed_system"] >= 3:
        out.append(_alert("oves.codes.system_failures", "warning", "Code generation errors",
                          f"{win15['failed_system']} platform-side failures in 15 min "
                          f"({', '.join(f'{k} {v}' for k, v in list(win15['by_reason'].items())[:3])})",
                          "codes"))
    attempts_sys = win15["ok"] + win15["failed_system"]
    if attempts_sys >= 10 and win15["ok"] / attempts_sys < 0.90:
        out.append(_alert("oves.codes.success_rate", "critical", "Code success rate low",
                          f"{win15['ok']}/{attempts_sys} codes succeeded in 15 min "
                          f"({100 * win15['ok'] / attempts_sys:.0f} %)", "codes"))
    if win60["attempts"] == 0 and baseline_hour is not None and baseline_hour >= 20:
        out.append(_alert("oves.codes.stalled", "warning", "No codes generated",
                          f"0 codes in the last hour; this hour usually has ~{baseline_hour:.0f}",
                          "codes"))
    if win15["ok"] >= 5 and (win15["p95_ms"] or 0) > 8000:
        out.append(_alert("oves.codes.slow", "warning", "Code generation slow",
                          f"p95 {win15['p95_ms'] / 1000:.1f} s over {win15['ok']} codes (15 min)",
                          "codes"))
    if win60["ok"] >= 20 and win60["index_failures"] >= 0.25 * win60["ok"]:
        out.append(_alert("oves.codes.index_failures", "info", "Code history indexing failing",
                          f"{win60['index_failures']} of {win60['ok']} codes not indexed in "
                          "Elasticsearch (60 min); code search is incomplete", "codes"))
    return out


def evaluate_db(db_errors_5m: int, hosts: list[dict]) -> list[dict]:
    out = []
    if db_errors_5m >= 5:
        out.append(_alert("oves.db.log_errors", "critical", "MongoDB errors in app logs",
                          f"{db_errors_5m} 'not primary' / server-selection errors in 5 min: "
                          "likely an rs0 election with a stale pod", "database"))
    for h in hosts:
        name = h["name"].split(" ")[0]
        if h.get("state") and h["state"] != "running":
            out.append(_alert(f"oves.db.host.{name}", "critical", f"DB host {h['name']} {h['state']}",
                              "MongoDB EC2 member is not running", "database"))
        elif "impaired" in (h.get("system_status"), h.get("instance_status")) or (h.get("status_check_failed") or 0) > 0:
            out.append(_alert(f"oves.db.host.{name}", "critical", f"DB host {h['name']} impaired",
                              "EC2 status check failing", "database"))
        credits = h.get("cpu_credits")
        if credits is None or credits >= CREDITS_WARN:
            continue
        if h.get("credit_mode") == "unlimited":
            # Not throttled: burst is billed as surplus credits instead.
            if credits <= 0:
                out.append(_alert(f"oves.db.credits.{name}", "info",
                                  f"DB host {h['name']} bursting on surplus credits",
                                  f"T2 Unlimited, 0 credits banked at {h.get('cpu_pct') or 0:.0f} % "
                                  "CPU: not throttled, but billed above baseline", "database"))
        else:
            out.append(_alert(f"oves.db.credits.{name}", "warning",
                              f"DB host {h['name']} out of CPU credits",
                              f"{credits:.0f} credits left at {h.get('cpu_pct') or 0:.0f} % CPU: "
                              "throttled members miss heartbeats and trigger elections", "database"))
    return out


def evaluate_probes(results: list[dict], streaks: dict[str, int]) -> list[dict]:
    out = []
    exposed = [r for r in results if r["group"] == "exposure" and r["status"] == "down"]
    if exposed:
        # One standing alert (and one inbox message a day), not one per port.
        out.append(_alert("oves.exposure.public_ports", "warning",
                          f"{len(exposed)} database port(s) open to the internet",
                          "; ".join(r["name"].replace(" public", "") for r in exposed),
                          "dependencies"))
    for r in results:
        if r["status"] != "down" or r["group"] == "exposure":
            continue
        n = streaks.get(r["id"], 0)
        need = CRITICAL_PROBE_STREAK if r["critical"] else PROBE_STREAK
        if n >= need:
            out.append(_alert(f"oves.probe.{r['id']}", "critical" if r["critical"] else "warning",
                              f"{r['name']} down",
                              f"{r['detail']} ({n} checks in a row)"
                              + (f"; affects {r['depends']}" if r.get("depends") else ""),
                              "dependencies"))
    return out


def evaluate_cluster(name: str, cl: dict, degraded_streaks: dict[str, int]) -> list[dict]:
    out = []
    for w in cl["workloads"]["problems"]:
        wid = f"{w['namespace']}/{w['name']}"
        important = w["namespace"] in CRITICAL_NAMESPACES
        if w["state"] == "down" and important:
            out.append(_alert(f"oves.k8s.{name}.workload.{wid}", "critical",
                              f"{name}: {wid} down", f"0/{w['desired']} replicas ready",
                              f"cluster.{name}"))
        elif degraded_streaks.get(f"{name}:{wid}", 0) >= DEGRADED_GRACE_CYCLES:
            out.append(_alert(f"oves.k8s.{name}.workload.{wid}", "warning",
                              f"{name}: {wid} degraded",
                              f"{w['ready']}/{w['desired']} ready for 10+ min", f"cluster.{name}"))
    for n in cl["nodes"]:
        if not n["ready"]:
            out.append(_alert(f"oves.k8s.{name}.node.{n['name']}", "critical",
                              f"{name}: node NotReady", n["name"], f"cluster.{name}"))
        elif (n.get("disk_pct") or 0) >= 90 or "DiskPressure" in n["pressure"]:
            out.append(_alert(f"oves.k8s.{name}.node.{n['name']}", "warning",
                              f"{name}: node disk {n.get('disk_pct') or '?'} %", n["name"],
                              f"cluster.{name}"))
        elif "MemoryPressure" in n["pressure"]:
            out.append(_alert(f"oves.k8s.{name}.node.{n['name']}", "warning",
                              f"{name}: node memory pressure", n["name"], f"cluster.{name}"))
    crash = cl["pods"]["crashloop"]
    if crash:
        out.append(_alert(f"oves.k8s.{name}.crashloop", "warning",
                          f"{name}: {len(crash)} pod(s) crash-looping",
                          ", ".join(f"{c['namespace']}/{c['pod']} {c['reason']}" for c in crash[:3]),
                          f"cluster.{name}"))
    if cl["pods"]["oom_1h"]:
        oom = [r for r in cl["pods"]["recent_restarts"] if r["reason"] == "OOMKilled"]
        out.append(_alert(f"oves.k8s.{name}.oom", "warning",
                          f"{name}: {cl['pods']['oom_1h']} OOM kill(s) in 1 h",
                          ", ".join(f"{r['namespace']}/{r['pod']}" for r in oom[:3]),
                          f"cluster.{name}"))
    return out


def evaluate_traffic(traffic_5m: dict[str, dict]) -> list[dict]:
    """5xx from real clients only. Scanner / crawler hits on dead URLs (e.g.
    `GET /.env` on shadow-api, ~99 % of its 5xx on 2026-10-12) are shown in the
    Errors tab but never alert. The message names the failing endpoint and the
    error the service itself logged."""
    out = []
    for svc, t in traffic_5m.items():
        real_req = t.get("real_requests", t["requests"])
        real_5xx = t.get("real_5xx", t["status_5xx"])
        if real_req < 20 or real_5xx / real_req <= 0.05:
            continue
        top = next((f for f in t.get("top_failures") or [] if not f.get("bots")), None)
        log = (t.get("log_errors") or [{}])[0].get("message")
        detail = f"{real_5xx}/{real_req} real requests failed in 5 min"
        if top:
            detail += f"; top: {top['method']} {top['route']} -> {top['status']} ({top['count']}x)"
        if log:
            detail += f"; service logged: {log[:140]}"
        if t.get("bot_5xx"):
            detail += f" (+{t['bot_5xx']} bot/scanner 5xx ignored)"
        out.append(_alert(f"oves.ingress.{svc}", "warning", f"{svc} returning 5xx",
                          detail, f"http.{svc}"))
    return out


def evaluate_collectors(sources: dict[str, dict], streaks: dict[str, int]) -> list[dict]:
    out = []
    for src, info in sources.items():
        if info.get("state") == "error" and streaks.get(src, 0) >= COLLECTOR_STREAK:
            out.append(_alert(f"oves.collector.{src}", "warning", f"Monitoring blind: {src}",
                              f"{info.get('error', 'failing')} ({streaks[src]} cycles)", "collector"))
    return out


GQL_MIN_REQUESTS = 50


def evaluate_graphql(summary: dict) -> list[dict]:
    """Rules over the Apollo 15-minute summary. Only PLATFORM errors count
    (schema mismatches, DB timeouts, duplicate keys, upstream failures);
    callers' own mistakes (bad credentials, rate limit, not found) never alert."""
    out = []
    db_hits, dup_hits = [], []
    for g in summary.get("graphs") or []:
        for e in g.get("top_errors") or []:
            if e.get("reason") == "database":
                db_hits.append((g["label"], e))
            elif e.get("reason") == "duplicate_code":
                dup_hits.append((g["label"], e))
        req, sys_err = g.get("requests") or 0, g.get("system_errors") or 0
        if req < GQL_MIN_REQUESTS or not sys_err:
            continue
        rate = sys_err / req
        if rate < 0.02:
            continue
        worst_err = next((e for e in g.get("top_errors") or [] if e.get("kind") == "system"), {})
        out.append(_alert(
            f"oves.gql.{g['graph']}", "critical" if rate >= 0.10 else "warning",
            f"{g['label']}: {rate * 100:.0f} % of requests failing",
            f"{sys_err}/{req} requests hit platform errors in 15 min; top: "
            f"{worst_err.get('operation_label', '?')}: {str(worst_err.get('message', ''))[:140]}",
            f"graphql.{g['graph']}"))
    code = summary.get("codes_15m") or {}
    if (code.get("requests") or 0) >= 20 and (code.get("system_errors") or 0) / code["requests"] >= 0.02:
        out.append(_alert("oves.gql.codes", "critical", "Code generation failing (GraphQL)",
                          f"{code['system_errors']}/{code['requests']} code requests failed on the "
                          "platform side in 15 min", "graphql.codes"))
    if db_hits:
        n = sum(e["count"] for _l, e in db_hits)
        label, e = db_hits[0]
        out.append(_alert("oves.gql.database", "critical", "MongoDB errors reaching API clients",
                          f"{n} in 15 min, e.g. {label} {e.get('operation_label')}: "
                          f"{str(e.get('message', ''))[:120]}", "graphql.database"))
    if dup_hits:
        n = sum(e["count"] for _l, e in dup_hits)
        out.append(_alert("oves.gql.duplicate_code", "warning", "Duplicate code collisions",
                          f"{n} E11000 duplicate code-event error(s) in 15 min: two generations "
                          "raced for the same code", "graphql.codes"))
    return out
