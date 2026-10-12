"""OVES platform health (app/services/oves_health/).

Parsers are exercised on log-line shapes copied from production
(thing-microservice-make and ingress-nginx, 2026-10-12); the full cycle runs
on the test database with collection stubbed, so no network is touched.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.admin_metrics_routes as routes_module
from app.api.admin_metrics_routes import router as admin_metrics_router
from app.db.database import get_db
from app.db.models import OvesHealthSnapshot, ResellerInboxMessage
from app.services.auth import verify_token
from app.services.oves_health import cloud, collectors, mongo_wire, parsers, probes, rules, service
from tests.factories import make_admin, make_reseller

TS = "2026-10-12T14:22:44.123456789Z"


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    service._state.update(probe_streaks={}, source_streaks={}, degraded_streaks={},
                          alert_memory={}, baseline={"hour": None, "value": None}, cycles=0)
    collectors._cursors.clear()
    service._history_cache.clear()
    service._cluster_cache.clear()
    monkeypatch.setattr(service.settings, "OVES_HEALTH_ENABLED", True, raising=False)
    monkeypatch.setattr(service.settings, "OPS_ALERT_SMS_PHONE", "", raising=False)
    import app.services.ops_health as ops_health
    monkeypatch.setattr(ops_health, "_db_pool_busy", lambda: False)
    yield


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------

def test_split_timestamp_and_cursor_drop_old_lines_and_strip_ansi():
    text = "\n".join([
        "2026-10-12T14:00:00.5Z old line",
        "2026-10-12T14:00:01.25Z \x1b[95m[Nest] 18\x1b[39m new line",
        "   continuation of the new line",
    ])
    lines, newest = parsers.lines_after(text, datetime(2026, 10, 12, 14, 0, 0, 500000))
    assert [l for _t, l in lines] == ["[Nest] 18 new line", "   continuation of the new line"]
    assert newest == datetime(2026, 10, 12, 14, 0, 1, 250000)


def test_ingress_lines_count_per_service_with_5xx_and_latency():
    raw = [
        '10.1.38.140 - - [12/Oct/2026:14:22:44 +0000] "POST /graphql HTTP/2.0" 200 32 "-" '
        '"curl/8.0.1" 261 0.006 [erm-thing-microservice-make-3101] [] 10.1.30.184:3101 32 0.006 200 a1',
        '10.1.38.140 - - [12/Oct/2026:14:22:45 +0000] "POST /graphql HTTP/2.0" 502 32 "-" '
        '"Mozilla/5.0 (x)" 261 1.500 [erm-thing-microservice-make-3101] [] 10.1.30.184:3101 32 1.5 502 a2',
        '10.1.38.140 - - [12/Oct/2026:14:22:45 +0000] "GET /x HTTP/1.1" 404 9 "-" "-" 10 0.001 '
        '[upstream-default-backend] [] - - - - a3',
        "garbage",
    ]
    traffic = parsers.parse_ingress_lines((datetime.utcnow(), l) for l in raw)
    s = traffic["thing-microservice-make"].summary()
    assert set(traffic) == {"thing-microservice-make"}
    assert (s["requests"], s["status_5xx"], s["error_rate"]) == (2, 1, 0.5)
    assert s["p95_ms"] == pytest.approx(1425.3, rel=0.01)


def _l(sec: float, text: str):
    return (datetime(2026, 10, 12, 14, 0, 0) + timedelta(seconds=sec), text)


def test_code_lines_count_successes_failures_and_side_signals():
    lines = [
        _l(0, "[Nest] 18  - 10/12/2026, 2:26:27 PM   DEBUG [RequestDurationInterceptor] Request to generateDaysCode took 2373 ms"),
        _l(1, "[Nest] 18  - DEBUG [RequestDurationInterceptor] Request to generateFreeCodeSafe took 900 ms"),
        _l(2, "[Nest] 18  - DEBUG [RequestDurationInterceptor] Request to itemBatch took 50 ms"),
        _l(3, "[Nest] 18  - ERROR [CodeEventRepository] Error: Minimum time lapse between codes 6 seconds."),
        _l(3.1, "[Nest] 18  - ERROR [CodeEventService] Error: Minimum time lapse between codes 6 seconds."),
        _l(5, '[Nest] 18  - ERROR [CodeEventService] Error: Item is not found - no item matched id "244907309"'),
        _l(6, "[Nest] 18  - ERROR [CodeEventService] Error indexing codeevent: {}"),
        _l(7, "[Nest] 18  - ERROR [CodegenService] connect ETIMEDOUT 10.0.0.1:443"),
        _l(8, "MongoServerError: not primary and secondaryOk=false"),
        _l(9, "Error on attempt 1: socket hang up"),
    ]
    s = parsers.parse_code_lines(lines, service="thing-microservice-make").summary()
    assert (s["ok"], s["failed"], s["failed_system"]) == (2, 3, 1)
    assert s["by_type"] == {"days": 1, "free": 1}
    assert s["by_reason"] == {"rate_limited": 1, "item_not_found": 1, "opentoken_service": 1}
    assert (s["index_failures"], s["db_errors"], s["opentoken_retries"]) == (1, 1, 1)
    assert s["success_rate"] == 0.4 and s["system_success_rate"] == pytest.approx(0.6667, 0.01)
    assert s["recent_failures"][1]["message"] == 'Error: Item is not found - no item matched id #'


# ---------------------------------------------------------------------------
# wire formats
# ---------------------------------------------------------------------------

def test_sigv4_matches_aws_published_get_vanilla_vector():
    # aws-sig-v4-test-suite/get-vanilla
    h = cloud.sigv4_headers("GET", "example.amazonaws.com", "us-east-1", "service", "",
                            "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                            now=datetime(2015, 8, 30, 12, 36, 0))
    assert h["Authorization"].endswith(
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")


def _fake_reply(doc_bytes: bytes) -> bytes:
    import struct
    body = struct.pack("<I", 0) + b"\x00" + doc_bytes
    return struct.pack("<iiii", 16 + len(body), 9, 1, mongo_wire.OP_MSG) + body


def test_mongo_hello_round_trip_and_replica_summary():
    msg = mongo_wire.build_hello(7)
    assert msg[12:16] == (2013).to_bytes(4, "little")
    doc = mongo_wire.encode_doc({"isWritablePrimary": True, "setName": "rs0",
                                 "primary": "mongo-1:27017", "maxWireVersion": 21})
    parsed = mongo_wire.parse_reply(_fake_reply(doc))
    assert parsed == {"isWritablePrimary": True, "setName": "rs0", "primary": "mongo-1:27017",
                      "maxWireVersion": 21}

    one = {"host": "a", "writable": True, "me": "a"}
    sec = {"host": "b", "writable": False}
    assert mongo_wire.summarize_members([one, sec])[0] == "up"
    assert mongo_wire.summarize_members([sec, dict(sec, host="c")])[0] == "down"
    assert "split brain" in mongo_wire.summarize_members([one, dict(one, host="b")])[1]
    assert mongo_wire.summarize_members([one, {"host": "c", "error": "TimeoutError"}])[0] == "slow"


def test_login_probe_interpretation_matches_the_runbook():
    assert probes.interpret_login('{"errors":[{"message":"Invalid Credentials"}]}')[0] == "up"
    assert probes.interpret_login('{"errors":[{"message":"not primary and secondaryOk=false"}]}')[0] == "down"
    assert probes.interpret_login('{"errors":[{"message":"Bad Request Exception"}]}')[0] == "unknown"


def test_registry_ids_are_unique_and_groups_labelled():
    reg = probes.registry()
    ids = [p.id for p in reg]
    assert len(ids) == len(set(ids))
    assert {p.group for p in reg} <= set(probes.GROUP_LABELS)
    assert any(p.group == "tencent" and p.critical for p in reg)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def _win(**kw):
    base = {"ok": 0, "failed": 0, "failed_system": 0, "attempts": 0, "by_reason": {},
            "p95_ms": None, "index_failures": 0}
    base.update(kw)
    base["attempts"] = base["ok"] + base["failed"]
    return base


def test_code_rules_success_rate_stall_and_slow():
    keys = lambda alerts: {a["key"] for a in alerts}  # noqa: E731
    bad = rules.evaluate_codes(_win(ok=8, failed=4, failed_system=4, by_reason={"other": 4}),
                               _win(ok=8, failed=4), None)
    assert keys(bad) == {"oves.codes.system_failures", "oves.codes.success_rate"}
    # user-caused failures (rate limit) never alert
    assert rules.evaluate_codes(_win(ok=8, failed=6, by_reason={"rate_limited": 6}),
                                _win(ok=8, failed=6), None) == []
    assert keys(rules.evaluate_codes(_win(), _win(), 40.0)) == {"oves.codes.stalled"}
    assert rules.evaluate_codes(_win(), _win(), 3.0) == []
    assert keys(rules.evaluate_codes(_win(ok=6, p95_ms=9500), _win(ok=6), None)) == {"oves.codes.slow"}


def test_probe_rules_need_consecutive_failures_and_exposure_is_inverted():
    down = {"id": "login", "name": "Login", "group": "oves_prod", "status": "down",
            "critical": True, "detail": "timed out", "depends": "all", "target": "x"}
    assert rules.evaluate_probes([down], {"login": 1}) == []
    fired = rules.evaluate_probes([down], {"login": 2})
    assert fired[0]["severity"] == "critical"
    exposed = dict(down, id="exposed_redis", name="Prod Redis :6379 public", group="exposure",
                   critical=False, target="redis:6379")
    other = dict(exposed, id="exposed_mongodb", name="MongoDB :27017 public")
    fired = rules.evaluate_probes([exposed, other], {})
    assert [a["key"] for a in fired] == ["oves.exposure.public_ports"]
    assert fired[0]["title"].startswith("2 database port(s)")


def test_db_rules_flag_credit_starvation_and_impaired_hosts():
    hosts = [{"name": "mongo1 (10.0.1.19)", "state": "running", "system_status": "ok",
              "instance_status": "impaired", "cpu_pct": 35, "cpu_credits": 0.0,
              "status_check_failed": 0}]
    keys = {a["key"]: a["severity"] for a in rules.evaluate_db(7, hosts)}
    assert keys == {"oves.db.log_errors": "critical", "oves.db.host.mongo1": "critical",
                    "oves.db.credits.mongo1": "warning"}
    # T2 Unlimited (all three members since 2026-10): 0 credits = surplus billing, not throttling
    unlimited = [dict(hosts[0], instance_status="ok", credit_mode="unlimited")]
    assert [(a["key"], a["severity"]) for a in rules.evaluate_db(0, unlimited)] == [
        ("oves.db.credits.mongo1", "info")]


def test_cluster_rules_workload_down_and_degraded_grace():
    cl = {"workloads": {"problems": [
              {"namespace": "erm", "name": "auth-microservice", "state": "down", "ready": 0, "desired": 3},
              {"namespace": "erm", "name": "thing-microservice", "state": "degraded", "ready": 3, "desired": 5}]},
          "nodes": [{"name": "n1", "ready": True, "pressure": [], "disk_pct": 93}],
          "pods": {"crashloop": [], "oom_1h": 0, "recent_restarts": []}}
    keys = {a["key"]: a["severity"] for a in rules.evaluate_cluster("prod", cl, {})}
    assert keys == {"oves.k8s.prod.workload.erm/auth-microservice": "critical",
                    "oves.k8s.prod.node.n1": "warning"}
    later = rules.evaluate_cluster("prod", cl, {"prod:erm/thing-microservice": 10})
    assert "oves.k8s.prod.workload.erm/thing-microservice" in {a["key"] for a in later}


# ---------------------------------------------------------------------------
# collectors (pure parts)
# ---------------------------------------------------------------------------

def test_workload_and_pod_summaries():
    deps = [{"metadata": {"namespace": "erm", "name": "a"}, "spec": {"replicas": 2},
             "status": {"readyReplicas": 2}},
            {"metadata": {"namespace": "erm", "name": "b"}, "spec": {"replicas": 2},
             "status": {"readyReplicas": 0}},
            {"metadata": {"namespace": "erm", "name": "z"}, "spec": {"replicas": 0}, "status": {}}]
    w = collectors.summarize_workloads(deps, [])
    assert (w["total"], w["ok"], w["down"]) == (2, 1, 1)
    now = datetime(2026, 10, 12, 12, 0)
    pods = [{"metadata": {"namespace": "erm", "name": "p1", "creationTimestamp": "2026-10-01T00:00:00Z"},
             "status": {"phase": "Running", "containerStatuses": [{
                 "restartCount": 4, "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                 "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137,
                                              "finishedAt": "2026-10-12T11:40:00Z"}}}]}}]
    p = collectors.summarize_pods(pods, now)
    assert (p["restarted_1h"], p["oom_1h"], len(p["crashloop"])) == (1, 1, 1)


def test_parse_instances_from_setting():
    assert collectors.parse_instances("mongo1 (10.0.1.19)=i-1, bad,=x,m=i-2") == [
        ("mongo1 (10.0.1.19)", "i-1"), ("m", "i-2")]


# ---------------------------------------------------------------------------
# windows + history
# ---------------------------------------------------------------------------

def test_code_window_and_history_sum_counts_from_every_row():
    t0 = datetime(2026, 10, 12, 10, 0)
    rows = [(t0 + timedelta(minutes=i), {"c_ok": 3, "c_fail": 1, "c_fail_sys": 0,
                                         "c_lat": [1000, 3000], "c_idx": 1,
                                         "p": {"login": [1, 200.0]}}) for i in range(30)]
    win = service.code_window(rows, t0 + timedelta(minutes=15))
    assert (win["ok"], win["failed"]) == (45, 15)
    scalars = [(at, {k: m.get(k) for k in service.SCALAR_KEYS}) for at, m in rows]
    hist = service.aggregate_history(scalars, rows[::5], t0, 1, probe_id="login")
    assert hist["totals"] == {"codes_ok": 90, "codes_failed": 30, "success_rate": 0.75}
    assert hist["probe_uptime"]["login"] == 1.0
    assert len(hist["points"]) == 60


def test_select_due_dedupes_escalates_and_recovers():
    now = datetime(2026, 10, 12, 10, 0)
    a = {"key": "oves.probe.login", "severity": "warning"}
    memory = {}
    assert service.select_due([dict(a)], [], now, memory) == [a]
    memory[a["key"]] = ("warning", now)
    assert service.select_due([dict(a)], [], now + timedelta(minutes=5), memory) == []
    assert service.select_due([dict(a, severity="critical")], [], now + timedelta(minutes=5), memory)
    prev = [dict(a, notified_at="2026-10-12T09:59:00Z", title="Login down")]
    assert service.recovered([], prev)[0]["title"] == "Login down"


# ---------------------------------------------------------------------------
# full cycle on the test database
# ---------------------------------------------------------------------------

def _collected(login_status="up"):
    login = {"id": "login", "name": "Login (auth -> MongoDB primary)", "group": "oves_prod",
             "kind": "login", "target": "x", "depends": "every session", "critical": True,
             "status": login_status, "latency_ms": 300.0, "http_status": 200, "detail": "d"}
    cluster = {"workloads": {"total": 1, "ok": 1, "degraded": 0, "down": 0, "problems": [], "items": []},
               "pods": {"total": 1, "running": 1, "restarted_1h": 0, "oom_1h": 0,
                        "recent_restarts": [], "crashloop": [], "pending": []},
               "nodes": [{"name": "n1", "ready": True, "pressure": [], "cpu_pct": 10.0,
                          "mem_pct": 40.0, "disk_pct": 60.0, "ip": "10.1.0.1"}]}
    codes = parsers.parse_code_lines([_l(0, "Request to generateDaysCode took 2000 ms")])
    logs = {"codes": codes, "codes_by_service": {"thing-microservice-make": codes},
            "db_errors": {}, "traffic": {}, "errors": [], "code_pods": 2}
    return {"clusters": {"prod": cluster}, "logs": logs, "probes": [login], "hosts": [],
            "sources": {"k8s_prod": {"state": "ok"}, "probes": {"state": "ok"}}}


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(admin_metrics_router)

    async def _override_get_db():
        async with session_factory() as s:
            yield s
            await s.commit()

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    return application


async def test_cycle_stores_alerts_admins_recovers_and_serves_api(db, app, monkeypatch, now):
    admin = await make_admin(db)
    reseller = await make_reseller(db)
    state = {"login": "down"}

    async def fake_collect(at):
        return _collected(state["login"])

    monkeypatch.setattr(service, "collect", fake_collect)
    now = datetime.utcnow() - timedelta(minutes=5)   # history reads relative to wall clock

    first = await service.run_cycle(now)
    assert first["overall_status"] == "ok" and first["delivered"] == 0     # 1 failure: no alert yet
    second = await service.run_cycle(now + timedelta(minutes=1))
    assert second["overall_status"] == "critical" and second["delivered"] == 1
    inbox = (await db.execute(select(ResellerInboxMessage))).scalars().all()
    assert [m.recipient_user_id for m in inbox] == [admin.id]
    assert "Login" in inbox[0].subject

    third = await service.run_cycle(now + timedelta(minutes=2))
    assert third["delivered"] == 0                                         # deduped

    state["login"] = "up"
    fourth = await service.run_cycle(now + timedelta(minutes=3))
    assert fourth["recovered"] == 1
    inbox = (await db.execute(select(ResellerInboxMessage))).scalars().all()
    assert "RECOVERED" in inbox[-1].subject

    assert (await db.execute(select(OvesHealthSnapshot))).scalars().all().__len__() == 4

    async def as_user(user):
        async def _fake(token, db_):
            return user
        monkeypatch.setattr(routes_module, "get_current_user", _fake)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await as_user(reseller)
        assert (await c.get("/api/admin/oves-health")).status_code == 403
        await as_user(admin)
        latest = (await c.get("/api/admin/oves-health")).json()
        assert latest["overall_status"] == "ok"
        assert latest["sections"]["codes"]["last_60m"]["ok"] == 4
        assert latest["sections"]["clusters"]["dev"]["not_configured"] is True
        hist = (await c.get("/api/admin/oves-health/history?hours=1&probe=login")).json()
        assert hist["totals"]["codes_ok"] == 4
        assert hist["probe_uptime"]["login"] == 0.25          # down, down, down, up


async def test_cycle_is_off_unless_enabled(monkeypatch):
    monkeypatch.setattr(service.settings, "OVES_HEALTH_ENABLED", False, raising=False)
    assert await service.run_cycle() == {"skipped": "disabled"}


def test_mqtt_connect_packet_and_connack_verdicts():
    pkt = probes.mqtt_connect_packet("c", "u", "p")
    # fixed header CONNECT, remaining length, "MQTT", level 4, user+pass+clean flags
    assert pkt[0] == 0x10 and pkt[1] == len(pkt) - 2
    assert pkt[2:8] == b"\x00\x04MQTT" and pkt[8] == 4 and pkt[9] == 0xC2
    assert probes.interpret_connack(5)[0] == "up"      # auth hook gave a verdict
    assert probes.interpret_connack(4)[0] == "up"
    assert probes.interpret_connack(3)[0] == "down"    # server unavailable


def test_key_services_lead_with_the_shadow_path_and_report_pod_state():
    now = datetime(2026, 10, 12, 12, 0)
    dep = lambda name, ready: {"metadata": {"namespace": "erm", "name": name},  # noqa: E731
                               "spec": {"replicas": 2, "selector": {"matchLabels": {"app": name}}},
                               "status": {"readyReplicas": ready}}
    pod = lambda app, n, **st: {"metadata": {"namespace": "erm", "name": f"{app}-{n}",  # noqa: E731
                                             "labels": {"app": app}, "creationTimestamp": "2026-10-10T12:00:00Z"},
                                "spec": {"nodeName": "ip-10-1-1-1"}, "status": st}
    ready = {"phase": "Running", "containerStatuses": [{"ready": True, "restartCount": 0}]}
    crash = {"phase": "Running", "containerStatuses": [{
        "ready": False, "restartCount": 7, "state": {"waiting": {"reason": "CrashLoopBackOff"}},
        "lastState": {"terminated": {"reason": "OOMKilled", "finishedAt": "2026-10-12T11:58:00Z"}}}]}
    workloads = [dep("auth-microservice", 1), dep("shadow-api", 2)]
    pods = [pod("shadow-api", "a", **ready), pod("shadow-api", "b", **ready),
            pod("auth-microservice", "a", **ready), pod("auth-microservice", "b", **crash),
            pod("auth-microservice", "old", phase="Failed")]
    svcs = collectors.key_services("prod", workloads, pods, now)
    assert [s["label"] for s in svcs] == ["Shadow API", "Auth"]
    auth = svcs[1]
    assert (auth["state"], auth["ready"], auth["restarts"], auth["dead_pods"]) == ("degraded", 1, 7, 1)
    assert auth["pods"][0]["state"] == "CrashLoopBackOff"          # problems sort first
    assert auth["pods"][0]["last_restart_reason"] == "OOMKilled"
    assert auth["pods"][0]["last_restart_ago_s"] == 120
