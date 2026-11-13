"""Apollo GraphOS insights for OVES health (app/services/oves_health/apollo.py).

Raw payloads mirror real Platform API responses captured on 2026-10-12 for
Thing-Microservice-Shadow-A and Event-Microservice-Prod; no network is used.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.admin_metrics_routes as routes_module
from app.api.admin_metrics_routes import router as admin_metrics_router
from app.db.database import get_db
from app.services.auth import verify_token
from app.services.oves_health import apollo, rules, service
from tests.factories import make_admin

START = datetime(2026, 10, 12, 16, 0)
END = START + timedelta(hours=1)


def raw_shadow() -> dict:
    return {
        "operationInsightsList": {"nodes": [
            {"id": "a", "name": "GenerateDaysCode", "type": "MUTATION", "requestCount": 1123,
             "requestCountPerMin": 18.7, "errorCount": 3, "errorPercentage": 0.267,
             "serviceTimeP50Ms": None, "serviceTimeP95Ms": None},
            {"id": "b", "name": "GenerateDaysCode_V2", "type": "MUTATION", "requestCount": 1039,
             "requestCountPerMin": 17.3, "errorCount": 38, "errorPercentage": 3.66,
             "serviceTimeP50Ms": None, "serviceTimeP95Ms": None},
            {"id": "c", "name": None, "type": "QUERY", "requestCount": 9, "requestCountPerMin": 0.1,
             "errorCount": 0, "errorPercentage": 0.0, "serviceTimeP50Ms": None, "serviceTimeP95Ms": None},
        ]},
        "errorInsightsList": {"nodes": [
            {"operationName": "GenerateDaysCode_V2", "path": "generateDaysCode_v2", "code": None,
             "service": None, "errorCount": 38, "traceRefs": {"items": [
                 {"errorMessage": "Error: Minimum time lapse between codes 6 seconds.",
                  "timestamp": "2026-10-12T16:40:00Z"}]}},
            {"operationName": "GenerateDaysCode", "path": "generateDaysCode", "code": None,
             "service": None, "errorCount": 3, "traceRefs": {"items": [
                 {"errorMessage": "E11000 duplicate key error collection: thing-microservice.codeevent "
                                  "index: codeType_1_codeDays_1_codeGenerator_1_codeDec",
                  "timestamp": "2026-10-12T16:41:00Z"}]}},
        ]},
        "statsWindow": {"queryStats": [
            {"timestamp": "2026-10-12T16:00:00Z", "groupBy": {"queryName": "GenerateDaysCode"},
             "metrics": {"totalRequestCount": 20, "requestsWithErrorsCount": 1}},
            {"timestamp": "2026-10-12T16:00:00Z", "groupBy": {"queryName": "GenerateDaysCode_V2"},
             "metrics": {"totalRequestCount": 15, "requestsWithErrorsCount": 2}},
            {"timestamp": "2026-10-12T16:30:00Z", "groupBy": {"queryName": "GenerateDaysCode"},
             "metrics": {"totalRequestCount": 10, "requestsWithErrorsCount": 0}},
            {"timestamp": "2026-10-12T18:00:00Z", "groupBy": {"queryName": "GenerateDaysCode"},
             "metrics": {"totalRequestCount": 99, "requestsWithErrorsCount": 0}},   # outside window
        ]},
    }


def raw_event() -> dict:
    return {
        "operationInsightsList": {"nodes": [
            {"id": "e", "name": "CreateEvents__event_microservice_prodomnivoltaiccomgraphql__0",
             "type": "MUTATION", "requestCount": 400, "requestCountPerMin": 26.7, "errorCount": 396,
             "errorPercentage": 99.0, "serviceTimeP50Ms": None, "serviceTimeP95Ms": None}]},
        "errorInsightsList": {"nodes": [
            {"operationName": "CreateEvents__event_microservice_prodomnivoltaiccomgraphql__0",
             "path": None, "code": "GRAPHQL_VALIDATION_FAILED", "service": None, "errorCount": 792,
             "traceRefs": {"items": [{"errorMessage": '# GraphQLValidationFailure: Cannot query field '
                                                      '"microserviceEvents_2024" on type "Mutation".',
                                      "timestamp": "2026-10-12T16:50:00Z"}]}}]},
        "statsWindow": {"queryStats": []},
    }


def test_classify_real_messages():
    cases = {
        "Error: Minimum time lapse between codes 6 seconds.": ("rate_limited", "user"),
        "E11000 duplicate key error collection: thing-microservice.codeevent": ("duplicate_code", "system"),
        "Server selection timed out after 30000 ms": ("database", "system"),
        '# GraphQLValidationFailure: Cannot query field "x" on type "Mutation".': ("schema_mismatch", "system"),
        "Item with id  could not be found": ("not_found", "user"),
        "Invalid refresh token": ("unauthorized", "user"),
        "search_phase_execution_exception": ("search", "system"),
        "upstream 503 Service Unavailable": ("upstream", "system"),
    }
    for message, expected in cases.items():
        assert apollo.classify(message) == expected, message


def test_graph_keys_must_belong_to_their_graph():
    keys = apollo.parse_graph_keys(
        "Thing-Microservice-Shadow-A=service:Thing-Microservice-Shadow-A:abc,"
        "Auth-Microservice-Prod=service:Other-Graph:zzz, junk ,Zeta=service:Zeta:q")
    assert keys == {"Thing-Microservice-Shadow-A": "service:Thing-Microservice-Shadow-A:abc",
                    "Zeta": "service:Zeta:q"}
    assert apollo.ordered_graphs(keys) == ["Thing-Microservice-Shadow-A", "Zeta"]
    assert apollo.resolution_for(5) == (6, "R5M", 5)
    assert apollo.resolution_for(400) == (336, "R6H", 360)


def test_summarize_builds_studio_view_and_zero_filled_series():
    out = apollo.summarize("Thing-Microservice-Shadow-A", raw_shadow(), START, END, 15)
    assert (out["requests"], out["errors"]) == (2171, 41)
    assert out["system_errors"] == 3                      # rate-limit errors are the caller's
    assert [o["label"] for o in out["operations"]] == ["GenerateDaysCode", "GenerateDaysCode_V2", "(unnamed)"]
    assert out["operations"][0]["is_code"] and not out["operations"][2]["is_code"]
    assert out["operations"][1]["error_rate"] == pytest.approx(0.0366)
    assert [p["requests"] for p in out["series"]] == [35, 0, 10, 0]
    assert out["series"][0]["error_rate"] == pytest.approx(3 / 35, rel=1e-3)
    assert out["error_groups"][1]["reason"] == "duplicate_code"

    only = apollo.summarize("Thing-Microservice-Shadow-A", raw_shadow(), START, END, 15,
                            operation="GenerateDaysCode")
    assert only["requests"] == 1123 and [e["operation"] for e in only["error_groups"]] == ["GenerateDaysCode"]
    assert [p["requests"] for p in only["series"]] == [20, 0, 10, 0]


def test_summarize_strips_federated_suffix_and_caps_system_errors():
    out = apollo.summarize("Event-Microservice-Prod", raw_event(), START, END, 15)
    assert out["operations"][0]["label"] == "CreateEvents"
    assert out["error_groups"][0]["kind"] == "system"
    assert out["system_errors"] == 396                    # 792 errors, capped at failing requests


async def test_cycle_summary_aggregates_codes_and_reports_failures(monkeypatch):
    apollo._summary.update(at=None, data=None)

    async def fake_fetch(client, graph, key, start, end, resolution):
        if graph == "Event-Microservice-Prod":
            return raw_event()
        if graph == "Thing-Microservice-Use":
            raise apollo.ApolloError("HTTP 401")
        return raw_shadow()

    monkeypatch.setattr(apollo, "fetch_raw", fake_fetch)
    keys = {g: f"service:{g}:k" for g in ("Thing-Microservice-Shadow-A", "Thing-Microservice-Use",
                                          "Event-Microservice-Prod")}
    s = await apollo.cycle_summary(keys, datetime(2026, 10, 12, 17, 0))
    assert s["failures"] == {"Thing-Microservice-Use": "ApolloError: HTTP 401"}
    assert s["codes_15m"]["requests"] == 2162 and s["codes_15m"]["system_errors"] == 3
    assert [o["label"] for o in s["code_operations"]] == ["GenerateDaysCode", "GenerateDaysCode_V2"]
    assert s["code_errors"][0]["reason"] == "duplicate_code"     # platform errors first
    event = next(g for g in s["graphs"] if g["graph"] == "Event-Microservice-Prod")
    assert event["system_error_rate"] == pytest.approx(0.99)

    alerts = {a["key"]: a["severity"] for a in rules.evaluate_graphql(s)}
    assert alerts == {"oves.gql.Event-Microservice-Prod": "critical",
                      "oves.gql.duplicate_code": "warning"}
    apollo._summary.update(at=None, data=None)


def test_graphql_rules_ignore_caller_errors_and_flag_db_timeouts():
    summary = {"graphs": [
        {"graph": "Auth-Microservice-Prod", "label": "Auth", "requests": 500, "errors": 120,
         "system_errors": 0, "top_errors": [{"reason": "unauthorized", "kind": "user", "count": 120}]},
        {"graph": "Thing-Microservice-Shadow-A", "label": "Thing (make) · shadow", "requests": 400,
         "errors": 6, "system_errors": 6, "top_errors": [
             {"reason": "database", "kind": "system", "count": 6, "operation_label": "GenerateFreeCodeSafe",
              "message": "Server selection timed out after 30000 ms"}]}],
        "codes_15m": {"requests": 400, "errors": 6, "system_errors": 6}}
    keys = {a["key"] for a in rules.evaluate_graphql(summary)}
    assert keys == {"oves.gql.database"}                 # 1.5 % < 2 %: no rate alert; auth ignored


def test_code_path_combines_probe_pods_and_error_rate():
    probes = {"shadow_api": {"status": "up", "latency_ms": 300},
              "thing_make_db": {"status": "up", "latency_ms": 400},
              "login": {"status": "down", "detail": "timed out", "latency_ms": None}}
    prod = {"services": [
        {"name": "shadow-api", "state": "ok", "ready": 3, "desired": 3, "restarts": 0},
        {"name": "thing-microservice-make", "state": "degraded", "ready": 1, "desired": 2, "restarts": 4}]}
    graphql = {"graphs": [{"graph": "Thing-Microservice-Shadow-A", "requests": 400, "errors": 50,
                           "error_rate": 0.125, "system_error_rate": 0.12, "top_errors": [
                               {"kind": "system", "message": "E11000 duplicate key"}]}]}
    path = {p["id"]: p for p in service.build_code_path(probes, prod, graphql, 0)}
    assert list(path)[:2] == ["shadow_api", "thing_make"]
    assert path["shadow_api"]["status"] == "ok" and path["shadow_api"]["pods"] == "3/3"
    assert path["thing_make"]["status"] == "critical"
    assert "1/2 pods ready" in path["thing_make"]["note"] and "E11000" in path["thing_make"]["note"]
    assert path["auth"]["status"] == "critical"
    assert path["mqtt"]["status"] == "unknown"


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(admin_metrics_router)

    async def _override_get_db():
        async with session_factory() as s:
            yield s
            await s.commit()

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://t") as c:
        yield c


async def test_graphql_routes(db, client, monkeypatch):
    admin = await make_admin(db)

    async def _fake_user(token, db_):
        return admin
    monkeypatch.setattr(routes_module, "get_current_user", _fake_user)
    monkeypatch.setattr(service.settings, "OVES_APOLLO_GRAPH_KEYS",
                        "Thing-Microservice-Shadow-A=service:Thing-Microservice-Shadow-A:k", raising=False)

    graphs = (await client.get("/api/admin/oves-health/graphql/graphs")).json()
    assert graphs["graphs"][0]["label"] == "Thing (make) · shadow"
    assert (await client.get("/api/admin/oves-health/graphql?graph=Nope")).status_code == 404

    async def fake_insights(keys, graph, hours, operation=None, now=None):
        return apollo.summarize(graph, raw_shadow(), START, END, 15, operation)
    monkeypatch.setattr(apollo, "insights", fake_insights)
    body = (await client.get("/api/admin/oves-health/graphql?graph=Thing-Microservice-Shadow-A&hours=1")).json()
    assert body["errors"] == 41 and body["studio_url"].endswith("/insights")

    async def broken(*a, **k):
        raise apollo.ApolloError("HTTP 401")
    monkeypatch.setattr(apollo, "insights", broken)
    r = await client.get("/api/admin/oves-health/graphql?graph=Thing-Microservice-Shadow-A")
    assert r.status_code == 502 and "401" in r.json()["detail"]


def test_generated_codes_are_masked_in_error_messages():
    raw = raw_shadow()
    raw["errorInsightsList"]["nodes"][1]["traceRefs"]["items"][0]["errorMessage"] = (
        'E11000 duplicate key error collection: thing-microservice.codeevent index: x dup key: '
        '{ codeType: "DAYSCODE", codeDays: 2, codeDecString: "*035 524 761 711 716 5 10 586#", '
        'codeHexString: "abc123" }')
    out = apollo.summarize("Thing-Microservice-Shadow-A", raw, START, END, 15)
    msg = out["error_groups"][1]["message"]
    assert "035 524" not in msg and "abc123" not in msg
    assert 'codeDecString: "***"' in msg and 'codeType: "DAYSCODE"' in msg
