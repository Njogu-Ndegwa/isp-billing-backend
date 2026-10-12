"""Black-box probes: every external endpoint OVES (and this app) depends on.

Each probe answers "would a real user of this service succeed right now?",
not "is the port open". The rules that matter, from the OVES runbook:

* The federated gateway, frontends and subgraphs all keep returning 200 during
  a total MongoDB outage. Only the bogus-login probe (``signInUser`` is
  unauthenticated and reads the users collection) proves the DB chain works:
  "Invalid Credentials" = healthy, "not primary" = failover not finished.
* ``/health/db`` (account, client, event, thing-use, auth-use, alpha-thing)
  pings Mongo from inside the service with a 5 s timeout -> 503 on failure.
* The OpenToken algorithm service is a pure function, so a fixed request has a
  fixed answer: the probe checks the TOKEN, not just the status code.
* ``open-token-microservice`` answers ``GET /`` with a 500 by design
  ("dbUri was not passed") -- that 500 means the process is up.
* ``exposure`` probes are inverted: an open port there is the alarm.

Never called with a DB session open.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

GROUP_LABELS = {
    "oves_prod": "OVES production",
    "oves_dev": "AWS dev cluster (production depends on it)",
    "tencent": "Tencent Cloud (TKE oves-dev, Singapore)",
    "third_party": "Third-party services",
    "bitwave": "Bitwave platform dependencies",
    "exposure": "Exposure checks",
}

LOGIN_PROBE_QUERY = (
    "mutation($c:SignInCredentialsDto!){signInUser(signInCredentials:$c){__typename}}"
)
# Strong-format password on purpose: a weak one is rejected by NestJS
# validation BEFORE any DB query and would look healthy during an outage.
LOGIN_PROBE_VARIABLES = {"c": {"email": "healthprobe@omnivoltaic.com",
                               "password": "Pr0be#Health9xQ!"}}
OPENTOKEN_PROBE_BODY = {"token_value": 1, "secret_key": "000102030405060708090a0b0c0d0e0f",
                        "starting_code": 123456789, "max_count": 1, "token_type": "ADD_TIME"}
OPENTOKEN_PROBE_EXPECTED = "198376790"


@dataclass(frozen=True)
class Probe:
    id: str
    name: str
    group: str
    kind: str                      # http | tcp | login | opentoken | statuspage | tcp_closed
    target: str                    # URL, or host:port for tcp kinds
    depends: str = ""              # who breaks when this breaks
    method: str = "GET"
    body: Optional[dict] = None
    expect_status: tuple[int, ...] = (200,)
    expect_text: str = ""
    critical: bool = False         # down -> critical alert (else warning)
    slow_ms: int = 3000


P = Probe
REGISTRY: list[Probe] = [
    # --- OVES production (EKS oves-prod, us-east-1) -------------------------
    P("login", "Login (auth -> MongoDB primary)", "oves_prod", "login",
      "https://federated-graphql-api.omnivoltaic.com/graphql",
      "Every ERM / distributor / app session", critical=True, slow_ms=4000),
    P("opentoken_algo", "OpenToken code algorithm", "oves_prod", "opentoken",
      "https://open-token.omnivoltaic.com/operate_token/",
      "Every OpenToken (OpenPAYGO) code", critical=True),
    P("thing_make_db", "Code generation service (thing-make)", "oves_prod", "http",
      "https://alpha-thing-microservice.omnivoltaic.com/health/db",
      "Device + shadow-API code generation", expect_text='"ok"', critical=True),
    P("thing_prod_gql", "thing-microservice (GraphQL)", "oves_prod", "http",
      "https://thing-microservice-prod.omnivoltaic.com/graphql",
      "ERM admin + ble-app code generation", method="POST",
      body={"query": "{__typename}"}, expect_text="__typename", critical=True),
    P("thing_use_db", "thing-use-microservice", "oves_prod", "http",
      "https://thing-use-microservice-prod.omnivoltaic.com/health/db", expect_text='"ok"'),
    P("account_db", "account-microservice", "oves_prod", "http",
      "https://account-microservice-prod.omnivoltaic.com/health/db", expect_text='"ok"'),
    P("client_db", "client-microservice", "oves_prod", "http",
      "https://client-microservice-prod.omnivoltaic.com/health/db", expect_text='"ok"'),
    P("client_use_db", "client-use-microservice", "oves_prod", "http",
      "https://client-use-microservice-prod.omnivoltaic.com/health/db", expect_text='"ok"'),
    P("event_db", "event-microservice", "oves_prod", "http",
      "https://event-microservice-prod.omnivoltaic.com/health/db", expect_text='"ok"'),
    P("auth_use_db", "auth-use-microservice", "oves_prod", "http",
      "https://auth-use-microservice-prod.omnivoltaic.com/health/db", expect_text='"ok"'),
    P("emqx_auth", "MQTT auth hook (EMQX -> auth)", "oves_prod", "http",
      "https://auth-microservice-prod.omnivoltaic.com/emqx-auth",
      "Every MQTT device connect", expect_text='"ok"', critical=True),
    P("open_token_store", "open-token-microservice", "oves_prod", "http",
      "https://open-token-microservice-prod.omnivoltaic.com/",
      "OpenToken secret sharing", expect_status=(500,), expect_text="dbUri"),
    P("shadow_api", "Shadow API (devices)", "oves_prod", "http",
      "https://api.omnivoltaic.com/", "Device OTP / code routes", expect_text="Welcome"),
    P("erm_admin", "ERM admin", "oves_prod", "http", "https://erm-admin.omnivoltaic.com/"),
    P("erm_distributor", "ERM distributor", "oves_prod", "http", "https://erm.omnivoltaic.com/"),
    P("dirac_fed", "dirac-fed", "oves_prod", "http", "https://dirac-fed.omnivoltaic.com/"),
    P("abs_platform", "ABS platform", "oves_prod", "http",
      "https://abs-platform-prod.omnivoltaic.com/"),

    # --- AWS dev cluster (EKS oves-dev): production still depends on these ---
    P("keycloak", "Keycloak", "oves_dev", "http",
      "https://keycloak.omnivoltaic.com/realms/master/.well-known/openid-configuration",
      "Prod client signup (signUpClient rolls back on failure), SSO",
      expect_text="issuer", critical=True),
    P("elasticsearch", "Elasticsearch", "oves_dev", "http",
      "https://elasticsearch.omnivoltaic.com/_cluster/health",
      "Prod agent + asset-account search, code-event index", expect_text='"timed_out":false'),
    P("influxdb", "InfluxDB (fluxdb)", "oves_dev", "http", "https://fluxdb.omnivoltaic.com/health",
      "Prod createItemFleet (bucket per fleet), aaas-dashboard", expect_text="pass"),
    P("vault", "Vault", "oves_dev", "http", "https://vault.omnivoltaic.com/v1/sys/health",
      "Secrets", expect_text='"sealed":false'),
    P("rabbitmq", "RabbitMQ (dev)", "oves_dev", "http", "https://rabbitmq.omnivoltaic.com/api/overview",
      expect_status=(401,)),
    P("app_policy", "App policy server", "oves_dev", "http", "https://app-policy.omnivoltaic.com/"),
    P("n8n", "n8n flows", "oves_dev", "http", "https://flows.omnivoltaic.com/healthz",
      expect_text='"ok"'),
    P("node_red", "Node-RED biz flows", "oves_dev", "http", "https://biz-flows.omnivoltaic.com/"),
    P("odoo_dev", "Odoo self-hosted (dev/test)", "oves_dev", "http",
      "https://odoo.omnivoltaic.com/web/health", "Dev/test only", expect_text="pass"),

    # --- third party ------------------------------------------------------
    P("odoo_crm", "Odoo SaaS (crm-omnivoltaic)", "third_party", "http",
      "https://crm-omnivoltaic.odoo.com/web/health",
      "Portal orders, ble-app sales, dirac-fed", expect_text="pass", critical=True, slow_ms=6000),
    P("ghcr", "GitHub container registry", "third_party", "http", "https://ghcr.io/v2/",
      "Every OVES deploy and pod restart (image pulls)", expect_status=(401,)),
    P("github_status", "GitHub", "third_party", "statuspage",
      "https://www.githubstatus.com/api/v2/status.json", "CI / deploys"),
    P("cloudflare_status", "Cloudflare", "third_party", "statuspage",
      "https://www.cloudflarestatus.com/api/v2/status.json", "DNS + proxy for both platforms"),
    P("tapd", "TAPD", "third_party", "http", "https://www.tapd.cn/",
      "Tasks, software-factory webhooks", expect_status=(200, 301, 302), slow_ms=8000),
    P("wecom", "WeCom", "third_party", "http", "https://work.weixin.qq.com/",
      "Team comms + approvals", expect_status=(200, 301, 302), slow_ms=8000),

    # --- Bitwave (this platform) dependencies --------------------------------
    P("mpesa_daraja", "M-Pesa Daraja API", "bitwave", "http",
      "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
      "STK push, C2B, B2B payouts", expect_status=(400, 401), critical=True),
    P("aws_transit", "AWS standby (router transit)", "bitwave", "tcp", "54.91.202.229:22",
      "Routers without a native Hetzner path"),

    # --- exposure (open = bad) --------------------------------------------
    P("exposed_mongodb", "data-services MongoDB :27017 public", "exposure", "tcp_closed",
      "adc391d8dd57847bba76e1f98dff089f-321199037.us-east-1.elb.amazonaws.com:27017",
      "Should not be reachable from the internet"),
    P("exposed_redis", "Prod Redis :6379 public", "exposure", "tcp_closed",
      "redis.omnivoltaic.com:6379", "Should not be reachable from the internet"),
    P("exposed_tencent_mongo", "Tencent dev MongoDB :27017 public", "exposure", "tcp_closed",
      "mongo-1.dev.global.omnivoltaic.com:27017", "Should not be reachable from the internet"),
    P("exposed_dev_mongo", "AWS dev MongoDB EC2 :27017 public", "exposure", "tcp_closed",
      "3.64.251.128:27017", "Should not be reachable from the internet"),
]


def registry() -> list[Probe]:
    from app.services.oves_health.tencent_probes import TENCENT_PROBES
    return REGISTRY + TENCENT_PROBES


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

def _result(probe: Probe, status: str, latency_ms: Optional[float], detail: str,
            http_status: Optional[int] = None) -> dict:
    if status == "up" and latency_ms is not None and latency_ms > probe.slow_ms:
        status = "slow"
    return {
        "id": probe.id, "name": probe.name, "group": probe.group, "kind": probe.kind,
        "target": probe.target, "depends": probe.depends, "critical": probe.critical,
        "status": status, "latency_ms": round(latency_ms, 1) if latency_ms is not None else None,
        "http_status": http_status, "detail": detail[:200],
    }


async def _tcp(host: str, port: int, timeout: float) -> float:
    start = time.perf_counter()
    _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    elapsed = (time.perf_counter() - start) * 1000
    w.close()
    try:
        await w.wait_closed()
    except Exception:  # noqa: BLE001
        pass
    return elapsed


def mqtt_connect_packet(client_id: str = "bitwave-health-probe",
                        username: str = "healthprobe@omnivoltaic.com",
                        password: str = "Pr0be#Health9xQ!") -> bytes:
    """MQTT 3.1.1 CONNECT with bogus credentials (clean session, 10 s keepalive)."""
    def s(v: str) -> bytes:
        b = v.encode()
        return len(b).to_bytes(2, "big") + b
    var = s("MQTT") + bytes([4, 0xC2]) + (10).to_bytes(2, "big")
    payload = s(client_id) + s(username) + s(password)
    body = var + payload
    n, rl = len(body), b""
    while True:
        byte, n = n % 128, n // 128
        rl += bytes([byte | (0x80 if n else 0)])
        if not n:
            break
    return b"\x10" + rl + body


def interpret_connack(rc: int) -> tuple[str, str]:
    # 4 = bad username/password, 5 = not authorized: the broker asked
    # auth-microservice and got a verdict, so broker AND auth chain work.
    if rc in (4, 5):
        return "up", f"broker + auth hook answered (CONNACK {rc})"
    if rc == 0:
        return "up", "CONNACK 0 (probe credentials accepted?!)"
    if rc == 3:
        return "down", "CONNACK 3: server unavailable"
    return "down", f"CONNACK {rc}"


async def mqtt_connect(host: str, port: int, timeout: float) -> tuple[float, int]:
    start = time.perf_counter()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(mqtt_connect_packet())
        await writer.drain()
        ack = await asyncio.wait_for(reader.readexactly(4), timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    if ack[0] != 0x20:
        raise ValueError("not a CONNACK")
    return (time.perf_counter() - start) * 1000, ack[3]


def interpret_login(text: str) -> tuple[str, str]:
    low = text.lower()
    if "invalid credentials" in low:
        return "up", "rejected on merit (DB reachable)"
    if "secondaryok" in low or "not primary" in low or "notwritableprimary" in low:
        return "down", "MongoDB failover: a pod is talking to a non-primary"
    if "password too weak" in low or "bad request" in low:
        return "unknown", "probe rejected by validation (probe is invalid)"
    try:
        msg = json.loads(text)["errors"][0]["message"]
    except Exception:  # noqa: BLE001
        msg = text[:120]
    return "down", f"unexpected: {msg}"


async def run_probe(client: httpx.AsyncClient, probe: Probe, timeout: float) -> dict:
    try:
        if probe.kind in ("tcp", "tcp_closed"):
            host, port = probe.target.rsplit(":", 1)
            try:
                ms = await _tcp(host, int(port), min(timeout, 6.0))
            except (OSError, asyncio.TimeoutError) as exc:
                if probe.kind == "tcp_closed":
                    return _result(probe, "up", None, "not reachable (good)")
                return _result(probe, "down", None, f"connect failed: {type(exc).__name__}")
            if probe.kind == "tcp_closed":
                return _result(probe, "down", ms, "REACHABLE from the internet")
            return _result(probe, "up", ms, "port open")

        if probe.kind == "mqtt_connect":
            host, port = probe.target.rsplit(":", 1)
            try:
                ms, rc = await mqtt_connect(host, int(port), min(timeout, 8.0))
            except (OSError, asyncio.TimeoutError, ValueError) as exc:
                return _result(probe, "down", None, f"no CONNACK: {type(exc).__name__}")
            status, detail = interpret_connack(rc)
            return _result(probe, status, ms, detail)

        if probe.kind == "mongo_rs":
            from app.services.oves_health import mongo_wire

            async def member(hp: str) -> dict:
                host, port = hp.rsplit(":", 1)
                try:
                    return {"host": hp, **await mongo_wire.hello(host, int(port), min(timeout, 6.0))}
                except Exception as exc:  # noqa: BLE001
                    return {"host": hp, "error": type(exc).__name__}

            members = await asyncio.gather(*(member(h) for h in probe.target.split(",")))
            status, detail = mongo_wire.summarize_members(list(members))
            lat = [m["latency_ms"] for m in members if m.get("latency_ms") is not None]
            res = _result(probe, status, max(lat) if lat else None, detail)
            res["members"] = list(members)
            return res

        start = time.perf_counter()
        if probe.kind == "login":
            resp = await client.post(probe.target, json={"query": LOGIN_PROBE_QUERY,
                                                         "variables": LOGIN_PROBE_VARIABLES},
                                     timeout=timeout)
            ms = (time.perf_counter() - start) * 1000
            status, detail = interpret_login(resp.text)
            return _result(probe, status, ms, detail, resp.status_code)
        if probe.kind == "opentoken":
            resp = await client.post(probe.target, json=OPENTOKEN_PROBE_BODY, timeout=timeout)
            ms = (time.perf_counter() - start) * 1000
            try:
                token = str(resp.json().get("token"))
            except Exception:  # noqa: BLE001
                token = ""
            if resp.status_code == 200 and token == OPENTOKEN_PROBE_EXPECTED:
                return _result(probe, "up", ms, "correct token", resp.status_code)
            return _result(probe, "down", ms, f"HTTP {resp.status_code}, wrong/no token",
                           resp.status_code)
        if probe.kind == "statuspage":
            resp = await client.get(probe.target, timeout=timeout)
            ms = (time.perf_counter() - start) * 1000
            st = resp.json().get("status", {})
            indicator = st.get("indicator", "unknown")
            # A vendor's partial outage is usually regional: amber, not red.
            status = {"none": "up", "minor": "slow", "major": "slow",
                      "critical": "down"}.get(indicator, "unknown")
            res = _result(probe, status, None, st.get("description", indicator),
                          resp.status_code)
            res["latency_ms"] = None    # vendor page latency says nothing useful
            return res

        resp = await client.request(probe.method, probe.target, json=probe.body,
                                    timeout=timeout)
        ms = (time.perf_counter() - start) * 1000
        if resp.status_code not in probe.expect_status:
            return _result(probe, "down", ms, f"HTTP {resp.status_code}", resp.status_code)
        if probe.expect_text and probe.expect_text not in resp.text:
            return _result(probe, "down", ms, f"unexpected body: {resp.text[:80]}",
                           resp.status_code)
        return _result(probe, "up", ms, f"HTTP {resp.status_code}", resp.status_code)
    except httpx.TimeoutException:
        return _result(probe, "down", timeout * 1000, "timed out")
    except Exception as exc:  # noqa: BLE001
        return _result(probe, "down", None, f"{type(exc).__name__}: {exc}"[:200])


async def run_all(probes: list[Probe], timeout: float, concurrency: int = 12) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(follow_redirects=False,
                                 headers={"User-Agent": "bitwave-oves-health/1"}) as client:
        async def one(p: Probe) -> dict:
            async with sem:
                return await run_probe(client, p, timeout)
        return await asyncio.gather(*(one(p) for p in probes))
