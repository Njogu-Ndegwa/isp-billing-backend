"""Zero-downtime deploy wiring (docs/zero-downtime-deploys.md).

The deploy swaps the app behind Caddy using a readiness endpoint, a drain flag
and a short-lived bridge container. These tests pin the pieces that must agree
with each other across the app, the compose file, the workflow and the
Caddyfile — a rename in one place silently brings the deploy gap back.
"""

import json
import logging
import re
from pathlib import Path

from app.api import dashboard_routes

DEPLOY = Path(".github/workflows/deploy.yml").read_text(encoding="utf-8")
COMPOSE = Path("docker-compose.hetzner.yml").read_text(encoding="utf-8")
CADDYFILE = Path("ops/caddy/Caddyfile").read_text(encoding="utf-8")


async def test_readiness_is_200_until_the_drain_flag_exists(tmp_path, monkeypatch):
    flag = tmp_path / "draining"
    monkeypatch.setattr(dashboard_routes, "DRAIN_FLAG", str(flag))

    assert await dashboard_routes.readiness_check() == {"status": "ready"}

    flag.touch()
    response = await dashboard_routes.readiness_check()
    assert response.status_code == 503
    assert json.loads(response.body) == {"status": "draining"}


def test_deploy_drain_flag_matches_the_app():
    assert f"DRAIN_FLAG={dashboard_routes.DRAIN_FLAG}" in DEPLOY
    # tmpfs in the read-only container, so the flag dies with the container.
    assert dashboard_routes.DRAIN_FLAG.startswith("/tmp/")
    assert "/tmp:size=" in COMPOSE


def test_readiness_probes_stay_out_of_the_access_log():
    import main  # noqa: F401  (installs the filter)

    access = logging.getLogger("uvicorn.access")

    def record(path):
        return logging.LogRecord(
            "uvicorn.access", logging.INFO, __file__, 0,
            '%s - "%s %s HTTP/%s" %d', ("127.0.0.1:1", "GET", path, "1.1", 200), None,
        )

    assert not access.filter(record("/health/ready"))
    assert access.filter(record("/health"))
    assert access.filter(record("/api/hotspot/register-and-pay"))


def test_compose_drains_in_flight_requests_before_docker_kills_the_app():
    assert '"--timeout-graceful-shutdown", "20"' in COMPOSE
    assert "stop_grace_period: 30s" in COMPOSE


def test_bridge_never_runs_the_scheduler_and_never_takes_port_8000():
    run = DEPLOY[DEPLOY.index('run -d --no-deps'):]
    run = run[: run.index("</dev/null")]
    assert "-e RUN_SCHEDULER=false -e SCHEDULER_ENABLED=false web" in run
    assert '-p "127.0.0.1:$BRIDGE_PORT:8000"' in run
    assert "--service-ports" not in run
    assert "BRIDGE_PORT=8001" in DEPLOY


def test_old_container_is_drained_before_it_is_stopped():
    zero = DEPLOY[DEPLOY.index('if [ "$ZERO_DOWNTIME" -eq 1 ]; then\n            echo "Starting'):]
    assert zero.index("wait_ready \"$BRIDGE\"") < zero.index('drain "$APP"') < zero.index('stop_timed "$APP" 30')
    assert zero.index('stop_timed "$APP" 30') < zero.index("dc up -d --no-deps --no-build web")
    # The bridge is only retired after the new canonical container is healthy.
    assert DEPLOY.index("if ! wait_healthy; then\n") < DEPLOY.rindex("retire_bridge\n")


def test_deploy_falls_back_to_stop_start_until_caddy_has_the_bridge_slot():
    assert "/reverse_proxy/upstreams" in DEPLOY
    assert 'grep -q "\\"127.0.0.1:$BRIDGE_PORT\\""' in DEPLOY
    assert 'stop_timed "$APP" 10' in DEPLOY
    commands = [line for line in DEPLOY.splitlines() if not line.strip().startswith("#")]
    assert not any("compose down" in line for line in commands)


def test_every_caddy_route_to_the_api_has_both_slots_and_the_shared_policy():
    api_routes = re.findall(r"reverse_proxy 127\.0\.0\.1:8000[^\n]*", CADDYFILE)
    assert len(api_routes) == 3
    for line in api_routes:
        assert line.strip() == "reverse_proxy 127.0.0.1:8000 127.0.0.1:8001 {"
    assert CADDYFILE.count("import isp_api_upstream") == 3

    snippet = CADDYFILE[CADDYFILE.index("(isp_api_upstream) {"):]
    snippet = snippet[: snippet.index("\n}") + 2]
    assert "health_uri /health/ready" in snippet
    assert "lb_policy first" in snippet
    # Never retry a POST that may have reached the app.
    retry = snippet[snippet.index("lb_retry_match"):]
    retry = retry[: retry.index("}")]
    assert "method GET HEAD OPTIONS" in retry
    assert "POST" not in retry
    # Caddy must give up an idle upstream connection before uvicorn does.
    keepalive = int(re.search(r"keepalive (\d+)s", snippet).group(1))
    uvicorn_keepalive = int(re.search(r'"--timeout-keep-alive", "(\d+)"', COMPOSE).group(1))
    assert keepalive < uvicorn_keepalive
