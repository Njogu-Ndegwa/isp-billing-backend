import importlib.util
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.admin_metrics_routes as routes_module
from app.api.admin_metrics_routes import router as admin_metrics_router
from app.db.database import get_db
from app.services.auth import verify_token
from app.services.management_tunnel_health import (
    build_management_tunnel_health,
    classify_primary_tunnel,
)
from tests.factories import make_admin, make_reseller, make_router


def _load_wg_manager_module():
    path = Path(__file__).parents[1] / "wg-manager" / "main.py"
    spec = importlib.util.spec_from_file_location("wg_manager_main_for_tests", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(admin_metrics_router)

    async def _override_get_db():
        async with session_factory() as session:
            yield session

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    return application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http_client:
        yield http_client


def test_classifies_primary_tunnel_ranges():
    assert classify_primary_tunnel("10.0.99.254") == "wireguard"
    assert classify_primary_tunnel("10.0.100.9") == "l2tp"
    assert classify_primary_tunnel("10.0.199.5") == "l2tp"
    assert classify_primary_tunnel("192.168.88.1") is None


def test_wg_manager_detects_required_udp_listeners(tmp_path):
    module = _load_wg_manager_module()
    udp = tmp_path / "udp"
    udp.write_text(
        "  sl  local_address rem_address st\n"
        "  1: 00000000:06A5 00000000:0000 07\n"
        "  2: 00000000:01F4 00000000:0000 07\n"
        "  3: 00000000:1194 00000000:0000 07\n",
        encoding="utf-8",
    )
    assert module._listening_udp_ports((str(udp),)) == {1701, 500, 4500}


def test_wg_manager_counts_only_l2tp_chap_peers(tmp_path):
    module = _load_wg_manager_module()
    secrets = tmp_path / "chap-secrets"
    secrets.write_text(
        '# client server secret ip\n'
        'router-1 l2tp-server "secret one" 10.0.100.1\n'
        'router-2 * "secret two" 10.0.100.2\n'
        'dsl-user pppoe "secret three" 10.10.0.2\n',
        encoding="utf-8",
    )
    assert module._configured_l2tp_peers(str(secrets)) == 2


def test_manager_health_is_unhealthy_when_l2tp_is_down(monkeypatch):
    module = _load_wg_manager_module()
    monkeypatch.setattr(module, "_wireguard_health", lambda: {"available": True})
    monkeypatch.setattr(
        module,
        "_l2tp_health",
        lambda: {"required": True, "available": False},
    )
    result = module.health()
    assert result["status"] == "unhealthy"
    assert result["wg_available"] is True


def test_combined_health_names_l2tp_blast_radius():
    fleet = {
        "wireguard": {"registered_routers": 100, "online_routers": 90},
        "l2tp": {"registered_routers": 59, "online_routers": 0},
    }
    manager = {
        "wireguard": {"available": True},
        "l2tp": {"required": True, "available": False, "active_sessions": 0},
    }
    result = build_management_tunnel_health(manager, fleet)
    assert result["overall_status"] == "critical"
    assert "59 registered routers" in result["summary"]


@pytest.mark.asyncio
async def test_admin_endpoint_combines_manager_and_router_counts(db, client, monkeypatch):
    admin = await make_admin(db)
    reseller = await make_reseller(db)
    await make_router(db, reseller, ip_address="10.0.0.25", last_status=True)
    await make_router(db, reseller, ip_address="10.0.100.9", last_status=False)

    async def fake_current_user(token, session):
        return admin

    async def fake_manager_health():
        return {
            "wireguard": {
                "available": True,
                "configured_peers": 1,
                "recent_handshakes": 1,
            },
            "l2tp": {
                "required": True,
                "available": True,
                "configured_peers": 1,
                "active_sessions": 1,
            },
        }

    monkeypatch.setattr(routes_module, "get_current_user", fake_current_user)
    monkeypatch.setattr(routes_module, "fetch_manager_health", fake_manager_health)

    response = await client.get("/api/admin/management-tunnels")
    assert response.status_code == 200
    payload = response.json()
    assert payload["overall_status"] == "healthy"
    assert payload["services"]["wireguard"]["registered_routers"] == 1
    assert payload["services"]["wireguard"]["online_routers"] == 1
    assert payload["services"]["l2tp"]["registered_routers"] == 1
    assert payload["services"]["l2tp"]["online_routers"] == 0
