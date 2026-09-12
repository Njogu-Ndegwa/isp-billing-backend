from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.runtime_mode import (
    ShadowModeBlockedError,
    require_external_side_effects_enabled,
    routeros_command_is_read_only,
    shadow_http_request_allowed,
)


def test_shadow_http_policy_is_fail_closed():
    assert shadow_http_request_allowed("GET", "/api/customers")
    assert shadow_http_request_allowed("HEAD", "/health")
    assert shadow_http_request_allowed("OPTIONS", "/api/auth/login")
    assert shadow_http_request_allowed("POST", "/api/auth/login")
    assert shadow_http_request_allowed("POST", "/api/auth/login/")
    assert not shadow_http_request_allowed("POST", "/api/payments")
    assert not shadow_http_request_allowed("PATCH", "/api/customers/1")
    assert not shadow_http_request_allowed("DELETE", "/api/routers/1")


def test_external_side_effect_guard(monkeypatch):
    monkeypatch.setattr(settings, "SHADOW_MODE", True)

    with pytest.raises(ShadowModeBlockedError, match="disabled"):
        require_external_side_effects_enabled("test operation")


def test_routeros_read_policy_is_fail_closed():
    assert routeros_command_is_read_only("/system/resource/print")
    assert routeros_command_is_read_only("/interface/monitor-traffic")
    assert routeros_command_is_read_only("/ping")
    assert not routeros_command_is_read_only("/ip/address/add")
    assert not routeros_command_is_read_only("/system/script/run")
    assert not routeros_command_is_read_only("/system/reboot")
    assert not routeros_command_is_read_only("unknown")


def test_mikrotik_gateway_blocks_writes_but_allows_reads(monkeypatch):
    from app.services.mikrotik_api import MikroTikAPI

    monkeypatch.setattr(settings, "SHADOW_MODE", True)
    api = MikroTikAPI("192.0.2.1", "reader", "unused")
    api.connected = True
    sent = []
    api.send_sentence = lambda words: sent.append(words)
    api.read_sentence = lambda: ["!done"]

    blocked = api.send_command("/ip/address/add", {"address": "192.0.2.2/32"})
    assert blocked["error"] == "shadow_mode_blocked"
    assert sent == []

    allowed = api.send_command("/system/resource/print")
    assert allowed == {"success": True, "data": []}
    assert sent == [["/system/resource/print"]]


def test_shadow_database_connections_are_read_only(monkeypatch):
    from app.db.database import connection_server_settings

    monkeypatch.setattr(settings, "SHADOW_MODE", True)
    server_settings = connection_server_settings()

    assert server_settings["default_transaction_read_only"] == "on"
    assert "idle_in_transaction_session_timeout" in server_settings
    assert "lock_timeout" in server_settings


@pytest.mark.asyncio
async def test_shadow_startup_registers_no_migrations_or_jobs(monkeypatch):
    import main

    class FakeScheduler:
        running = False

        def __init__(self):
            self.removed = False

        def remove_all_jobs(self):
            self.removed = True

        def add_job(self, *_args, **_kwargs):
            pytest.fail("shadow startup reached scheduler registration")

        def start(self):
            pytest.fail("shadow startup started the scheduler")

    fake_scheduler = FakeScheduler()
    monkeypatch.setattr(settings, "SHADOW_MODE", True)
    monkeypatch.setattr(main, "scheduler", fake_scheduler)
    monkeypatch.setattr(
        main,
        "run_radius_migrations",
        lambda: pytest.fail("shadow startup reached migrations"),
    )

    await main.startup_event()

    assert fake_scheduler.removed
    assert not fake_scheduler.running


def test_shadow_middleware_exposes_health_and_blocks_writes(monkeypatch):
    import main

    monkeypatch.setattr(settings, "SHADOW_MODE", True)

    with TestClient(main.app) as client:
        health = client.get("/health")
        blocked = client.post("/api/auth/register", json={})

    assert health.status_code == 200
    assert health.json()["runtime_mode"] == "shadow"
    assert health.headers["X-ISP-Runtime-Mode"] == "shadow"
    assert blocked.status_code == 503
    assert blocked.json()["code"] == "shadow_mode_blocked"


@pytest.mark.asyncio
async def test_shadow_login_does_not_write_last_login(monkeypatch):
    from app.api import auth_routes

    role = SimpleNamespace(value="ADMIN")
    user = SimpleNamespace(
        id=1,
        email="admin@example.test",
        user_code="ADMIN-1",
        role=role,
        organization_name="Test",
        business_name=None,
        support_phone=None,
        mpesa_shortcode=None,
        subscription_status=None,
        subscription_expires_at=None,
        last_login_at=None,
    )

    class FakeDB:
        def __init__(self):
            self.added = False
            self.flushed = False
            self.committed = False
            self.rolled_back = False

        def add(self, _row):
            self.added = True

        async def flush(self):
            self.flushed = True

        async def commit(self):
            self.committed = True

        async def rollback(self):
            self.rolled_back = True

    async def fake_authenticate(*_args, **_kwargs):
        return user

    async def no_alert(*_args, **_kwargs):
        return None

    db = FakeDB()
    monkeypatch.setattr(settings, "SHADOW_MODE", True)
    monkeypatch.setattr(auth_routes, "authenticate_user", fake_authenticate)
    monkeypatch.setattr(auth_routes, "get_invoice_alert_for_user", no_alert)

    response = await auth_routes.login_api(
        auth_routes.LoginRequest(email=user.email, password="unused"), db
    )

    assert response["token_type"] == "bearer"
    assert user.last_login_at is None
    assert not db.added
    assert not db.flushed
    assert not db.committed
    assert db.rolled_back


@pytest.mark.asyncio
async def test_shadow_blocks_insurance_and_pull_mutations(monkeypatch):
    from app.services.insurance_wireguard import insurance_manager_request
    from app.services import pull_provisioning

    monkeypatch.setattr(settings, "SHADOW_MODE", True)

    with pytest.raises(ShadowModeBlockedError):
        await insurance_manager_request("POST", "/add-peer", json={})

    handoff = await pull_provisioning.handoff_to_pull_service(
        "router-1", "command-1", "/system identity print"
    )
    cleared = await pull_provisioning.clear_pull_service("router-1", "command-1")
    assert handoff == {"ok": False, "error": "shadow_mode_blocked"}
    assert cleared == {"ok": False, "error": "shadow_mode_blocked"}


@pytest.mark.asyncio
async def test_shadow_blocks_payment_and_messaging_providers(monkeypatch):
    from app.services import fapshi, mpesa, mtn_momo, zenopay
    from app.services.email_service import send_email
    from app.services.messaging.africas_talking import AfricasTalkingProvider

    monkeypatch.setattr(settings, "SHADOW_MODE", True)

    with pytest.raises(ShadowModeBlockedError):
        await mpesa.initiate_stk_push_direct("254700000000", 10, "shadow-test")
    with pytest.raises(ShadowModeBlockedError):
        await fapshi.initiate_direct_payment(
            api_user="unused",
            api_key="unused",
            environment="sandbox",
            amount=10,
            phone="237670000000",
            name="Shadow Test",
            user_id="1",
            external_id="shadow-test",
        )
    with pytest.raises(ShadowModeBlockedError):
        await mtn_momo.initiate_request_to_pay(
            reference_id="00000000-0000-0000-0000-000000000000",
            amount=10,
            currency="EUR",
            phone="237670000000",
            external_id="shadow-test",
            payer_message="test",
            payee_note="test",
            target_environment="sandbox",
            base_url="https://example.test",
            api_user="unused",
            api_key="unused",
            subscription_key="unused",
        )
    with pytest.raises(ShadowModeBlockedError):
        await zenopay.initiate_zenopay_payment(
            "unused", "shadow-test", "255700000000", 10, "Test", "test@example.test"
        )

    provider = AfricasTalkingProvider("unused", "unused", "https://example.test")
    with pytest.raises(ShadowModeBlockedError):
        await provider.send_bulk(["254700000000"], "test", "TEST")

    assert not await send_email("test@example.test", "test", "<p>test</p>")


@pytest.mark.asyncio
async def test_shadow_blocks_primary_tunnel_manager_and_payout(monkeypatch):
    from app.services import mpesa_b2b, provisioning

    monkeypatch.setattr(settings, "SHADOW_MODE", True)

    with pytest.raises(ShadowModeBlockedError):
        await provisioning.register_wireguard_peer("unused", "10.0.0.2")
    with pytest.raises(ShadowModeBlockedError):
        await mpesa_b2b.execute_payout(
            None,
            1,
            triggered_by="shadow-test",
        )


def test_compose_wires_shadow_and_pull_configuration():
    from pathlib import Path

    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert "SHADOW_MODE=${SHADOW_MODE:-false}" in compose
    assert "PULL_SERVICE_URL=${PULL_SERVICE_URL:-}" in compose
    assert "35.170.199.141:8443" not in compose
