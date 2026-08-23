"""Safety guards for running a neutralized backend standby during migration."""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest


MIGRATION_CALLS = (
    "run_radius_migrations",
    "run_monitoring_migrations",
    "run_payment_method_migrations",
    "run_user_migrations",
    "run_password_reset_migrations",
    "run_reconnection_migrations",
    "run_device_pairing_migrations",
    "run_subscription_sharing_migrations",
    "run_plan_router_scope_migrations",
    "run_router_payout_attribution_migrations",
    "run_b2b_migrations",
    "run_subscription_migrations",
    "run_growth_targets_migration",
    "run_lead_pipeline_migrations",
    "run_access_credential_migrations",
    "run_fup_usage_migrations",
    "run_payment_history_migrations",
    "run_shop_migrations",
    "run_portal_settings_migrations",
    "run_agent_queue_migrations",
    "run_c2b_migrations",
    "run_anti_tethering_migrations",
    "run_messaging_migrations",
    "run_compensation_voucher_migrations",
    "run_pull_channel_migrations",
    "run_load_balancing_migrations",
    "run_router_status_alert_migrations",
    "run_payment_port_attribution_migrations",
    "run_feedback_migrations",
)


@pytest.mark.asyncio
async def test_startup_kill_switch_leaves_scheduler_empty(monkeypatch):
    import main
    from app.config import settings

    for name in MIGRATION_CALLS:
        monkeypatch.setattr(main, name, AsyncMock())

    async def no_database_sessions():
        if False:
            yield None

    monkeypatch.setattr(main, "get_db", no_database_sessions)
    monkeypatch.setattr(settings, "RUN_SCHEDULER", False, raising=False)

    main.scheduler.remove_all_jobs()
    try:
        await main.startup_event()
        assert main.scheduler.running is False
        assert main.scheduler.get_jobs() == []
        await main.shutdown_event()
    finally:
        if main.scheduler.running:
            main.scheduler.shutdown(wait=False)
        main.scheduler.remove_all_jobs()


def test_migration_environment_is_passed_through_compose():
    compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text()

    assert "RUN_SCHEDULER=${RUN_SCHEDULER:-true}" in compose
    assert "SERVER_PUBLIC_IP=${SERVER_PUBLIC_IP:-54.91.202.229}" in compose
    assert "PULL_SERVICE_URL=${PULL_SERVICE_URL:-http://35.170.199.141:8443}" in compose


def test_radius_accepts_primary_and_hetzner_tunnel_subnets():
    clients = (Path(__file__).parents[1] / "radius" / "clients.conf").read_text()

    assert "ipaddr = 10.0.0.0/16" in clients
    assert "ipaddr = 10.251.0.0/16" in clients
