from pathlib import Path


def test_scheduler_defaults_on_but_can_be_disabled_after_migrations():
    config = Path("app/config.py").read_text(encoding="utf-8")
    startup = Path("main.py").read_text(encoding="utf-8")

    assert "SCHEDULER_ENABLED: bool = True" in config
    assert "if not scheduler_enabled():" in startup
    migration_position = startup.index("await run_hot_path_index_migrations()")
    scheduler_guard_position = startup.index("if not scheduler_enabled():")
    first_job_position = startup.index("scheduler.add_job(", scheduler_guard_position)
    assert migration_position < scheduler_guard_position < first_job_position


def test_hetzner_compose_is_dark_and_does_not_replace_tunnel_manager():
    compose = Path("docker-compose.hetzner.yml").read_text(encoding="utf-8")

    assert '"127.0.0.1:${HETZNER_WEB_PORT:-8000}:8000"' in compose
    assert '"10.251.0.1:1812:1812/udp"' in compose
    assert '"10.251.0.1:1813:1813/udp"' in compose
    assert "SCHEDULER_ENABLED: ${SCHEDULER_ENABLED:-false}" in compose
    assert "RUN_SCHEDULER: ${RUN_SCHEDULER:-false}" in compose
    assert "SHADOW_MODE: ${SHADOW_MODE:-true}" in compose
    assert "SMS_DISPATCH_ENABLED: ${SMS_DISPATCH_ENABLED:-false}" in compose
    assert "MPESA_B2B_DAILY_PAYOUT_ENABLED: ${MPESA_B2B_DAILY_PAYOUT_ENABLED:-false}" in compose
    assert "ports:\n      - \"543" not in compose
    assert "wg-manager:" not in compose
    assert 'profiles: ["active"]' in compose
    assert "no-new-privileges:true" in compose
    assert "read_only: true" in compose
    assert "subnet: 172.20.0.0/16" in compose


def test_hetzner_radius_uses_environment_secrets_and_target_subnet():
    sql = Path("radius/mods-enabled/sql.hetzner").read_text(encoding="utf-8")
    clients = Path("radius/clients.hetzner.conf").read_text(encoding="utf-8")

    assert '$ENV{POSTGRES_PASSWORD}' in sql
    assert "isp_secure_pass_2024" not in sql
    assert "$ENV{RADIUS_SHARED_SECRET}" in clients
    assert "10.251.0.0/16" in clients
    assert "testing123" not in clients
