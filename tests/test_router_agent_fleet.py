import pytest

from app.services import router_agent_fleet as fleet
from tests.factories import make_reseller, make_router


def test_agent_policy_can_create_and_import_command_files():
    policies = set(fleet.AGENT_ROUTEROS_POLICY.split(","))

    assert "ftp" in policies
    assert {"read", "write", "test", "policy", "sensitive"}.issubset(policies)


def test_current_source_and_scheduler_verification_rejects_old_cadence():
    source = fleet.render_router_agent_source(
        identity="Router-Verify",
        endpoint_base_url="https://isp.bitwavetechnologies.net",
        tunnel_type="wireguard",
    )

    assert fleet._source_is_current(source, "Router-Verify") is True
    assert fleet._source_is_current(
        source.replace("bitwavePollSkips", "oldPollSkips"),
        "Router-Verify",
    ) is False
    assert fleet._source_is_current(source + "\n:rndnum from=0 to=1", "Router-Verify") is False
    assert fleet._scheduler_is_current(
        {
            "disabled": "false",
            "on-event": "/system script run bitwave-command-agent",
            "interval": "30s",
        }
    ) is True
    assert fleet._scheduler_is_current(
        {
            "disabled": "false",
            "on-event": "/system script run bitwave-command-agent",
            "interval": "90s",
        }
    ) is False


def test_installer_applies_and_verifies_file_policy_on_script_and_scheduler(monkeypatch):
    class FakeAPI:
        instances = []

        def __init__(self, *_args, **_kwargs):
            self.script = None
            self.scheduler = None
            self.__class__.instances.append(self)

        def connect(self):
            return True

        def disconnect(self):
            return None

        def send_command_optimized(self, path, **_kwargs):
            if path == "/system/script/print":
                return {"success": True, "data": [self.script] if self.script else []}
            if path == "/system/scheduler/print":
                return {"success": True, "data": [self.scheduler] if self.scheduler else []}
            raise AssertionError(path)

        def send_command(self, path, params):
            if path == "/system/script/add":
                self.script = {".id": "*1", **params}
            elif path == "/system/scheduler/add":
                self.scheduler = {".id": "*2", **params}
            else:
                raise AssertionError(path)
            return {"success": True, "data": []}

    monkeypatch.setattr(fleet, "MikroTikAPI", FakeAPI)
    candidate = fleet.RouterAgentCandidate(
        router_id=1,
        identity="Router-Policy-Test",
        ip_address="10.0.0.2",
        username="api",
        password="secret",
        port=8728,
        tunnel_type="wireguard",
        already_enabled=False,
    )

    result = fleet.install_router_agent_sync(
        candidate,
        endpoint_base_url="https://isp.bitwavetechnologies.net",
    )

    assert result["ok"] is True
    api = FakeAPI.instances[0]
    assert "ftp" in api.script["policy"].split(",")
    assert "ftp" in api.scheduler["policy"].split(",")
    assert api.scheduler["interval"] == "30s"


async def test_install_batches_advance_past_already_enabled_routers(db):
    reseller = await make_reseller(db)
    enabled = await make_router(
        db,
        reseller,
        identity="Router-Enabled",
        router_agent_enabled=True,
    )
    disabled = await make_router(
        db,
        reseller,
        identity="Router-Disabled",
        router_agent_enabled=False,
    )

    rows = await fleet.load_router_agent_candidates(limit=1, enabled=False)

    assert [row.router_id for row in rows] == [disabled.id]
    assert enabled.id not in [row.router_id for row in rows]


async def test_failed_install_never_enables_router(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        identity="Router-Unreachable",
        router_agent_enabled=False,
    )

    monkeypatch.setattr(
        fleet,
        "install_router_agent_sync",
        lambda *_args, **_kwargs: {
            "ok": False,
            "router_id": router.id,
            "error": "connect_failed",
        },
    )
    results = await fleet.run_router_agent_fleet_change(
        mode="install",
        router_ids=[router.id],
    )

    await db.refresh(router)
    assert results[0]["ok"] is False
    assert router.router_agent_enabled is False


async def test_successful_install_enables_only_after_verification(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        identity="Router-Verified",
        router_agent_enabled=False,
    )

    monkeypatch.setattr(
        fleet,
        "install_router_agent_sync",
        lambda *_args, **_kwargs: {
            "ok": True,
            "router_id": router.id,
            "identity": router.identity,
            "tunnel_type": "wireguard",
            "script_bytes": 2048,
        },
    )
    results = await fleet.run_router_agent_fleet_change(
        mode="install",
        router_ids=[router.id],
    )

    await db.refresh(router)
    assert results[0]["ok"] is True
    assert router.router_agent_enabled is True


async def test_uninstall_disables_db_even_when_router_is_unreachable(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        identity="Router-Rollback",
        router_agent_enabled=True,
    )
    monkeypatch.setattr(
        fleet,
        "uninstall_router_agent_sync",
        lambda *_args, **_kwargs: {
            "ok": False,
            "router_id": router.id,
            "error": "connect_failed",
        },
    )

    results = await fleet.run_router_agent_fleet_change(
        mode="uninstall",
        router_ids=[router.id],
    )

    await db.refresh(router)
    assert results[0]["ok"] is False
    assert router.router_agent_enabled is False


async def test_upgrade_selects_enabled_router_and_reenables_after_verification(
    db, monkeypatch
):
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        identity="Router-Upgrade",
        router_agent_enabled=True,
    )
    monkeypatch.setattr(
        fleet,
        "install_router_agent_sync",
        lambda *_args, **_kwargs: {
            "ok": True,
            "router_id": router.id,
            "identity": router.identity,
            "tunnel_type": "wireguard",
            "script_bytes": 2048,
        },
    )

    results = await fleet.run_router_agent_fleet_change(
        mode="upgrade",
        router_ids=[router.id],
    )

    await db.refresh(router)
    assert results[0]["ok"] is True
    assert results[0]["already_enabled"] is True
    assert router.router_agent_enabled is True


async def test_failed_upgrade_leaves_router_disabled(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        identity="Router-Upgrade-Failed",
        router_agent_enabled=True,
    )
    monkeypatch.setattr(
        fleet,
        "install_router_agent_sync",
        lambda *_args, **_kwargs: {
            "ok": False,
            "router_id": router.id,
            "error": "verification_failed",
        },
    )

    results = await fleet.run_router_agent_fleet_change(
        mode="upgrade",
        router_ids=[router.id],
    )

    await db.refresh(router)
    assert results[0]["ok"] is False
    assert router.router_agent_enabled is False


async def test_upgrade_requires_explicit_router_ids():
    with pytest.raises(ValueError, match="explicit router_ids"):
        await fleet.run_router_agent_fleet_change(mode="upgrade")
