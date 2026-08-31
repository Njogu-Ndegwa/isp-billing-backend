from app.services import router_agent_fleet as fleet
from tests.factories import make_reseller, make_router


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
