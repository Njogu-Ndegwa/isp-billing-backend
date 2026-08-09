"""Endpoint tests for app/api/load_balancing_routes.py.

The router layer is monkeypatched (canned _run_locked_router_thread results),
so these tests cover validation, ownership, confirm gating, and the DB state
transitions on enable/disable — not live RouterOS behaviour.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from app.api import load_balancing_routes as lbr
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def _no_availability(*_args, **_kwargs):
    return None


@pytest.fixture(autouse=True)
def _quiet_side_effects(monkeypatch):
    monkeypatch.setattr(lbr, "record_router_availability", _no_availability)


def _fake_runner(result, calls=None):
    async def run(router_obj, sync_func, *args, **kwargs):
        if calls is not None:
            calls.append({"sync_func": sync_func.__name__, "args": args,
                          "kwargs": kwargs})
        return result

    return run


_ENABLE_OK = {
    "success": True,
    "preflight": {"blockers": [], "warnings": ["dns warning"], "per_port": {}},
    "apply": {"steps": [], "success": True},
    "convert": {"ether2": {"steps": [], "success": True}},
    "converted_ports": ["ether2"],
    "dormant_ports": [],
    "seed": {"added": [], "skipped": []},
    "verify": {"success": True, "warnings": []},
}


# ---------------------------------------------------------------------------
# GET status
# ---------------------------------------------------------------------------

async def test_get_status_defaults_to_disabled(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    resp = await lbr.get_load_balancing_status(router.id, db, _token(reseller))
    assert resp == {
        "success": True,
        "router_id": router.id,
        "enabled": False,
        "config": None,
        "applied_at": None,
    }


async def test_get_status_other_resellers_router_is_404(db):
    owner = await make_reseller(db)
    intruder = await make_reseller(db)
    router = await make_router(db, owner)

    with pytest.raises(HTTPException) as exc:
        await lbr.get_load_balancing_status(router.id, db, _token(intruder))
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

async def test_enable_rejects_too_few_ports(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    monkeypatch.setattr(lbr, "_run_locked_router_thread",
                        _fake_runner({"error": "should not be called"}))

    with pytest.raises(HTTPException) as exc:
        await lbr.enable_load_balancing(
            router.id, lbr.LBEnableRequest(wan_ports=["ether1"], confirm=True),
            db, _token(reseller),
        )
    assert exc.value.status_code == 422


async def test_enable_rejects_bad_port_names(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    for ports in (["ether1", "wlan1"], ["ether1", "ether2; drop"],
                  ["ether1", "ether1"]):
        with pytest.raises(HTTPException) as exc:
            await lbr.enable_load_balancing(
                router.id, lbr.LBEnableRequest(wan_ports=ports, confirm=True),
                db, _token(reseller),
            )
        assert exc.value.status_code == 422


async def test_enable_rejects_ports_serving_customers(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, plain_ports=["ether2"],
                               pppoe_ports=["ether4"], dual_ports=["ether5"])

    for ports in (["ether1", "ether2"], ["ether1", "ether4"],
                  ["ether1", "ether5"]):
        with pytest.raises(HTTPException) as exc:
            await lbr.enable_load_balancing(
                router.id, lbr.LBEnableRequest(wan_ports=ports, confirm=True),
                db, _token(reseller),
            )
        assert exc.value.status_code == 422
        assert "serve customers" in str(exc.value.detail)


async def test_preflight_applies_same_port_validation(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, plain_ports=["ether3"])

    with pytest.raises(HTTPException) as exc:
        await lbr.preflight_load_balancing(
            router.id, lbr.LBPreflightRequest(wan_ports=["ether1", "ether3"]),
            db, _token(reseller),
        )
    assert exc.value.status_code == 422


async def test_enable_requires_confirm(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    async def _boom(*_a, **_k):
        raise AssertionError("router I/O must not run without confirm")

    monkeypatch.setattr(lbr, "_run_locked_router_thread", _boom)
    with pytest.raises(HTTPException) as exc:
        await lbr.enable_load_balancing(
            router.id,
            lbr.LBEnableRequest(wan_ports=["ether1", "ether2"], confirm=False),
            db, _token(reseller),
        )
    assert exc.value.status_code == 400


async def test_disable_requires_confirm(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    async def _boom(*_a, **_k):
        raise AssertionError("router I/O must not run without confirm")

    monkeypatch.setattr(lbr, "_run_locked_router_thread", _boom)
    with pytest.raises(HTTPException) as exc:
        await lbr.disable_load_balancing(
            router.id, lbr.LBDisableRequest(confirm=False), db, _token(reseller),
        )
    assert exc.value.status_code == 400


async def test_enable_other_resellers_router_is_404(db):
    owner = await make_reseller(db)
    intruder = await make_reseller(db)
    router = await make_router(db, owner)

    with pytest.raises(HTTPException) as exc:
        await lbr.enable_load_balancing(
            router.id,
            lbr.LBEnableRequest(wan_ports=["ether1", "ether2"], confirm=True),
            db, _token(intruder),
        )
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# enable / disable state transitions (router layer canned)
# ---------------------------------------------------------------------------

async def test_enable_persists_state_and_passes_active_customers(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    active = await make_customer(
        db, reseller, plan, router,
        expiry=datetime.utcnow() + timedelta(days=3),
        mac_address="AA:BB:CC:DD:EE:10",
    )
    await make_customer(  # expired — must NOT be seeded
        db, reseller, plan, router,
        expiry=datetime.utcnow() - timedelta(days=1),
        mac_address="AA:BB:CC:DD:EE:11",
        phone="254700000099",
    )

    calls = []
    monkeypatch.setattr(lbr, "_run_locked_router_thread",
                        _fake_runner(dict(_ENABLE_OK), calls))

    resp = await lbr.enable_load_balancing(
        router.id,
        lbr.LBEnableRequest(wan_ports=["ether1", "ether2"], confirm=True),
        db, _token(reseller),
    )

    assert resp["success"] is True
    assert resp["enabled"] is True
    assert resp["wan_ports"] == ["ether1", "ether2"]
    assert resp["converted_ports"] == ["ether2"]
    assert resp["dormant_ports"] == []
    assert "dns warning" in resp["warnings"]

    # the worker got the active customer list from the short DB session
    assert calls[0]["sync_func"] == "_lb_enable_sync"
    _info, wan_ports, active_customers = calls[0]["args"]
    assert wan_ports == ["ether1", "ether2"]
    assert [c["mac"] for c in active_customers] == [active.mac_address]

    await db.refresh(router)
    assert router.lb_enabled is True
    assert router.lb_config["wan_ports"] == ["ether1", "ether2"]
    assert router.lb_config["applied_at"]
    assert router.lb_applied_at is not None


async def test_enable_preflight_blockers_are_422_and_do_not_persist(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    blocked = {
        "error": "preflight_blocked",
        "preflight": {"blockers": ["ether2 serves customers"], "warnings": []},
    }
    monkeypatch.setattr(lbr, "_run_locked_router_thread", _fake_runner(blocked))

    with pytest.raises(HTTPException) as exc:
        await lbr.enable_load_balancing(
            router.id,
            lbr.LBEnableRequest(wan_ports=["ether1", "ether2"], confirm=True),
            db, _token(reseller),
        )
    assert exc.value.status_code == 422
    assert exc.value.detail["blockers"] == ["ether2 serves customers"]

    await db.refresh(router)
    assert router.lb_enabled is False
    assert router.lb_config is None


async def test_enable_error_mapping(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    for error, status in (("connect_failed", 503), ("busy", 429),
                          ("timeout", 504), ("something broke", 502)):
        monkeypatch.setattr(lbr, "_run_locked_router_thread",
                            _fake_runner({"error": error}))
        with pytest.raises(HTTPException) as exc:
            await lbr.enable_load_balancing(
                router.id,
                lbr.LBEnableRequest(wan_ports=["ether1", "ether2"], confirm=True),
                db, _token(reseller),
            )
        assert exc.value.status_code == status, error

    await db.refresh(router)
    assert router.lb_enabled is False


async def test_disable_keeps_config_for_reenable(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    router.lb_enabled = True
    router.lb_config = {"wan_ports": ["ether1", "ether2"],
                        "applied_at": "2026-08-01T00:00:00"}
    router.lb_applied_at = datetime(2026, 8, 1)
    await db.commit()

    monkeypatch.setattr(
        lbr, "_run_locked_router_thread",
        _fake_runner({"success": True, "steps": [], "state": "LB off"}),
    )
    resp = await lbr.disable_load_balancing(
        router.id, lbr.LBDisableRequest(confirm=True), db, _token(reseller),
    )

    assert resp["success"] is True
    assert resp["enabled"] is False
    assert resp["config"]["wan_ports"] == ["ether1", "ether2"]

    await db.refresh(router)
    assert router.lb_enabled is False
    assert router.lb_config == {"wan_ports": ["ether1", "ether2"],
                                "applied_at": "2026-08-01T00:00:00"}
    assert router.lb_applied_at is None


async def test_disable_router_error_does_not_change_db(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    router.lb_enabled = True
    router.lb_config = {"wan_ports": ["ether1", "ether2"]}
    await db.commit()

    monkeypatch.setattr(lbr, "_run_locked_router_thread",
                        _fake_runner({"error": "connect_failed"}))
    with pytest.raises(HTTPException) as exc:
        await lbr.disable_load_balancing(
            router.id, lbr.LBDisableRequest(confirm=True), db, _token(reseller),
        )
    assert exc.value.status_code == 503

    await db.refresh(router)
    assert router.lb_enabled is True  # router untouched -> DB says still enabled


async def test_verify_returns_live_report_and_db_state(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    router.lb_enabled = True
    router.lb_config = {"wan_ports": ["ether1", "ether2"]}
    router.lb_applied_at = datetime(2026, 8, 5, 12, 0)
    await db.commit()

    verify_report = {"success": True, "warnings": [], "counters": {},
                     "flow_attribution": {}}
    monkeypatch.setattr(lbr, "_run_locked_router_thread",
                        _fake_runner(verify_report))
    resp = await lbr.verify_load_balancing(router.id, db, _token(reseller))

    assert resp["success"] is True
    assert resp["enabled"] is True
    assert resp["config"] == {"wan_ports": ["ether1", "ether2"]}
    assert resp["applied_at"] == "2026-08-05T12:00:00"
    assert resp["verify"] == verify_report
