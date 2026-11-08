"""Deleting a hotspot customer must take its access off the router.

2026-11-07, router 627: a deleted customer's hotspot user (from a comp voucher)
stayed on the MikroTik and the device kept free internet until expiry. PPPoE,
static and shared customers were cleaned on delete; plain hotspot ones were not.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, text

from app.api import customer_routes
from app.db.models import (
    AppSetting,
    ConnectionType,
    CustomerStatus,
    ProvisioningLog,
    RouterAuthMethod,
    RouterCommand,
)
from app.services import deleted_customer_cleanup as cleanup
from app.services import router_agent_commands as commands
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

MAC = "62:39:3A:F0:4D:5F"


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def _setup(db, **router_overrides):
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_check (customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_reply (customer_id INTEGER)"))
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller, **router_overrides)
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1), mac_address=MAC,
    )
    await db.commit()
    return reseller, plan, router, customer


@pytest.fixture
def router_calls(monkeypatch):
    """Records router cleanups; ``state["online"]`` picks the outcome."""
    state = {"online": True, "calls": []}

    def fake(router_info, customers_data):
        state["calls"].append((router_info["id"], [c["mac_address"] for c in customers_data]))
        if state["online"]:
            return {"removed": [{"id": c["id"]} for c in customers_data], "failed": [], "connected": True}
        return {
            "removed": [],
            "failed": [{"id": c["id"], "error": "Failed to connect to router"} for c in customers_data],
            "connected": False,
        }

    monkeypatch.setattr(cleanup, "_cleanup_on_router", fake)
    return state


async def _pending(db):
    db.expire_all()
    return (
        await db.execute(select(ProvisioningLog).where(ProvisioningLog.action == cleanup.CLEANUP_ACTION))
    ).scalars().all()


async def test_delete_hotspot_customer_removes_it_from_the_router(db, router_calls):
    reseller, _plan, router, customer = await _setup(db)

    response = await customer_routes.delete_customer(customer.id, db, _token(reseller))

    assert response["success"] is True
    assert response["router_cleanup"] == "removed"
    assert router_calls["calls"] == [(router.id, [MAC])]
    assert await _pending(db) == []


async def test_delete_with_router_offline_still_deletes_and_queues_cleanup(db, router_calls):
    router_calls["online"] = False
    reseller, _plan, router, customer = await _setup(db)
    router_id = router.id

    response = await customer_routes.delete_customer(customer.id, db, _token(reseller))

    assert response["success"] is True
    assert response["router_cleanup"] == "queued"
    rows = await _pending(db)
    assert [(r.router_id, r.mac_address, r.status, r.customer_id) for r in rows] == [
        (router_id, MAC, cleanup.STATUS_PENDING, None)
    ]


async def test_delete_leaves_a_mac_another_live_customer_uses(db, router_calls):
    reseller, plan, router, customer = await _setup(db)
    await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1), mac_address=MAC.lower(),
        phone="254700000009",
    )

    response = await customer_routes.delete_customer(customer.id, db, _token(reseller))

    assert response["router_cleanup"] == "skipped"
    assert router_calls["calls"] == []
    assert await _pending(db) == []


async def test_only_direct_api_hotspot_customers_get_a_target(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    radius_router = await make_router(db, reseller, auth_method=RouterAuthMethod.RADIUS)
    hotspot = await make_plan(db, reseller)
    pppoe = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    static = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP)

    async def target(plan, rtr, **kw):
        c = await make_customer(db, reseller, plan, rtr, **kw)
        await db.refresh(c, ["plan", "router"])
        return cleanup.cleanup_target(c)

    assert (await target(hotspot, router))["router_id"] == router.id
    assert await target(pppoe, router, pppoe_username="u1") is None
    assert await target(static, router) is None
    assert await target(hotspot, radius_router) is None
    assert await target(hotspot, None) is None


async def test_retry_removes_once_router_is_back(db, router_calls):
    router_calls["online"] = False
    reseller, _plan, router, customer = await _setup(db)
    await customer_routes.delete_customer(customer.id, db, _token(reseller))

    first = await cleanup.retry_pending_cleanups()
    assert first["still_pending"] == 1
    assert (await _pending(db))[0].status == cleanup.STATUS_PENDING

    router_calls["online"] = True
    backed_off = await cleanup.retry_pending_cleanups()
    assert backed_off["removed"] == 0, "a router that just failed waits out its back-off"

    cleanup._router_failed_at.clear()
    second = await cleanup.retry_pending_cleanups()
    assert second["removed"] == 1
    assert (await _pending(db))[0].status == cleanup.STATUS_DONE


async def test_retry_skips_a_mac_that_became_live_again(db, router_calls):
    router_calls["online"] = False
    reseller, plan, router, customer = await _setup(db)
    await customer_routes.delete_customer(customer.id, db, _token(reseller))
    router_calls["calls"].clear()
    await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1), mac_address=MAC,
    )

    result = await cleanup.retry_pending_cleanups()

    assert result["skipped"] == 1
    assert router_calls["calls"] == []
    assert (await _pending(db))[0].status == cleanup.STATUS_SKIPPED


async def test_retry_gives_up_after_the_window(db, router_calls):
    router_calls["online"] = False
    reseller, _plan, _router, customer = await _setup(db)
    await customer_routes.delete_customer(customer.id, db, _token(reseller))

    result = await cleanup.retry_pending_cleanups(datetime.utcnow() + timedelta(days=8))

    assert result["abandoned"] == 1
    assert (await _pending(db))[0].status == cleanup.STATUS_ABANDONED


async def test_agent_router_offline_gets_a_customerless_remove_command(db, router_calls):
    router_calls["online"] = False
    reseller, plan, router, customer = await _setup(
        db, identity="Router-Agent-Test", router_agent_enabled=True,
    )
    db.add(AppSetting(key="router_agent_enabled", value="true"))
    await db.commit()
    router_id = router.id

    await customer_routes.delete_customer(customer.id, db, _token(reseller))

    db.expire_all()
    command = (await db.execute(select(RouterCommand))).scalar_one()
    assert command.command_type == "hotspot_remove"
    assert command.customer_id is None
    assert MAC in command.action_script
    command_id = command.id
    assert "agent command" in (await _pending(db))[0].details

    delivered = await commands.next_command_for_router(router_id)
    assert delivered is not None and delivered.id == command_id


async def test_customerless_remove_is_cancelled_when_the_mac_is_live_again(db, router_calls):
    router_calls["online"] = False
    reseller, plan, router, customer = await _setup(
        db, identity="Router-Agent-Test", router_agent_enabled=True,
    )
    db.add(AppSetting(key="router_agent_enabled", value="true"))
    await db.commit()
    await customer_routes.delete_customer(customer.id, db, _token(reseller))
    await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1), mac_address=MAC,
    )

    assert await commands.next_command_for_router(router.id) is None
    db.expire_all()
    command = (await db.execute(select(RouterCommand))).scalar_one()
    assert command.state == "cancelled"


async def test_agent_remove_script_also_removes_the_mac_login_user():
    script = commands.render_hotspot_remove_action(mac_address=MAC, username=MAC.replace(":", ""))
    assert f'/ip hotspot user remove [find name="{MAC}"]' in script
    assert f'/ip hotspot user find name="{MAC}"' in script
