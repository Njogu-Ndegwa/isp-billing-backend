from datetime import datetime, timedelta

import pytest

from app.api import router_operations
from app.db.models import CustomerStatus
from app.services import hotspot_provisioning, mikrotik_background
from app.services.mikrotik_api import MikroTikAPI, is_hotspot_parent_queue_name
from tests.factories import make_customer, make_plan, make_reseller, make_router


def test_hotspot_parent_queue_detection_matches_routeros_angle_brackets():
    assert is_hotspot_parent_queue_name("hs-hotspot")
    assert is_hotspot_parent_queue_name("<hs-unlimite>")
    assert is_hotspot_parent_queue_name(" <hs-unlimited> ")
    assert not is_hotspot_parent_queue_name("plan_AABBCCDDEEFF")
    assert not is_hotspot_parent_queue_name("<pppoe-customer1>")


def test_remove_hotspot_parent_queues_removes_angle_bracket_names():
    api = MikroTikAPI.__new__(MikroTikAPI)
    api.connected = True
    removed = []

    def fake_send_command(path, args=None):
        if path == "/queue/simple/print":
            return {
                "success": True,
                "data": [
                    {".id": "*1", "name": "<hs-unlimite>", "target": "bridge", "max-limit": "unlimited/unlimited"},
                    {".id": "*2", "name": "plan_AABBCCDDEEFF", "target": "192.168.88.10/32", "max-limit": "5M/5M"},
                ],
            }
        if path == "/queue/simple/remove":
            removed.append(args["numbers"])
            return {"success": True}
        raise AssertionError(f"Unexpected command: {path}")

    api.send_command = fake_send_command

    result = MikroTikAPI.remove_hotspot_parent_queues(api)

    assert result == {"success": True, "removed": 1, "errors": []}
    assert removed == ["*1"]


def test_queue_pending_is_retryable_provisioning_error():
    result = hotspot_provisioning._extract_provisioning_error(
        {
            "profile_result": {"success": True},
            "hotspot_user_result": {"success": True},
            "ip_binding_result": {"success": True},
            "queue_result": {"pending": True, "message": "Client not connected, queue pending"},
        }
    )

    assert result == "queue_pending: Client not connected, queue pending"


@pytest.mark.asyncio
async def test_queue_sync_processes_only_capped_router_batch(db, session_factory, monkeypatch):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "queue_sync_running", False)
    monkeypatch.setattr(mikrotik_background, "_queue_sync_router_cursor", 0)
    monkeypatch.setattr(mikrotik_background, "QUEUE_SYNC_MAX_ROUTERS_PER_RUN", 2)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job_name: False)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    for idx in range(5):
        router = await make_router(
            db,
            reseller,
            name=f"QueueRouter-{idx}",
            ip_address=f"10.20.0.{idx + 1}",
        )
        await make_customer(
            db,
            reseller,
            plan,
            router,
            status=CustomerStatus.ACTIVE,
            expiry=datetime.utcnow() + timedelta(hours=2),
            mac_address=f"AA:BB:CC:DD:EE:{idx:02X}",
            phone=f"25472200000{idx}",
        )

    calls = []

    def fake_sync_single_router(router_info, customers_data):
        calls.append((router_info["name"], [c["id"] for c in customers_data]))
        return {
            "synced": 0,
            "errors": 0,
            "skipped": len(customers_data),
            "routers_connected": 1,
            "details": {"router": router_info["name"]},
        }

    monkeypatch.setattr(
        mikrotik_background,
        "_sync_single_router_queues_sync",
        fake_sync_single_router,
    )

    await mikrotik_background.sync_active_user_queues()

    assert len(calls) == 2
    assert all(len(customer_ids) == 1 for _router_name, customer_ids in calls)


@pytest.mark.asyncio
async def test_bandwidth_check_flags_hotspot_parent_queue_shadowing(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, speed="5M/5M")
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=2),
        mac_address="AA:BB:CC:DD:EE:99",
    )

    async def fake_current_user(_token, _db):
        return reseller

    async def fake_get_router_by_id(_db, router_id, _user_id, _role):
        assert router_id == router.id
        return router

    def fake_bandwidth_data(_router_info):
        return {
            "all_queues": [
                {
                    ".id": "*1",
                    "name": "<hs-unlimite>",
                    "target": "bridge",
                    "max-limit": "unlimited/unlimited",
                    "disabled": "false",
                },
                {
                    ".id": "*2",
                    "name": "plan_AABBCCDDEE99",
                    "target": "192.168.88.20/32",
                    "max-limit": "5M/5M",
                    "comment": f"MAC:{customer.mac_address}|Plan rate limit",
                },
            ],
            "arp_entries": [
                {"mac-address": customer.mac_address, "address": "192.168.88.20"},
            ],
            "dhcp_leases": [],
        }

    monkeypatch.setattr(router_operations, "get_current_user", fake_current_user)
    monkeypatch.setattr(router_operations, "get_router_by_id", fake_get_router_by_id)
    monkeypatch.setattr(router_operations, "_get_bandwidth_check_data_sync", fake_bandwidth_data)

    result = await router_operations.check_bandwidth_limits(
        router_id=router.id,
        db=db,
        token="token",
    )

    assert result["has_hotspot_parent_queues"] is True
    assert result["has_shadowing_hotspot_parent_queues"] is True
    assert result["has_unlimited_users"] is True
    assert result["hotspot_parent_queues"][0]["name"] == "<hs-unlimite>"
    assert result["customers_with_queues"] == 0
    assert result["customers_without_queues_count"] == 1
    assert result["customers_WITHOUT_limits"][0]["issue"] == "HOTSPOT PARENT QUEUE MAY SHADOW PLAN QUEUE"
