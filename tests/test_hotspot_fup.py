from datetime import datetime, timedelta

import pytest

from app.db.models import ConnectionType, CustomerUsagePeriod, FupAction
from app.api import plan_routes
from app.services import fup
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest.mark.asyncio
async def test_hotspot_fup_throttle_sets_queue_and_marks_period(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.HOTSPOT,
        data_cap_mb=1,
        fup_action=FupAction.THROTTLE,
        fup_throttle_profile="512K/512K",
    )
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        mac_address="AA:BB:CC:DD:EE:FF",
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    now = datetime.utcnow()
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=now - timedelta(hours=1),
        period_end=now + timedelta(hours=1),
        upload_bytes=1_200_000,
        download_bytes=1_200_000,
        total_bytes=2_400_000,
        cap_mb_snapshot=1,
        fup_action_snapshot=FupAction.THROTTLE,
    )
    db.add(period)
    await db.commit()
    await db.refresh(period)

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    calls = []

    def fake_set_queue(router_info, mac_address, rate_limit, *, disabled="no"):
        calls.append(
            {
                "router": router_info["ip"],
                "mac": mac_address,
                "rate": rate_limit,
                "disabled": disabled,
            }
        )
        return {"success": True}

    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(fup, "_set_hotspot_queue_limit_sync", fake_set_queue)

    action = await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=now)

    assert action == FupAction.THROTTLE
    assert period.fup_triggered_at == now
    assert period.fup_action_taken == FupAction.THROTTLE
    assert period.fup_reverted_at is None
    assert calls == [
        {
            "router": router.ip_address,
            "mac": "AA:BB:CC:DD:EE:FF",
            "rate": "512K/512K",
            "disabled": "no",
        }
    ]


@pytest.mark.asyncio
async def test_hotspot_revert_without_triggered_period_skips_router_io(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.HOTSPOT,
        data_cap_mb=1,
        fup_action=FupAction.BLOCK,
    )
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        mac_address="AA:BB:CC:DD:EE:11",
        expiry=datetime.utcnow() + timedelta(days=30),
    )

    calls = []

    async def fake_restore(*args, **kwargs):
        calls.append((args, kwargs))
        return {"success": True}

    monkeypatch.setattr(fup, "restore_normal_profile", fake_restore)

    assert await fup.revert(db, customer, plan=plan, period=None) is False
    assert calls == []


def test_hotspot_block_sync_sets_blocked_binding_and_disables_queue(monkeypatch):
    instances = []

    class FakeMikroTik:
        def __init__(self, *args, **kwargs):
            self.commands = []
            instances.append(self)

        def connect(self):
            return True

        def disconnect(self):
            self.commands.append(("disconnect", None))

        def get_simple_queues_minimal(self):
            return {
                "success": True,
                "data": [
                    {
                        ".id": "*2",
                        "name": "plan_AABBCCDDEEFF",
                        "comment": "MAC:AA:BB:CC:DD:EE:FF|Plan rate limit",
                    }
                ],
            }

        def send_command(self, command, args=None):
            self.commands.append((command, args))
            if command == "/ip/hotspot/ip-binding/print":
                return {
                    "success": True,
                    "data": [
                        {
                            ".id": "*1",
                            "mac-address": "AA:BB:CC:DD:EE:FF",
                            "type": "bypassed",
                        }
                    ],
                }
            if command in {
                "/ip/hotspot/ip-binding/set",
                "/queue/simple/set",
                "/ip/hotspot/active/remove",
                "/ip/hotspot/host/remove",
            }:
                return {"success": True}
            if command == "/ip/hotspot/active/print":
                return {
                    "success": True,
                    "data": [
                        {
                            ".id": "*3",
                            "mac-address": "AA:BB:CC:DD:EE:FF",
                            "user": "AABBCCDDEEFF",
                        }
                    ],
                }
            if command == "/ip/hotspot/host/print":
                return {
                    "success": True,
                    "data": [{".id": "*4", "mac-address": "AA:BB:CC:DD:EE:FF"}],
                }
            raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(fup, "MikroTikAPI", FakeMikroTik)

    result = fup._block_hotspot_sync(
        {"ip": "10.0.0.2", "username": "admin", "password": "pw", "port": 8728},
        "AA:BB:CC:DD:EE:FF",
    )

    assert result["success"] is True
    commands = instances[0].commands
    assert (
        "/ip/hotspot/ip-binding/set",
        {
            "numbers": "*1",
            "type": "blocked",
            "comment": commands[1][1]["comment"],
        },
    ) in commands
    assert ("/queue/simple/set", {"numbers": "*2", "disabled": "yes"}) in commands
    assert ("/ip/hotspot/active/remove", {"numbers": "*3"}) in commands
    assert ("/ip/hotspot/host/remove", {"numbers": "*4"}) in commands


@pytest.mark.asyncio
async def test_plan_update_can_clear_fup_fields(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.HOTSPOT,
        data_cap_mb=1024,
        fup_action=FupAction.BLOCK,
        fup_throttle_profile="512K/512K",
    )

    async def fake_current_user(_token, _db):
        return reseller

    async def fake_invalidate_plan_cache():
        return None

    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda _user: None)
    monkeypatch.setattr(plan_routes, "invalidate_plan_cache", fake_invalidate_plan_cache)

    response = await plan_routes.update_plan_api(
        plan.id,
        plan_routes.PlanUpdateRequest(
            data_cap_mb=None,
            fup_action=None,
            fup_throttle_profile=None,
        ),
        db=db,
        token="token",
    )

    assert response["data_cap_mb"] is None
    assert response["fup_action"] is None
    assert response["fup_throttle_profile"] is None
