"""A phone-number reconnect moves one entitlement, never duplicates it."""

from datetime import datetime, timedelta

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import select

from app.api import public_routes
from app.db.models import Customer, CustomerStatus, ReconnectionAttempt
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

OLD_MAC = "AA:BB:CC:00:10:01"
NEW_MAC = "AA:BB:CC:00:10:02"


class FakeMikroTik:
    def __init__(self, *_args, **_kwargs):
        self.rows = {
            "/ip/hotspot/ip-binding": [
                {".id": "*1", "mac-address": OLD_MAC, "type": "bypassed"},
            ],
            "/ip/hotspot/active": [
                {".id": "*2", "mac-address": OLD_MAC, "user": OLD_MAC.replace(":", "")},
            ],
            "/ip/hotspot/host": [
                {
                    ".id": "*3", "mac-address": OLD_MAC,
                    "address": "192.168.88.10", "authorized": "true", "bypassed": "true",
                },
            ],
            "/ip/hotspot/user": [
                {".id": "*4", "name": OLD_MAC.replace(":", "")},
            ],
            "/queue/simple": [
                {".id": "*5", "name": f"plan_{OLD_MAC.replace(':', '')}"},
            ],
            "/ip/dhcp-server/lease": [
                {".id": "*6", "mac-address": OLD_MAC},
            ],
        }

    def connect(self):
        return True

    def disconnect(self):
        return None

    def send_command(self, command, arguments=None):
        if command.endswith("/print"):
            path = command.removesuffix("/print")
            return {"success": True, "data": [dict(row) for row in self.rows.get(path, [])]}
        if command.endswith("/remove"):
            path = command.removesuffix("/remove")
            row_id = (arguments or {}).get("numbers")
            self.rows[path] = [row for row in self.rows.get(path, []) if row.get(".id") != row_id]
            return {"success": True}
        return {"success": False, "error": "unexpected command"}


async def _active_customer(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=1)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=2),
        mac_address=OLD_MAC,
        phone="254700001001",
    )
    return router, customer


async def test_cleanup_removes_and_verifies_every_authorization_artifact(monkeypatch):
    fake = FakeMikroTik()
    monkeypatch.setattr(public_routes, "MikroTikAPI", lambda *_args, **_kwargs: fake)

    result = public_routes._cleanup_old_mac_from_router_sync(
        {"ip": "10.0.0.2", "username": "admin", "password": "x", "port": 8728},
        OLD_MAC,
    )

    assert result["success"] is True
    assert result["removed"] == {
        "bindings": 1, "sessions": 1, "hosts": 1, "users": 1,
        "queues": 1, "leases": 1, "lb_paid": 0,
    }


async def test_cleanup_fails_closed_when_bypass_binding_remains(monkeypatch):
    fake = FakeMikroTik()

    def fail_binding_remove(command, arguments=None):
        if command == "/ip/hotspot/ip-binding/remove":
            return {"success": False, "error": "router rejected removal"}
        return FakeMikroTik.send_command(fake, command, arguments)

    fake.send_command = fail_binding_remove
    monkeypatch.setattr(public_routes, "MikroTikAPI", lambda *_args, **_kwargs: fake)

    result = public_routes._cleanup_old_mac_from_router_sync(
        {"ip": "10.0.0.2", "username": "admin", "password": "x", "port": 8728},
        OLD_MAC,
    )

    assert "error" in result
    assert result["remaining"]["bindings"] == 1


async def test_cleanup_allows_connected_but_unauthorized_host_to_reappear(monkeypatch):
    fake = FakeMikroTik()
    original_send = fake.send_command
    host_prints = 0

    def reconnecting_host(command, arguments=None):
        nonlocal host_prints
        if command == "/ip/hotspot/host/print":
            host_prints += 1
            if host_prints > 1:
                return {
                    "success": True,
                    "data": [{
                        ".id": "*9", "mac-address": OLD_MAC,
                        "authorized": "false", "bypassed": "false",
                    }],
                }
        return original_send(command, arguments)

    fake.send_command = reconnecting_host
    monkeypatch.setattr(public_routes, "MikroTikAPI", lambda *_args, **_kwargs: fake)

    result = public_routes._cleanup_old_mac_from_router_sync(
        {"ip": "10.0.0.2", "username": "admin", "password": "x", "port": 8728},
        OLD_MAC,
    )

    assert result["success"] is True


async def test_device_move_revokes_old_before_updating_and_provisioning(db, monkeypatch):
    router, customer = await _active_customer(db)
    events = []

    async def cleanup_ok(_router_info, old_mac):
        current = await db.get(Customer, customer.id)
        await db.refresh(current)
        events.append(("cleanup", old_mac, current.mac_address))
        return {"success": True}

    async def provision_ok(**kwargs):
        events.append(("provision", kwargs["hotspot_payload"]["mac_address"]))
        return {"success": True}

    monkeypatch.setattr(public_routes, "_cleanup_old_mac_with_retry", cleanup_ok)
    from app.services import hotspot_provisioning
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", provision_ok)

    tasks = BackgroundTasks()
    result = await public_routes.reconnect_self_service(
        public_routes.ReconnectRequest(
            phone="0700001001", mac_address=NEW_MAC, router_id=router.id,
        ),
        tasks,
        db,
    )
    current = await db.get(Customer, customer.id)
    await db.refresh(current)

    assert result["success"] is True
    assert events == [("cleanup", OLD_MAC, OLD_MAC)]
    assert current.mac_address == NEW_MAC

    await tasks()
    assert events[-1] == ("provision", NEW_MAC)


async def test_failed_revocation_keeps_database_on_old_mac(db, monkeypatch):
    router, customer = await _active_customer(db)
    provisioned = []

    async def cleanup_failed(*_args, **_kwargs):
        return {"error": "unverified", "remaining": {"bindings": 1}}

    async def provision_ok(**kwargs):
        provisioned.append(kwargs)
        return {"success": True}

    monkeypatch.setattr(public_routes, "_cleanup_old_mac_with_retry", cleanup_failed)
    from app.services import hotspot_provisioning
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", provision_ok)

    with pytest.raises(HTTPException) as exc:
        await public_routes.reconnect_self_service(
            public_routes.ReconnectRequest(
                phone="254700001001", mac_address=NEW_MAC, router_id=router.id,
            ),
            BackgroundTasks(),
            db,
        )

    assert exc.value.status_code == 503
    current = await db.get(Customer, customer.id)
    await db.refresh(current)
    assert current.mac_address == OLD_MAC
    assert provisioned == []

    attempts = (
        await db.execute(select(ReconnectionAttempt).where(
            ReconnectionAttempt.customer_id == customer.id
        ))
    ).scalars().all()
    assert len(attempts) == 1
    assert attempts[0].success is False
    assert attempts[0].failure_reason == "old_mac_cleanup_unverified"


async def test_stale_background_provision_is_skipped(db, monkeypatch):
    router, customer = await _active_customer(db)
    called = []

    async def provision_ok(**kwargs):
        called.append(kwargs)
        return {"success": True}

    from app.services import hotspot_provisioning
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", provision_ok)
    customer.mac_address = NEW_MAC
    await db.commit()

    await public_routes._provision_reconnected_mac_if_current(
        customer_id=customer.id,
        router_id=router.id,
        target_mac=OLD_MAC,
        hotspot_payload={"mac_address": OLD_MAC},
        customer_name=customer.name,
        router_name=router.name,
    )

    assert called == []
