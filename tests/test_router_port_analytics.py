from types import SimpleNamespace
from datetime import datetime, timedelta

import pytest

from app.api import router_operations
from app.db.models import CustomerPayment, CustomerStatus
from tests.factories import make_customer, make_plan, make_reseller, make_router


class FakePortAnalyticsAPI:
    def __init__(self, *_args, **_kwargs):
        self.connected = False

    def connect(self):
        self.connected = True
        return True

    def disconnect(self):
        self.connected = False

    def send_command(self, command, args=None):
        if command == "/system/identity/print":
            return {"success": True, "data": [{"name": "Router-A"}]}
        if command == "/system/resource/print":
            return {
                "success": True,
                "data": [
                    {
                        "version": "7.14",
                        "board-name": "RB4011",
                        "architecture-name": "arm",
                        "uptime": "1d",
                        "cpu-load": "4",
                        "free-memory": "1000",
                        "total-memory": "2000",
                    }
                ],
            }
        if command == "/interface/ethernet/monitor":
            port = args["numbers"]
            return {
                "success": True,
                "data": [
                    {
                        "name": port,
                        "status": "link-ok",
                        "rate": "1Gbps",
                        "full-duplex": "true",
                    }
                ],
            }
        raise AssertionError(f"unexpected command {command}")

    def send_command_optimized(self, command, proplist=None, query=None):
        if command == "/interface/print":
            return {
                "success": True,
                "data": [
                    {
                        "name": "ether6",
                        "type": "ether",
                        "running": "true",
                        "disabled": "false",
                        "rx-byte": "100",
                        "tx-byte": "200",
                        "rx-packet": "10",
                        "tx-packet": "20",
                        "rx-error": "0",
                        "tx-error": "0",
                        "link-downs": "0",
                    },
                    {
                        "name": "ether7",
                        "type": "ether",
                        "running": "true",
                        "disabled": "false",
                        "rx-byte": "0",
                        "tx-byte": "50",
                        "rx-packet": "0",
                        "tx-packet": "5",
                        "rx-error": "0",
                        "tx-error": "0",
                        "link-downs": "0",
                    },
                ],
            }
        if command == "/interface/ethernet/print":
            return {
                "success": True,
                "data": [
                    {"name": "ether6", "mac-address": "AA:AA:AA:00:00:06"},
                    {"name": "ether7", "mac-address": "AA:AA:AA:00:00:07"},
                ],
            }
        if command == "/interface/bridge/print":
            return {"success": True, "data": [{"name": "bridge", "running": "true"}]}
        if command == "/interface/bridge/port/print":
            return {
                "success": True,
                "data": [
                    {"interface": "ether6", "bridge": "bridge", "status": "in-bridge"},
                    {"interface": "ether7", "bridge": "bridge", "status": "in-bridge"},
                ],
            }
        if command == "/interface/bridge/host/print":
            return {
                "success": True,
                "data": [
                    {
                        "mac-address": "10:5F:02:A5:1A:CD",
                        "interface": "ether6",
                        "on-interface": "ether6",
                        "local": "false",
                    },
                    {
                        "mac-address": "AA:BB:CC:DD:EE:01",
                        "interface": "ether6",
                        "on-interface": "ether6",
                        "local": "false",
                    },
                    {
                        "mac-address": "AA:BB:CC:DD:EE:02",
                        "interface": "ether6",
                        "on-interface": "ether6",
                        "local": "false",
                    },
                ],
            }
        if command == "/ip/neighbor/print":
            return {
                "success": True,
                "data": [
                    {
                        "interface": "ether6",
                        "address": "192.168.120.1",
                        "mac-address": "10:5F:02:A5:1A:CD",
                        "identity": "Ruijie",
                        "platform": "",
                        "board": "",
                        "version": "",
                    }
                ],
            }
        if command == "/ip/dhcp-server/lease/print":
            return {
                "success": True,
                "data": [
                    {
                        "active-address": "192.168.88.10",
                        "active-mac-address": "AA:BB:CC:DD:EE:01",
                        "host-name": "phone-1",
                        "status": "bound",
                    },
                    {
                        "active-address": "192.168.88.11",
                        "active-mac-address": "AA:BB:CC:DD:EE:02",
                        "host-name": "phone-2",
                        "status": "bound",
                    },
                    {
                        "active-address": "192.168.120.1",
                        "active-mac-address": "10:5F:02:A5:1A:CD",
                        "host-name": "ruijie-ap",
                        "status": "bound",
                    },
                ],
            }
        if command == "/ip/arp/print":
            return {"success": True, "data": []}
        if command == "/ip/hotspot/host/print":
            return {
                "success": True,
                "data": [
                    {
                        "mac-address": "AA:BB:CC:DD:EE:01",
                        "address": "192.168.88.10",
                        "authorized": "true",
                        "bypassed": "false",
                    },
                    {
                        "mac-address": "AA:BB:CC:DD:EE:02",
                        "address": "192.168.88.11",
                        "authorized": "false",
                        "bypassed": "true",
                    },
                ],
            }
        if command == "/ip/hotspot/active/print":
            return {
                "success": True,
                "data": [
                    {
                        "user": "AABBCCDDEE01",
                        "mac-address": "AA:BB:CC:DD:EE:01",
                        "address": "192.168.88.10",
                    }
                ],
            }
        if command == "/ppp/active/print":
            return {"success": True, "data": []}
        raise AssertionError(f"unexpected optimized command {command}")


def test_port_analytics_groups_downstream_devices_by_port(monkeypatch):
    monkeypatch.setattr(router_operations, "MikroTikAPI", FakePortAnalyticsAPI)

    result = router_operations._get_port_analytics_sync(
        {
            "id": 10,
            "name": "Router A",
            "identity": "Router-A",
            "ip": "10.0.0.5",
            "username": "admin",
            "password": "pw",
            "port": 8728,
        },
        {
            "AA:BB:CC:DD:EE:01": {
                "id": 1,
                "name": "Customer One",
                "status": "active",
                "revenue": {"total": 1500.0, "today": 100.0, "this_week": 300.0, "this_month": 700.0},
            },
            "AA:BB:CC:DD:EE:02": {
                "id": 2,
                "name": "Customer Two",
                "status": "active",
                "revenue": {"total": 500.0, "today": 0.0, "this_week": 0.0, "this_month": 200.0},
            },
        },
    )

    assert result["success"] is True
    ether6 = next(port for port in result["ports"] if port["port"] == "ether6")
    assert ether6["health"]["status"] == "active"
    assert ether6["counts"]["learned_macs"] == 3
    assert ether6["counts"]["known_customers_seen"] == 2
    assert ether6["counts"]["known_customers_connected"] == 2
    assert ether6["counts"]["hotspot_authorized"] == 1
    assert ether6["counts"]["hotspot_bypassed"] == 1
    assert ether6["infrastructure"][0]["name"] == "Ruijie"
    assert ether6["revenue"] == {
        "total": 2000.0,
        "today": 100.0,
        "this_week": 300.0,
        "this_month": 900.0,
        "paying_customers_seen": 2,
    }
    customer_sample = next(
        sample
        for sample in ether6["downstream_devices_sample"]
        if sample.get("customer_id") == 1
    )
    assert customer_sample["revenue_total"] == 1500.0

    ether7 = next(port for port in result["ports"] if port["port"] == "ether7")
    assert ether7["health"]["status"] == "silent_link"
    assert "received 0 packets" in ether7["health"]["warnings"][0]
    assert ether7["revenue"]["total"] == 0.0
    assert ether7["revenue"]["paying_customers_seen"] == 0

    assert result["revenue"] == {
        "attributed_total": 2000.0,
        "attributed_today": 100.0,
        "attributed_this_week": 300.0,
        "attributed_this_month": 900.0,
    }


@pytest.mark.asyncio
async def test_port_analytics_endpoint_matches_customers_and_uses_cache(db, monkeypatch):
    router_operations._port_analytics_cache.clear()
    router_operations._port_analytics_locks.clear()
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Router A")
    plan = await make_plan(db, reseller)
    await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        mac_address="aa-bb-cc-dd-ee-01",
        name="Customer One",
    )

    async def fake_current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=reseller.role)

    calls = {"count": 0}

    def fake_sync(router_info, customer_by_mac):
        calls["count"] += 1
        assert router_info["id"] == router.id
        assert "AA:BB:CC:DD:EE:01" in customer_by_mac
        return {
            "success": True,
            "router": {"id": router.id, "name": router.name},
            "generated_at": "2026-07-08T00:00:00",
            "cached": False,
            "ports": [],
        }

    monkeypatch.setattr(router_operations, "get_current_user", fake_current_user)
    monkeypatch.setattr(router_operations, "_get_port_analytics_sync", fake_sync)

    first = await router_operations.get_router_port_analytics(
        router.id,
        refresh=True,
        db=db,
        token="token",
    )
    second = await router_operations.get_router_port_analytics(
        router.id,
        refresh=False,
        db=db,
        token="token",
    )

    assert first["cached"] is False
    assert second["cached"] is True
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_port_analytics_endpoint_attaches_customer_and_router_revenue(db, monkeypatch):
    router_operations._port_analytics_cache.clear()
    router_operations._port_analytics_locks.clear()
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Router A")
    plan = await make_plan(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        mac_address="aa-bb-cc-dd-ee-01",
        name="Customer One",
    )
    db.add(
        CustomerPayment(
            customer_id=customer.id,
            reseller_id=reseller.id,
            amount=800.0,
            days_paid_for=30,
        )
    )
    # Compensation-style rows must not count toward port revenue
    db.add(
        CustomerPayment(
            customer_id=customer.id,
            reseller_id=reseller.id,
            amount=200.0,
            days_paid_for=7,
            counts_as_revenue=False,
        )
    )
    await db.commit()

    async def fake_current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=reseller.role)

    def fake_sync(router_info, customer_by_mac):
        entry = customer_by_mac["AA:BB:CC:DD:EE:01"]
        assert entry["revenue"]["total"] == 800.0
        assert entry["revenue"]["today"] == 800.0
        return {
            "success": True,
            "router": {"id": router.id, "name": router.name},
            "generated_at": "2026-07-08T00:00:00",
            "cached": False,
            "revenue": {
                "attributed_total": 300.0,
                "attributed_today": 300.0,
                "attributed_this_week": 300.0,
                "attributed_this_month": 300.0,
            },
            "ports": [],
        }

    monkeypatch.setattr(router_operations, "get_current_user", fake_current_user)
    monkeypatch.setattr(router_operations, "_get_port_analytics_sync", fake_sync)

    response = await router_operations.get_router_port_analytics(
        router.id,
        refresh=True,
        db=db,
        token="token",
    )

    assert response["revenue"]["router_total"] == 800.0
    assert response["revenue"]["router_today"] == 800.0
    assert response["revenue"]["attributed_total"] == 300.0
    assert response["revenue"]["unattributed_total"] == 500.0


@pytest.mark.asyncio
async def test_port_analytics_refresh_true_is_rate_limited_by_recent_cache(db, monkeypatch):
    router_operations._port_analytics_cache.clear()
    router_operations._port_analytics_locks.clear()
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Router A")

    async def fake_current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=reseller.role)

    calls = {"count": 0}

    def fake_sync(_router_info, _customer_by_mac):
        calls["count"] += 1
        return {
            "success": True,
            "router": {"id": router.id, "name": router.name},
            "generated_at": "2026-07-08T00:00:00",
            "cached": False,
            "ports": [],
        }

    monkeypatch.setattr(router_operations, "get_current_user", fake_current_user)
    monkeypatch.setattr(router_operations, "_get_port_analytics_sync", fake_sync)

    first = await router_operations.get_router_port_analytics(
        router.id,
        refresh=True,
        db=db,
        token="token",
    )
    second = await router_operations.get_router_port_analytics(
        router.id,
        refresh=True,
        db=db,
        token="token",
    )

    assert first["cached"] is False
    assert second["cached"] is True
    assert second["refresh_skipped"] is True
    assert second["refresh_skip_reason"] == "recent_cache"
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_port_analytics_returns_cached_result_when_refresh_already_running(db, monkeypatch):
    router_operations._port_analytics_cache.clear()
    router_operations._port_analytics_locks.clear()
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Router A")

    async def fake_current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=reseller.role)

    monkeypatch.setattr(router_operations, "get_current_user", fake_current_user)
    router_operations._port_analytics_cache[router.id] = {
        "timestamp": datetime.utcnow()
        - timedelta(seconds=router_operations._PORT_ANALYTICS_REFRESH_FLOOR + 5),
        "data": {
            "success": True,
            "router": {"id": router.id, "name": router.name},
            "generated_at": "2026-07-08T00:00:00",
            "cached": False,
            "ports": [],
        },
    }
    lock = router_operations._port_analytics_locks.setdefault(router.id, router_operations.asyncio.Lock())
    await lock.acquire()
    try:
        response = await router_operations.get_router_port_analytics(
            router.id,
            refresh=True,
            db=db,
            token="token",
        )
    finally:
        lock.release()

    assert response["cached"] is True
    assert response["stale"] is True
    assert response["refresh_pending"] is True
    assert response["refresh_skip_reason"] == "refresh_already_running"
