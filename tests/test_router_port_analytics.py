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
                "revenue_total": 1500.0,
            },
            "AA:BB:CC:DD:EE:02": {
                "id": 2,
                "name": "Customer Two",
                "status": "active",
                "revenue_total": 500.0,
            },
        },
        {
            "ether6": {
                "total": 2000.0,
                "today": 100.0,
                "this_week": 300.0,
                "this_month": 900.0,
                "paying_customers": 2,
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
        "paying_customers": 2,
    }
    customer_sample = next(
        sample
        for sample in ether6["downstream_devices_sample"]
        if sample.get("customer_id") == 1
    )
    assert customer_sample["revenue_total"] == 1500.0

    # Additive computed classification fields (no schema changes).
    assert result["hotspot_subnets_inferred"] == ["192.168.88"]
    assert customer_sample["device_class"] == "customer"
    assert customer_sample["vendor"] is None
    assert customer_sample["router_mode_suspect"] is False
    ruijie_sample = next(
        sample
        for sample in ether6["downstream_devices_sample"]
        if sample["mac"] == "10:5F:02:A5:1A:CD"
    )
    assert ruijie_sample["kind"] == "infrastructure"
    assert ruijie_sample["device_class"] == "infrastructure"
    assert ruijie_sample["vendor"] == "Ruijie"
    assert ruijie_sample["router_mode_suspect"] is False
    assert ether6["infrastructure"][0]["vendor"] == "Ruijie"
    assert ether6["infrastructure"][0]["router_mode_suspect"] is False

    ether7 = next(port for port in result["ports"] if port["port"] == "ether7")
    assert ether7["health"]["status"] == "silent_link"
    assert "received 0 packets" in ether7["health"]["warnings"][0]
    assert ether7["revenue"]["total"] == 0.0
    assert ether7["revenue"]["paying_customers"] == 0


class FakePortAnalyticsAPIWithApSuspects(FakePortAnalyticsAPI):
    """Same fake router plus a Tenda-OUI AP and a router-mode CPE suspect.

    The suspect claims gateway identity 192.168.0.1 while the hotspot subnet
    is 192.168.88.0/24 — the field signature of a misconfigured router-mode
    AP plugged into the hotspot bridge (Beyond #1, 2026-07-24).
    """

    def send_command_optimized(self, command, proplist=None, query=None):
        result = super().send_command_optimized(command, proplist, query)
        if command == "/interface/bridge/host/print":
            result["data"] = result["data"] + [
                {
                    "mac-address": "B4:0F:3B:12:34:56",
                    "interface": "ether6",
                    "on-interface": "ether6",
                    "local": "false",
                },
                {
                    "mac-address": "AA:BB:CC:DD:EE:99",
                    "interface": "ether6",
                    "on-interface": "ether6",
                    "local": "false",
                },
            ]
        if command == "/ip/hotspot/host/print":
            result["data"] = result["data"] + [
                {
                    "mac-address": "AA:BB:CC:DD:EE:99",
                    "address": "192.168.0.1",
                    "authorized": "false",
                    "bypassed": "false",
                },
            ]
        return result


def test_port_analytics_classifies_vendor_aps_and_router_mode_suspects(monkeypatch):
    monkeypatch.setattr(router_operations, "MikroTikAPI", FakePortAnalyticsAPIWithApSuspects)

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
            "AA:BB:CC:DD:EE:01": {"id": 1, "name": "Customer One", "status": "active"},
            "AA:BB:CC:DD:EE:02": {"id": 2, "name": "Customer Two", "status": "active"},
        },
        {},
    )

    assert result["success"] is True
    assert result["hotspot_subnets_inferred"] == ["192.168.88"]
    ether6 = next(port for port in result["ports"] if port["port"] == "ether6")
    samples = {sample["mac"]: sample for sample in ether6["downstream_devices_sample"]}

    # Tenda OUI, no DHCP lease / neighbor entry: legacy "kind" is unchanged
    # but the computed classification recognizes the AP vendor.
    tenda = samples["B4:0F:3B:12:34:56"]
    assert tenda["kind"] == "unknown_device"
    assert tenda["device_class"] == "infrastructure"
    assert tenda["vendor"] == "Tenda"
    assert tenda["router_mode_suspect"] is False

    # Unknown OUI claiming a foreign gateway identity (192.168.0.1 while the
    # hotspot subnet is 192.168.88.0/24) => router-mode AP suspect.
    suspect = samples["AA:BB:CC:DD:EE:99"]
    assert suspect["device_class"] == "infrastructure"
    assert suspect["vendor"] is None
    assert suspect["router_mode_suspect"] is True

    # Registered billing customers on non-hardware MACs stay "customer".
    assert samples["AA:BB:CC:DD:EE:01"]["device_class"] == "customer"
    assert samples["AA:BB:CC:DD:EE:01"]["router_mode_suspect"] is False


def test_port_analytics_hardware_precedence_over_hotspot_accounts(monkeypatch):
    """Product ruling 2026-07-25: AP/CPE hardware renders as equipment even
    when a hotspot account pays through its MAC (reseller zone boxes);
    PPPoE accounts are the exception — their CPE genuinely IS the customer."""
    monkeypatch.setattr(router_operations, "MikroTikAPI", FakePortAnalyticsAPIWithApSuspects)
    router_info = {
        "id": 10,
        "name": "Router A",
        "identity": "Router-A",
        "ip": "10.0.0.5",
        "username": "admin",
        "password": "pw",
        "port": 8728,
    }

    # Tenda-OUI device with a HOTSPOT account on its MAC -> equipment wins.
    result = router_operations._get_port_analytics_sync(
        router_info,
        {"B4:0F:3B:12:34:56": {"id": 7, "name": "Zone Box", "status": "active",
                               "pppoe": False}},
        {},
    )
    ether6 = next(port for port in result["ports"] if port["port"] == "ether6")
    samples = {s["mac"]: s for s in ether6["downstream_devices_sample"]}
    zone_box = samples["B4:0F:3B:12:34:56"]
    assert zone_box["device_class"] == "infrastructure"
    assert zone_box["vendor"] == "Tenda"
    # the paying identity stays available for annotation/attribution
    assert zone_box["customer_id"] == 7

    # Same hardware MAC but a PPPoE account -> the exception applies.
    result = router_operations._get_port_analytics_sync(
        router_info,
        {"B4:0F:3B:12:34:56": {"id": 7, "name": "PPPoE Sub", "status": "active",
                               "pppoe": True}},
        {},
    )
    ether6 = next(port for port in result["ports"] if port["port"] == "ether6")
    samples = {s["mac"]: s for s in ether6["downstream_devices_sample"]}
    assert samples["B4:0F:3B:12:34:56"]["device_class"] == "customer"


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

    def fake_sync(router_info, customer_by_mac, revenue_by_port=None):
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
async def test_port_analytics_endpoint_uses_recorded_port_attribution(db, monkeypatch):
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
    # Stamped payment -> attributed to ether2
    db.add(
        CustomerPayment(
            customer_id=customer.id,
            reseller_id=reseller.id,
            amount=800.0,
            days_paid_for=30,
            port_name="ether2",
        )
    )
    # Never stamped -> unattributed
    db.add(
        CustomerPayment(
            customer_id=customer.id,
            reseller_id=reseller.id,
            amount=300.0,
            days_paid_for=7,
        )
    )
    # Compensation-style rows must not count toward revenue at all
    db.add(
        CustomerPayment(
            customer_id=customer.id,
            reseller_id=reseller.id,
            amount=200.0,
            days_paid_for=7,
            counts_as_revenue=False,
            port_name="ether2",
        )
    )
    await db.commit()

    async def fake_current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=reseller.role)

    seen = {}

    def fake_sync(router_info, customer_by_mac, revenue_by_port=None):
        seen["revenue_by_port"] = revenue_by_port
        entry = customer_by_mac["AA:BB:CC:DD:EE:01"]
        assert entry["revenue_total"] == 1100.0
        return {
            "success": True,
            "router": {"id": router.id, "name": router.name},
            "generated_at": "2026-07-08T00:00:00",
            "cached": False,
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

    assert seen["revenue_by_port"]["ether2"]["total"] == 800.0
    assert seen["revenue_by_port"]["ether2"]["paying_customers"] == 1
    assert response["revenue"]["attribution"] == "recorded"
    assert response["revenue"]["attributed_total"] == 800.0
    assert response["revenue"]["unattributed_total"] == 300.0
    assert response["revenue"]["router_total"] == 1100.0
    assert response["revenue"]["router_today"] == 1100.0


@pytest.mark.asyncio
async def test_port_analytics_refresh_true_is_rate_limited_by_recent_cache(db, monkeypatch):
    router_operations._port_analytics_cache.clear()
    router_operations._port_analytics_locks.clear()
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Router A")

    async def fake_current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=reseller.role)

    calls = {"count": 0}

    def fake_sync(_router_info, _customer_by_mac, _revenue_by_port=None):
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
