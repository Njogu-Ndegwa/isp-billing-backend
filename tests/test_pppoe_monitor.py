import pytest

from app.api import pppoe_monitor
from app.services.mikrotik_api import MikroTikAPI


def _install_fake_overview_api(
    monkeypatch, *, access_state=None, interfaces=None, bridge_ports=None,
    server_interface="bridge-dual", server_disabled=False, discover_access=False,
):
    access_state = access_state if access_state is not None else {
        "success": True,
        "mode": "dual",
        "ports": ["ether2", "ether3"],
        "has_dual": True,
        "attachment_map": {
            "ether2": {"mode": "dual", "server_interface": "bridge-dual"},
            "ether3": {"mode": "dual", "server_interface": "bridge-dual"},
        },
    }
    interfaces = interfaces or [
        {"name": "ether2", "running": True, "rx_error": 0, "tx_error": 0},
        {"name": "ether3", "running": False, "rx_error": 0, "tx_error": 0},
    ]

    class FakeMikroTikAPI:
        connected = True

        def __init__(self, *_args, **_kwargs):
            pass

        def connect(self):
            return True

        def disconnect(self):
            pass

        def get_pppoe_server_status(self):
            return {
                "success": True,
                "data": [
                    {
                        "service_name": "pppoe-dual-bridge-dual",
                        "interface": server_interface,
                        "disabled": server_disabled,
                        "default_profile": "default-pppoe",
                    }
                ],
            }

        def get_pppoe_access_state(self):
            if discover_access:
                return MikroTikAPI.get_pppoe_access_state(self)
            return access_state

        def get_bridge_ports_status(self):
            return {
                "success": True,
                "bridges": {
                    "bridge": {"running": True},
                    "bridge-dual": {"running": True},
                },
                "ports": bridge_ports if bridge_ports is not None else [
                    {"interface": "ether2", "bridge": "bridge-dual"},
                    {"interface": "ether3", "bridge": "bridge-dual"},
                ],
            }

        def get_all_interfaces_detail(self):
            return {"success": True, "data": interfaces}

        def get_ppp_profiles(self):
            return {
                "success": True,
                "data": [
                    {
                        "name": "default-pppoe",
                        "remote_address": "pppoe-pool",
                    }
                ],
            }

        def get_ip_pool_status(self, _pool_name):
            return {
                "success": True,
                "pools": [
                    {
                        "name": "pppoe-pool",
                        "used_count": 1,
                        "total_addresses": 253,
                        "exhausted": False,
                    }
                ],
            }

        def get_nat_rules(self):
            return {
                "success": True,
                "data": [
                    {
                        "action": "masquerade",
                        "disabled": False,
                        "src_address": "192.168.89.0/24",
                        "comment": "NAT for PPPoE clients",
                    }
                ],
            }

        def get_active_pppoe_sessions(self):
            return {"success": True, "count": 1, "data": []}

    monkeypatch.setattr(pppoe_monitor, "MikroTikAPI", FakeMikroTikAPI)


def test_pppoe_overview_dual_ports_do_not_require_all_links_up(monkeypatch):
    _install_fake_overview_api(monkeypatch)

    result = pppoe_monitor._pppoe_overview_sync(
        {"ip": "10.0.0.26", "username": "admin", "password": "pw", "port": 8728},
        db_pppoe_ports=[],
        db_dual_ports=["ether2", "ether3"],
    )

    dual_check = next(c for c in result["checks"] if c["check"] == "dual_ports")
    assert dual_check["passed"] is True
    assert dual_check["any_port_up"] is True
    assert result["healthy"] is True


def test_pppoe_overview_dual_ports_fail_when_not_attached(monkeypatch):
    _install_fake_overview_api(
        monkeypatch,
        access_state={
            "success": True,
            "mode": "dual",
            "ports": ["ether2"],
            "has_dual": True,
            "attachment_map": {
                "ether2": {"mode": "dual", "server_interface": "bridge-dual"},
                "ether3": {"mode": "none", "server_interface": ""},
            },
        },
    )

    result = pppoe_monitor._pppoe_overview_sync(
        {"ip": "10.0.0.26", "username": "admin", "password": "pw", "port": 8728},
        db_pppoe_ports=[],
        db_dual_ports=["ether2", "ether3"],
    )

    dual_check = next(c for c in result["checks"] if c["check"] == "dual_ports")
    assert dual_check["passed"] is False
    assert result["healthy"] is False


def test_pppoe_overview_recognizes_shared_hotspot_bridge_dual_ports(monkeypatch):
    _install_fake_overview_api(
        monkeypatch,
        server_interface="bridge",
        bridge_ports=[
            {"interface": "ether2", "bridge": "bridge"},
            {"interface": "ether3", "bridge": "bridge"},
        ],
        discover_access=True,
    )

    result = pppoe_monitor._pppoe_overview_sync(
        {"ip": "10.0.0.26", "username": "admin", "password": "pw", "port": 8728},
        db_pppoe_ports=[],
        db_dual_ports=["ether2", "ether3"],
    )

    dual_check = next(c for c in result["checks"] if c["check"] == "dual_ports")
    assert result["healthy"] is True
    assert dual_check["passed"] is True
    assert dual_check["any_port_up"] is True
    assert "dual bridge" not in dual_check["description"]
    assert all(p["pppoe_server_on_bridge"] for p in dual_check["detail"])
    assert all(
        p["pppoe_attachment_mode"] == "shared_hotspot_bridge"
        for p in dual_check["detail"]
    )


@pytest.mark.parametrize("port_bridge", [None, "bridge-plain", "bridge-dual"])
def test_pppoe_overview_shared_bridge_requires_each_dual_port_attached(monkeypatch, port_bridge):
    ports = [{"interface": "ether2", "bridge": "bridge"}]
    if port_bridge is not None:
        ports.append({"interface": "ether3", "bridge": port_bridge})
    _install_fake_overview_api(
        monkeypatch, server_interface="bridge", bridge_ports=ports, discover_access=True,
    )

    result = pppoe_monitor._pppoe_overview_sync(
        {"ip": "10.0.0.26", "username": "admin", "password": "pw", "port": 8728},
        db_pppoe_ports=[],
        db_dual_ports=["ether2", "ether3"],
    )

    dual_check = next(c for c in result["checks"] if c["check"] == "dual_ports")
    assert result["healthy"] is False
    assert dual_check["passed"] is False
    assert dual_check["detail"][0]["pppoe_server_on_bridge"] is True
    assert dual_check["detail"][1]["pppoe_server_on_bridge"] is False


@pytest.mark.parametrize("server_interface,server_disabled", [("bridge", True), ("ether4", False)])
def test_pppoe_overview_shared_bridge_requires_enabled_pppoe_server(
    monkeypatch, server_interface, server_disabled,
):
    _install_fake_overview_api(
        monkeypatch,
        server_interface=server_interface,
        server_disabled=server_disabled,
        bridge_ports=[
            {"interface": "ether2", "bridge": "bridge"},
            {"interface": "ether3", "bridge": "bridge"},
        ],
        discover_access=True,
    )

    result = pppoe_monitor._pppoe_overview_sync(
        {"ip": "10.0.0.26", "username": "admin", "password": "pw", "port": 8728},
        db_pppoe_ports=[],
        db_dual_ports=["ether2", "ether3"],
    )

    dual_check = next(c for c in result["checks"] if c["check"] == "dual_ports")
    assert result["healthy"] is False
    assert dual_check["passed"] is False
    assert not any(p["pppoe_server_on_bridge"] for p in dual_check["detail"])
