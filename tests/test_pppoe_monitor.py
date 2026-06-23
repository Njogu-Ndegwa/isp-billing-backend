from app.api import pppoe_monitor


def _install_fake_overview_api(monkeypatch, *, access_state=None, interfaces=None):
    access_state = access_state or {
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
                        "interface": "bridge-dual",
                        "disabled": False,
                        "default_profile": "default-pppoe",
                    }
                ],
            }

        def get_pppoe_access_state(self):
            return access_state

        def get_bridge_ports_status(self):
            return {
                "success": True,
                "bridges": {},
                "ports": [
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
