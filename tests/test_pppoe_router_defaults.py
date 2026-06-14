from app.api.router_operations import _heal_dual_mode_sync
from app.services.mikrotik_api import MikroTikAPI, parse_speed_to_mikrotik


def _connected_api():
    api = MikroTikAPI("10.0.0.1", "admin", "secret")
    api.connected = True
    return api


def test_parse_speed_to_mikrotik_preserves_explicit_up_down_limits():
    assert parse_speed_to_mikrotik("15Mbps") == "15M/15M"
    assert parse_speed_to_mikrotik("2M/5M") == "2M/5M"
    assert parse_speed_to_mikrotik("5/10") == "5M/10M"
    assert parse_speed_to_mikrotik("5000000/10000000") == "5000000/10000000"


def test_hotspot_html_dir_defaults_to_hotspot_for_live_repairs():
    api = _connected_api()
    api.send_command = lambda command, args=None: {
        "success": True,
        "data": [{"board-name": "hEX S", "version": "7.15"}],
    }

    assert api._resolve_hotspot_html_dir() == "hotspot"


def test_hotspot_html_dir_flash_is_only_v6_routerboard_opt_in():
    api = _connected_api()
    api.send_command = lambda command, args=None: {
        "success": True,
        "data": [{"board-name": "hEX S", "version": "6.49.10"}],
    }

    assert api._resolve_hotspot_html_dir(prefer_routerboard_flash=True) == "flash/hotspot"


def test_ensure_pppoe_profile_sets_only_one_on_create():
    api = _connected_api()
    calls = []

    def send_command(command, args=None):
        calls.append((command, args or {}))
        if command == "/ppp/profile/print":
            return {"success": True, "data": []}
        return {"success": True}

    api.send_command = send_command

    result = api.ensure_pppoe_profile(
        "pppoe_10M_10M",
        "10000000/10000000",
        local_address="192.168.89.1",
        pool_name="pppoe-pool",
    )

    assert result == {"success": True}
    assert calls[-1] == (
        "/ppp/profile/add",
        {
            "name": "pppoe_10M_10M",
            "rate-limit": "10000000/10000000",
            "local-address": "192.168.89.1",
            "remote-address": "pppoe-pool",
            "only-one": "yes",
        },
    )


def test_ensure_pppoe_server_sets_reconnect_defaults_on_create():
    api = _connected_api()
    calls = []

    def send_command_optimized(command, proplist=None, query=""):
        calls.append((command, {"proplist": proplist, "query": query}))
        return {"success": True, "data": []}

    def send_command(command, args=None):
        calls.append((command, args or {}))
        return {"success": True}

    api.send_command_optimized = send_command_optimized
    api.send_command = send_command

    result = api.ensure_pppoe_server_on_interface("ether2", verify=False)

    assert result == {"success": True, "action": "created", "interface": "ether2"}
    assert calls[-1] == (
        "/interface/pppoe-server/server/add",
        {
            "service-name": "pppoe-server-ether2",
            "interface": "ether2",
            "default-profile": "default-pppoe",
            "disabled": "no",
            "keepalive-timeout": "10",
            "one-session-per-host": "yes",
        },
    )


def test_ensure_pppoe_server_sets_reconnect_defaults_on_update():
    api = _connected_api()
    calls = []

    def send_command_optimized(command, proplist=None, query=""):
        calls.append((command, {"proplist": proplist, "query": query}))
        return {
            "success": True,
            "data": [{
                ".id": "*1",
                "interface": "ether2",
                "disabled": "false",
                "service-name": "old",
                "default-profile": "default",
            }],
        }

    def send_command(command, args=None):
        calls.append((command, args or {}))
        return {"success": True}

    api.send_command_optimized = send_command_optimized
    api.send_command = send_command

    result = api.ensure_pppoe_server_on_interface("ether2", verify=False)

    assert result == {"success": True, "action": "updated", "interface": "ether2"}
    assert calls[-1] == (
        "/interface/pppoe-server/server/set",
        {
            "numbers": "*1",
            "service-name": "pppoe-server-ether2",
            "interface": "ether2",
            "default-profile": "default-pppoe",
            "disabled": "no",
            "keepalive-timeout": "10",
            "one-session-per-host": "yes",
        },
    )


def test_teardown_pppoe_can_preserve_shared_pool_and_nat_for_dual_mode():
    api = _connected_api()
    commands = []

    def send_command_optimized(command, proplist=None, query=None):
        if command == "/interface/pppoe-server/server/print":
            return {
                "success": True,
                "data": [
                    {".id": "*1", "interface": "ether2", "service-name": "pppoe-server1-ether2"},
                    {".id": "*2", "interface": "bridge", "service-name": "pppoe-dual-bridge"},
                ],
            }
        return {"success": True, "data": []}

    def send_command(command, args=None):
        commands.append((command, args or {}))
        if command == "/ip/address/print":
            return {"success": True, "data": [{".id": "*3", "interface": "bridge-pppoe"}]}
        if command == "/interface/bridge/print":
            return {"success": True, "data": [{".id": "*4", "name": "bridge-pppoe"}]}
        if command == "/ip/pool/print":
            return {"success": True, "data": [{".id": "*5", "name": "pppoe-pool"}]}
        if command == "/ip/firewall/nat/print":
            return {"success": True, "data": [{".id": "*6", "comment": "NAT for PPPoE clients"}]}
        return {"success": True}

    api.send_command_optimized = send_command_optimized
    api.send_command = send_command
    api.add_bridge_port = lambda *args, **kwargs: {"success": True}

    result = api.teardown_pppoe_infrastructure(
        ports_to_restore=["ether2"],
        remove_shared_resources=False,
    )

    assert result["success"] is True
    assert (
        "/interface/pppoe-server/server/remove",
        {"numbers": "*1"},
    ) in commands
    assert not any(command == "/ip/pool/remove" for command, _ in commands)
    assert not any(command == "/ip/firewall/nat/remove" for command, _ in commands)


def test_setup_plain_infrastructure_repairs_existing_bridge_stack():
    api = _connected_api()
    commands = []

    def send_command_optimized(command, proplist=None, query=None):
        if command == "/ip/dhcp-server/print":
            return {"success": True, "data": []}
        return {"success": True, "data": []}

    def send_command(command, args=None):
        commands.append((command, args or {}))
        if command == "/interface/bridge/port/print":
            return {"success": True, "data": [{"interface": "ether5", "bridge": "bridge"}]}
        if command == "/interface/bridge/add":
            return {"error": "failure: already have bridge with such name"}
        if command in {
            "/ip/address/print",
            "/ip/pool/print",
            "/ip/dhcp-server/network/print",
            "/ip/firewall/nat/print",
        }:
            return {"success": True, "data": []}
        return {"success": True}

    api.send_command_optimized = send_command_optimized
    api.send_command = send_command
    api.remove_bridge_port = lambda *args, **kwargs: {"success": True}
    api.add_bridge_port = lambda *args, **kwargs: {"success": True}

    result = api.setup_plain_infrastructure(["ether5"])

    assert result["success"] is True
    assert any(command == "/ip/address/add" for command, _ in commands)
    assert any(command == "/ip/pool/add" for command, _ in commands)
    assert any(command == "/ip/dhcp-server/add" for command, _ in commands)
    assert any(command == "/ip/dhcp-server/network/add" for command, _ in commands)
    assert any(command == "/ip/firewall/nat/add" for command, _ in commands)


def test_ensure_hotspot_server_sets_keepalive_default_on_create():
    api = _connected_api()
    calls = []

    def send_command(command, args=None):
        calls.append((command, args or {}))
        if command == "/ip/hotspot/print":
            return {"success": True, "data": []}
        return {"success": True}

    api.send_command = send_command

    result = api.ensure_hotspot_server_on_interface(
        "bridge",
        server_name="hotspot1",
        profile_name="hsprof1",
        address_pool="hs-pool",
        verify=False,
    )

    assert result == {"success": True, "name": "hotspot1", "interface": "bridge"}
    assert calls[-1] == (
        "/ip/hotspot/add",
        {
            "name": "hotspot1",
            "interface": "bridge",
            "address-pool": "hs-pool",
            "profile": "hsprof1",
            "disabled": "no",
            "keepalive-timeout": "2m",
        },
    )


def test_apply_pppoe_reconnect_defaults_updates_servers_and_used_profiles():
    api = _connected_api()
    commands = []

    def send_command_optimized(command, proplist=None, query=None):
        if command == "/interface/pppoe-server/server/print":
            return {
                "success": True,
                "data": [{
                    ".id": "*1",
                    "interface": "ether2",
                    "service-name": "pppoe-server-ether2",
                    "default-profile": "default-pppoe",
                }],
            }
        if command == "/ppp/secret/print":
            return {
                "success": True,
                "data": [{
                    "name": "Festo",
                    "service": "pppoe",
                    "profile": "pppoe_10M_10M",
                }],
            }
        if command == "/ppp/profile/print":
            profile_name = query.split("=", 1)[1]
            return {
                "success": True,
                "data": [{
                    ".id": f"*{profile_name}",
                    "name": profile_name,
                }],
            }
        raise AssertionError(f"unexpected optimized command: {command}")

    def send_command(command, args=None):
        commands.append((command, args or {}))
        return {"success": True}

    api.send_command_optimized = send_command_optimized
    api.send_command = send_command

    result = api.apply_pppoe_reconnect_defaults()

    assert result["success"] is True
    assert result["servers_updated"] == 1
    assert result["profiles_updated"] == 2
    assert (
        "/interface/pppoe-server/server/set",
        {
            "numbers": "*1",
            "keepalive-timeout": "10",
            "one-session-per-host": "yes",
        },
    ) in commands
    assert (
        "/ppp/profile/set",
        {
            "numbers": "*default-pppoe",
            "only-one": "yes",
        },
    ) in commands
    assert (
        "/ppp/profile/set",
        {
            "numbers": "*pppoe_10M_10M",
            "only-one": "yes",
        },
    ) in commands


def test_apply_hotspot_reconnect_defaults_updates_existing_servers():
    api = _connected_api()
    commands = []

    def send_command_optimized(command, proplist=None, query=None):
        assert command == "/ip/hotspot/print"
        return {
            "success": True,
            "data": [{
                ".id": "*2",
                "name": "hotspot1",
                "interface": "bridge",
            }],
        }

    def send_command(command, args=None):
        commands.append((command, args or {}))
        return {"success": True}

    api.send_command_optimized = send_command_optimized
    api.send_command = send_command

    result = api.apply_hotspot_reconnect_defaults()

    assert result["success"] is True
    assert result["servers_updated"] == 1
    assert commands == [(
        "/ip/hotspot/set",
        {
            "numbers": "*2",
            "keepalive-timeout": "2m",
        },
    )]


def test_hotspot_bridge_pppoe_server_does_not_make_all_bridge_ports_dedicated_pppoe():
    api = _connected_api()

    api.get_pppoe_server_status = lambda: {
        "success": True,
        "data": [{
            "interface": "bridge",
            "disabled": False,
            "service_name": "pppoe-dual-bridge",
        }],
    }
    api.get_bridge_ports_status = lambda: {
        "success": True,
        "bridges": {"bridge": {"name": "bridge"}},
        "ports": [
            {"interface": "ether2", "bridge": "bridge"},
            {"interface": "ether3", "bridge": "bridge"},
        ],
    }

    result = api.get_pppoe_access_state()

    assert result["success"] is True
    assert result["mode"] == "shared_hotspot_bridge"
    assert result["ports"] == []
    assert result["has_hotspot_bridge_pppoe"] is True
    assert result["hotspot_bridge_servers"][0]["ports"] == ["ether2", "ether3"]


def test_setup_dual_infrastructure_keeps_ports_on_hotspot_bridge():
    api = _connected_api()
    commands = []
    pppoe_servers = []
    hotspot_portal_calls = []

    api.get_bridge_ports_status = lambda: {
        "success": True,
        "bridges": {"bridge": {"name": "bridge"}},
        "ports": [{"interface": "ether3", "bridge": "bridge"}],
    }
    api.verify_port_bridges = lambda expected, retries=1, delay=0.0: {"success": True}
    api.ensure_pppoe_profile = lambda **kwargs: {"success": True}
    api.ensure_pppoe_fasttrack_bypass = lambda **kwargs: {"success": True}
    api.ensure_existing_hotspot_captive_portal = lambda **kwargs: (
        hotspot_portal_calls.append(kwargs) or {"success": True, "warnings": []}
    )
    api.get_pppoe_access_state = lambda **kwargs: {
        "success": True,
        "has_hotspot_bridge_pppoe": True,
    }

    def ensure_pppoe_server_on_interface(interface, **kwargs):
        pppoe_servers.append((interface, kwargs))
        return {"success": True}

    def send_command(command, args=None):
        commands.append((command, args or {}))
        return {"success": True}

    api.ensure_pppoe_server_on_interface = ensure_pppoe_server_on_interface
    api.send_command = send_command

    result = api.setup_dual_infrastructure(["ether3"])

    assert result["success"] is True
    assert result["mode"] == "shared_hotspot_bridge"
    assert hotspot_portal_calls == [{
        "interface": "bridge",
        "profile_name": "hsprof1",
        "server_name": "hotspot1",
        "hotspot_address": "192.168.88.1",
        "address_pool": "dhcp-pool",
        "html_directory": None,
        "login_page_url": None,
        "fetch_check_certificate": False,
    }]
    assert pppoe_servers == [(
        "bridge",
        {
            "profile_name": "default-pppoe",
            "service_name_prefix": "pppoe-dual",
            "verify": True,
        },
    )]
    assert (
        "/interface/bridge/add",
        {"name": "bridge-dual"},
    ) not in commands
    assert not any(command == "/ip/hotspot/add" for command, _ in commands)
    assert not any(
        command == "/interface/bridge/port/add" and args.get("bridge") == "bridge-dual"
        for command, args in commands
    )


def test_setup_dual_infrastructure_restores_legacy_bridge_dual_ports():
    api = _connected_api()
    teardown_calls = []

    def get_bridge_ports_status():
        return {
            "success": True,
            "bridges": {"bridge": {"name": "bridge"}},
            "ports": [{"interface": "ether3", "bridge": "bridge-dual"}],
        }

    def teardown_dual_infrastructure(**kwargs):
        teardown_calls.append(kwargs)
        return {"success": True}

    api.get_bridge_ports_status = get_bridge_ports_status
    api.teardown_dual_infrastructure = teardown_dual_infrastructure
    api.add_bridge_port = lambda *args, **kwargs: {"success": True}
    api.verify_port_bridges = lambda expected, retries=1, delay=0.0: {"success": True}
    api.send_command = lambda command, args=None: {"success": True}
    api.ensure_pppoe_profile = lambda **kwargs: {"success": True}
    api.ensure_pppoe_server_on_interface = lambda *args, **kwargs: {"success": True}
    api.ensure_pppoe_fasttrack_bypass = lambda **kwargs: {"success": True}
    api.ensure_existing_hotspot_captive_portal = lambda **kwargs: {"success": True, "warnings": []}
    api.get_pppoe_access_state = lambda **kwargs: {
        "success": True,
        "has_hotspot_bridge_pppoe": True,
    }

    result = api.setup_dual_infrastructure(["ether3"])

    assert result["success"] is True
    assert teardown_calls
    assert teardown_calls[0]["ports_to_restore"] == ["ether3"]
    assert teardown_calls[0]["remove_hotspot_bridge_pppoe"] is False


def test_heal_dual_mode_sync_uses_db_and_legacy_dual_ports(monkeypatch):
    created = []

    class FakeAPI:
        def __init__(self, *args, **kwargs):
            self.connected = False
            self.setup_ports = None
            self.healed = False
            created.append(self)

        def connect(self):
            self.connected = True
            return True

        def disconnect(self):
            self.connected = False

        def get_bridge_ports_status(self):
            if self.healed:
                return {
                    "success": True,
                    "ports": [
                        {"interface": "ether2", "bridge": "bridge"},
                        {"interface": "ether3", "bridge": "bridge"},
                    ],
                }
            return {
                "success": True,
                "ports": [
                    {"interface": "ether2", "bridge": "bridge-dual"},
                    {"interface": "ether3", "bridge": "bridge"},
                ],
            }

        def setup_dual_infrastructure(self, dual_ports, **kwargs):
            self.setup_ports = dual_ports
            self.setup_kwargs = kwargs
            self.healed = True
            return {"success": True, "mode": "shared_hotspot_bridge"}

        def apply_access_reconnect_defaults(self, include_pppoe=True, include_hotspot=True):
            return {
                "success": True,
                "include_pppoe": include_pppoe,
                "include_hotspot": include_hotspot,
            }

        def get_pppoe_access_state(self):
            return {"success": True, "has_hotspot_bridge_pppoe": True}

    monkeypatch.setattr("app.api.router_operations.MikroTikAPI", FakeAPI)

    result = _heal_dual_mode_sync(
        {
            "ip": "10.0.0.1",
            "username": "admin",
            "password": "secret",
            "port": 8728,
            "dual_ports": ["ether3"],
        }
    )

    assert result["success"] is True
    assert result["target_ports"] == ["ether3", "ether2"]
    assert result["legacy_bridge_dual_ports"] == ["ether2"]
    assert result["mode"] == "shared_hotspot_bridge"
    assert created[0].setup_ports == ["ether3", "ether2"]
