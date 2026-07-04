from app.api.router_operations import _heal_dual_mode_sync
from app.services import pppoe_provisioning
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


def test_ensure_pppoe_fasttrack_bypass_rebuilds_rules_after_fasttrack():
    api = _connected_api()
    commands = []

    api.get_ip_pool_status = lambda pool_name: {
        "success": True,
        "pools": [{"name": pool_name, "ranges": "192.168.89.254-192.168.89.254"}],
    }

    def send_command_optimized(command, proplist=None, query=""):
        assert command == "/ip/firewall/filter/print"
        return {
            "success": True,
            "data": [
                {".id": "*1", "chain": "forward", "action": "fasttrack-connection", "disabled": "false"},
                {
                    ".id": "*2",
                    "chain": "forward",
                    "action": "accept",
                    "src-address": "192.168.89.254",
                    "comment": "PPPoE bypass FastTrack (src) 192.168.89.254/32",
                    "disabled": "false",
                },
                {
                    ".id": "*3",
                    "chain": "forward",
                    "action": "accept",
                    "dst-address": "192.168.89.254",
                    "comment": "PPPoE bypass FastTrack (dst) 192.168.89.254/32",
                    "disabled": "false",
                },
            ],
        }

    def send_command(command, args=None):
        commands.append((command, args or {}))
        return {"success": True}

    api.send_command_optimized = send_command_optimized
    api.send_command = send_command

    result = api.ensure_pppoe_fasttrack_bypass(pool_name="pppoe-pool")

    assert result["success"] is True
    assert result["rules_removed"] == 2
    assert result["rules_added"] == 2
    assert (
        "/ip/firewall/filter/remove",
        {"numbers": "*2"},
    ) in commands
    assert (
        "/ip/firewall/filter/remove",
        {"numbers": "*3"},
    ) in commands
    assert (
        "/ip/firewall/filter/add",
        {
            "chain": "forward",
            "src-address": "192.168.89.254/32",
            "action": "accept",
            "comment": "PPPoE bypass FastTrack (src) 192.168.89.254/32",
            "place-before": "*1",
        },
    ) in commands
    assert (
        "/ip/firewall/filter/add",
        {
            "chain": "forward",
            "dst-address": "192.168.89.254/32",
            "action": "accept",
            "comment": "PPPoE bypass FastTrack (dst) 192.168.89.254/32",
            "place-before": "*1",
        },
    ) in commands


def test_ensure_pppoe_fasttrack_bypass_reuses_rules_before_fasttrack():
    api = _connected_api()
    commands = []

    api.get_ip_pool_status = lambda pool_name: {
        "success": True,
        "pools": [{"name": pool_name, "ranges": "192.168.89.254-192.168.89.254"}],
    }

    def send_command_optimized(command, proplist=None, query=""):
        return {
            "success": True,
            "data": [
                {
                    ".id": "*2",
                    "chain": "forward",
                    "action": "accept",
                    "src-address": "192.168.89.254/32",
                    "comment": "PPPoE bypass FastTrack (src) 192.168.89.254/32",
                    "disabled": "false",
                },
                {
                    ".id": "*3",
                    "chain": "forward",
                    "action": "accept",
                    "dst-address": "192.168.89.254/32",
                    "comment": "PPPoE bypass FastTrack (dst) 192.168.89.254/32",
                    "disabled": "false",
                },
                {".id": "*1", "chain": "forward", "action": "fasttrack-connection", "disabled": "false"},
            ],
        }

    api.send_command_optimized = send_command_optimized
    api.send_command = lambda command, args=None: commands.append((command, args or {})) or {"success": True}

    result = api.ensure_pppoe_fasttrack_bypass(pool_name="pppoe-pool")

    assert result["success"] is True
    assert result["rules_reused"] == 2
    assert result["rules_added"] == 0
    assert result["rules_removed"] == 0
    assert commands == []


def test_add_pppoe_secret_updates_when_router_reports_same_name_exists():
    api = _connected_api()
    commands = []

    def send_command(command, args=None):
        commands.append((command, args or {}))
        if command == "/ppp/secret/add":
            return {"error": "failure: secret with the same name already exists"}
        if command == "/ppp/secret/print":
            return {"success": True, "data": [{".id": "*7", "name": "Festo"}]}
        return {"success": True}

    api.send_command = send_command

    result = api.add_pppoe_secret(
        username="Festo",
        password="secret",
        profile="pppoe_3M_2M",
        comment="CID:8257|repair",
    )

    assert result == {"success": True}
    assert commands[-1] == (
        "/ppp/secret/set",
        {
            "numbers": "*7",
            "password": "secret",
            "profile": "pppoe_3M_2M",
            "service": "pppoe",
            "comment": "CID:8257|repair",
        },
    )


def test_pppoe_provisioning_creates_missing_default_pool_before_profile(monkeypatch):
    class FakeMikroTikAPI:
        instances = []

        def __init__(self, *_args, **_kwargs):
            self.calls = []
            FakeMikroTikAPI.instances.append(self)

        def connect(self):
            return True

        def disconnect(self):
            self.calls.append(("disconnect", None))

        def _parse_speed_to_mikrotik(self, speed):
            assert speed == "7Mbps"
            return "7M/7M"

        def get_active_pppoe_profile(self):
            self.calls.append(("get_active_pppoe_profile", None))
            return {"success": True, "found": False, "data": None}

        def ensure_ip_pool(self, pool_name, pool_range):
            self.calls.append(("ensure_ip_pool", pool_name, pool_range))
            return {"success": True, "action": "created"}

        def ensure_pppoe_profile(self, profile_name, rate_limit, **kwargs):
            self.calls.append(("ensure_pppoe_profile", profile_name, rate_limit, kwargs))
            return {"success": True}

        def add_pppoe_secret(self, username, password, profile, comment=""):
            self.calls.append(("add_pppoe_secret", username, password, profile, comment))
            return {"success": True}

        def ensure_pppoe_fasttrack_bypass(self, pool_name=""):
            self.calls.append(("ensure_pppoe_fasttrack_bypass", pool_name))
            return {"success": True}

        def disconnect_pppoe_session(self, username):
            self.calls.append(("disconnect_pppoe_session", username))
            return {"success": True, "disconnected": 0}

    monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", FakeMikroTikAPI)

    result = pppoe_provisioning._provision_pppoe_sync({
        "pppoe_username": "benny254",
        "pppoe_password": "secret",
        "bandwidth_limit": "7Mbps",
        "comment": "CID:8112|Benny|2026-06-23",
        "router_ip": "10.0.0.23",
        "router_username": "admin",
        "router_password": "router-secret",
        "router_port": 8728,
    })

    assert result["success"] is True
    api = FakeMikroTikAPI.instances[0]
    pool_call = (
        "ensure_ip_pool",
        pppoe_provisioning.PPPOE_DEFAULT_POOL_NAME,
        pppoe_provisioning.PPPOE_DEFAULT_POOL_RANGE,
    )
    profile_call = next(call for call in api.calls if call[0] == "ensure_pppoe_profile")
    assert pool_call in api.calls
    assert api.calls.index(pool_call) < api.calls.index(profile_call)
    assert profile_call[3]["local_address"] == pppoe_provisioning.PPPOE_DEFAULT_LOCAL_ADDRESS
    assert profile_call[3]["pool_name"] == pppoe_provisioning.PPPOE_DEFAULT_POOL_NAME


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
