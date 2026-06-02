from app.services.mikrotik_api import MikroTikAPI


def _connected_api():
    api = MikroTikAPI("10.0.0.1", "admin", "secret")
    api.connected = True
    return api


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
