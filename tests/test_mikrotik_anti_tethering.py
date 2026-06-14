from app.services.mikrotik_api import MikroTikAPI


class FakeMikroTikAPI(MikroTikAPI):
    def __init__(self, *, hotspots=None, raw_rules=None, mangle_rules=None, filter_rules=None):
        self.connected = True
        self.hotspots = hotspots or [{"interface": "bridge", "disabled": "false"}]
        self.raw_rules = raw_rules or []
        self.mangle_rules = mangle_rules or []
        self.filter_rules = filter_rules or []
        self.commands = []

    def send_command_optimized(self, command, proplist=None, query=None):
        if command == "/ip/hotspot/print":
            return {"success": True, "data": self.hotspots}
        if command == "/ip/firewall/raw/print":
            return {"success": True, "data": self.raw_rules}
        if command == "/ip/firewall/mangle/print":
            return {"success": True, "data": self.mangle_rules}
        if command == "/ip/firewall/filter/print":
            return {"success": True, "data": self.filter_rules}
        return {"error": f"Unexpected optimized command: {command}"}

    def send_command(self, command, arguments=None):
        args = dict(arguments or {})
        self.commands.append((command, args))
        return {"success": True, "data": []}


def _commands(api, command, action=None):
    matches = [args for cmd, args in api.commands if cmd == command]
    if action is None:
        return matches
    return [args for args in matches if args.get("action") == action]


def test_enable_anti_tethering_uses_raw_prerouting_ttl_drops_by_default():
    api = FakeMikroTikAPI(
        raw_rules=[
            {".id": "*r", "chain": "prerouting", "action": "notrack"},
        ],
        mangle_rules=[
            {".id": "*10", "chain": "prerouting", "action": "mark-connection"},
            {".id": "*20", "chain": "postrouting", "action": "mark-packet"},
        ],
        filter_rules=[
            {".id": "*1", "chain": "forward", "action": "fasttrack-connection"},
            {".id": "*2", "chain": "forward", "action": "accept"},
        ],
    )

    result = api.enable_anti_tethering()

    assert result["success"] is True
    assert result["mode"] == MikroTikAPI.ANTI_TETHER_RAW_TTL_MODE
    assert result["added_raw"] == len(MikroTikAPI.ANTI_TETHER_TTL_MATCHES)
    assert result["added_mangle"] == 0
    assert result["added_filter"] == 0

    raw_drops = _commands(api, "/ip/firewall/raw/add", "drop")
    assert [rule["ttl"] for rule in raw_drops] == list(MikroTikAPI.ANTI_TETHER_TTL_MATCHES)
    assert {rule["in-interface"] for rule in raw_drops} == {"bridge"}
    assert {rule["place-before"] for rule in raw_drops} == {"*r"}
    assert _commands(api, "/ip/firewall/mangle/add") == []
    assert _commands(api, "/ip/firewall/filter/add") == []


def test_enable_anti_tethering_strict_mode_orders_drop_before_fasttrack_and_clamps_return_ttl():
    api = FakeMikroTikAPI(
        mangle_rules=[
            {".id": "*10", "chain": "prerouting", "action": "mark-connection"},
            {".id": "*20", "chain": "postrouting", "action": "mark-packet"},
        ],
        filter_rules=[
            {".id": "*1", "chain": "forward", "action": "fasttrack-connection"},
            {".id": "*2", "chain": "forward", "action": "accept"},
        ],
    )

    result = api.enable_anti_tethering(mode="strict")

    assert result["success"] is True
    assert result["mode"] == MikroTikAPI.ANTI_TETHER_STRICT_TTL_MODE

    ttl_markers = _commands(api, "/ip/firewall/mangle/add", "mark-packet")
    assert [rule["ttl"] for rule in ttl_markers] == list(MikroTikAPI.ANTI_TETHER_TTL_MATCHES)
    assert {rule["in-interface"] for rule in ttl_markers} == {"bridge"}
    assert {rule["new-packet-mark"] for rule in ttl_markers} == {
        MikroTikAPI.ANTI_TETHER_PACKET_MARK
    }
    assert {rule["place-before"] for rule in ttl_markers} == {"*10"}

    ttl_clamps = _commands(api, "/ip/firewall/mangle/add", "change-ttl")
    assert ttl_clamps == [
        {
            "chain": "postrouting",
            "action": "change-ttl",
            "new-ttl": "set:1",
            "passthrough": "yes",
            "out-interface": "bridge",
            "comment": MikroTikAPI.ANTI_TETHER_COMMENT,
            "place-before": "*20",
        }
    ]

    forward_drops = _commands(api, "/ip/firewall/filter/add", "drop")
    assert forward_drops == [
        {
            "chain": "forward",
            "action": "drop",
            "packet-mark": MikroTikAPI.ANTI_TETHER_PACKET_MARK,
            "comment": MikroTikAPI.ANTI_TETHER_COMMENT,
            "place-before": "*1",
        }
    ]


def test_enable_anti_tethering_removes_stale_managed_rules_before_recreating():
    api = FakeMikroTikAPI(
        raw_rules=[
            {".id": "*r", "chain": "prerouting", "comment": MikroTikAPI.ANTI_TETHER_COMMENT},
            {".id": "*u", "chain": "prerouting", "comment": "unrelated raw rule"},
        ],
        mangle_rules=[
            {".id": "*a", "chain": "prerouting", "comment": MikroTikAPI.ANTI_TETHER_COMMENT},
            {".id": "*b", "chain": "prerouting", "comment": "customer queue marks"},
        ],
        filter_rules=[
            {".id": "*c", "chain": "forward", "comment": MikroTikAPI.ANTI_TETHER_COMMENT},
            {".id": "*1", "chain": "forward", "action": "accept"},
        ],
    )

    result = api.enable_anti_tethering()

    assert result["success"] is True
    assert result["removed_raw"] == 1
    assert result["removed_mangle"] == 1
    assert result["removed_filter"] == 1
    assert ("/ip/firewall/raw/remove", {"numbers": "*r"}) in api.commands
    assert ("/ip/firewall/mangle/remove", {"numbers": "*a"}) in api.commands
    assert ("/ip/firewall/filter/remove", {"numbers": "*c"}) in api.commands
    assert ("/ip/firewall/raw/remove", {"numbers": "*u"}) not in api.commands
    assert ("/ip/firewall/mangle/remove", {"numbers": "*b"}) not in api.commands


def test_disable_anti_tethering_removes_only_managed_rules():
    api = FakeMikroTikAPI(
        raw_rules=[
            {".id": "*r", "comment": MikroTikAPI.ANTI_TETHER_COMMENT},
            {".id": "*u", "comment": "unrelated raw rule"},
        ],
        mangle_rules=[
            {".id": "*a", "comment": MikroTikAPI.ANTI_TETHER_COMMENT},
            {".id": "*b", "comment": "unrelated mangle rule"},
        ],
        filter_rules=[
            {".id": "*c", "comment": f"{MikroTikAPI.ANTI_TETHER_COMMENT}:legacy"},
            {".id": "*d", "comment": "unrelated filter rule"},
        ],
    )

    result = api.disable_anti_tethering()

    assert result == {"success": True, "removed_raw": 1, "removed_mangle": 1, "removed_filter": 1}
    assert api.commands == [
        ("/ip/firewall/raw/remove", {"numbers": "*r"}),
        ("/ip/firewall/mangle/remove", {"numbers": "*a"}),
        ("/ip/firewall/filter/remove", {"numbers": "*c"}),
    ]
