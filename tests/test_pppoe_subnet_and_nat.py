"""PPPoE subnet clash handling and idempotent PPPoE NAT (router 483/537, 2026-09-29).

Router 483's internet is a PPPoE session from router 537, which hands out
192.168.89.x — the same /24 our PPPoE server uses by default. And every
PPPoE/dual save added another identical NAT rule (17 copies on 537).
"""
from app.services.mikrotik_api import MikroTikAPI
from app.services.pppoe_provisioning import _local_address_from_pool


class FakeRouter:
    def __init__(self, tables):
        self.tables = {k: [dict(r) for r in v] for k, v in tables.items()}
        self.calls = []

    def send_command(self, command, args=None):
        self.calls.append((command, dict(args or {})))
        if command.endswith("/print"):
            return {"success": True, "data": [dict(r) for r in self.tables.get(command[: -len("/print")], [])]}
        path, verb = command.rsplit("/", 1)
        rows = self.tables.setdefault(path, [])
        if verb == "add":
            rows.append({".id": f"*{len(rows) + 100}", **args})
        elif verb == "set":
            for row in rows:
                if row.get(".id") == args["numbers"]:
                    row.update({k: v for k, v in args.items() if k != "numbers"})
        elif verb == "remove":
            self.tables[path] = [r for r in rows if r.get(".id") != args["numbers"]]
        return {"success": True}

    def writes(self, verb):
        return [c for c in self.calls if c[0].endswith("/" + verb)]


def _api(fake):
    api = MikroTikAPI("10.0.0.1", "u", "p", 8728)
    api.connected = True
    api.send_command = fake.send_command
    return api


CASCADED_483 = {
    "/ip/address": [
        {".id": "*1", "address": "192.168.88.1/24", "network": "192.168.88.0", "interface": "bridge"},
        {".id": "*12", "address": "192.168.89.244/32", "network": "192.168.89.1", "interface": "pppoe-out1"},
    ],
    "/ip/pool": [
        {".id": "*1", "name": "dhcp", "ranges": "192.168.88.10-192.168.88.254"},
        {".id": "*3", "name": "pppoe-pool", "ranges": "192.168.89.2-192.168.89.254"},
    ],
    "/ppp/profile": [
        {".id": "*0", "name": "default"},
        {".id": "*1", "name": "default-pppoe", "local-address": "192.168.89.1", "remote-address": "pppoe-pool"},
        {".id": "*2", "name": "pppoe_6M_6M", "local-address": "192.168.89.1", "remote-address": "pppoe-pool"},
    ],
    "/ip/firewall/filter": [
        {".id": "*A", "comment": "PPPoE bypass FastTrack (src) 192.168.89.2/31"},
        {".id": "*B", "comment": "defconf: fasttrack"},
    ],
    "/ppp/active": [{".id": "*S1", "address": "192.168.89.7"}],
    "/interface/pppoe-client": [{"name": "pppoe-out1", "interface": "ether1", "disabled": "false"}],
}


def test_keeps_default_subnet_when_it_does_not_clash():
    fake = FakeRouter({
        "/ip/address": [
            {"address": "192.168.88.1/24", "network": "192.168.88.0", "interface": "bridge"},
            {"address": "192.168.100.9/24", "network": "192.168.100.0", "interface": "ether1"},
            # server side of our own sessions must not count as a clash
            {"address": "192.168.89.1/32", "network": "192.168.89.244", "interface": "<pppoe-Hotspot3>"},
        ],
        "/ip/pool": [{".id": "*4", "name": "pppoe-pool", "ranges": "192.168.89.2-192.168.89.254"}],
    })
    result = _api(fake).prepare_pppoe_subnet()
    assert result["subnet"] == "192.168.89.0/24"
    assert "moved_from" not in result
    assert not fake.writes("set") and not fake.writes("remove")


def test_moves_pppoe_off_the_uplink_subnet():
    fake = FakeRouter(CASCADED_483)
    result = _api(fake).prepare_pppoe_subnet()

    assert result["subnet"] == "192.168.189.0/24"
    assert result["moved_from"] == "192.168.89.0/24"
    pool = next(p for p in fake.tables["/ip/pool"] if p["name"] == "pppoe-pool")
    assert pool["ranges"] == "192.168.189.2-192.168.189.254"
    locals_ = {p["name"]: p.get("local-address") for p in fake.tables["/ppp/profile"]}
    assert locals_["default-pppoe"] == "192.168.189.1"
    assert locals_["pppoe_6M_6M"] == "192.168.189.1"
    assert [r["comment"] for r in fake.tables["/ip/firewall/filter"]] == ["defconf: fasttrack"]
    assert fake.tables["/ppp/active"] == []
    # the uplink itself is never touched
    assert any(a["interface"] == "pppoe-out1" for a in fake.tables["/ip/address"])


def test_fresh_router_on_cascaded_uplink_gets_free_subnet():
    tables = {k: v for k, v in CASCADED_483.items() if k != "/ip/pool"}
    fake = FakeRouter(tables)
    result = _api(fake).prepare_pppoe_subnet()
    assert result["subnet"] == "192.168.189.0/24"
    assert "moved_from" not in result


def test_nat_deduplicates_and_follows_pppoe_client_wan():
    rule = {"chain": "srcnat", "action": "masquerade", "src-address": "192.168.89.0/24",
            "out-interface": "ether1", "comment": "NAT for PPPoE clients"}
    fake = FakeRouter({
        "/ip/firewall/nat": [{".id": f"*{i}", **rule} for i in range(17)],
        "/interface/pppoe-client": [{"name": "pppoe-out1", "interface": "ether1", "disabled": "false"}],
    })
    result = _api(fake).ensure_pppoe_nat("192.168.189.0/24")

    assert result["removed_duplicates"] == 16
    nat = fake.tables["/ip/firewall/nat"]
    assert len(nat) == 1
    assert nat[0]["src-address"] == "192.168.189.0/24"
    assert nat[0]["out-interface"] == "pppoe-out1"


def test_nat_is_not_added_twice():
    fake = FakeRouter({"/ip/firewall/nat": [], "/interface/pppoe-client": []})
    api = _api(fake)
    first = api.ensure_pppoe_nat("192.168.89.0/24")
    second = api.ensure_pppoe_nat("192.168.89.0/24")
    assert first["action"] == "added" and first["out_interface"] == "ether1"
    assert second["action"] == "exists"
    assert len(fake.tables["/ip/firewall/nat"]) == 1


def test_customer_profile_gateway_follows_moved_pool():
    fake = FakeRouter({"/ip/pool": [{".id": "*3", "name": "pppoe-pool", "ranges": "192.168.189.2-192.168.189.254"}]})
    assert _local_address_from_pool(_api(fake)) == "192.168.189.1"
    assert _local_address_from_pool(_api(FakeRouter({}))) == "192.168.89.1"
