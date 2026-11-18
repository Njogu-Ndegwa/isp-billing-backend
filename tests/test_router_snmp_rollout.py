"""SNMP enrolment planner/rollback against a fake RouterOS API (no real router)."""

from app.services import router_snmp_rollout as r

COMMUNITY = "bw-ro"


class FakeApi:
    def __init__(self, *, snmp_enabled="false", public_addresses="0.0.0.0/0",
                 api_address="10.0.0.1/32,10.251.0.1/32"):
        self.snmp = {"enabled": snmp_enabled}
        self.communities = [{".id": "*0", "name": "public", "default": "true",
                             "addresses": public_addresses}]
        self.api_address = api_address
        self.writes = []
        self.filter = [
            {".id": "*A", "chain": "input", "action": "accept", "protocol": "tcp",
             "dst-port": "8728", "src-address": "10.0.0.1", "comment": "Allow API"},
            {".id": "*B", "chain": "forward", "action": "fasttrack-connection"},
            {".id": "*C", "chain": "input", "action": "drop",
             "comment": "defconf: drop all not coming from LAN"},
        ]

    def send_command(self, path, args):
        if path == "/ip/service/print":
            return {"data": [{"name": "api", "address": self.api_address}, {"name": "ssh"}]}
        if path == "/snmp/print":
            return {"data": [dict(self.snmp)]}
        if path == "/snmp/community/print":
            return {"data": [dict(c) for c in self.communities]}
        if path == "/ip/firewall/filter/print":
            return {"data": [dict(f) for f in self.filter]}
        self.writes.append((path, dict(args)))
        if path == "/snmp/set":
            self.snmp["enabled"] = "true" if args["enabled"] == "yes" else "false"
        elif path == "/snmp/community/add":
            self.communities.append({".id": f"*{len(self.communities)}", **args})
        elif path == "/snmp/community/set":
            for c in self.communities:
                if c[".id"] == args["numbers"]:
                    c["addresses"] = args["addresses"]
        elif path == "/snmp/community/remove":
            self.communities = [c for c in self.communities if c[".id"] != args["numbers"]]
        elif path == "/ip/firewall/filter/add":
            rule = {".id": f"*F{len(self.filter)}", **{k: v for k, v in args.items() if k != "place-before"}}
            before = args.get("place-before")
            idx = next((i for i, f in enumerate(self.filter) if f[".id"] == before), len(self.filter))
            self.filter.insert(idx, rule)
        elif path == "/ip/firewall/filter/remove":
            self.filter = [f for f in self.filter if f[".id"] != args["numbers"]]
        return {"data": []}


def test_plan_is_read_only_and_lists_every_change():
    api = FakeApi()
    plan = r.build_plan(api, 371, "lee net hotspot #1", "10.0.0.138", COMMUNITY)
    assert api.writes == []
    assert plan.sources == "10.0.0.1/32,10.251.0.1/32"
    assert plan.actions == [
        "restrict default community to 127.0.0.1/32",
        "add read-only community limited to 10.0.0.1/32,10.251.0.1/32",
        "allow SNMP (udp/161) from 10.0.0.1/32,10.251.0.1/32 in firewall input",
        "enable SNMP",
    ]


def test_apply_restricts_public_adds_read_only_community_and_enables():
    api = FakeApi()
    plan = r.build_plan(api, 1, "x", "10.0.0.2", COMMUNITY)
    r.apply_plan(api, plan, COMMUNITY)
    public = next(c for c in api.communities if c["name"] == "public")
    ours = next(c for c in api.communities if c["name"] == COMMUNITY)
    assert public["addresses"] == "127.0.0.1/32"
    assert ours["addresses"] == "10.0.0.1/32,10.251.0.1/32"
    assert ours["read-access"] == "yes" and ours["write-access"] == "no"
    assert api.snmp["enabled"] == "true"


def test_rollback_restores_exactly_the_saved_state():
    api = FakeApi()
    plan = r.build_plan(api, 1, "x", "10.0.0.2", COMMUNITY)
    saved = dict(plan.__dict__)
    r.apply_plan(api, plan, COMMUNITY)
    r.rollback_plan(api, saved, COMMUNITY)
    assert api.snmp["enabled"] == "false"
    assert [c["name"] for c in api.communities] == ["public"]
    assert api.communities[0]["addresses"] == "0.0.0.0/0"


def test_already_enabled_router_is_left_enabled_on_rollback():
    api = FakeApi(snmp_enabled="true", public_addresses="10.9.9.9/32")
    plan = r.build_plan(api, 1, "x", "10.0.0.2", COMMUNITY)
    assert plan.actions == [
        "add read-only community limited to 10.0.0.1/32,10.251.0.1/32",
        "allow SNMP (udp/161) from 10.0.0.1/32,10.251.0.1/32 in firewall input",
    ]
    saved = dict(plan.__dict__)
    r.apply_plan(api, plan, COMMUNITY)
    r.rollback_plan(api, saved, COMMUNITY)
    assert api.snmp["enabled"] == "true"
    assert [c["name"] for c in api.communities] == ["public"]


def test_missing_api_address_falls_back_to_server_sources():
    plan = r.build_plan(FakeApi(api_address=""), 1, "x", "10.0.0.2", COMMUNITY)
    assert plan.sources == r.FALLBACK_SOURCES


async def test_run_refuses_big_batches_and_missing_community(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        await r.run(list(range(11)), COMMUNITY, apply=False, state_path=tmp_path / "s.json")
    with pytest.raises(ValueError):
        await r.run([1], "", apply=False, state_path=tmp_path / "s.json")


def test_snmp_allow_rules_go_above_the_input_drop_and_are_scoped_to_our_sources():
    api = FakeApi()
    plan = r.build_plan(api, 1, "x", "10.0.0.2", COMMUNITY)
    r.apply_plan(api, plan, COMMUNITY)
    inputs = [f for f in api.filter if f["chain"] == "input"]
    ours = [f for f in inputs if f.get("comment") == r.FIREWALL_COMMENT]
    assert [f["src-address"] for f in ours] == ["10.0.0.1/32", "10.251.0.1/32"]
    assert all(f["protocol"] == "udp" and f["dst-port"] == "161" and f["action"] == "accept"
               for f in ours)
    # Both sit at the very top of the input chain, above the LAN-only drop.
    assert inputs[0].get("comment") == r.FIREWALL_COMMENT
    assert inputs[1].get("comment") == r.FIREWALL_COMMENT
    assert inputs[-1]["action"] == "drop"


def test_rollback_removes_only_our_firewall_rules():
    api = FakeApi()
    before = [dict(f) for f in api.filter]
    plan = r.build_plan(api, 1, "x", "10.0.0.2", COMMUNITY)
    saved = dict(plan.__dict__)
    r.apply_plan(api, plan, COMMUNITY)
    r.rollback_plan(api, saved, COMMUNITY)
    assert api.filter == before


def test_existing_snmp_rule_is_not_duplicated():
    api = FakeApi()
    api.filter.insert(0, {".id": "*Z", "chain": "input", "action": "accept", "protocol": "udp",
                          "dst-port": "161", "src-address": "10.0.0.1/32",
                          "comment": r.FIREWALL_COMMENT})
    plan = r.build_plan(api, 1, "x", "10.0.0.2", COMMUNITY)
    assert not any(a.startswith("allow SNMP") for a in plan.actions)
