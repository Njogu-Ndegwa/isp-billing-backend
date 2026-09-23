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

    def send_command(self, path, args):
        if path == "/ip/service/print":
            return {"data": [{"name": "api", "address": self.api_address}, {"name": "ssh"}]}
        if path == "/snmp/print":
            return {"data": [dict(self.snmp)]}
        if path == "/snmp/community/print":
            return {"data": [dict(c) for c in self.communities]}
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
        return {"data": []}


def test_plan_is_read_only_and_lists_every_change():
    api = FakeApi()
    plan = r.build_plan(api, 371, "lee net hotspot #1", "10.0.0.138", COMMUNITY)
    assert api.writes == []
    assert plan.sources == "10.0.0.1/32,10.251.0.1/32"
    assert plan.actions == [
        "restrict default community to 127.0.0.1/32",
        "add read-only community limited to 10.0.0.1/32,10.251.0.1/32",
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
    assert plan.actions == ["add read-only community limited to 10.0.0.1/32,10.251.0.1/32"]
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
