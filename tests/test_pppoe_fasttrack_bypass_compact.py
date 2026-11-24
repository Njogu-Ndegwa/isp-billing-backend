"""scripts/pppoe_fasttrack_bypass_compact.py: which routers it touches, and that
it only reports without APPLY=1."""
import importlib.util
from pathlib import Path

import pytest

from app.services.mikrotik_api import MikroTikAPI

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pppoe_fasttrack_bypass_compact.py"
POOL_RANGE = "192.168.89.2-192.168.89.254"
ROUTER = {"id": 354, "name": "RB951", "ip_address": "10.0.0.9", "username": "u", "password": "p", "port": 8728}


def _legacy(cidrs):
    rules = []
    for cidr in cidrs:
        for side, field in (("src", "src-address"), ("dst", "dst-address")):
            rules.append({".id": f"*{len(rules) + 16:X}", "chain": "forward", "action": "accept", field: cidr,
                          "comment": f"PPPoE bypass FastTrack ({side}) {cidr}", "disabled": "false"})
    return rules


FASTTRACK = {".id": "*1", "chain": "forward", "action": "fasttrack-connection", "disabled": "false"}
RANGE_RULES = [
    {".id": "*2", "chain": "forward", "action": "accept", "src-address": POOL_RANGE,
     "comment": f"PPPoE bypass FastTrack (src) {POOL_RANGE}", "disabled": "false"},
    {".id": "*3", "chain": "forward", "action": "accept", "dst-address": POOL_RANGE,
     "comment": f"PPPoE bypass FastTrack (dst) {POOL_RANGE}", "disabled": "false"},
]


class FakeAPI(MikroTikAPI):
    filter_rules: list = []
    pools: list = []
    reachable = True
    writes: list = []

    def connect(self):
        self.connected = type(self).reachable
        self.last_connect_error = None if self.connected else "timed out"
        return self.connected

    def disconnect(self):
        self.connected = False

    def send_command_optimized(self, command, proplist=None, query=None):
        if command == "/ip/firewall/filter/print":
            return {"success": True, "data": [dict(r) for r in type(self).filter_rules]}
        if command == "/ip/pool/print":
            return {"success": True, "data": [dict(p) for p in type(self).pools]}
        raise AssertionError(command)

    def get_ip_pool_status(self, pool_name):
        return {"success": True, "pools": [p for p in type(self).pools if p["name"] == pool_name]}

    def send_command(self, command, arguments=None):
        type(self).writes.append((command, dict(arguments or {})))
        return {"success": True}


@pytest.fixture
def script(monkeypatch):
    spec = importlib.util.spec_from_file_location("pppoe_fasttrack_bypass_compact", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "MikroTikAPI", FakeAPI)
    FakeAPI.filter_rules, FakeAPI.pools, FakeAPI.reachable, FakeAPI.writes = [], [], True, []
    return module


def test_reports_only_without_apply(script):
    FakeAPI.filter_rules = _legacy(["192.168.89.2/31", "192.168.89.4/30", "192.168.89.8/29"]) + [FASTTRACK]
    FakeAPI.pools = [{"name": "dhcp", "ranges": "192.168.88.10-192.168.88.254"}, {"name": "pppoe-pool", "ranges": POOL_RANGE}]

    out = script.compact_router(ROUTER)

    assert out["status"] == "would_compact"
    assert out["rules_now"] == 6 and out["rules_after"] == 2
    assert out["pools"] == {"pppoe-pool": {"matchers": [POOL_RANGE], "old_rules": 6}}
    assert FakeAPI.writes == []


def test_apply_adds_the_pair_then_removes_the_old_rules(script, monkeypatch):
    monkeypatch.setattr(script, "APPLY", True)
    FakeAPI.filter_rules = _legacy(["192.168.89.2/31", "192.168.89.4/30"]) + [FASTTRACK]
    FakeAPI.pools = [{"name": "pppoe-pool", "ranges": POOL_RANGE}]

    out = script.compact_router(ROUTER)

    assert out["status"] == "compacted"
    assert out["results"]["pppoe-pool"]["rules_added"] == 2
    assert out["results"]["pppoe-pool"]["rules_superseded"] == 4
    assert [c.rsplit("/", 1)[1] for c, _ in FakeAPI.writes] == ["add", "add", "remove", "remove", "remove", "remove"]


def test_leaves_alone_what_it_should(script, monkeypatch):
    monkeypatch.setattr(script, "APPLY", True)

    FakeAPI.filter_rules = [FASTTRACK]
    assert script.compact_router(ROUTER)["status"] == "none"

    FakeAPI.filter_rules = RANGE_RULES + [FASTTRACK]
    FakeAPI.pools = [{"name": "pppoe-pool", "ranges": POOL_RANGE}]
    assert script.compact_router(ROUTER)["status"] == "compact"

    # old rules whose pool no longer exists: reported, not guessed at
    FakeAPI.filter_rules = _legacy(["192.168.89.2/31"]) + [FASTTRACK]
    FakeAPI.pools = [{"name": "dhcp", "ranges": "192.168.88.10-192.168.88.254"}]
    assert script.compact_router(ROUTER)["status"] == "no_pool"

    FakeAPI.reachable = False
    assert script.compact_router(ROUTER)["status"] == "unreachable"
    assert FakeAPI.writes == []


def test_router_without_fasttrack_is_not_changed(script, monkeypatch):
    monkeypatch.setattr(script, "APPLY", True)
    FakeAPI.filter_rules = _legacy(["192.168.89.2/31"])
    FakeAPI.pools = [{"name": "pppoe-pool", "ranges": POOL_RANGE}]

    out = script.compact_router(ROUTER)

    assert out["status"] == "no_fasttrack"
    assert FakeAPI.writes == []
