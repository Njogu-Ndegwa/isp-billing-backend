"""RB951 CPU relief (fleet pass 2026-11-23).

1. ``isp_queue_limited_clients`` only ever grew (75: 1,551 entries / 110 live),
   and every ``address-list find`` in the router scripts scans it: the queue
   sync now prunes entries no device holds.
2. The WireGuard watchdog takes its fast path while wg-hz is fresh, so a dead
   wg-aws peer no longer forces the slow path every minute.
3. ``CHECKIN_TUNNEL_ROUTER_IDS=ros7`` gives every RouterOS 7 router the
   tunnel-first check-in (no TLS handshake per check-in).
(The PPPoE bypass compaction found in the same pass landed in #439.)
"""
import re

import pytest

from app.config import settings
from app.services import mgmt_watchdog_script as wd
from app.services import mikrotik_background
from app.services import standard_runtime_enrol as enrol
from app.services.mikrotik_api import (
    QUEUE_BYPASS_PRUNE_CHUNK,
    QUEUE_BYPASS_PRUNE_MAX_REMOVE,
    QUEUE_FASTTRACK_BYPASS_LIST,
    MikroTikAPI,
    live_router_ips,
)


# --- 1. bypass-list prune ----------------------------------------------------------

def test_live_router_ips_reads_every_address_field_and_queue_targets():
    live = live_router_ips(
        [{"address": "192.168.88.10"}, {"address": "192.168.88.11/32"}],
        [{"address": "192.168.88.12", "active-address": "192.168.88.13"}],
        [{"address": "192.168.88.14", "to-address": "10.5.50.14"}],
        [{"address": "192.168.88.0/24"}, {"address": ""}, {"address": "junk"}],
        queues=[{"target": "192.168.88.20/32,192.168.88.21/32"}, {"target": "bridge"}],
    )
    assert live == {"192.168.88.10", "192.168.88.11", "192.168.88.12", "192.168.88.13",
                    "192.168.88.14", "10.5.50.14", "192.168.88.20", "192.168.88.21"}


class PruneAPI(MikroTikAPI):
    """MikroTikAPI with the RouterOS side faked: an address list plus live reads."""

    def __init__(self, listed, live_reads=None, failing=()):
        super().__init__("10.0.0.1", "u", "p")
        self.connected = True
        self.listed = listed
        self.live_reads = live_reads or {}
        self.failing = set(failing)
        self.removed = []
        self.reads = []

    def send_command_optimized(self, command, proplist=None, query=None):
        self.reads.append((command, query))
        if command in self.failing:
            return {"error": "timeout"}
        if command == "/ip/firewall/address-list/print":
            assert query == f"?list={QUEUE_FASTTRACK_BYPASS_LIST}"
            return {"success": True, "data": self.listed}
        return {"success": True, "data": self.live_reads.get(command, [])}

    def send_command(self, command, arguments=None):
        assert command == "/ip/firewall/address-list/remove"
        ids = arguments["numbers"].split(",")
        self.removed.append(ids)
        return {"success": True, "data": []}


def _entries(n, start=1, dynamic="false"):
    return [{".id": f"*{i}", "address": f"10.9.{i // 250}.{i % 250 + 1}", "dynamic": dynamic}
            for i in range(start, start + n)]


def test_prune_leaves_a_small_list_alone():
    api = PruneAPI(_entries(30))
    out = api.prune_queue_fasttrack_bypass_list({"1.2.3.4"})
    assert out["removed"] == 0 and out["skipped"] == "small list"
    assert api.removed == []


def test_prune_removes_only_stale_static_entries_in_chunks():
    listed = _entries(150) + _entries(20, start=500, dynamic="true")
    live = {e["address"] for e in listed[:10]}
    api = PruneAPI(listed)
    out = api.prune_queue_fasttrack_bypass_list(live)
    removed = [i for chunk in api.removed for i in chunk]
    assert out["entries"] == 150 and out["stale"] == 140 and out["removed"] == 140
    assert set(removed) == {e[".id"] for e in listed[10:150]}          # never live, never dynamic
    assert all(len(chunk) <= QUEUE_BYPASS_PRUNE_CHUNK for chunk in api.removed)


def test_prune_caps_removals_per_call():
    api = PruneAPI(_entries(QUEUE_BYPASS_PRUNE_MAX_REMOVE + 300))
    out = api.prune_queue_fasttrack_bypass_list({"1.2.3.4"})
    assert out["removed"] == QUEUE_BYPASS_PRUNE_MAX_REMOVE
    assert out["stale"] == QUEUE_BYPASS_PRUNE_MAX_REMOVE + 300


def test_prune_ignores_a_handful_of_stale_entries():
    listed = _entries(100)
    api = PruneAPI(listed)
    out = api.prune_queue_fasttrack_bypass_list({e["address"] for e in listed[:95]})
    assert out["removed"] == 0 and out["skipped"] == "few stale"


def test_prune_never_removes_on_an_empty_live_set():
    api = PruneAPI(_entries(200))
    out = api.prune_queue_fasttrack_bypass_list(set())
    assert out["removed"] == 0 and out["skipped"] == "no live IPs read"
    assert api.removed == []


def test_prune_reads_the_router_itself_and_keeps_every_live_ip():
    listed = _entries(100)
    live_reads = {
        "/ip/arp/print": [{"address": listed[0]["address"]}],
        "/ip/dhcp-server/lease/print": [{"address": listed[1]["address"]}],
        "/ip/hotspot/host/print": [{"address": "x", "to-address": listed[2]["address"]}],
        "/ip/hotspot/active/print": [{"address": listed[3]["address"]}],
        "/ip/hotspot/ip-binding/print": [{"address": listed[4]["address"]}],
        "/queue/simple/print": [{"target": listed[5]["address"] + "/32"}],
    }
    api = PruneAPI(listed, live_reads)
    out = api.prune_queue_fasttrack_bypass_list()
    removed = {i for chunk in api.removed for i in chunk}
    assert out["removed"] == 94
    assert not removed & {e[".id"] for e in listed[:6]}


@pytest.mark.parametrize("failing", ["/ip/arp/print", "/ip/hotspot/host/print", "/queue/simple/print"])
def test_prune_removes_nothing_when_a_self_read_fails(failing):
    api = PruneAPI(_entries(200), failing={failing})
    out = api.prune_queue_fasttrack_bypass_list()
    assert out.get("error") and api.removed == []


def test_sync_prunes_with_the_reads_it_already_has(monkeypatch):
    from tests.test_queue_ip_conflicts import FakeSyncAPI, _run_sync

    class SyncWithPrune(FakeSyncAPI):
        pruned_with = None

        def prune_queue_fasttrack_bypass_list(self, live_ips=None):
            self.pruned_with = live_ips
            return {"success": True, "removed": 0}

    api = SyncWithPrune(queues=[{".id": "*9", "name": "plan_AABBCC000001", "target": "192.168.88.77/32",
                                 "max-limit": "5M/5M", "disabled": "false", "comment": ""}],
                        hosts=[{"address": "192.168.88.50", "mac-address": "AA:BB:CC:00:00:01"}])
    _run_sync(monkeypatch, api, [{"id": 1, "mac_address": "AA:BB:CC:00:00:01", "plan_speed": "5M"}], False)
    assert api.pruned_with is not None
    assert {"192.168.88.50", "192.168.88.77"} <= api.pruned_with


def test_sync_skips_the_prune_when_a_read_failed(monkeypatch):
    from tests.test_queue_ip_conflicts import FakeSyncAPI, _run_sync

    class FailingHosts(FakeSyncAPI):
        pruned = False

        def get_hotspot_hosts_minimal(self):
            return {"error": "timeout"}

        def prune_queue_fasttrack_bypass_list(self, live_ips=None):
            self.pruned = True
            return {"success": True}

    api = FailingHosts(queues=[], hosts=[])
    _run_sync(monkeypatch, api, [{"id": 1, "mac_address": "AA:BB:CC:00:00:01", "plan_speed": "5M"}], False)
    assert api.pruned is False


def test_prune_wrapper_never_breaks_the_sync():
    class Boom:
        def prune_queue_fasttrack_bypass_list(self, live_ips=None):
            raise RuntimeError("socket closed")

    assert "socket closed" in mikrotik_background._prune_queue_bypass_list(Boom(), "R", set())["error"]


# --- 2. watchdog fast path on fresh wg-hz -------------------------------------------

def test_wg_watchdog_exits_early_while_wg_hz_is_fresh():
    src = wd.render_watchdog_source(wd.KIND_WG, "10.0.7.15")
    assert "# bw-mgmt-watchdog-wg v6" in src                          # after the bw-gate prefix
    fast = src.index(':foreach q in=[/interface wireguard peers find where interface="wg-hz" disabled=no]')
    slow = src.index(":if ($fresh = false) do={")
    assert src.index(":local fresh true") < fast < slow
    block = src[fast:slow]
    assert ":if ($qh < 4m) do={ :set fresh true }" in block
    assert "address-list" not in block and "/ping" not in block        # the fast path stays scan-free
    # v4 behaviour kept: the AWS interface state is still read (other tooling checks for it)
    assert ':local awsOn ([:len [/interface wireguard find where name="wg-aws" disabled=no]] > 0)' in src
    # and nothing in the script ever disables an interface (wg-aws carries the 10.0.X.Y address)
    assert not re.search(r"/interface wireguard (set|disable)\b", src)


# --- 3. tunnel check-in for RouterOS 7 ---------------------------------------------

@pytest.mark.parametrize("setting,router_id,version,expected", [
    ("ros7", 75, "7.20.7 (long-term)", True),
    ("ROS7 ", 75, "7.25.1", True),
    ("ros7", 354, "6.49.20 (long-term)", False),
    ("ros7", 9, "", False),
    ("597,563", 597, "6.49.1", True),      # an explicit id list is honoured as before
    ("597,563", 75, "7.20.7", False),
    ("", 75, "7.20.7", False),
])
def test_wants_checkin_tunnel(monkeypatch, setting, router_id, version, expected):
    monkeypatch.setattr(settings, "CHECKIN_TUNNEL_ROUTER_IDS", setting)
    assert enrol.wants_checkin_tunnel(router_id, version) is expected


def test_ros7_setting_installs_the_tunnel_transport(monkeypatch):
    from app.services import checkin_applier_script as applier
    from app.services.checkin_tunnel_transport import BEGIN
    from tests.test_standard_runtime_enrol import FakeRouterOS

    monkeypatch.setattr(settings, "CHECKIN_TUNNEL_ROUTER_IDS", "ros7")
    monkeypatch.setattr(settings, "CHECKIN_TUNNEL_ENDPOINT_URL", "http://10.251.0.1:8088/api/router/checkin")
    candidate = enrol.Candidate(75, "Kaloleni", "Router-0075", "10.0.0.4", "u", "p", 8728, True, False)
    api = FakeRouterOS(candidate.identity, version="7.20.7")
    result = enrol._checkin_sync(api, candidate, candidate.identity, api.board, api.arch, api.version)
    assert result.installed
    assert BEGIN in api.named("/system/script", applier.SCRIPT_NAME)["source"]
