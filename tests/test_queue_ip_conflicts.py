"""Stale per-customer queues must not swallow another device's traffic.

Simple queues match top-down, so a ``plan_<MAC>`` queue left on an IP that DHCP
later gave to another device counts and rate-limits that device, and the real
owner's queue reads 0 bytes. On 2026-09-24 this was 71 of the 88 zero-usage
customers on push routers.
"""

from app.services import mikrotik_background
from app.services.mikrotik_api import (
    customer_queue_mac,
    find_conflicting_customer_queues,
    queue_single_target_ip,
)

NEW_MAC = "AA:BB:CC:00:00:01"      # device on 192.168.88.50 right now
STALE_MAC = "AA:BB:CC:00:00:02"    # expired customer, queue still on .50
PAYING_MAC = "AA:BB:CC:00:00:03"   # paying customer, offline, queue still on .60
ROAMER_MAC = "AA:BB:CC:00:00:04"   # device now on .60


def _q(qid, mac, target, disabled="false", name=None):
    return {
        ".id": qid,
        "name": name or f"plan_{mac.replace(':', '')}",
        "target": target,
        "max-limit": "5M/5M",
        "disabled": disabled,
        "comment": f"MAC:{mac}|Plan rate limit",
    }


def test_customer_queue_mac_only_claims_our_queue_names():
    assert customer_queue_mac({"name": "plan_AABBCC000001"}) == NEW_MAC
    assert customer_queue_mac({"name": "queue_aabbcc000001"}) == NEW_MAC
    assert customer_queue_mac({"name": "cred_36"}) is None
    assert customer_queue_mac({"name": "<pppoe-john>"}) is None
    assert customer_queue_mac({"name": "plan_premium"}) is None


def test_queue_single_target_ip():
    assert queue_single_target_ip({"target": "192.168.88.5/32"}) == "192.168.88.5"
    assert queue_single_target_ip({"target": "192.168.88.5"}) == "192.168.88.5"
    assert queue_single_target_ip({"target": "192.168.88.0/24"}) is None
    assert queue_single_target_ip({"target": "10.0.0.1/32,10.0.0.2/32"}) is None
    assert queue_single_target_ip({"target": "bridge"}) is None
    assert queue_single_target_ip({}) is None


def test_finds_only_enabled_customer_queues_on_someone_elses_ip():
    queues = [
        _q("*1", STALE_MAC, "192.168.88.50/32"),              # conflict
        _q("*2", NEW_MAC, "192.168.88.50/32"),                # rightful owner
        _q("*3", PAYING_MAC, "192.168.88.61/32", "true"),     # disabled: matches nothing
        _q("*4", PAYING_MAC, "192.168.88.99/32"),             # nobody on .99
        {".id": "*5", "name": "cred_7", "target": "192.168.88.50/32"},  # not ours
    ]
    ip_owner = {"192.168.88.50": NEW_MAC, "192.168.88.61": ROAMER_MAC}

    conflicts = find_conflicting_customer_queues(queues, ip_owner)

    assert [c["queue"][".id"] for c in conflicts] == ["*1"]
    assert conflicts[0]["holder_mac"] == NEW_MAC
    assert conflicts[0]["queue_mac"] == STALE_MAC


def test_ip_owner_prefers_live_hotspot_state_over_leases():
    ip_owner = mikrotik_background._build_ip_owner_map(
        dhcp_leases=[
            {"address": "192.168.88.50", "mac-address": STALE_MAC, "status": "bound"},
            {"address": "192.168.88.70", "mac-address": PAYING_MAC, "status": "waiting"},
        ],
        arp_entries=[],
        hotspot_hosts=[{"address": "192.168.88.50", "mac-address": NEW_MAC.lower()}],
        hotspot_active=[],
    )
    assert ip_owner == {"192.168.88.50": NEW_MAC}


class FakeSyncAPI:
    """Just enough MikroTikAPI surface for _sync_single_router_queues_sync."""

    def __init__(self, queues, hosts, bindings=(), bindings_error=None):
        self.queues = queues
        self.hosts = hosts
        self.bindings = list(bindings)
        self.bindings_error = bindings_error
        self.commands = []
        self.connected = False

    def connect(self):
        self.connected = True
        return True

    def disconnect(self):
        self.connected = False

    def get_arp_minimal(self):
        return {"success": True, "data": []}

    def get_dhcp_leases_minimal(self):
        return {"success": True, "data": []}

    def get_hotspot_hosts_minimal(self):
        return {"success": True, "data": list(self.hosts)}

    def get_hotspot_active_minimal(self):
        return {"success": True, "data": []}

    def get_ip_bindings_minimal(self):
        if self.bindings_error:
            return {"error": self.bindings_error}
        return {"success": True, "data": self.bindings}

    def get_simple_queues_minimal(self):
        return {"success": True, "data": self.queues}

    def ensure_queue_fasttrack_bypass(self, ips):
        return {"success": True}

    def _parse_speed_to_mikrotik(self, speed):
        return "5M/5M"

    def send_command(self, command, arguments=None):
        self.commands.append((command, dict(arguments or {})))
        return {"success": True, "data": []}


def _run_sync(monkeypatch, api, customers, queue_hygiene=True):
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *a, **k: api)
    monkeypatch.setattr(mikrotik_background.time, "sleep", lambda *_: None)
    router = {"ip": "10.0.0.9", "username": "u", "password": "p", "port": 8728, "name": "R"}
    return mikrotik_background._sync_single_router_queues_sync(router, customers, queue_hygiene)


def test_sync_removes_stale_queue_and_disables_paying_customers_old_ip(monkeypatch):
    api = FakeSyncAPI(
        queues=[
            _q("*1", STALE_MAC, "192.168.88.50/32"),    # expired customer on NEW's IP
            _q("*2", NEW_MAC, "192.168.88.50/32"),
            _q("*3", PAYING_MAC, "192.168.88.60/32"),   # paying but offline; .60 reassigned
            _q("*4", ROAMER_MAC, "192.168.88.60/32"),
        ],
        hosts=[
            {"address": "192.168.88.50", "mac-address": NEW_MAC},
            {"address": "192.168.88.60", "mac-address": ROAMER_MAC},
        ],
    )
    customers = [
        {"id": 1, "mac_address": NEW_MAC, "plan_speed": "5M"},
        {"id": 3, "mac_address": PAYING_MAC, "plan_speed": "5M"},
        {"id": 4, "mac_address": ROAMER_MAC, "plan_speed": "5M"},
    ]

    result = _run_sync(monkeypatch, api, customers)

    assert ("/queue/simple/remove", {"numbers": "*1"}) in api.commands
    assert ("/queue/simple/set", {"numbers": "*3", "disabled": "yes"}) in api.commands
    touched = {args.get("numbers") for cmd, args in api.commands if cmd.startswith("/queue/simple/")}
    assert touched == {"*1", "*3"}
    assert result["details"]["shadowing_queues_fixed"] == 2


def test_sync_judges_a_retargeted_queue_on_its_new_ip(monkeypatch):
    # PAYING's queue still points at .60, but PAYING is back online on .61.
    # The per-customer pass moves it to .61; the conflict pass must then see
    # .61 (no conflict), not the stale .60 (ROAMER's IP).
    api = FakeSyncAPI(
        queues=[
            _q("*3", PAYING_MAC, "192.168.88.60/32"),
            _q("*4", ROAMER_MAC, "192.168.88.60/32"),
        ],
        hosts=[
            {"address": "192.168.88.61", "mac-address": PAYING_MAC},
            {"address": "192.168.88.60", "mac-address": ROAMER_MAC},
        ],
    )
    customers = [
        {"id": 3, "mac_address": PAYING_MAC, "plan_speed": "5M"},
        {"id": 4, "mac_address": ROAMER_MAC, "plan_speed": "5M"},
    ]

    result = _run_sync(monkeypatch, api, customers)

    assert api.commands == [
        ("/queue/simple/set", {"numbers": "*3", "target": "192.168.88.61/32", "max-limit": "5M/5M"}),
    ]
    assert result["details"]["shadowing_queues_fixed"] == 0


EXPIRED_MAC = "AA:BB:CC:00:00:05"   # expired months ago, offline, binding gone
GUEST_MAC = "AA:BB:CC:00:00:06"     # not active in the DB here, but still bound


def test_sync_sweeps_queues_with_no_active_customer_and_no_binding(monkeypatch):
    # Wangige, 2026-09-24: 60 of 71 queues belonged to nobody. They shadow a
    # new customer the moment DHCP reuses their IP, even while that customer
    # is offline, so the conflict pass alone (which needs the IP in use) is
    # not enough.
    api = FakeSyncAPI(
        queues=[
            _q("*5", EXPIRED_MAC, "192.168.88.160/32"),
            _q("*6", GUEST_MAC, "192.168.88.161/32"),
            _q("*2", NEW_MAC, "192.168.88.50/32"),
        ],
        hosts=[{"address": "192.168.88.50", "mac-address": NEW_MAC}],
        bindings=[
            {"mac-address": NEW_MAC, "type": "bypassed"},
            {"mac-address": GUEST_MAC.lower(), "type": "bypassed"},
        ],
    )
    customers = [{"id": 1, "mac_address": NEW_MAC, "plan_speed": "5M"}]

    result = _run_sync(monkeypatch, api, customers)

    assert api.commands == [("/queue/simple/remove", {"numbers": "*5"})]
    assert result["details"]["shadowing_queues_fixed"] == 1


def test_sync_removes_nothing_when_bindings_cannot_be_read(monkeypatch):
    api = FakeSyncAPI(
        queues=[_q("*5", EXPIRED_MAC, "192.168.88.160/32")],
        hosts=[],
        bindings_error="Not connected",
    )
    customers = [{"id": 1, "mac_address": NEW_MAC, "plan_speed": "5M"}]

    _run_sync(monkeypatch, api, customers)

    assert api.commands == []


def test_sync_leaves_queues_alone_on_non_pilot_routers(monkeypatch):
    api = FakeSyncAPI(
        queues=[_q("*5", EXPIRED_MAC, "192.168.88.160/32"), _q("*1", STALE_MAC, "192.168.88.50/32")],
        hosts=[{"address": "192.168.88.50", "mac-address": NEW_MAC}],
    )
    customers = [{"id": 1, "mac_address": NEW_MAC, "plan_speed": "5M"}]

    _run_sync(monkeypatch, api, customers, queue_hygiene=False)

    removed_or_disabled = [
        args for cmd, args in api.commands
        if cmd == "/queue/simple/remove" or args.get("disabled") == "yes"
    ]
    assert removed_or_disabled == []
