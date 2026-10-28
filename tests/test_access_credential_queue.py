"""An access credential's device is always rate-limited by its cred_<id> queue.

A bypassed ip-binding skips the hotspot user profile, so the simple queue is
the only thing enforcing the credential's rate-limit. Incident 2026-10-25
(router 448, credential "kadot", 5M/5M): the queue was never created because
the device's IP was unknown at login and nothing retried, and the device moved
~23 GB in two days unthrottled.
"""

from app.services import access_credentials, mikrotik_background
from app.services.access_credentials import (
    ensure_credential_queue_sync,
    rate_limits_equal,
)

MAC = "AA:BB:CC:DD:EE:48"
ROUTER = {"ip": "10.0.0.48", "username": "admin", "password": "pw",
          "port": 8728, "name": "R448"}


class FakeRouter:
    def __init__(self, *, hosts=None, queues=None, arp=None, queue_print_ok=True,
                 address_list=None, idle="1m"):
        self.hosts = hosts if hosts is not None else [
            {".id": "*H1", "mac-address": MAC, "address": "192.168.88.50",
             "idle-time": idle, "bypassed": "true", "bytes-in": "10", "bytes-out": "20"}
        ]
        self.queues = list(queues or [])
        self.arp = list(arp or [])
        self.queue_print_ok = queue_print_ok
        self.address_list = list(address_list or [])
        self.bindings = [{".id": "*B1", "mac-address": MAC, "type": "bypassed",
                          "comment": "ACCESS_CRED|cred:77|user:kadot"}]
        self.commands = []
        self.fasttrack_calls = []
        self.connected = True

    def connect(self):
        return True

    def disconnect(self):
        pass

    def send_command(self, command, arguments=None):
        self.commands.append((command, arguments))
        if command == "/ip/hotspot/host/print":
            return {"success": True, "data": list(self.hosts)}
        if command == "/ip/hotspot/ip-binding/print":
            return {"success": True, "data": list(self.bindings)}
        if command == "/ip/arp/print":
            return {"success": True, "data": list(self.arp)}
        if command == "/queue/simple/print":
            if not self.queue_print_ok:
                return {"success": False, "error": "timeout"}
            return {"success": True, "data": [dict(q) for q in self.queues]}
        if command == "/queue/simple/add":
            self.queues.append({".id": f"*Q{len(self.queues) + 1}", **arguments})
            return {"success": True}
        if command == "/queue/simple/remove":
            self.queues = [q for q in self.queues if q[".id"] != arguments["numbers"]]
            return {"success": True}
        if command == "/ip/hotspot/ip-binding/remove":
            self.bindings = []
            return {"success": True}
        if command == "/ip/hotspot/host/remove":
            self.hosts = []
            return {"success": True}
        return {"success": True}

    def send_command_optimized(self, command, proplist=None, query=None):
        self.commands.append((command, {"query": query}))
        if command == "/ip/firewall/address-list/print":
            return {"success": True, "data": [{"address": a} for a in self.address_list]}
        return {"success": True, "data": []}

    def ensure_queue_fasttrack_bypass(self, ips):
        self.fasttrack_calls.append(list(ips))
        return {"success": True, "fasttrack_enabled": True}

    def sent(self, command):
        return [args for cmd, args in self.commands if cmd == command]


def _cred(**overrides):
    cred = {"id": 77, "bound_mac_address": MAC, "bound_at": None,
            "username": "kadot", "rate_limit": "5M/5M"}
    cred.update(overrides)
    return cred


def _scan(monkeypatch, router, cred):
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *_a, **_k: router)
    return mikrotik_background._scan_router_idle_credentials_sync(ROUTER, [cred], 15 * 60)


# --- helper ---------------------------------------------------------------

def test_rate_limits_compare_in_bps():
    assert rate_limits_equal("5000000/5000000", "5M/5M")
    assert rate_limits_equal("512000/2000000", "512K/2M")
    assert not rate_limits_equal("2000000/2000000", "5M/5M")
    assert not rate_limits_equal("", "5M/5M")


def test_helper_creates_missing_queue():
    router = FakeRouter()
    outcome = ensure_credential_queue_sync(
        router, cred_id=77, username="kadot", rate_limit="5M/5M",
        client_ip="192.168.88.50", existing_queue=None)
    assert outcome == "created"
    assert router.queues[0]["name"] == "cred_77"
    assert router.queues[0]["target"] == "192.168.88.50/32"
    assert router.queues[0]["max-limit"] == "5M/5M"


def test_helper_leaves_correct_queue_alone():
    router = FakeRouter()
    existing = {".id": "*Q1", "name": "cred_77", "target": "192.168.88.50/32",
                "max-limit": "5000000/5000000", "disabled": "false"}
    outcome = ensure_credential_queue_sync(
        router, cred_id=77, username="kadot", rate_limit="5M/5M",
        client_ip="192.168.88.50", existing_queue=existing)
    assert outcome == "unchanged"
    assert router.commands == []


def test_helper_retargets_queue_when_device_ip_changes():
    router = FakeRouter()
    existing = {".id": "*Q1", "name": "cred_77", "target": "192.168.88.10/32",
                "max-limit": "5000000/5000000", "disabled": "false"}
    outcome = ensure_credential_queue_sync(
        router, cred_id=77, username="kadot", rate_limit="5M/5M",
        client_ip="192.168.88.50", existing_queue=existing)
    assert outcome == "updated"
    [args] = router.sent("/queue/simple/set")
    assert args["target"] == "192.168.88.50/32"
    assert args["disabled"] == "no"


def test_helper_removes_queue_when_rate_limit_cleared():
    router = FakeRouter(queues=[{".id": "*Q1", "name": "cred_77"}])
    outcome = ensure_credential_queue_sync(
        router, cred_id=77, username="kadot", rate_limit=None,
        client_ip="192.168.88.50", existing_queue={".id": "*Q1", "name": "cred_77"})
    assert outcome == "removed"
    assert router.queues == []


def test_helper_without_ip_does_nothing():
    router = FakeRouter()
    outcome = ensure_credential_queue_sync(
        router, cred_id=77, username="kadot", rate_limit="5M/5M",
        client_ip=None, existing_queue=None)
    assert outcome == "no_ip"
    assert router.commands == []


# --- reaper re-sync -------------------------------------------------------

def test_reaper_creates_missing_queue_for_bound_credential(monkeypatch):
    """The kadot case: bound, online, bypassed, and no queue on the router."""
    router = FakeRouter()
    result = _scan(monkeypatch, router, _cred())
    assert [e["id"] for e in result["to_update"]] == [77]
    assert result["to_release"] == []
    [queue] = router.queues
    assert queue["name"] == "cred_77"
    assert queue["target"] == "192.168.88.50/32"
    assert queue["max-limit"] == "5M/5M"
    assert router.fasttrack_calls == [["192.168.88.50"]]


def test_reaper_leaves_steady_state_untouched(monkeypatch):
    router = FakeRouter(
        queues=[{".id": "*Q1", "name": "cred_77", "target": "192.168.88.50/32",
                 "max-limit": "5000000/5000000", "disabled": "false"}],
        address_list=["192.168.88.50"],
    )
    _scan(monkeypatch, router, _cred())
    assert router.sent("/queue/simple/add") == []
    assert router.sent("/queue/simple/set") == []
    assert router.fasttrack_calls == []


def test_reaper_does_not_add_blind_when_queue_table_unreadable(monkeypatch):
    router = FakeRouter(queue_print_ok=False)
    result = _scan(monkeypatch, router, _cred())
    assert [e["id"] for e in result["to_update"]] == [77]
    assert router.sent("/queue/simple/add") == []


def test_reaper_skips_queue_for_unthrottled_credential(monkeypatch):
    router = FakeRouter()
    _scan(monkeypatch, router, _cred(rate_limit=None))
    assert router.queues == []
    assert router.fasttrack_calls == []


def test_reaper_still_removes_queue_when_releasing_idle_credential(monkeypatch):
    router = FakeRouter(idle="20m", queues=[{".id": "*Q1", "name": "cred_77",
                                             "target": "192.168.88.50/32"}])
    result = _scan(monkeypatch, router, _cred())
    assert [e["id"] for e in result["to_release"]] == [77]
    assert router.queues == []


# --- login bind path ------------------------------------------------------

def _bind(monkeypatch, router):
    monkeypatch.setattr(access_credentials, "MikroTikAPI", lambda *_a, **_k: router)
    monkeypatch.setattr(access_credentials, "CMD_DELAY", 0)
    return access_credentials._bind_mac_direct_api_sync(ROUTER, {
        "mac_address": MAC, "username": "kadot", "cred_id": 77,
        "rate_limit": "5M/5M", "previous_mac_address": None,
    })


def test_login_creates_queue_when_ip_known(monkeypatch):
    router = FakeRouter()
    router.bindings = []
    result = _bind(monkeypatch, router)
    assert result["success"] and result["queue"] == "created"
    assert router.queues[0]["target"] == "192.168.88.50/32"


def test_login_without_ip_still_succeeds_and_leaves_queue_to_reaper(monkeypatch):
    router = FakeRouter(hosts=[], arp=[])
    router.bindings = []
    result = _bind(monkeypatch, router)
    assert result["success"] and result["client_ip"] is None
    assert router.queues == []
