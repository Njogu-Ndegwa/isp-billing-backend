"""One PPPoE username logged in on several devices at once.

RouterOS allows it when the secret's profile has ``only-one=no``; each session
then gets its own address and its own dynamic ``<pppoe-…>`` queue. The monitor
must list every device instead of collapsing them to one row per username.
"""
from unittest.mock import Mock

from app.api import pppoe_monitor
from app.services.mikrotik_api import MikroTikAPI
from app.services.monitor_liveness import clear_live_state


ACTIVE_TWO_DEVICES = [
    {".id": "*1", "name": "alice", "service": "pppoe", "caller-id": "AA:AA:AA:AA:AA:01",
     "address": "192.168.89.10", "uptime": "2h5m", "session-id": "0x81"},
    {".id": "*2", "name": "alice", "service": "pppoe", "caller-id": "AA:AA:AA:AA:AA:02",
     "address": "192.168.89.11", "uptime": "1d03:00:00", "session-id": "0x82"},
    {".id": "*3", "name": "bob", "service": "pppoe", "caller-id": "BB:BB:BB:BB:BB:01",
     "address": "192.168.89.20", "uptime": "15m", "session-id": "0x83"},
]

QUEUES = [
    {".id": "*Q1", "name": "<pppoe-alice>", "target": "192.168.89.10/32",
     "max-limit": "5400000/5400000", "rate": "1000/2000", "bytes": "100/200"},
    # RouterOS gives a second same-name session's queue a suffixed name; only
    # the target ties it back to its session.
    {".id": "*Q2", "name": "<pppoe-alice-1>", "target": "192.168.89.11/32",
     "max-limit": "5400000/5400000", "rate": "3000/4000", "bytes": "300/400"},
    {".id": "*Q3", "name": "<pppoe-bob>", "target": "192.168.89.20/32",
     "max-limit": "10800000/10800000", "rate": "50/60", "bytes": "5/6"},
]


def _api(active, queues):
    api = MikroTikAPI.__new__(MikroTikAPI)
    api.connected = True
    api.send_command = Mock(return_value={"success": True, "data": active})

    def optimized(command, proplist=None, query=None):
        if command == "/ppp/active/print":
            name = (query or "").removeprefix("?name=")
            return {"success": True, "data": [s for s in active if s["name"] == name]}
        if command == "/queue/simple/print":
            if query and query.startswith("?name="):
                rows = [q for q in queues if q["name"] == query.removeprefix("?name=")]
            elif query and query.startswith("?target="):
                rows = [q for q in queues if q["target"] == query.removeprefix("?target=")]
            else:
                rows = list(queues)
            return {"success": True, "data": rows}
        raise AssertionError(f"unexpected command {command}")

    api.send_command_optimized = Mock(side_effect=optimized)
    return api


def test_each_session_gets_its_own_queue_by_address():
    api = _api(ACTIVE_TWO_DEVICES, QUEUES)

    result = api.get_pppoe_sessions_with_bandwidth()

    by_address = {s["address"]: s for s in result["data"]}
    assert result["count"] == 3
    assert by_address["192.168.89.10"]["upload_bytes"] == 100
    assert by_address["192.168.89.11"]["upload_bytes"] == 300
    assert by_address["192.168.89.11"]["download_rate"] == "4000"
    assert by_address["192.168.89.11"]["id"] == "*2"
    assert all(s["has_queue"] for s in result["data"])


def test_name_match_for_another_sessions_address_is_not_borrowed():
    # Only the first session's queue exists; the second must not inherit it.
    api = _api(ACTIVE_TWO_DEVICES[:2], QUEUES[:1])

    result = api.get_pppoe_sessions_with_bandwidth()

    by_address = {s["address"]: s for s in result["data"]}
    assert by_address["192.168.89.10"]["has_queue"] is True
    assert by_address["192.168.89.11"]["has_queue"] is False
    assert by_address["192.168.89.11"]["upload_bytes"] == 0


def test_name_fallback_still_works_without_target():
    queues = [dict(QUEUES[2], target="")]
    api = _api(ACTIVE_TWO_DEVICES[2:], queues)

    result = api.get_pppoe_sessions_with_bandwidth()

    assert result["data"][0]["has_queue"] is True
    assert result["data"][0]["upload_bytes"] == 5


def test_single_user_lookup_returns_every_session():
    api = _api(ACTIVE_TWO_DEVICES, QUEUES)

    result = api.get_pppoe_session_with_bandwidth("alice")

    assert result["found"] is True
    assert [s["address"] for s in result["sessions"]] == ["192.168.89.10", "192.168.89.11"]
    assert [s["upload_bytes"] for s in result["sessions"]] == [100, 300]
    assert result["data"]["address"] == "192.168.89.10"


def test_single_user_lookup_offline():
    api = _api(ACTIVE_TWO_DEVICES, QUEUES)

    result = api.get_pppoe_session_with_bandwidth("carol")

    assert result == {"success": True, "found": False, "data": None, "sessions": []}


def _install_fake_users_api(monkeypatch):
    class FakeMikroTikAPI:
        def __init__(self, *_args, **_kwargs):
            self._real = _api(ACTIVE_TWO_DEVICES, QUEUES)

        def connect(self):
            return True

        def disconnect(self):
            pass

        def get_ppp_secrets_full(self):
            return {"success": True, "data": [
                {"name": "alice", "profile": "pppoe_5M", "service": "pppoe", "disabled": False},
                {"name": "bob", "profile": "pppoe_10M", "service": "pppoe", "disabled": False},
                {"name": "carol", "profile": "pppoe_5M", "service": "pppoe", "disabled": False},
            ]}

        def get_pppoe_sessions_with_bandwidth(self):
            return self._real.get_pppoe_sessions_with_bandwidth()

        def get_ppp_profiles(self):
            return {"success": True, "data": [
                {"name": "pppoe_5M", "rate_limit": "5400000/5400000", "only_one": "no"},
                {"name": "pppoe_10M", "rate_limit": "10800000/10800000", "only_one": "yes"},
            ]}

    monkeypatch.setattr(pppoe_monitor, "MikroTikAPI", FakeMikroTikAPI)


def test_users_lists_every_device_under_one_username(monkeypatch):
    _install_fake_users_api(monkeypatch)

    result = pppoe_monitor._pppoe_users_sync(
        {"ip": "10.0.0.2", "username": "admin", "password": "x", "port": 8728}
    )

    users = {u["username"]: u for u in result["users"]}
    alice = users["alice"]
    assert alice["online"] is True
    assert alice["session_count"] == 2
    assert alice["profile_only_one"] == "no"
    # Longest-connected device first.
    assert [d["address"] for d in alice["sessions"]] == ["192.168.89.11", "192.168.89.10"]
    assert [d["caller_id"] for d in alice["sessions"]] == ["AA:AA:AA:AA:AA:02", "AA:AA:AA:AA:AA:01"]
    assert alice["address"] == "192.168.89.11"
    # Totals cover both devices.
    assert alice["upload_bytes"] == 400
    assert alice["download_bytes"] == 600
    assert alice["upload_rate"] == "4000"
    assert alice["download_rate"] == "6000"

    assert users["bob"]["session_count"] == 1
    assert users["carol"]["online"] is False
    assert users["carol"]["sessions"] == []

    summary = result["summary"]
    assert summary["online"] == 2
    assert summary["online_sessions"] == 3
    assert summary["multi_device_users"] == 1
    assert summary["total_upload_rate_bps"] == 4050
    assert summary["total_download_rate_bps"] == 6060


def test_unreachable_router_snapshot_drops_devices(monkeypatch):
    _install_fake_users_api(monkeypatch)
    live = pppoe_monitor._pppoe_users_sync(
        {"ip": "10.0.0.2", "username": "admin", "password": "x", "port": 8728}
    )

    offline = clear_live_state(live, reason="connect_failed")

    alice = next(u for u in offline["users"] if u["username"] == "alice")
    assert alice["online"] is False
    assert alice["sessions"] == []
    assert alice["session_count"] == 0
    assert offline["summary"]["online_sessions"] == 0
    assert offline["summary"]["multi_device_users"] == 0


def test_uptime_parsing():
    assert pppoe_monitor._uptime_seconds("") == 0
    assert pppoe_monitor._uptime_seconds("15m") == 900
    assert pppoe_monitor._uptime_seconds("2h5m") == 7500
    assert pppoe_monitor._uptime_seconds("1w2d3h4m5s") == 604800 + 2 * 86400 + 3 * 3600 + 245
    assert pppoe_monitor._uptime_seconds("1d03:00:00") == 86400 + 3 * 3600
    assert pppoe_monitor._uptime_seconds("00:00:42") == 42
