"""Access-credential rate limits reach RouterOS in a form it accepts.

Production, 2026-10-28:
  * cred 319 "king1" was saved as "50/10". RouterOS reads unit-less numbers as
    bits/s, so the device got 50 bit/s. Bare numbers are Mbps now, the same as
    plan speeds.
  * creds 166/167/274/281 were saved as "5m/2m", "5m/3m", "20m/15m", "5m/5m".
    RouterOS rejects lowercase m and every reaper pass logged
    "value of upload-max-limit contains invalid trailing characters", so those
    devices were never rate-limited.
  * A MAC-NAT repeater puts several IPs behind one bound MAC; the queue only
    targeted the first, so the other devices ran unlimited.
"""

import re
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.access_credential_routes import _validate_rate_limit
from app.services import access_credentials, mikrotik_background
from app.services.access_credentials import (
    InvalidRateLimit,
    _ensure_cred_profile,
    _provision_radius,
    ensure_credential_queue_sync,
    normalize_rate_limit,
    profile_name_for_rate,
    rate_limit_has_bare_numbers,
    router_rate_limit,
)

from tests.test_access_credential_queue import MAC, ROUTER, FakeRouter

# RouterOS rate syntax: digits with an optional k/K, M or G.
ROUTEROS_RATE = re.compile(r"^\d+[kKMG]?/\d+[kKMG]?$")


class StrictRouter(FakeRouter):
    """Rejects rates RouterOS rejects, with RouterOS's own error text."""

    def send_command(self, command, arguments=None):
        rate = (arguments or {}).get("max-limit") or (arguments or {}).get("rate-limit")
        if rate and not ROUTEROS_RATE.match(rate):
            self.commands.append((command, arguments))
            return {"success": False,
                    "error": "value of upload-max-limit contains invalid trailing characters"}
        return super().send_command(command, arguments)


# --- input normalisation (create / update) --------------------------------

@pytest.mark.parametrize("raw, expected", [
    # unit-less, as typed by resellers (cred 319 and older rows)
    ("50/10", "50M/10M"),
    ("5/2", "5M/2M"),
    ("3/2", "3M/2M"),
    ("10/10M", "10M/10M"),
    # lowercase units seen in prod (creds 166, 167, 274, 281)
    ("5m/2m", "5M/2M"),
    ("5m/3m", "5M/3M"),
    ("20m/15m", "20M/15M"),
    ("5m/5m", "5M/5M"),
    ("5M/2m", "5M/2M"),
    # already fine
    ("5M/2M", "5M/2M"),
    ("100M/100M", "100M/100M"),
    ("1G/1G", "1G/1G"),
    # spacing and spelled-out units
    (" 5M / 2M ", "5M/2M"),
    ("5 Mbps/2 Mbps", "5M/2M"),
    ("5mbps/2mbps", "5M/2M"),
    # kilo is RouterOS's lowercase k
    ("512K/1M", "512k/1M"),
    ("512k/1m", "512k/1M"),
    # fractions step down a unit (RouterOS rejects "1.5M")
    ("1.5/0.5", "1500k/500k"),
    ("1.5M/2M", "1500k/2M"),
    # one value sets both directions
    ("5M", "5M/5M"),
    ("8", "8M/8M"),
    # 1000+ with no unit is raw bps, as RouterOS prints it (same as plans)
    ("10000/10000", "10000/10000"),
    ("5000000/2000000", "5000000/2000000"),
])
def test_normalize_rate_limit(raw, expected):
    assert normalize_rate_limit(raw) == expected
    assert ROUTEROS_RATE.match(expected)


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_empty_rate_limit_means_unlimited(raw):
    assert normalize_rate_limit(raw) is None


@pytest.mark.parametrize("raw", [
    "fast", "5X/2", "-5/2", "5M/2M/1M", "5M-2M", "5,2", "M/M", "/", "5/",
    "0/0", "0/5M", "50000M/1M", "5M 2M",
])
def test_garbage_rate_limit_rejected(raw):
    with pytest.raises(InvalidRateLimit):
        normalize_rate_limit(raw)


def test_route_validation_returns_400_with_hint():
    with pytest.raises(HTTPException) as exc:
        _validate_rate_limit("fast")
    assert exc.value.status_code == 400
    assert "Mbps" in exc.value.detail
    assert _validate_rate_limit("50/10") == "50M/10M"
    assert _validate_rate_limit("") is None
    assert _validate_rate_limit(None) is None


def test_bare_number_detection_for_reporting():
    assert rate_limit_has_bare_numbers("50/10")
    assert rate_limit_has_bare_numbers("10/10M")
    assert not rate_limit_has_bare_numbers("5M/2M")
    assert not rate_limit_has_bare_numbers("5m/2m")
    assert not rate_limit_has_bare_numbers(None)


# --- re-sending stored rows -----------------------------------------------

def test_stored_rows_are_respelled_not_reinterpreted():
    assert router_rate_limit("5m/2m") == "5M/2M"
    assert router_rate_limit("20m/15m") == "20M/15M"
    # bare numbers keep their (bits/s) meaning until the reseller edits them
    assert router_rate_limit("50/10") == "50/10"
    # unparseable rows go out exactly as before
    assert router_rate_limit("5M/2M 10M/4M") == "5M/2M 10M/4M"
    assert router_rate_limit(None) is None
    assert router_rate_limit("") is None


@pytest.mark.parametrize("stored, sent", [
    ("5m/2m", "5M/2M"), ("5m/3m", "5M/3M"), ("20m/15m", "20M/15M"), ("5m/5m", "5M/5M"),
])
def test_queue_for_lowercase_rows_is_accepted_by_router(stored, sent):
    router = StrictRouter()
    outcome = ensure_credential_queue_sync(
        router, cred_id=166, username="mary", rate_limit=stored,
        client_ip="192.168.88.50", existing_queue=None)
    assert outcome == "created"
    assert router.queues[0]["max-limit"] == sent


def test_lowercase_row_matching_router_queue_is_left_alone():
    router = StrictRouter()
    existing = {".id": "*Q1", "name": "cred_166", "target": "192.168.88.50/32",
                "max-limit": "5000000/2000000", "disabled": "false"}
    outcome = ensure_credential_queue_sync(
        router, cred_id=166, username="mary", rate_limit="5m/2m",
        client_ip="192.168.88.50", existing_queue=existing)
    assert outcome == "unchanged"


def test_reaper_limits_lowercase_row(monkeypatch):
    router = StrictRouter()
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *_a, **_k: router)
    cred = {"id": 77, "bound_mac_address": MAC, "bound_at": None,
            "username": "kadot", "rate_limit": "5m/5m"}
    mikrotik_background._scan_router_idle_credentials_sync(ROUTER, [cred], 15 * 60)
    [queue] = router.queues
    assert queue["max-limit"] == "5M/5M"


def test_hotspot_profile_uses_routeros_spelling():
    router = StrictRouter()
    assert profile_name_for_rate("5m/2m") == "cred-5M_2M"
    assert profile_name_for_rate("5M/2M") == "cred-5M_2M"
    assert profile_name_for_rate(None) == "cred-unlimited"
    result = _ensure_cred_profile(router, profile_name_for_rate("5m/2m"), "5m/2m")
    assert result.get("success")
    [args] = router.sent("/ip/hotspot/user/profile/add")
    assert args["rate-limit"] == "5M/2M"


class _FakeDB:
    def __init__(self):
        self.params = []

    async def execute(self, _stmt, params=None):
        self.params.append(params or {})

    async def commit(self):
        pass


async def test_radius_reply_uses_routeros_spelling():
    db = _FakeDB()
    cred = SimpleNamespace(username="mary", password="pw", rate_limit="5m/2m")
    await _provision_radius(db, cred)
    [reply] = [p for p in db.params if p.get("attr") == "Mikrotik-Rate-Limit"]
    assert reply["val"] == "5M/2M"


# --- several devices behind one MAC (repeater) ----------------------------

def _repeater_hosts(idle="1m"):
    return [
        {".id": "*H1", "mac-address": MAC, "address": "192.168.88.50",
         "idle-time": idle, "bypassed": "true", "bytes-in": "10", "bytes-out": "20"},
        {".id": "*H2", "mac-address": MAC, "address": "192.168.88.7",
         "idle-time": idle, "bypassed": "true", "bytes-in": "5", "bytes-out": "6"},
        {".id": "*H3", "mac-address": "AA:BB:CC:00:00:01", "address": "192.168.88.9",
         "idle-time": idle, "bypassed": "false"},
    ]


def test_queue_targets_every_ip_behind_the_mac():
    router = FakeRouter()
    outcome = ensure_credential_queue_sync(
        router, cred_id=77, username="kadot", rate_limit="5M/5M",
        client_ip=["192.168.88.50", "192.168.88.7", "192.168.88.50"], existing_queue=None)
    assert outcome == "created"
    assert router.queues[0]["target"] == "192.168.88.7/32,192.168.88.50/32"


def test_multi_ip_queue_in_any_order_is_unchanged():
    router = FakeRouter()
    existing = {".id": "*Q1", "name": "cred_77",
                "target": "192.168.88.50/32,192.168.88.7/32",
                "max-limit": "5000000/5000000", "disabled": "false"}
    outcome = ensure_credential_queue_sync(
        router, cred_id=77, username="kadot", rate_limit="5M/5M",
        client_ip=["192.168.88.7", "192.168.88.50"], existing_queue=existing)
    assert outcome == "unchanged"
    assert router.commands == []


def test_queue_grows_when_a_second_device_appears():
    router = FakeRouter()
    existing = {".id": "*Q1", "name": "cred_77", "target": "192.168.88.50/32",
                "max-limit": "5000000/5000000", "disabled": "false"}
    outcome = ensure_credential_queue_sync(
        router, cred_id=77, username="kadot", rate_limit="5M/5M",
        client_ip=["192.168.88.50", "192.168.88.7"], existing_queue=existing)
    assert outcome == "updated"
    [args] = router.sent("/queue/simple/set")
    assert args["target"] == "192.168.88.7/32,192.168.88.50/32"


def test_reaper_limits_every_device_behind_repeater(monkeypatch):
    router = FakeRouter(hosts=_repeater_hosts())
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *_a, **_k: router)
    cred = {"id": 77, "bound_mac_address": MAC, "bound_at": None,
            "username": "kadot", "rate_limit": "5M/5M"}
    result = mikrotik_background._scan_router_idle_credentials_sync(ROUTER, [cred], 15 * 60)
    assert [e["id"] for e in result["to_update"]] == [77]
    [queue] = router.queues
    assert queue["target"] == "192.168.88.7/32,192.168.88.50/32"
    assert router.fasttrack_calls == [["192.168.88.7", "192.168.88.50"]]


def test_login_limits_every_device_behind_repeater(monkeypatch):
    router = FakeRouter(hosts=_repeater_hosts())
    router.bindings = []
    monkeypatch.setattr(access_credentials, "MikroTikAPI", lambda *_a, **_k: router)
    monkeypatch.setattr(access_credentials, "CMD_DELAY", 0)
    result = access_credentials._bind_mac_direct_api_sync(ROUTER, {
        "mac_address": MAC, "username": "kadot", "cred_id": 77,
        "rate_limit": "5M/5M", "previous_mac_address": None,
    })
    assert result["success"] and result["queue"] == "created"
    assert result["client_ip"] == "192.168.88.7"
    assert router.queues[0]["target"] == "192.168.88.7/32,192.168.88.50/32"
