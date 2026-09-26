"""What is ailing a problem router (app/services/router_diagnosis.py).

Pinned on what we confirmed in production on 2026-09-25/26:
* overloaded: Powernet #3 (483), Pamoja #3 (486), lee net #1 (371) answer every
  TCP connect but time out the API login, or report CPU 100% / ~5 MB free; the
  hAP lites (32 MB, smips) are simply too small, worse on RouterOS 7, and 483
  had 17 script jobs stacked;
* isp_blocks_server: RONGAI (448), HOME951 (351), LEADERS APLITE (426) sit on one
  ISP line whose ISP drops the Hetzner server's replies (wg-hz never handshakes,
  wg-aws does);
* replaced_router: Powernet #8 (182) went dark on 09-24 when the owner moved its
  customers to Powernet #3 (483);
* congested_line: Lux #2 (210) pings 0.8-10 s on a saturated line;
* site dark vs tunnel down: a router still checking in over HTTPS has internet.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import pytest

from app.db import database
from app.db.models import RouterHealth
from app.services import ops_health_problem_routers as pr
from app.services import router_diagnosis as rd
from tests.factories import make_reseller, make_router

NOW = datetime(2026, 9, 25, 12, 0)
MB = 1024 * 1024


def _health(minutes_ago=3, cpu=None, source="push", free=None, board=None, version=None):
    return {"source": source, "sampled_at": NOW - timedelta(minutes=minutes_ago), "cpu_load": cpu,
            "memory_free_bytes": free, "board_name": board, "routeros_version": version}


def _classify(tcp_ok, login, tunnel="wireguard", health=None, **kw):
    return rd.classify(tcp_ok, 5, login, tunnel, health, NOW, **kw)


FAST = [0.15, 0.14, 0.16, 0.15, 0.17]


# ---------------------------------------------------------------------------
# overloaded
# ---------------------------------------------------------------------------

def test_clean_line_but_login_times_out_is_an_overloaded_router():
    d = _classify(5, "timeout", health=_health(3, cpu=100), tcp_times=FAST)
    assert d == {
        "ailment": "overloaded",
        "title": "Router overloaded",
        "evidence": "TCP 5/5, API login timed out, CPU 100% (push 3 min ago)",
        "facts": ["TCP 5/5", "API login timed out", "CPU 100% (push 3 min ago)"],
        "action": "Reboot the router; if it recurs, upgrade hardware or RouterOS",
        "hints": [],
        "sstp_candidate": False,
    }
    # Four of five connects is still a clean line.
    assert _classify(4, "timeout")["ailment"] == "overloaded"


def test_router_reporting_cpu_90_or_more_is_overloaded_whatever_the_probe_saw():
    for tcp_ok, login in ((2, "timeout"), (5, "ok"), (0, "skipped")):
        d = _classify(tcp_ok, login, health=_health(8, cpu=95, source="snmp"))
        assert d["ailment"] == "overloaded" and d["sstp_candidate"] is False
    # ...but only a recent reading counts.
    assert _classify(2, "timeout", health=_health(15, cpu=100))["ailment"] == "lossy_line"
    assert _classify(5, "ok", health=_health(3, cpu=89))["ailment"] == "healthy_now"


def test_almost_no_free_memory_is_overloaded():
    d = _classify(5, "ok", health=_health(2, cpu=40, free=6 * MB))
    assert d["ailment"] == "overloaded"
    assert d["facts"][-1] == "6 MB free"
    assert _classify(5, "ok", health=_health(2, cpu=40, free=60 * MB))["ailment"] == "healthy_now"


def test_overload_read_at_login_counts_when_there_is_no_push():
    # hAP lites have no router_health rows: the login's own /system/resource read decides.
    readings = {"resource": {"cpu": 100, "free_memory": 5 * MB, "board": "hAP lite",
                             "arch": "smips", "version": "6.49.21 (long-term)"},
                "script_jobs": 17, "tunnels": []}
    d = _classify(5, "ok", tunnel="sstp", readings=readings)
    assert d["ailment"] == "overloaded"
    assert d["evidence"] == "TCP 5/5, API login ok, no push, CPU 100% (at login), 5 MB free"
    assert d["hints"] == ["Scripts piling up (17 running jobs)",
                          "Hardware too small (hAP lite, 32 MB RAM)"]
    assert d["action"] == rd.ACTION_SCRIPTS


def test_small_board_on_routeros_7_is_told_to_downgrade_or_replace():
    # Pamoja #3 (486): hAP lite on 7.24.1, login times out.
    d = _classify(5, "timeout", tunnel="wireguard",
                  facts={"board": "RB941-2nD", "arch": "smips", "version": "7.24.1 (stable)"})
    assert d["ailment"] == "overloaded"
    assert d["hints"] == ["RouterOS 7 too heavy for this board (RB941-2nD, 7.24.1 (stable))"]
    assert d["action"] == "RouterOS 7 is too heavy for this board — downgrade to v6 or replace it"
    # Board learnt from router_health works the same.
    d = _classify(5, "timeout", health=_health(30, board="hAP lite", version="7.19.6"))
    assert d["action"] == rd.ACTION_ROS7_SMALL


def test_small_board_on_routeros_6_is_hardware_too_small():
    d = _classify(5, "timeout", facts={"board": "hAP lite", "version": "6.48.7"})
    assert d["hints"] == ["Hardware too small (hAP lite, 32 MB RAM)"]
    assert d["action"] == "Hardware too small (32 MB) — replace with a bigger board"
    # smips architecture alone is enough.
    assert _classify(5, "timeout", facts={"arch": "smips", "version": "6.49"})["action"] == (
        rd.ACTION_SMALL_BOARD)
    # A big board gets the generic advice.
    d = _classify(5, "timeout", facts={"board": "hEX S", "version": "7.20"})
    assert d["hints"] == [] and d["action"] == rd.ACTION_REBOOT


def test_a_few_script_jobs_are_not_piling_up():
    d = _classify(5, "timeout", readings={"resource": {}, "script_jobs": 4, "tunnels": []})
    assert d["hints"] == [] and d["action"] == rd.ACTION_REBOOT


# ---------------------------------------------------------------------------
# congested line
# ---------------------------------------------------------------------------

def test_slow_connects_are_a_congested_line_not_an_overloaded_router():
    # Lux #2 (210): connects get through, slowly.
    slow = [1.9, 2.4, 0.8, 3.6, 2.1]
    d = _classify(5, "timeout", tunnel="l2tp", tcp_times=slow)
    assert d["ailment"] == "congested_line" and d["title"] == "Internet line congested"
    assert d["facts"][-1] == "connects took 0.8–3.6 s (median 2.1 s)"
    assert "SSTP won't fix this" in d["action"] and d["sstp_candidate"] is False
    # A login that got through does not make a congested line healthy.
    assert _classify(5, "ok", tcp_times=slow)["ailment"] == "congested_line"


def test_erratic_connects_are_congested_even_with_a_fast_median():
    assert _classify(5, "ok", tcp_times=[0.2, 0.3, 2.6, 0.2, 0.3])["ailment"] == "congested_line"


def test_three_slow_connects_are_congested_three_fast_ones_are_lossy():
    assert _classify(3, "ok", tcp_times=[2.0, None, 2.2, None, 1.8])["ailment"] == "congested_line"
    assert _classify(3, "ok", tcp_times=[0.2, None, 0.2, None, 0.3])["ailment"] == "lossy_line"


def test_fast_clean_line_with_login_timeout_stays_overloaded():
    assert _classify(5, "timeout", tcp_times=FAST)["ailment"] == "overloaded"


def test_line_is_congested_needs_three_samples():
    assert rd.line_is_congested([3.0, None, None, 2.0, None]) is None
    assert rd.line_is_congested(None) is None


# ---------------------------------------------------------------------------
# ISP blocks the Hetzner server
# ---------------------------------------------------------------------------

def _wg(name, endpoint, handshake, disabled="false"):
    return {"interface": name, "endpoint-address": endpoint, "last-handshake": handshake,
            "disabled": disabled}


def test_hetzner_tunnel_dead_while_aws_alive_is_isp_blocking_our_server():
    # HOME951 (351): wg-hz 9h47m stale, wg-aws fresh.
    tunnels = rd.summarize_tunnels([_wg("wg-hz", "91.98.238.12", "9h47m12s"),
                                    _wg("wg-aws", "54.91.202.229", "40s")], [], [])
    d = _classify(5, "ok", readings={"resource": {}, "script_jobs": 1, "tunnels": tunnels})
    assert d["ailment"] == "isp_blocks_server" and d["title"] == "ISP blocks our server"
    assert d["facts"][-2:] == ["wg-hz handshake 9h47m ago", "wg-aws handshake 40s ago"]
    assert d["action"].startswith("The site's ISP drops our Hetzner server's replies")
    assert d["hints"] == ["Reachable only through the AWS fallback"]
    # Never handshaked at all reads "never".
    never = rd.summarize_tunnels([_wg("wg-hz", "91.98.238.12", ""),
                                  _wg("wg-aws", "54.91.202.229", "1m5s")], [], [])
    assert "wg-hz handshake never" in _classify(5, "ok", readings={"tunnels": never})["facts"]


def test_isp_block_needs_every_hetzner_tunnel_dead_and_an_aws_one_alive():
    def diag(peers):
        return _classify(5, "ok", readings={"tunnels": rd.summarize_tunnels(peers, [], [])})["ailment"]

    hz_ok, aws_ok = _wg("wg-hz", "91.98.238.12", "1m"), _wg("wg-aws", "54.91.202.229", "30s")
    assert diag([hz_ok, aws_ok]) == "healthy_now"
    assert diag([_wg("wg-hz", "91.98.238.12", "2h"), _wg("wg-aws", "54.91.202.229", "3h")]) == "healthy_now"
    assert diag([aws_ok]) == "healthy_now"  # no Hetzner tunnel at all
    # A disabled Hetzner peer is a deliberate choice, not a block.
    assert diag([_wg("wg-hz", "91.98.238.12", "", disabled="true"), aws_ok]) == "healthy_now"
    # Handshake 5-15 min old: not sure it is dead, no verdict.
    assert diag([_wg("wg-hz", "91.98.238.12", "8m"), aws_ok]) == "healthy_now"


def test_isp_block_on_a_routeros_6_l2tp_router():
    # LEADERS APLITE (426): L2TP to Hetzner not running, L2TP to AWS running.
    tunnels = rd.summarize_tunnels([], [
        {"name": "l2tp-hz", "connect-to": "91.98.238.12", "running": "false", "disabled": "false"},
        {"name": "l2tp-out1", "connect-to": "54.91.202.229", "running": "true", "disabled": "false"},
    ], [])
    d = _classify(5, "ok", tunnel="l2tp", readings={"tunnels": tunnels})
    assert d["ailment"] == "isp_blocks_server"
    assert d["facts"][-2:] == ["l2tp-hz not running", "l2tp-out1 running"]


def test_isp_block_is_only_judged_from_a_successful_login():
    tunnels = rd.summarize_tunnels([_wg("wg-hz", "91.98.238.12", ""),
                                    _wg("wg-aws", "54.91.202.229", "40s")], [], [])
    assert _classify(2, "timeout", readings={"tunnels": tunnels})["ailment"] == "lossy_line"


def test_overload_beats_the_isp_block():
    tunnels = rd.summarize_tunnels([_wg("wg-hz", "91.98.238.12", ""),
                                    _wg("wg-aws", "54.91.202.229", "40s")], [], [])
    assert _classify(5, "ok", health=_health(2, cpu=99),
                     readings={"tunnels": tunnels})["ailment"] == "overloaded"


def test_tunnel_side_by_endpoint_then_name():
    assert rd.tunnel_side("l2tp-aws2", "91.98.238.12") == "hetzner"  # name lies, endpoint wins
    assert rd.tunnel_side("wg-aws", "54.91.202.229") == "aws"
    assert rd.tunnel_side("wg-hz", None) == "hetzner"
    assert rd.tunnel_side("sstp-hetzner", "") == "hetzner"
    assert rd.tunnel_side("wg-aws2", "") == "aws"
    assert rd.tunnel_side("wireguard1", "1.2.3.4") is None


@pytest.mark.parametrize("text,seconds", [
    ("40s", 40), ("4m36s", 276), ("9h47m12s", 35232), ("1d2h", 93600), ("1w", 604800),
    ("1s500ms", 1.5), ("00:04:36", 276), ("1d 02:00:00", 93600), ("", None), (None, None),
    ("garbage", None),
])
def test_parse_ros_duration(text, seconds):
    assert rd.parse_ros_duration(text) == seconds


# ---------------------------------------------------------------------------
# replaced router
# ---------------------------------------------------------------------------

def _payments_every(start, end, hours):
    out, t = [], start
    while t < end:
        out.append(t)
        t += timedelta(hours=hours)
    return out


def test_sibling_taking_over_the_payments_is_a_replacement():
    # Powernet #8 (182): ~40/day until 09-24 05:06, then silent; Powernet #3 (483)
    # took ~5/day before and ~45/day since.
    now = datetime(2026, 9, 26, 12, 0)
    cut = datetime(2026, 9, 24, 5, 6)
    payments = {
        182: _payments_every(now - timedelta(days=7), cut, 0.6),
        483: (_payments_every(now - timedelta(days=7), cut, 5)
              + _payments_every(cut, now, 0.55)),
        300: _payments_every(now - timedelta(days=7), now, 2),  # a steady sibling
    }
    owner = {182: "Powernet #8", 483: "Powernet #3", 300: "Powernet #1"}
    r = rd.detect_replacement(182, owner, payments, now)
    assert r["router_id"] == 483 and r["router_name"] == "Powernet #3"
    assert r["last_payment_at"] == max(payments[182]) and r["taken"] >= 5


def test_no_replacement_when_the_router_is_still_paid_into_or_nobody_took_over():
    now = datetime(2026, 9, 26, 12, 0)
    owner = {1: "A", 2: "B"}
    busy = _payments_every(now - timedelta(days=7), now - timedelta(hours=30), 1)
    steady = _payments_every(now - timedelta(days=7), now, 2)
    # Silent for less than 24 h.
    recent = _payments_every(now - timedelta(days=3), now - timedelta(hours=10), 1)
    assert rd.detect_replacement(1, owner, {1: recent, 2: steady}, now) is None
    # Sibling kept its usual rate: the site just went dark.
    assert rd.detect_replacement(1, owner, {1: busy, 2: steady}, now) is None
    # Router was hardly used.
    fresh = _payments_every(now - timedelta(days=1), now, 1)
    assert rd.detect_replacement(1, owner, {1: busy[:3], 2: fresh}, now) is None
    # No sibling at all.
    assert rd.detect_replacement(1, {1: "A"}, {1: busy}, now) is None


def test_replaced_router_label():
    rep = {"router_id": 483, "router_name": "Powernet #3", "taken": 90,
           "last_payment_at": datetime(2026, 9, 24, 5, 6)}
    d = _classify(0, "skipped", tunnel="l2tp", replacement=rep)
    assert d["ailment"] == "replaced_router" and d["title"] == "Probably replaced"
    assert d["facts"] == ["TCP 0/5", "no push", "no payments since 24 Sep 05:06 UTC",
                          "Powernet #3 took 90 payments since"]
    assert d["hints"] == ["Owner probably replaced this router with Powernet #3"]
    assert d["action"] == "Owner probably replaced this router — confirm and retire it"
    # A router that answers cleanly is not called replaced.
    assert _classify(5, "ok", replacement=rep, tcp_times=FAST)["ailment"] == "healthy_now"


# ---------------------------------------------------------------------------
# site dark vs tunnel down
# ---------------------------------------------------------------------------

def test_dead_udp_tunnel_while_the_push_still_arrives_is_udp_blocked():
    d = _classify(0, "skipped", tunnel="wireguard", health=_health(2))
    assert d["ailment"] == "udp_blocked" and d["title"] == "Tunnel blocked, site online"
    assert d["evidence"] == "TCP 0/5, push 2 min ago"
    assert d["action"] == "Move management to SSTP" and d["sstp_candidate"] is True
    assert _classify(0, "skipped", tunnel="l2tp", health=_health(2))["ailment"] == "udp_blocked"


def test_push_alive_but_sstp_tunnel_dead_is_a_tunnel_problem_not_udp():
    d = _classify(0, "skipped", tunnel="sstp", health=_health(2))
    assert d["ailment"] == "tunnel_down" and d["sstp_candidate"] is False
    assert d["title"] == "Tunnel down, site online"


def test_router_still_checking_in_is_tunnel_down_not_dark():
    life = {"checkin_at": NOW - timedelta(minutes=1)}
    d = _classify(0, "skipped", tunnel="sstp", life=life)
    assert d["ailment"] == "tunnel_down"
    assert d["facts"] == ["TCP 0/5", "no push", "check-in 1 min ago"]
    assert d["hints"] == ["Check-in still delivering"]
    assert d["action"] == ("Management tunnel is down; payments still deliver via check-in — "
                           "fix the tunnel")
    # On a UDP tunnel it is udp_blocked, still noting the check-in.
    d = _classify(0, "skipped", tunnel="wireguard", life=life)
    assert d["ailment"] == "udp_blocked" and d["hints"] == ["Check-in still delivering"]


def test_payments_or_command_agent_also_show_the_site_is_online():
    d = _classify(0, "skipped", tunnel="sstp", life={"last_payment_at": NOW - timedelta(minutes=20)})
    assert d["ailment"] == "tunnel_down" and d["facts"][-1] == "payment 20 min ago"
    assert d["action"] == rd.ACTION_TUNNEL_DOWN
    d = _classify(0, "skipped", tunnel="sstp", life={"agent_at": NOW - timedelta(minutes=2)})
    assert d["ailment"] == "tunnel_down" and d["facts"][-1] == "command agent 2 min ago"


def test_nothing_through_and_no_sign_of_life_is_a_dark_site():
    for health in (None, _health(6), _health(2, source="snmp")):
        d = _classify(0, "skipped", health=health)
        assert d["ailment"] == "offline" and d["title"] == "Site dark"
        assert d["action"] == "Site power or internet is down — contact reseller"
        assert d["sstp_candidate"] is False
    assert _classify(0, "skipped")["evidence"] == "TCP 0/5, no push, no check-in, no payments in 7 days"
    stale = {"checkin_at": NOW - timedelta(minutes=30), "agent_at": NOW - timedelta(hours=2),
             "last_payment_at": NOW - timedelta(hours=3)}
    assert _classify(0, "skipped", health=_health(180), life=stale)["evidence"] == (
        "TCP 0/5, last push 3h ago, no check-in, last payment 3h ago")


# ---------------------------------------------------------------------------
# the rest
# ---------------------------------------------------------------------------

def test_some_tcp_connects_is_a_lossy_line_and_sstp_is_the_candidate():
    for tcp_ok in (1, 2, 3):
        d = _classify(tcp_ok, "timeout", tunnel="l2tp")
        assert d["ailment"] == "lossy_line" and d["title"] == "Line dropping packets"
        assert d["action"] == "Move management to SSTP" and d["sstp_candidate"] is True
    # A single login that got through does not make a lossy line healthy.
    assert _classify(3, "ok")["ailment"] == "lossy_line"
    assert _classify(2, "timeout", health=_health(1))["evidence"] == (
        "TCP 2/5, API login timed out, push 1 min ago")


def test_lossy_line_already_on_sstp_points_at_the_uplink():
    d = _classify(2, "timeout", tunnel="sstp")
    assert d["ailment"] == "lossy_line"
    assert d["action"] == "Site line losing packets — reseller should check the uplink"
    assert d["sstp_candidate"] is False


def test_login_ok_on_a_clean_line_is_healthy_now():
    d = _classify(5, "ok", tcp_times=FAST)
    assert d["ailment"] == "healthy_now" and d["title"] == "Reachable now"
    assert d["action"] == "Reachable again — waiting payments will retry"
    assert d["evidence"] == "TCP 5/5, API login ok, no push"


def test_clean_line_with_rejected_or_skipped_login():
    assert _classify(5, "rejected")["ailment"] == "login_rejected"
    assert _classify(5, "skipped")["ailment"] == "inconclusive"
    assert _classify(4, "error")["ailment"] == "inconclusive"


def test_every_ailment_has_a_title():
    assert set(rd.TITLES) == set(rd.AILMENTS)


def test_reused_login_timeout_says_how_old_it_is():
    d = _classify(5, "timeout", login_age=timedelta(minutes=10), tcp_times=FAST)
    assert d["ailment"] == "overloaded"
    assert d["facts"][1] == "API login timed out 10 min ago (not retried)"


# ---------------------------------------------------------------------------
# skip-login rule
# ---------------------------------------------------------------------------

def test_login_is_spared_for_a_router_already_reporting_overload():
    assert rd.login_skip_reason(1, _health(3, cpu=95), NOW) == "busy"
    assert rd.login_skip_reason(1, _health(3, cpu=30, free=4 * MB), NOW) == "busy"
    assert rd.login_skip_reason(1, _health(30, cpu=100), NOW) is None  # stale reading
    assert rd.login_skip_reason(1, _health(3, cpu=50), NOW) is None
    assert rd.login_skip_reason(1, None, NOW) is None


def test_login_is_spared_for_fifteen_minutes_after_a_timeout():
    rd._LOGIN_MEMO[7] = {"login": "timeout", "at": NOW - timedelta(minutes=5)}
    assert rd.login_skip_reason(7, None, NOW) == "recent_timeout"
    assert rd.login_skip_reason(7, None, NOW + timedelta(minutes=10)) is None


def test_probe_router_does_not_log_in_when_told_to_spare_the_router(monkeypatch):
    monkeypatch.setattr(rd, "tcp_probe_timed", lambda host, port: [0.1] * 5)
    monkeypatch.setattr(rd, "login_probe", lambda *a, **k: pytest.fail("login must not run"))
    target = {"ip": "10.0.0.5", "port": 8728, "username": "u", "password": "p", "skip_login": "busy"}
    assert rd.probe_router(target) == {"tcp_ok": 5, "tcp_times": [0.1] * 5, "login": "skipped",
                                       "readings": None}


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

class _Conn:
    def close(self):
        pass


def test_tcp_probe_counts_successful_connects_and_waits_between_them():
    outcomes = iter([True, False, True, False, True])
    sleeps = []

    def connect(addr, timeout):
        assert addr == ("10.0.0.5", 8728) and timeout == 4.0
        if next(outcomes):
            return _Conn()
        raise TimeoutError("timed out")

    assert rd.tcp_probe("10.0.0.5", 8728, connect=connect, sleep=sleeps.append) == 3
    assert sleeps == [1.0] * 4


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def test_tcp_probe_timed_records_each_connect_time():
    clock = _Clock()
    durations = iter([0.2, None, 2.5])

    def connect(addr, timeout):
        d = next(durations)
        if d is None:
            raise ConnectionRefusedError()
        clock.advance(d)
        return _Conn()

    assert rd.tcp_probe_timed("h", 1, attempts=3, connect=connect, sleep=lambda s: None,
                              clock=clock) == [0.2, None, 2.5]


class _FakeAPI:
    def __init__(self, ok=False, error=None, took=0.0, clock=None):
        self.ok, self.last_connect_error, self.took, self.clock = ok, error, took, clock
        self.disconnected = False

    def connect(self):
        self.clock.advance(self.took)
        return self.ok

    def disconnect(self):
        self.disconnected = True


@pytest.mark.parametrize("ok,error,took,expected", [
    (True, None, 0.3, "ok"),
    (False, "Connection to 10.0.0.5:8728 timed out after 5s (router unreachable)", 5.0, "timeout"),
    (False, "API login rejected by 10.0.0.5:8728 (check the router's API username/password)", 10.0, "timeout"),
    (False, "API login rejected by 10.0.0.5:8728: invalid user name or password (6)", 0.2, "rejected"),
    (False, "API login rejected by 10.0.0.5:8728 (check the router's API username/password)", 0.2, "error"),
    (False, "Circuit breaker open for 10.0.0.5:8728 after repeated failures", 0.0, "skipped"),
])
def test_login_probe_tells_timeout_from_rejection(ok, error, took, expected):
    clock = _Clock()
    api = _FakeAPI(ok, error, took, clock)
    assert rd.login_probe("10.0.0.5", "u", "p", 8728, api_factory=lambda: api, clock=clock) == expected
    assert api.disconnected


def test_login_probe_runs_the_reads_only_when_logged_in_and_survives_their_errors():
    clock = _Clock()
    seen = []
    api = _FakeAPI(True, None, 0.1, clock)

    def reads(a):
        seen.append(a)
        raise RuntimeError("router dropped the session")

    assert rd.login_probe("h", "u", "p", 1, api_factory=lambda: api, clock=clock,
                          on_login=reads) == "ok"
    assert seen == [api] and api.disconnected
    rd.login_probe("h", "u", "p", 1, api_factory=lambda: _FakeAPI(False, "timed out", 5, clock),
                   clock=clock, on_login=lambda a: pytest.fail("not logged in"))


def test_login_probe_uses_the_background_lane(monkeypatch):
    seen = {}

    class API(_FakeAPI):
        def __init__(self, host, user, pw, port, timeout, connect_timeout, lane):
            seen.update(timeout=timeout, connect_timeout=connect_timeout, lane=lane)
            super().__init__(True, None, 0.0, _Clock())

    monkeypatch.setattr("app.services.mikrotik_api.MikroTikAPI", API)
    assert rd.login_probe("10.0.0.5", "u", "p", 8728) == "ok"
    assert seen == {"timeout": 10, "connect_timeout": 5, "lane": "background"}


def test_login_is_not_attempted_when_no_tcp_connect_got_through(monkeypatch):
    monkeypatch.setattr(rd, "tcp_probe_timed", lambda host, port: [None] * 5)
    monkeypatch.setattr(rd, "login_probe", lambda *a, **k: pytest.fail("login must not run"))
    target = {"ip": "10.0.0.5", "port": 8728, "username": "u", "password": "p"}
    assert rd.probe_router(target) == {"tcp_ok": 0, "tcp_times": [None] * 5, "login": "skipped",
                                       "readings": None}


class _PrintAPI:
    """Answers the read-only prints the diagnosis makes while logged in."""

    def __init__(self, tables, clock=None, cost=0.0):
        self.tables, self.calls, self.clock, self.cost = tables, [], clock, cost

    def send_command_optimized(self, cmd, proplist=None, query=None):
        self.calls.append(cmd)
        if self.clock:
            self.clock.advance(self.cost)
        if cmd not in self.tables:
            return {"error": "no such command"}
        return {"success": True, "data": self.tables[cmd]}


def test_read_router_state_on_a_routeros_7_router():
    api = _PrintAPI({
        "/system/resource/print": [{"cpu-load": "97", "free-memory": "6291456",
                                    "total-memory": "33554432", "board-name": "hAP lite",
                                    "architecture-name": "smips", "version": "7.24.1 (stable)"}],
        "/system/script/job/print": [{".id": f"*{i}"} for i in range(6)],
        "/interface/wireguard/peers/print": [_wg("wg-hz", "91.98.238.12", ""),
                                             _wg("wg-aws", "54.91.202.229", "12s")],
    })
    state = rd.read_router_state(api)
    assert state["resource"] == {"cpu": 97, "free_memory": 6291456, "total_memory": 33554432,
                                 "board": "hAP lite", "arch": "smips", "version": "7.24.1 (stable)"}
    assert state["script_jobs"] == 6
    assert [(t["name"], t["side"], t["state"]) for t in state["tunnels"]] == [
        ("wg-hz", "hetzner", "dead"), ("wg-aws", "aws", "alive")]
    # WireGuard answered, so the dial-out clients are not read.
    assert "/interface/l2tp-client/print" not in api.calls
    # Only prints: nothing that changes the router.
    assert all(c.endswith("/print") for c in api.calls)


def test_read_router_state_on_routeros_6_reads_the_dial_out_clients():
    api = _PrintAPI({
        "/system/resource/print": [{"cpu-load": "20", "board-name": "RB951Ui-2HnD",
                                    "version": "6.49.17"}],
        "/system/script/job/print": [],
        "/interface/l2tp-client/print": [{"name": "l2tp-hz", "connect-to": "91.98.238.12",
                                          "running": "false", "disabled": "false"}],
        "/interface/sstp-client/print": [{"name": "sstp-hetzner", "connect-to": "91.98.238.12",
                                          "running": "true", "disabled": "false"}],
    })
    state = rd.read_router_state(api)
    assert state["script_jobs"] == 0
    assert [(t["kind"], t["state"]) for t in state["tunnels"]] == [("l2tp", "dead"), ("sstp", "alive")]


def test_read_router_state_stops_when_the_router_is_slow():
    clock = _Clock()
    api = _PrintAPI({"/system/resource/print": [{"cpu-load": "50"}],
                     "/system/script/job/print": []}, clock=clock, cost=5.0)
    state = rd.read_router_state(api, clock=clock)
    assert api.calls == ["/system/resource/print", "/system/script/job/print"]
    assert state["script_jobs"] is None  # finished past the budget: not trusted
    assert state["resource"]["cpu"] == 50


# ---------------------------------------------------------------------------
# job
# ---------------------------------------------------------------------------

def _seed_section(rows, at=NOW):
    pr._CACHE.update(at=at, value={"routers": rows, "counts": {}})


def _row(rid, state="attention"):
    return {"router_id": rid, "state": state, "reason": "x", "waiting": 1}


@pytest.fixture
def pool_idle(monkeypatch):
    monkeypatch.setattr(rd, "db_pool_snapshot",
                        lambda: {"checked_out_percent": 10, "pressure": {"level": "ok"}})


@pytest.mark.asyncio
async def test_cycle_probes_attention_routers_with_no_db_session_open(db, monkeypatch, pool_idle):
    reseller = await make_reseller(db)
    overloaded = await make_router(db, reseller, ip_address="10.0.0.21", port=8728)
    blocked = await make_router(db, reseller, ip_address="10.0.0.22", port=8728)
    recovering = await make_router(db, reseller, ip_address="10.0.0.23", port=8728)
    db.add(RouterHealth(router_id=overloaded.id, source="push", cpu_load=100,
                        sampled_at=NOW - timedelta(minutes=3)))
    db.add(RouterHealth(router_id=blocked.id, source="push", cpu_load=12,
                        sampled_at=NOW - timedelta(minutes=1)))
    await db.commit()
    _seed_section([_row(overloaded.id), _row(blocked.id), _row(recovering.id, "recovering")],
                  at=NOW - timedelta(minutes=2))

    # Count sessions the job has open while it probes: must be zero.
    real_factory = database.async_session
    open_sessions = {"n": 0}

    @asynccontextmanager
    async def tracking_session():
        open_sessions["n"] += 1
        try:
            async with real_factory() as s:
                yield s
        finally:
            open_sessions["n"] -= 1

    monkeypatch.setattr(database, "async_session", tracking_session)
    probed = {}

    def probe(target):
        assert open_sessions["n"] == 0, "DB session held across router I/O"
        probed[target["id"]] = target["skip_login"]
        return {overloaded.id: {"tcp_ok": 5, "login": "skipped"},
                blocked.id: {"tcp_ok": 0, "login": "skipped"}}[target["id"]]

    summary = await rd.run_diagnosis_cycle(NOW, probe=probe)
    # The recovering row is not probed; the router at CPU 100% is spared the login.
    assert probed == {overloaded.id: "busy", blocked.id: None}
    assert summary["probed"] == 2 and summary["logins_spared"] == 1
    assert summary["ailments"] == {"overloaded": 1, "udp_blocked": 1}

    d = rd.diagnosis_for(overloaded.id, NOW)
    assert d["ailment"] == "overloaded" and d["tcp_ok"] == 5 and d["login"] == "spared"
    assert d["evidence"] == "TCP 5/5, API login not tried (router busy), CPU 100% (push 3 min ago)"
    assert d["probed_at"].endswith("Z") and "_probed_at" not in d
    assert rd.diagnosis_for(blocked.id, NOW)["sstp_candidate"] is True

    # Attached to the section rows (in memory, rows not mutated); absent -> None.
    rows = rd.attach_diagnoses([_row(overloaded.id), _row(recovering.id)], NOW)
    assert rows[0]["diagnosis"]["ailment"] == "overloaded"
    assert rows[1]["diagnosis"] is None
    # Old results expire rather than show as current.
    assert rd.diagnosis_for(overloaded.id, NOW + timedelta(minutes=30)) is None


@pytest.mark.asyncio
async def test_a_timed_out_login_is_reused_not_retried_for_fifteen_minutes(db, pool_idle):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, ip_address="10.0.0.41", port=8728)
    logins = []

    def probe(target):
        if not target["skip_login"]:
            logins.append(1)
            return {"tcp_ok": 5, "tcp_times": FAST, "login": "timeout"}
        return {"tcp_ok": 5, "tcp_times": FAST, "login": "skipped"}

    for minutes in (0, 5, 10):
        now = NOW + timedelta(minutes=minutes)
        _seed_section([_row(router.id)], at=now)
        await rd.run_diagnosis_cycle(now, probe=probe)
    assert len(logins) == 1
    d = rd.diagnosis_for(router.id, NOW + timedelta(minutes=10))
    assert d["ailment"] == "overloaded" and d["login"] == "timeout"
    assert "API login timed out 10 min ago (not retried)" in d["facts"]

    # After the backoff the router gets one fresh try.
    later = NOW + timedelta(minutes=16)
    _seed_section([_row(router.id)], at=later)
    await rd.run_diagnosis_cycle(later, probe=probe)
    assert len(logins) == 2


@pytest.mark.asyncio
async def test_board_learnt_at_a_login_is_kept_for_later_rounds(db, pool_idle):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, ip_address="10.0.0.42", port=8728)
    readings = {"resource": {"cpu": 60, "free_memory": 12 * MB, "board": "hAP lite",
                             "arch": "smips", "version": "7.24.1"},
                "script_jobs": 1, "tunnels": []}
    _seed_section([_row(router.id)], at=NOW)
    await rd.run_diagnosis_cycle(NOW, probe=lambda t: {"tcp_ok": 5, "tcp_times": FAST,
                                                       "login": "ok", "readings": readings})
    assert rd.diagnosis_for(router.id, NOW)["ailment"] == "healthy_now"

    later = NOW + timedelta(minutes=5)
    _seed_section([_row(router.id)], at=later)
    await rd.run_diagnosis_cycle(later, probe=lambda t: {"tcp_ok": 5, "tcp_times": FAST,
                                                         "login": "timeout"})
    d = rd.diagnosis_for(router.id, later)
    assert d["ailment"] == "overloaded" and d["action"] == rd.ACTION_ROS7_SMALL


@pytest.mark.asyncio
async def test_cycle_uses_check_in_and_payments_to_tell_dark_from_tunnel_down(db, monkeypatch, pool_idle):
    from app.db.models import CustomerStatus, ProvisioningState
    from tests.factories import make_customer, make_plan
    from tests.test_ops_health import _attempt

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    checking_in = await make_router(db, reseller, ip_address="10.0.0.51", management_tunnel="sstp")
    dark = await make_router(db, reseller, ip_address="10.0.0.52", management_tunnel="sstp")
    paying = await make_router(db, reseller, ip_address="10.0.0.53", management_tunnel="sstp")
    customer = await make_customer(db, reseller, plan, paying, status=CustomerStatus.ACTIVE)
    db.add(_attempt(customer, paying, state=ProvisioningState.RETRY_PENDING,
                    created=NOW - timedelta(minutes=12)))
    await db.commit()
    monkeypatch.setattr(rd, "last_checkin_at",
                        lambda rid: NOW - timedelta(minutes=1) if rid == checking_in.id else None)
    _seed_section([_row(checking_in.id), _row(dark.id), _row(paying.id)])

    await rd.run_diagnosis_cycle(NOW, probe=lambda t: {"tcp_ok": 0, "tcp_times": [None] * 5,
                                                       "login": "skipped"})
    assert rd.diagnosis_for(checking_in.id, NOW)["ailment"] == "tunnel_down"
    assert rd.diagnosis_for(checking_in.id, NOW)["hints"] == ["Check-in still delivering"]
    assert rd.diagnosis_for(dark.id, NOW)["ailment"] == "offline"
    assert rd.diagnosis_for(paying.id, NOW)["ailment"] == "tunnel_down"
    assert "payment 12 min ago" in rd.diagnosis_for(paying.id, NOW)["facts"]


def test_last_checkin_at_reads_the_pilot_state():
    from app.services import checkin_delivery

    checkin_delivery.reset_state()
    assert rd.last_checkin_at(99) is None
    checkin_delivery._stats[99] = checkin_delivery.RouterCheckinStats(last_checkin_at=NOW)
    try:
        assert rd.last_checkin_at(99) == NOW
    finally:
        checkin_delivery.reset_state()


@pytest.mark.asyncio
async def test_cycle_names_the_router_that_took_over(db, pool_idle):
    from app.db.models import CustomerStatus, ProvisioningState
    from tests.factories import make_customer, make_plan
    from tests.test_ops_health import _attempt

    reseller = await make_reseller(db)
    other = await make_reseller(db)
    plan = await make_plan(db, reseller)
    old = await make_router(db, reseller, name="Powernet #8", ip_address="10.0.100.8")
    new = await make_router(db, reseller, name="Powernet #3", ip_address="10.0.100.3")
    stranger = await make_router(db, other, name="Elsewhere", ip_address="10.0.100.9")
    customer = await make_customer(db, reseller, plan, old, status=CustomerStatus.ACTIVE)
    cut = NOW - timedelta(hours=40)
    done = ProvisioningState.ROUTER_UPDATED
    for h in range(8):
        db.add(_attempt(customer, old, state=done, created=cut - timedelta(hours=3 * h)))
    for h in range(12):
        db.add(_attempt(customer, new, state=done, created=cut + timedelta(hours=2 * h + 1)))
        db.add(_attempt(customer, stranger, state=done, created=cut + timedelta(hours=2 * h + 1)))
    await db.commit()
    _seed_section([_row(old.id)])

    await rd.run_diagnosis_cycle(NOW, probe=lambda t: {"tcp_ok": 0, "login": "skipped"})
    d = rd.diagnosis_for(old.id, NOW)
    assert d["ailment"] == "replaced_router"
    assert d["hints"] == ["Owner probably replaced this router with Powernet #3"]


@pytest.mark.asyncio
async def test_cycle_skips_when_the_db_pool_is_busy(monkeypatch):
    monkeypatch.setattr(rd, "db_pool_snapshot",
                        lambda: {"checked_out_percent": 75, "pressure": {"level": "ok"}})
    _seed_section([_row(1)])
    out = await rd.run_diagnosis_cycle(NOW, probe=lambda t: pytest.fail("must not probe"))
    assert out == {"skipped": "db_pool_busy"}

    monkeypatch.setattr(rd, "db_pool_snapshot",
                        lambda: {"checked_out_percent": 5, "pressure": {"level": "critical"}})
    assert (await rd.run_diagnosis_cycle(NOW))["skipped"] == "db_pool_busy"


@pytest.mark.asyncio
async def test_cycle_does_nothing_without_a_fresh_section(pool_idle):
    assert await rd.run_diagnosis_cycle(NOW) == {"probed": 0}
    _seed_section([_row(1)], at=NOW - timedelta(minutes=20))
    assert await rd.run_diagnosis_cycle(NOW, probe=lambda t: pytest.fail("stale")) == {"probed": 0}


def test_at_most_fifteen_attention_routers_are_probed():
    _seed_section([_row(i) for i in range(1, 30)])
    assert rd.attention_router_ids(NOW) == list(range(1, 16))


@pytest.mark.asyncio
async def test_problem_routers_section_carries_diagnosis_or_none(db, pool_idle):
    from app.db.models import CustomerStatus, ProvisioningState
    from tests.factories import make_customer, make_plan
    from tests.test_ops_health import _attempt

    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    bad = await make_router(db, reseller, ip_address="10.0.0.31", last_online_at=now)
    customer = await make_customer(db, reseller, plan, bad, status=CustomerStatus.ACTIVE)
    for h in (1, 2, 3):
        db.add(_attempt(customer, bad, state=ProvisioningState.FAILED, created=now - timedelta(hours=h),
                        error="Failed to connect"))
    await db.commit()

    section = await pr.build_problem_routers_section(now)
    assert section["routers"][0]["diagnosis"] is None

    await rd.run_diagnosis_cycle(now, probe=lambda t: {"tcp_ok": 2, "login": "timeout"})
    again = await pr.build_problem_routers_section(now + timedelta(minutes=1))
    assert again["cached"] is True
    diag = again["routers"][0]["diagnosis"]
    assert diag["ailment"] == "lossy_line" and diag["title"] == "Line dropping packets"
    assert diag["facts"] and diag["action"]
    # The cached section itself is left untouched (the job reads it).
    assert "diagnosis" not in pr.latest_section()[0]["routers"][0]

    # The admin's on-demand window view carries it too.
    window = await pr.build_problem_routers_window(now + timedelta(minutes=1), 6)
    assert window["routers"][0]["diagnosis"]["ailment"] == "lossy_line"
