"""What is ailing a problem router (app/services/router_diagnosis.py).

Pinned on the 2026-09-25 picture: overloaded routers (Pamoja #3, lee net #1)
answer every TCP connect but time out the API login, one at CPU 100%; lossy
lines (RONGAI, HOME951, QUBIT #2) connect only sometimes; a WireGuard router
whose HTTPS push still arrives while the tunnel is dead is behind a UDP block.
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


def _health(minutes_ago=3, cpu=None, source="push"):
    return {"source": source, "sampled_at": NOW - timedelta(minutes=minutes_ago), "cpu_load": cpu}


def _classify(tcp_ok, login, tunnel="wireguard", health=None):
    return rd.classify(tcp_ok, 5, login, tunnel, health, NOW)


# ---------------------------------------------------------------------------
# classifier
# ---------------------------------------------------------------------------

def test_clean_line_but_login_times_out_is_an_overloaded_router():
    d = _classify(5, "timeout", health=_health(3, cpu=100))
    assert d == {
        "ailment": "overloaded",
        "evidence": "TCP 5/5, API login timed out, CPU 100% (push 3 min ago)",
        "action": "Reboot the router; if it recurs, upgrade hardware or RouterOS",
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


def test_some_tcp_connects_is_a_lossy_line_and_sstp_is_the_candidate():
    for tcp_ok in (1, 2, 3):
        d = _classify(tcp_ok, "timeout", tunnel="l2tp")
        assert d["ailment"] == "lossy_line"
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


def test_dead_udp_tunnel_while_the_push_still_arrives_is_udp_blocked():
    d = _classify(0, "skipped", tunnel="wireguard", health=_health(2))
    assert d == {
        "ailment": "udp_blocked",
        "evidence": "TCP 0/5, push 2 min ago",
        "action": "Move management to SSTP",
        "sstp_candidate": True,
    }
    assert _classify(0, "skipped", tunnel="l2tp", health=_health(2))["ailment"] == "udp_blocked"


def test_push_alive_but_sstp_tunnel_dead_is_a_tunnel_problem_not_udp():
    d = _classify(0, "skipped", tunnel="sstp", health=_health(2))
    assert d["ailment"] == "tunnel_down" and d["sstp_candidate"] is False


def test_nothing_through_and_no_recent_push_is_offline():
    for health in (None, _health(6), _health(2, source="snmp")):
        d = _classify(0, "skipped", health=health)
        assert d["ailment"] == "offline"
        assert d["action"] == "Site power or internet is down — contact reseller"
        assert d["sstp_candidate"] is False
    assert _classify(0, "skipped")["evidence"] == "TCP 0/5, no push"
    assert _classify(0, "skipped", health=_health(180))["evidence"] == "TCP 0/5, last push 3h ago"


def test_login_ok_on_a_clean_line_is_healthy_now():
    d = _classify(5, "ok")
    assert d["ailment"] == "healthy_now"
    assert d["action"] == "Reachable again — waiting payments will retry"
    assert d["evidence"] == "TCP 5/5, API login ok, no push"


def test_clean_line_with_rejected_or_skipped_login():
    assert _classify(5, "rejected")["ailment"] == "login_rejected"
    assert _classify(5, "skipped")["ailment"] == "inconclusive"
    assert _classify(4, "error")["ailment"] == "inconclusive"


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
        assert addr == ("10.0.0.5", 8728) and timeout == 3.0
        if next(outcomes):
            return _Conn()
        raise TimeoutError("timed out")

    assert rd.tcp_probe("10.0.0.5", 8728, connect=connect, sleep=sleeps.append) == 3
    assert sleeps == [1.0] * 4


class _FakeAPI:
    def __init__(self, ok=False, error=None, took=0.0, clock=None):
        self.ok, self.last_connect_error, self.took, self.clock = ok, error, took, clock
        self.disconnected = False

    def connect(self):
        self.clock.advance(self.took)
        return self.ok

    def disconnect(self):
        self.disconnected = True


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


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
    monkeypatch.setattr(rd, "tcp_probe", lambda host, port: 0)
    monkeypatch.setattr(rd, "login_probe", lambda *a: pytest.fail("login must not run"))
    target = {"ip": "10.0.0.5", "port": 8728, "username": "u", "password": "p"}
    assert rd.probe_router(target) == {"tcp_ok": 0, "login": "skipped"}


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
    probed = []

    def probe(target):
        assert open_sessions["n"] == 0, "DB session held across router I/O"
        probed.append(target["id"])
        return {overloaded.id: {"tcp_ok": 5, "login": "timeout"},
                blocked.id: {"tcp_ok": 0, "login": "skipped"}}[target["id"]]

    summary = await rd.run_diagnosis_cycle(NOW, probe=probe)
    assert sorted(probed) == sorted([overloaded.id, blocked.id])  # recovering row is not probed
    assert summary["probed"] == 2
    assert summary["ailments"] == {"overloaded": 1, "udp_blocked": 1}

    d = rd.diagnosis_for(overloaded.id, NOW)
    assert d["ailment"] == "overloaded" and d["tcp_ok"] == 5 and d["login"] == "timeout"
    assert d["evidence"] == "TCP 5/5, API login timed out, CPU 100% (push 3 min ago)"
    assert d["probed_at"].endswith("Z") and "_probed_at" not in d
    assert rd.diagnosis_for(blocked.id, NOW)["sstp_candidate"] is True

    # Attached to the section rows (in memory, rows not mutated); absent -> None.
    rows = rd.attach_diagnoses([_row(overloaded.id), _row(recovering.id)], NOW)
    assert rows[0]["diagnosis"]["ailment"] == "overloaded"
    assert rows[1]["diagnosis"] is None
    # Old results expire rather than show as current.
    assert rd.diagnosis_for(overloaded.id, NOW + timedelta(minutes=30)) is None


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
    assert again["routers"][0]["diagnosis"]["ailment"] == "lossy_line"
    # The cached section itself is left untouched (the job reads it).
    assert "diagnosis" not in pr.latest_section()[0]["routers"][0]
