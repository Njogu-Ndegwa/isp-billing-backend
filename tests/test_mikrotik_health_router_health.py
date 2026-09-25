"""Dashboard health tile shows the router's own reported health (router_health,
written by the push agent or the SNMP pilot) while fresh, says where it came
from, skips the RouterOS login for routers that push, and checks router
ownership before serving any cached payload.

Why: Dennis (2026-09-25) - "I want the numbers to come from push data so I can
actually know whether it's working". Before this the dials came from a
dashboard-triggered RouterOS login (instantaneous, and itself a load spike on
small routers) while the alerts used the pushed numbers.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import mikrotik_routes as mr
from app.db.models import RouterHealth, UserRole
from tests.factories import make_admin, make_reseller, make_router


class _Tasks:
    def __init__(self):
        self.calls = []

    def add_task(self, *a, **k):
        self.calls.append(a)


def _health(**kw):
    base = dict(source="push", sampled_at=datetime.utcnow() - timedelta(minutes=2),
                cpu_load=7, memory_free_bytes=966_565_888, memory_total_bytes=1_073_741_824,
                storage_free_bytes=508_751_872, storage_total_bytes=536_870_912,
                uptime_seconds=1_853_766, routeros_version="7.14 (stable)",
                board_name="RB4011iGS+", wan_link_downs=13)
    base.update(kw)
    return SimpleNamespace(**base)


def _payload(**kw):
    base = {"cpu_load_percent": 100, "router_reachable": True,
            "memory": {"total_bytes": 0, "free_bytes": 0, "used_bytes": 0, "used_percent": 0},
            "storage": {"total_bytes": 0, "free_bytes": 0, "used_bytes": 0, "used_percent": 0},
            "system": {"uptime": "", "version": "", "board_name": "", "platform": "MikroTik"}}
    base.update(kw)
    return base


def test_fresh_push_report_fills_every_dial():
    out = mr._apply_router_health(_payload(), _health(), datetime.utcnow())
    assert out["cpu_load_percent"] == 7
    assert out["memory"]["total_bytes"] == 1_073_741_824
    assert out["memory"]["used_percent"] == pytest.approx(10.0, abs=0.1)
    assert out["storage"]["free_bytes"] == 508_751_872
    assert out["system"]["uptime"] == "3w10h56m6s"
    assert out["system"]["version"] == "7.14 (stable)"
    assert out["system"]["board_name"] == "RB4011iGS+"
    assert out["system"]["platform"] == "MikroTik"          # untouched fields survive
    assert out["health_source"] == "push" and out["health_sampled_at"]


def test_push_report_marks_the_tile_current_not_updating():
    """A pushing router gets no RouterOS refresh, so a 'stale / updating' fast
    snapshot would otherwise show 'Updating' forever on the card."""
    stale_snapshot = _payload(stale=True, cached=True, live=False, refresh_in_progress=True,
                              fallback_reason="dashboard_fast_snapshot",
                              generated_at="2026-09-24T00:00:00")
    h = _health()
    out = mr._apply_router_health(stale_snapshot, h, datetime.utcnow())
    assert out["stale"] is False and out["cached"] is False and out["live"] is True
    assert out["refresh_in_progress"] is False and out["fallback_reason"] is None
    assert out["generated_at"] == h.sampled_at.isoformat()


def test_snmp_report_does_not_claim_the_whole_tile_is_current():
    h = _health(source="snmp", memory_free_bytes=None, memory_total_bytes=None)
    out = mr._apply_router_health(_payload(stale=True, live=False), h, datetime.utcnow())
    assert out["stale"] is True and out["live"] is False


def test_snmp_report_fills_cpu_only():
    h = _health(source="snmp", memory_free_bytes=None, memory_total_bytes=None,
                storage_free_bytes=None, storage_total_bytes=None, uptime_seconds=None,
                routeros_version=None, board_name=None, cpu_load=64)
    out = mr._apply_router_health(_payload(), h, datetime.utcnow())
    assert out["cpu_load_percent"] == 64 and out["health_source"] == "snmp"
    assert out["memory"]["total_bytes"] == 0                  # left as the live payload had it


@pytest.mark.parametrize("health", [
    _health(sampled_at=datetime.utcnow() - timedelta(minutes=11)),   # stale
    None,                                                             # never reported
])
def test_routeros_values_kept_without_a_fresh_report(health):
    out = mr._apply_router_health(_payload(), health, datetime.utcnow())
    assert out["cpu_load_percent"] == 100 and out["health_source"] == "routeros"
    assert "health_sampled_at" not in out


def test_offline_router_is_not_dressed_up_as_live():
    out = mr._apply_router_health(_payload(router_reachable=False), _health(), datetime.utcnow())
    assert out["cpu_load_percent"] == 100 and out["health_source"] == "routeros"


def test_non_dict_responses_pass_through():
    assert mr._apply_router_health("x", _health(), datetime.utcnow()) == "x"


@pytest.mark.parametrize("seconds,text", [(0, "0s"), (59, "59s"), (3600, "1h0s"),
                                          (1_853_766, "3w10h56m6s"), (90061, "1d1h1m1s")])
def test_uptime_format_matches_routeros(seconds, text):
    assert mr._format_uptime(seconds) == text


def test_only_fresh_push_with_memory_skips_the_login():
    now = datetime.utcnow()
    assert mr._push_covers_live_fields(_health(), now) is True
    assert mr._push_covers_live_fields(_health(source="snmp"), now) is False
    assert mr._push_covers_live_fields(_health(memory_total_bytes=None), now) is False
    assert mr._push_covers_live_fields(
        _health(sampled_at=now - timedelta(minutes=11)), now) is False
    assert mr._push_covers_live_fields(None, now) is False


# --- through the endpoint -----------------------------------------------------------

@pytest.fixture
def clean_state():
    saved = dict(mr._health_cache)
    mr._health_cache.clear()
    mr._health_refresh_inflight.clear()
    mr._health_refresh_last_started.clear()
    yield
    mr._health_cache.clear()
    mr._health_cache.update(saved)
    mr._health_refresh_inflight.clear()
    mr._health_refresh_last_started.clear()


def _cache(router_id, cpu=100):
    mr._health_cache[router_id] = {
        "timestamp": datetime.utcnow(),
        "data": {"cpu_load_percent": cpu, "router_reachable": True, "_full_pppoe_sessions": [],
                 "system": {"uptime": "1h", "version": "", "board_name": ""}},
    }


def _as(monkeypatch, user):
    async def _user(token, db_):
        return user
    monkeypatch.setattr(mr, "get_current_user", _user)


async def _push_health(db, router_id, **kw):
    h = _health(**kw)
    db.add(RouterHealth(router_id=router_id, **h.__dict__))
    await db.commit()


async def test_endpoint_serves_push_numbers_on_the_cached_path(db, monkeypatch, clean_state):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    await _push_health(db, router.id)
    _as(monkeypatch, owner)
    _cache(router.id, cpu=100)
    out = await mr.get_mikrotik_health(_Tasks(), router_id=router.id, db=db, token="t")
    assert out["cpu_load_percent"] == 7 and out["health_source"] == "push"
    assert out["system"]["board_name"] == "RB4011iGS+"


async def test_pushing_router_gets_no_background_login(db, monkeypatch, clean_state):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    await _push_health(db, router.id)
    _as(monkeypatch, owner)
    # Stale cache entry -> the fast path would normally queue a RouterOS refresh.
    _cache(router.id)
    mr._health_cache[router.id]["timestamp"] = datetime.utcnow() - timedelta(
        seconds=mr._health_cache_ttl + 1)
    tasks = _Tasks()
    out = await mr.get_mikrotik_health(tasks, router_id=router.id, db=db, token="t")
    assert tasks.calls == []
    assert out["health_source"] == "push"


async def test_non_pushing_router_still_refreshes_via_login(db, monkeypatch, clean_state):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    _as(monkeypatch, owner)
    _cache(router.id)
    mr._health_cache[router.id]["timestamp"] = datetime.utcnow() - timedelta(
        seconds=mr._health_cache_ttl + 1)
    tasks = _Tasks()
    out = await mr.get_mikrotik_health(tasks, router_id=router.id, db=db, token="t")
    assert len(tasks.calls) == 1
    assert out["health_source"] == "routeros"


async def test_other_resellers_cannot_read_a_cached_router(db, monkeypatch, clean_state):
    owner = await make_reseller(db)
    stranger = await make_reseller(db)
    router = await make_router(db, owner)
    _as(monkeypatch, stranger)
    _cache(router.id)
    with pytest.raises(HTTPException) as exc:
        await mr.get_mikrotik_health(_Tasks(), router_id=router.id, db=db, token="t")
    assert exc.value.status_code == 404


async def test_admin_can_read_any_router(db, monkeypatch, clean_state):
    owner = await make_reseller(db)
    admin = await make_admin(db)
    router = await make_router(db, owner)
    assert admin.role == UserRole.ADMIN
    _as(monkeypatch, admin)
    _cache(router.id, cpu=37)
    out = await mr.get_mikrotik_health(_Tasks(), router_id=router.id, db=db, token="t")
    assert out["cpu_load_percent"] == 37 and out["health_source"] == "routeros"
