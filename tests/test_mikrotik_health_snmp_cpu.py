"""Dashboard CPU dial uses the SNMP reading for enrolled routers, and the health
endpoint checks router ownership before serving any cached payload.

Why: on 2026-09-24 lee net (hAP lite) read 62-68% over SNMP (1-minute average,
what the overload alerts act on) but 100% on the dashboard (instantaneous
RouterOS cpu-load, spiked by the dashboard's own login). One number everywhere.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import mikrotik_routes as mr
from app.db.models import UserRole
from tests.factories import make_admin, make_reseller, make_router


class _Tasks:
    def add_task(self, *a, **k):
        pass


def _row(**kw):
    base = dict(snmp_enabled=True, cpu_load=64, cpu_checked_at=datetime.utcnow() - timedelta(minutes=3))
    base.update(kw)
    return SimpleNamespace(**base)


def _payload(**kw):
    base = {"cpu_load_percent": 100, "router_reachable": True}
    base.update(kw)
    return base


def test_fresh_snmp_reading_replaces_routeros_cpu():
    out = mr._apply_snmp_cpu(_payload(), _row(), datetime.utcnow())
    assert out["cpu_load_percent"] == 64 and out["cpu_source"] == "snmp"
    assert out["cpu_checked_at"]


@pytest.mark.parametrize("row", [
    _row(cpu_checked_at=datetime.utcnow() - timedelta(minutes=11)),   # stale
    _row(snmp_enabled=False),                                           # not enrolled
    _row(cpu_load=None),                                                # never read
    None,                                                               # no router scope
])
def test_routeros_cpu_kept_when_snmp_not_usable(row):
    out = mr._apply_snmp_cpu(_payload(), row, datetime.utcnow())
    assert out["cpu_load_percent"] == 100 and out["cpu_source"] == "routeros"


def test_offline_router_is_not_given_a_live_looking_cpu():
    out = mr._apply_snmp_cpu(_payload(router_reachable=False), _row(), datetime.utcnow())
    assert out["cpu_load_percent"] == 100 and out["cpu_source"] == "routeros"


def test_non_dict_responses_pass_through():
    assert mr._apply_snmp_cpu("x", _row(), datetime.utcnow()) == "x"


@pytest.fixture
def fresh_cache():
    saved = dict(mr._health_cache)
    yield mr._health_cache
    mr._health_cache.clear()
    mr._health_cache.update(saved)


def _cache(router_id, cpu=100):
    mr._health_cache[router_id] = {
        "timestamp": datetime.utcnow(),
        "data": {"cpu_load_percent": cpu, "router_reachable": True, "_full_pppoe_sessions": []},
    }


async def test_endpoint_serves_snmp_cpu_on_the_cached_fast_path(db, monkeypatch, fresh_cache):
    owner = await make_reseller(db)
    router = await make_router(db, owner, snmp_enabled=True, cpu_load=66,
                               cpu_checked_at=datetime.utcnow() - timedelta(minutes=2))

    async def _user(token, db_):
        return owner
    monkeypatch.setattr(mr, "get_current_user", _user)
    _cache(router.id, cpu=100)

    out = await mr.get_mikrotik_health(_Tasks(), router_id=router.id, db=db, token="t")
    assert out["cpu_load_percent"] == 66 and out["cpu_source"] == "snmp"


async def test_other_resellers_cannot_read_a_cached_router(db, monkeypatch, fresh_cache):
    owner = await make_reseller(db)
    stranger = await make_reseller(db)
    router = await make_router(db, owner)

    async def _user(token, db_):
        return stranger
    monkeypatch.setattr(mr, "get_current_user", _user)
    _cache(router.id)

    with pytest.raises(HTTPException) as exc:
        await mr.get_mikrotik_health(_Tasks(), router_id=router.id, db=db, token="t")
    assert exc.value.status_code == 404


async def test_admin_can_read_any_router(db, monkeypatch, fresh_cache):
    owner = await make_reseller(db)
    admin = await make_admin(db)
    router = await make_router(db, owner)
    assert admin.role == UserRole.ADMIN

    async def _user(token, db_):
        return admin
    monkeypatch.setattr(mr, "get_current_user", _user)
    _cache(router.id, cpu=37)

    out = await mr.get_mikrotik_health(_Tasks(), router_id=router.id, db=db, token="t")
    assert out["cpu_load_percent"] == 37 and out["cpu_source"] == "routeros"
