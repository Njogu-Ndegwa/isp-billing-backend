"""Routers on an older reaper script upgrade themselves in place when they
check in (app/services/expiry_reaper_upgrade.py)."""
from contextlib import asynccontextmanager

import pytest

from app.db import database
from app.services import expiry_reaper_upgrade as up
from app.services.expiry_reaper_script import SCRIPT_NAME, SCRIPT_VERSION
from tests.factories import make_reseller, make_router

OPEN = {"n": 0}


def counting(session_factory):
    @asynccontextmanager
    async def factory():
        OPEN["n"] += 1
        try:
            async with session_factory() as s:
                yield s
        finally:
            OPEN["n"] -= 1
    return factory


class FakeRouterOS:
    def __init__(self, source=None, reachable=True, set_error=None):
        self.scripts = [] if source is None else [{".id": "*1", "name": SCRIPT_NAME, "source": source}]
        self.reachable, self.set_error, self.sets = reachable, set_error, []

    def connect(self):
        assert OPEN["n"] == 0, "DB session held across RouterOS I/O"
        return self.reachable

    def disconnect(self):
        pass

    def send_command(self, cmd, args=None):
        if cmd == "/system/script/print":
            return {"data": [dict(s) for s in self.scripts]}
        if cmd == "/system/script/set":
            self.sets.append(dict(args))
            if self.set_error:
                return {"error": self.set_error}
            self.scripts[0]["source"] = args["source"]
            return {"data": []}
        return {"data": []}


@pytest.fixture
def wired(session_factory, monkeypatch):
    OPEN["n"] = 0
    up.reset_state()
    monkeypatch.setattr(database, "async_session", counting(session_factory))
    monkeypatch.setattr(up.settings, "EXPIRY_REAPER_AUTO_UPGRADE", True)
    routers = {}
    monkeypatch.setattr(up, "MikroTikAPI", lambda ip, *a, **k: routers[ip])
    return routers


async def _router(db, enabled=True):
    reseller = await make_reseller(db)
    return await make_router(db, reseller, ip_address="10.0.7.1", identity="Router-7001",
                             expiry_reaper_enabled=enabled)


@pytest.mark.asyncio
async def test_old_script_is_rewritten_in_place_with_the_current_version(db, wired):
    await _router(db)
    fake = wired["10.0.7.1"] = FakeRouterOS(source=':local body ("ident=" . $ident . "&now=" . $nows')
    assert await up.upgrade_router("Router-7001") == "upgraded"
    assert up.version_marker() in fake.scripts[0]["source"]
    assert "Router-7001" in fake.scripts[0]["source"]
    # in place: only the source was set (scheduler and globals untouched)
    assert [list(s) for s in fake.sets] == [[".id", "source"]]


@pytest.mark.asyncio
async def test_current_script_is_left_alone(db, wired):
    await _router(db)
    fake = wired["10.0.7.1"] = FakeRouterOS(source=f"...{up.version_marker()}...")
    assert await up.upgrade_router("Router-7001") == "current"
    assert fake.sets == []


@pytest.mark.asyncio
@pytest.mark.parametrize("fake,enabled,expected", [
    (FakeRouterOS(source=None), True, "no script"),          # never installs from here
    (FakeRouterOS(source="old", reachable=False), True, "unreachable"),
    (FakeRouterOS(source="old", set_error="failure"), True, "error: failure"),
    (FakeRouterOS(source="old"), False, None),               # not on the reaper: not touched
])
async def test_what_is_never_changed(db, wired, fake, enabled, expected):
    await _router(db, enabled=enabled)
    wired["10.0.7.1"] = fake
    assert await up.upgrade_router("Router-7001") == expected
    if not enabled:
        assert fake.sets == []


@pytest.mark.asyncio
async def test_scheduling_only_for_old_versions_and_at_most_every_six_hours(monkeypatch):
    up.reset_state()
    monkeypatch.setattr(up.settings, "EXPIRY_REAPER_AUTO_UPGRADE", True)
    started = []

    async def fake_upgrade(identity):
        started.append(identity)
    monkeypatch.setattr(up, "upgrade_router", fake_upgrade)

    assert not up.maybe_schedule_upgrade("R1", SCRIPT_VERSION, now_mono=0)
    assert up.maybe_schedule_upgrade("R1", 1, now_mono=0)
    assert not up.maybe_schedule_upgrade("R1", 1, now_mono=3600)           # retry window
    assert up.maybe_schedule_upgrade("R1", 1, now_mono=up.UPGRADE_RETRY_SECONDS + 1)
    monkeypatch.setattr(up.settings, "EXPIRY_REAPER_AUTO_UPGRADE", False)
    assert not up.maybe_schedule_upgrade("R2", 1, now_mono=0)


def test_auto_upgrade_is_on_by_default():
    from app.config import Settings
    assert Settings.model_fields["EXPIRY_REAPER_AUTO_UPGRADE"].default is True


def test_endpoint_asks_for_an_upgrade_with_the_reported_version():
    import inspect
    from app.api import router_expiry_routes
    assert "maybe_schedule_upgrade(req.identity, req.version)" in inspect.getsource(router_expiry_routes)


@pytest.mark.asyncio
async def test_an_unreachable_router_is_retried_after_ten_minutes_not_six_hours(db, wired):
    await _router(db)
    wired["10.0.7.1"] = FakeRouterOS(source="old", reachable=False)
    up._attempted["Router-7001"] = 1000.0            # as maybe_schedule_upgrade records it
    assert await up.upgrade_router("Router-7001") == "unreachable"
    retry_at = up._attempted["Router-7001"] + up.UPGRADE_RETRY_SECONDS
    assert retry_at == 1000.0 + up.UNREACHABLE_RETRY_SECONDS

    wired["10.0.7.1"] = FakeRouterOS(source="old")
    up._attempted["Router-7001"] = 1000.0
    assert await up.upgrade_router("Router-7001") == "upgraded"
    assert up._attempted["Router-7001"] == 1000.0     # a real attempt keeps the 6-hour window
