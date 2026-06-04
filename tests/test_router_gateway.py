import asyncio
import dataclasses
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from app.services.router_availability import router_recently_offline


def test_router_recently_offline_true_when_recent_failure():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(last_status=False, last_checked_at=now - timedelta(minutes=5))
    assert router_recently_offline(router, now) is True


def test_router_recently_offline_false_when_window_passed():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(last_status=False, last_checked_at=now - timedelta(minutes=45))
    assert router_recently_offline(router, now) is False


def test_router_recently_offline_false_when_online_or_unknown():
    now = datetime(2026, 6, 3, 12, 0, 0)
    assert router_recently_offline(
        SimpleNamespace(last_status=True, last_checked_at=now), now
    ) is False
    assert router_recently_offline(
        SimpleNamespace(last_status=None, last_checked_at=None), now
    ) is False


def test_router_recently_offline_false_at_exact_threshold():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(last_status=False, last_checked_at=now - timedelta(minutes=30))
    assert router_recently_offline(router, now) is False


from app.services.router_gateway import (
    Priority,
    RouterOpStatus,
    RouterOpResult,
    RouterSnapshot,
)


def test_router_snapshot_from_router_copies_connection_fields():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(
        id=7, name="R7", ip_address="10.0.0.7", port=8728,
        username="admin", password="pw", identity="ident-7",
        last_status=True, last_checked_at=now,
    )
    snap = RouterSnapshot.from_router(router, now=now)
    assert (snap.id, snap.ip_address, snap.port, snap.username, snap.password) == (
        7, "10.0.0.7", 8728, "admin", "pw"
    )
    assert snap.recently_offline is False


def test_router_snapshot_marks_recently_offline():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(
        id=8, name="R8", ip_address="10.0.0.8", port=8728,
        username="admin", password="pw", identity=None,
        last_status=False, last_checked_at=now - timedelta(minutes=5),
    )
    snap = RouterSnapshot.from_router(router, now=now)
    assert snap.recently_offline is True


def test_router_snapshot_is_frozen():
    snap = RouterSnapshot(
        id=1, name="x", ip_address="1.1.1.1", port=8728,
        username="u", password="p", identity=None, recently_offline=False,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.password = "leak"


def test_result_ok_helper_sets_status_and_value():
    r = RouterOpResult.ok(value={"hello": 1}, router_id=3, duration_ms=12.5)
    assert r.status is RouterOpStatus.OK
    assert r.is_ok is True
    assert r.value == {"hello": 1}


def test_result_skipped_helper_is_not_ok():
    r = RouterOpResult.skipped(RouterOpStatus.SKIPPED_OFFLINE, router_id=3)
    assert r.is_ok is False
    assert r.value is None


def test_result_failed_helper_carries_error_and_is_not_ok():
    r = RouterOpResult.failed(RouterOpStatus.FAILED_CONNECT, error="boom", router_id=5)
    assert r.is_ok is False
    assert r.error == "boom"
    assert r.value is None


def test_result_factories_reject_wrong_status():
    with pytest.raises(ValueError):
        RouterOpResult.skipped(RouterOpStatus.OK)
    with pytest.raises(ValueError):
        RouterOpResult.failed(RouterOpStatus.OK, error="x")


def test_router_snapshot_identity_defaults_to_none_when_absent():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(
        id=9, name="R9", ip_address="10.0.0.9", port=8728,
        username="u", password="p", last_status=True, last_checked_at=now,
    )  # no `identity` attribute at all
    snap = RouterSnapshot.from_router(router, now=now)
    assert snap.identity is None


import app.services.router_gateway as gw


def _snap(recently_offline=False, ip="10.0.0.9", port=8728):
    return RouterSnapshot(
        id=9, name="R9", ip_address=ip, port=port, username="u",
        password="p", identity=None, recently_offline=recently_offline,
    )


def test_preflight_skips_circuit_open(monkeypatch):
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: True)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)
    assert gw._preflight_skip(_snap(), Priority.INTERACTIVE) is RouterOpStatus.SKIPPED_CIRCUIT_OPEN
    assert gw._preflight_skip(_snap(), Priority.BACKGROUND) is RouterOpStatus.SKIPPED_CIRCUIT_OPEN


def test_preflight_offline_skips_background_only(monkeypatch):
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)
    assert gw._preflight_skip(_snap(recently_offline=True), Priority.BACKGROUND) is RouterOpStatus.SKIPPED_OFFLINE
    assert gw._preflight_skip(_snap(recently_offline=True), Priority.INTERACTIVE) is None


def test_preflight_pressure_skips_background_only(monkeypatch):
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: True)
    assert gw._preflight_skip(_snap(), Priority.BACKGROUND) is RouterOpStatus.SKIPPED_DB_PRESSURE
    assert gw._preflight_skip(_snap(), Priority.INTERACTIVE) is None


def test_preflight_returns_none_when_clear(monkeypatch):
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)
    assert gw._preflight_skip(_snap(), Priority.BACKGROUND) is None


class _FakeApi:
    def __init__(self, connect_ok=True):
        self._connect_ok = connect_ok
        self.disconnected = False
        self.last_connect_error = "boom" if not connect_ok else None

    def connect(self):
        return self._connect_ok

    def disconnect(self):
        self.disconnected = True


def _install_fake_connect(monkeypatch, api):
    monkeypatch.setattr(gw, "connect_to_router", lambda snapshot: api)
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)


async def test_run_router_op_ok_runs_op_with_connected_api(monkeypatch):
    api = _FakeApi(connect_ok=True)
    _install_fake_connect(monkeypatch, api)
    result = await gw.run_router_op(
        _snap(), lambda a: {"ran": True}, priority=Priority.INTERACTIVE, purpose="unit"
    )
    assert result.is_ok
    assert result.value == {"ran": True}
    assert api.disconnected is True


async def test_run_router_op_connect_failure_maps_to_failed_connect(monkeypatch):
    api = _FakeApi(connect_ok=False)
    _install_fake_connect(monkeypatch, api)
    result = await gw.run_router_op(
        _snap(), lambda a: {"ran": True}, priority=Priority.INTERACTIVE, purpose="unit"
    )
    assert result.status is RouterOpStatus.FAILED_CONNECT
    assert result.error == "boom"


async def test_run_router_op_op_exception_maps_to_failed_op(monkeypatch):
    api = _FakeApi(connect_ok=True)
    _install_fake_connect(monkeypatch, api)
    def boom(a):
        raise ValueError("kaboom")
    result = await gw.run_router_op(_snap(), boom, priority=Priority.BACKGROUND, purpose="unit")
    assert result.status is RouterOpStatus.FAILED_OP
    assert "kaboom" in result.error
    assert api.disconnected is True


async def test_run_router_op_honours_preflight_skip(monkeypatch):
    api = _FakeApi(connect_ok=True)
    _install_fake_connect(monkeypatch, api)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: True)
    result = await gw.run_router_op(
        _snap(), lambda a: {"ran": True}, priority=Priority.BACKGROUND, purpose="unit"
    )
    assert result.status is RouterOpStatus.SKIPPED_DB_PRESSURE
    assert api.disconnected is False


async def test_run_router_op_respects_global_semaphore(monkeypatch):
    monkeypatch.setattr(gw, "_SEMAPHORE", asyncio.Semaphore(2))
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)
    active = 0
    max_seen = 0

    class _SleepApi(_FakeApi):
        pass

    monkeypatch.setattr(gw, "connect_to_router", lambda snapshot: _SleepApi())

    def slow_op(a):
        nonlocal active, max_seen
        active += 1
        max_seen = max(max_seen, active)
        time.sleep(0.03)
        active -= 1
        return True

    await asyncio.gather(*[
        gw.run_router_op(_snap(), slow_op, priority=Priority.BACKGROUND, purpose="unit")
        for _ in range(6)
    ])
    assert max_seen <= 2
