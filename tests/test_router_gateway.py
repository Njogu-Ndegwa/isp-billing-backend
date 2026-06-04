from datetime import datetime, timedelta
from types import SimpleNamespace

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
    import dataclasses
    try:
        snap.password = "leak"
        assert False, "snapshot must be immutable"
    except dataclasses.FrozenInstanceError:
        pass


def test_result_ok_helper_sets_status_and_value():
    r = RouterOpResult.ok(value={"hello": 1}, router_id=3, duration_ms=12.5)
    assert r.status is RouterOpStatus.OK
    assert r.is_ok is True
    assert r.value == {"hello": 1}


def test_result_skipped_helper_is_not_ok():
    r = RouterOpResult.skipped(RouterOpStatus.SKIPPED_OFFLINE, router_id=3)
    assert r.is_ok is False
    assert r.value is None
