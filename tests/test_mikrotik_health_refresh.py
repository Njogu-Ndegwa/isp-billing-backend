from datetime import datetime, timedelta

import pytest

from app.api import mikrotik_routes


class DummyBackgroundTasks:
    def __init__(self):
        self.calls = []

    def add_task(self, *args, **kwargs):
        self.calls.append((args, kwargs))


@pytest.fixture(autouse=True)
def reset_health_refresh_state():
    mikrotik_routes._health_refresh_inflight.clear()
    mikrotik_routes._health_refresh_last_started.clear()
    yield
    mikrotik_routes._health_refresh_inflight.clear()
    mikrotik_routes._health_refresh_last_started.clear()


def test_health_refresh_queue_respects_active_inflight_marker():
    cache_key = 240
    started = datetime.utcnow()
    tasks = DummyBackgroundTasks()

    mikrotik_routes._health_refresh_inflight.add(cache_key)
    mikrotik_routes._health_refresh_last_started[cache_key] = started

    meta = mikrotik_routes._queue_health_cache_refresh(
        tasks,
        cache_key,
        {"ip": "10.0.0.95", "username": "u", "password": "p", "port": 8728},
        "fastnet #3",
        cache_key,
    )

    assert meta == {"refresh_in_progress": True, "retry_after_seconds": 5}
    assert tasks.calls == []
    assert cache_key in mikrotik_routes._health_refresh_inflight
    assert mikrotik_routes._health_refresh_last_started[cache_key] is started


def test_health_refresh_queue_replaces_stale_inflight_marker():
    cache_key = 240
    stale_started = datetime.utcnow() - timedelta(
        seconds=mikrotik_routes._health_refresh_inflight_max_age_seconds + 1
    )
    router_info = {"ip": "10.0.0.95", "username": "u", "password": "p", "port": 8728}
    tasks = DummyBackgroundTasks()

    mikrotik_routes._health_refresh_inflight.add(cache_key)
    mikrotik_routes._health_refresh_last_started[cache_key] = stale_started

    meta = mikrotik_routes._queue_health_cache_refresh(
        tasks,
        cache_key,
        router_info,
        "fastnet #3",
        cache_key,
    )

    assert meta == {"refresh_in_progress": True, "retry_after_seconds": 5}
    assert len(tasks.calls) == 1
    args, kwargs = tasks.calls[0]
    assert kwargs == {}
    assert args == (
        mikrotik_routes._refresh_health_cache_from_router,
        cache_key,
        router_info,
        "fastnet #3",
        cache_key,
    )
    assert cache_key in mikrotik_routes._health_refresh_inflight
    assert mikrotik_routes._health_refresh_last_started[cache_key] > stale_started


def test_health_refresh_queue_replaces_inflight_marker_without_timestamp():
    cache_key = 240
    tasks = DummyBackgroundTasks()

    mikrotik_routes._health_refresh_inflight.add(cache_key)

    meta = mikrotik_routes._queue_health_cache_refresh(
        tasks,
        cache_key,
        {"ip": "10.0.0.95", "username": "u", "password": "p", "port": 8728},
        "fastnet #3",
        cache_key,
    )

    assert meta == {"refresh_in_progress": True, "retry_after_seconds": 5}
    assert len(tasks.calls) == 1
    assert cache_key in mikrotik_routes._health_refresh_inflight
    assert cache_key in mikrotik_routes._health_refresh_last_started
