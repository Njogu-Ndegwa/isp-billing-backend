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
