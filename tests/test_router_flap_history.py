from datetime import datetime, timedelta

from app.services.management_tunnel_health import build_fleet_flap_history
from app.services.router_availability import summarize_router_flaps


def _check(at, online, source="bandwidth_snapshot", router_id=1):
    return {
        "router_id": router_id,
        "checked_at": at,
        "is_online": online,
        "source": source,
    }


def test_single_failed_probe_does_not_create_a_flap():
    start = datetime(2026, 9, 21, 9, 0)
    summary = summarize_router_flaps([
        _check(start, True),
        _check(start + timedelta(minutes=1), False),
        _check(start + timedelta(minutes=2), True),
    ])

    assert summary["status"] == "online"
    assert summary["transition_count"] == 0
    assert summary["outage_count"] == 0
    assert summary["is_flapping"] is False


def test_repeated_confirmed_outages_are_classified_as_flapping():
    start = datetime(2026, 9, 21, 9, 0)
    checks = [_check(start, True)]
    for minute, online in [
        (1, False), (2, False), (3, True),
        (4, False), (5, False), (6, True),
    ]:
        checks.append(_check(start + timedelta(minutes=minute), online))

    summary = summarize_router_flaps(checks, now=start + timedelta(minutes=10))

    assert summary["status"] == "online"
    assert summary["transition_count"] == 4
    assert summary["outage_count"] == 2
    assert summary["recovery_count"] == 2
    assert summary["is_flapping"] is True
    assert [event["to"] for event in summary["transitions"]] == [
        "offline", "online", "offline", "online",
    ]


def test_fleet_summary_only_lists_repeated_flappers():
    start = datetime(2026, 9, 21, 9, 0)
    routers = [
        {"id": 1, "name": "Unstable", "identity": "Router-1", "ip_address": "10.0.100.1"},
        {"id": 2, "name": "Stable", "identity": "Router-2", "ip_address": "10.0.0.2"},
    ]
    checks = [
        _check(start, True),
        _check(start + timedelta(minutes=1), False),
        _check(start + timedelta(minutes=2), False),
        _check(start + timedelta(minutes=3), True),
        _check(start + timedelta(minutes=4), False),
        _check(start + timedelta(minutes=5), False),
        _check(start + timedelta(minutes=6), True),
        _check(start, True, router_id=2),
        _check(start + timedelta(minutes=6), True, router_id=2),
    ]

    result = build_fleet_flap_history(routers, checks, now=start + timedelta(minutes=10))

    assert result["monitored_routers"] == 2
    assert result["affected_count"] == 1
    assert result["total_transitions"] == 4
    assert result["routers"][0]["router_id"] == 1
    assert result["routers"][0]["tunnel_type"] == "l2tp"
