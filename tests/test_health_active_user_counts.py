"""The dashboard's two user counts must each be MEASURED, never inferred.

Incident 2026-08-06: the health endpoint skipped the live PPPoE read and
recovered the number as ``active_queues - active_hotspot_users``. The moment a
second writer disagreed about what ``active_queues`` meant, router 10 published
0 hotspot / 99 PPPoE while having no PPPoE customers at all.

Pinned properties:

* hotspot = hotspot HOSTS that are authorized or bypassed — devices actually on
  the router and allowed through, not portal logins and not provisioned queues;
* a device carrying both flags counts once;
* PPPoE is read from ``/ppp/active``, never derived from the hotspot count or
  from ``active_queues``;
* a read that fails degrades THAT number to its persisted value — it never
  turns into the other number, and never silently reads 0;
* the payload states, per number, whether it is live.
"""

from datetime import datetime, timedelta

from app.api.mikrotik_routes import (
    _count_admitted_hotspot_hosts,
    _count_live_pppoe,
    _health_payload_from_live_result,
    _health_payload_from_snapshot,
    _persisted_pppoe_users,
)
from app.db.models import BandwidthSnapshot


def _hosts(*rows):
    return {"success": True, "data": list(rows)}


def _resources():
    return {"success": True, "data": {"total_memory": 1024, "free_memory": 512,
                                      "total_hdd_space": 1024, "free_hdd_space": 512}}


def _snapshot(**kw):
    kw.setdefault("recorded_at", datetime.utcnow() - timedelta(minutes=3))
    kw.setdefault("avg_download_bps", 0)
    kw.setdefault("avg_upload_bps", 0)
    return BandwidthSnapshot(router_id=10, **kw)


# --------------------------------------------------------------------------
# what counts as an active hotspot user
# --------------------------------------------------------------------------

def test_only_authorized_or_bypassed_hosts_count():
    hosts = _hosts(
        {"authorized": "true", "bypassed": "false"},   # paid, portal login
        {"authorized": "false", "bypassed": "true"},   # paid, MAC bypass
        {"authorized": "false", "bypassed": "false"},  # connected, has NOT paid
    )
    assert _count_admitted_hotspot_hosts(hosts) == 2


def test_host_with_both_flags_counts_once():
    hosts = _hosts({"authorized": "true", "bypassed": "true"})
    assert _count_admitted_hotspot_hosts(hosts) == 1


def test_a_failed_host_read_is_none_not_zero():
    """None lets the caller fall back to the persisted figure. Zero would
    publish 'nobody is online' every time a router answered slowly."""
    assert _count_admitted_hotspot_hosts({"success": False, "skipped": True}) is None


# --------------------------------------------------------------------------
# PPPoE is measured, not inferred
# --------------------------------------------------------------------------

def test_hotspot_only_router_reports_zero_pppoe():
    """The exact shape of the incident: a stale snapshot claims 99 combined
    'queues' while the router itself has no PPPoE sessions."""
    payload = _health_payload_from_live_result(
        mikrotik_result={
            "resources": _resources(),
            "health": {"success": True, "data": {}},
            "hotspot_hosts": _hosts(*([{"authorized": "false", "bypassed": "true"}] * 31)),
            "pppoe_active": {"success": True, "data": [], "count": 0},
        },
        latest_snapshot=_snapshot(active_queues=99, active_hotspot_users=0),
        router_id=10,
        router_name="Bitwave Wangige",
    )

    assert payload["active_hotspot_users"] == 31
    assert payload["active_pppoe_users"] == 0
    assert payload["active_total_users"] == 31
    assert payload["hotspot_count_live"] is True
    assert payload["pppoe_count_live"] is True


def test_pppoe_comes_from_the_live_session_list():
    payload = _health_payload_from_live_result(
        mikrotik_result={
            "resources": _resources(),
            "health": {"success": True, "data": {}},
            "hotspot_hosts": _hosts({"authorized": "true", "bypassed": "false"}),
            "pppoe_active": {"success": True, "data": [{"user": "a"}, {"user": "b"}], "count": 2},
        },
        latest_snapshot=_snapshot(active_queues=500, active_hotspot_users=0),
        router_id=11,
        router_name="mixed",
    )

    assert payload["active_hotspot_users"] == 1
    assert payload["active_pppoe_users"] == 2
    # active_queues=500 is ignored entirely — nothing is derived from it.
    assert payload["active_total_users"] == 3


# --------------------------------------------------------------------------
# degradation
# --------------------------------------------------------------------------

def test_failed_hotspot_read_falls_back_without_inflating_pppoe():
    payload = _health_payload_from_live_result(
        mikrotik_result={
            "resources": _resources(),
            "health": {"success": True, "data": {}},
            "hotspot_hosts": {"success": False, "skipped": True},
            "pppoe_active": {"success": True, "data": [], "count": 0},
        },
        latest_snapshot=_snapshot(
            active_queues=99, active_hotspot_users=31, active_pppoe_users=0
        ),
        router_id=10,
        router_name="Bitwave Wangige",
    )

    assert payload["active_hotspot_users"] == 31       # carried, not zeroed
    assert payload["active_pppoe_users"] == 0          # still measured live
    assert payload["hotspot_count_live"] is False
    assert payload["pppoe_count_live"] is True


def test_failed_pppoe_read_uses_persisted_pppoe_not_a_subtraction():
    payload = _health_payload_from_live_result(
        mikrotik_result={
            "resources": _resources(),
            "health": {"success": True, "data": {}},
            "hotspot_hosts": _hosts(*([{"authorized": "true", "bypassed": "false"}] * 4)),
            "pppoe_active": {"success": False, "skipped": True},
        },
        latest_snapshot=_snapshot(
            active_queues=99, active_hotspot_users=31, active_pppoe_users=2
        ),
        router_id=10,
        router_name="Bitwave Wangige",
    )

    assert payload["active_hotspot_users"] == 4
    assert payload["active_pppoe_users"] == 2   # NOT 99 - 4
    assert payload["pppoe_count_live"] is False


# --------------------------------------------------------------------------
# router unreachable — snapshot only
# --------------------------------------------------------------------------

def test_snapshot_payload_reads_both_numbers_back_independently():
    payload = _health_payload_from_snapshot(
        latest_snapshot=_snapshot(
            active_queues=99, active_hotspot_users=31, active_pppoe_users=0
        ),
        router_id=10,
        router_name="Bitwave Wangige",
        reason="unreachable",
    )

    assert payload["active_hotspot_users"] == 31
    assert payload["active_pppoe_users"] == 0
    assert payload["hotspot_count_live"] is False
    assert payload["pppoe_count_live"] is False


def test_legacy_rows_still_fall_back_to_the_old_subtraction():
    """Rows written before active_pppoe_users existed carry NULL. The old
    estimate is all we have for them — but only for them."""
    legacy = _snapshot(active_queues=10, active_hotspot_users=4, active_pppoe_users=None)
    assert _persisted_pppoe_users(legacy) == 6

    current = _snapshot(active_queues=10, active_hotspot_users=4, active_pppoe_users=0)
    assert _persisted_pppoe_users(current) == 0


def test_no_snapshot_at_all_is_zero_not_an_exception():
    assert _persisted_pppoe_users(None) == 0
    assert _count_live_pppoe({"success": False}) is None
