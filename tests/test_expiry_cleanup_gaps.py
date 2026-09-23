"""Expired-user cleanup gaps found in the 2026-09-23 production audit.

Most expired-but-ACTIVE customers sit on routers whose management tunnel is
down, and nothing server-side can remove them until the site comes back. These
tests pin the smaller defects around that case:

1. a back-off outlives the router's recovery (free internet on return);
2. a router that goes silent keeps ``last_status = true`` and is never
   quarantined;
3. another job's failures (payment provisioning on router 371) kept the shared
   summary "recently offline", so cleanup never retried the router;
4. expired rows with no MAC and no PPPoE username can never be selected;
5. removals were queued for outbound agents that never check in.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import CustomerStatus, RouterAvailabilityCheck
from app.services import mikrotik_background, ops_health, router_agent_commands
from app.services.provisioning import generate_rsc_script
from app.services.router_agent_script import SCRIPT_NAME
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.test_expired_hotspot_cleanup import _patch_cleanup_side_effects
from tests.test_provisioning_script import _token


def _record_router_cleanup(monkeypatch, *, connected=True):
    calls = []

    def fake_router_cleanup(router_info, customers_data):
        calls.append((router_info["id"], [c["id"] for c in customers_data]))
        if connected:
            return {
                "removed": [{"id": c["id"], "details": {}} for c in customers_data],
                "failed": [],
                "connected": True,
            }
        return {
            "removed": [],
            "failed": [{"id": c["id"], "error": "router unavailable"} for c in customers_data],
            "connected": False,
        }

    monkeypatch.setattr(
        mikrotik_background, "_cleanup_single_router_hotspot_sync", fake_router_cleanup
    )
    return calls


async def _expired_customer(db, reseller, plan, router, **kwargs):
    return await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=kwargs.pop("expiry", datetime.utcnow() - timedelta(minutes=10)),
        **kwargs,
    )


# --- 1. back-off ends when the router is seen online again -------------------


async def test_backoff_ends_when_router_reports_online_after_the_failure(
    db, session_factory, monkeypatch
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(
        db, reseller, last_status=True, last_online_at=now - timedelta(minutes=1)
    )
    customer = await _expired_customer(db, reseller, plan, router)
    mikrotik_background._expiry_cleanup_backoff_hydrated = True
    mikrotik_background._expiry_cleanup_unreachable_routers[router.id] = now - timedelta(minutes=5)
    calls = _record_router_cleanup(monkeypatch)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert calls == [(router.id, [customer.id])]
    assert customer.status == CustomerStatus.INACTIVE
    assert router.id not in mikrotik_background._expiry_cleanup_unreachable_routers


async def test_backoff_holds_when_no_online_signal_since_the_failure(
    db, session_factory, monkeypatch
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(
        db, reseller, last_status=True, last_online_at=now - timedelta(minutes=20)
    )
    customer = await _expired_customer(db, reseller, plan, router)
    mikrotik_background._expiry_cleanup_backoff_hydrated = True
    mikrotik_background._expiry_cleanup_unreachable_routers[router.id] = now - timedelta(minutes=5)
    calls = _record_router_cleanup(monkeypatch)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert calls == []
    assert customer.status == CustomerStatus.ACTIVE


# --- 2. silent routers are quarantined on cleanup's own evidence -------------


async def test_silent_router_is_quarantined_after_cleanup_fails_to_reach_it(
    db, session_factory, monkeypatch
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    # Stale summary: still "online", but nothing has heard from it in 4 days.
    router = await make_router(
        db,
        reseller,
        last_status=True,
        last_checked_at=now - timedelta(days=4),
        last_online_at=now - timedelta(days=4),
    )
    customer = await _expired_customer(db, reseller, plan, router)
    calls = _record_router_cleanup(monkeypatch, connected=False)

    # First run: no evidence yet, so cleanup tries (and fails).
    await mikrotik_background.cleanup_expired_users_background()
    assert calls == [(router.id, [customer.id])]

    # Once cleanup itself has failed, the router is quarantined even after the
    # 30-minute back-off would have expired.
    failed_at = mikrotik_background._expiry_cleanup_unreachable_routers[router.id]
    mikrotik_background._expiry_cleanup_unreachable_routers[router.id] = failed_at - timedelta(hours=1)
    calls.clear()
    await mikrotik_background.cleanup_expired_users_background()
    assert calls == []

    # Any later online signal releases it.
    router.last_online_at = datetime.utcnow()
    await db.commit()
    calls = _record_router_cleanup(monkeypatch, connected=True)
    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)
    assert calls == [(router.id, [customer.id])]
    assert customer.status == CustomerStatus.INACTIVE


async def test_silent_router_cleanup_can_reach_is_not_quarantined(
    db, session_factory, monkeypatch
):
    """A stalled telemetry job must not stop expiry on a router cleanup reaches."""
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(
        db, reseller, last_status=True, last_online_at=now - timedelta(days=5)
    )
    customer = await _expired_customer(db, reseller, plan, router)
    calls = _record_router_cleanup(monkeypatch)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert calls == [(router.id, [customer.id])]
    assert customer.status == CustomerStatus.INACTIVE


# --- 3. other jobs' failures do not lock cleanup out -------------------------


async def test_router_marked_offline_by_another_job_is_still_tried(
    db, session_factory, monkeypatch
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    # Payment provisioning keeps failing, so the shared summary says offline
    # and was refreshed a minute ago.
    router = await make_router(
        db,
        reseller,
        last_status=False,
        last_checked_at=now - timedelta(minutes=1),
        last_online_at=now - timedelta(hours=3),
        last_status_source="provisioning",
    )
    customer = await _expired_customer(db, reseller, plan, router)
    calls = _record_router_cleanup(monkeypatch)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert calls == [(router.id, [customer.id])]
    assert customer.status == CustomerStatus.INACTIVE


async def test_routers_believed_offline_go_last_in_the_batch(
    db, session_factory, monkeypatch
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    monkeypatch.setattr(mikrotik_background, "EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_RUN", 1)
    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    offline_router = await make_router(
        db,
        reseller,
        last_status=False,
        last_checked_at=now - timedelta(minutes=1),
        last_online_at=now - timedelta(hours=3),
    )
    online_router = await make_router(
        db, reseller, ip_address="10.0.0.3", last_status=True, last_online_at=now
    )
    # The offline router's customer expired first, so it would lead the batch.
    await _expired_customer(
        db, reseller, plan, offline_router, expiry=now - timedelta(hours=2)
    )
    online_customer = await _expired_customer(
        db, reseller, plan, online_router, expiry=now - timedelta(minutes=5)
    )
    calls = _record_router_cleanup(monkeypatch)

    await mikrotik_background.cleanup_expired_users_background()

    assert calls == [(online_router.id, [online_customer.id])]


# --- 4. rows with no device identity -----------------------------------------


async def test_expired_customer_without_mac_or_pppoe_username_is_deactivated(
    db, session_factory, monkeypatch
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    expired = await _expired_customer(db, reseller, plan, router, phone="254700000001")
    current = await _expired_customer(
        db, reseller, plan, router, phone="254700000002", expiry=now + timedelta(hours=1)
    )
    # Self-service reconnect moved their MACs to other customer rows.
    expired.mac_address = None
    current.mac_address = None
    await db.commit()
    calls = _record_router_cleanup(monkeypatch)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(expired)
    await db.refresh(current)

    assert expired.status == CustomerStatus.INACTIVE
    assert current.status == CustomerStatus.ACTIVE
    assert calls == []


# --- 5. no removals queued for agents that never check in --------------------


async def _run_failed_cleanup_capturing_agent_queue(db, session_factory, monkeypatch, agent_seen_at):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(
        db,
        reseller,
        identity="Router-0001",
        router_agent_enabled=True,
        agent_last_seen_at=agent_seen_at,
    )
    customer = await _expired_customer(db, reseller, plan, router)
    _record_router_cleanup(monkeypatch, connected=False)
    queued = []

    async def fake_queue(**kwargs):
        queued.append(kwargs["customer_id"])
        return 1

    monkeypatch.setattr(router_agent_commands, "queue_hotspot_remove_command", fake_queue)
    await mikrotik_background.cleanup_expired_users_background()
    return customer, queued


async def test_removal_is_not_queued_for_an_agent_that_stopped_checking_in(
    db, session_factory, monkeypatch
):
    _customer, queued = await _run_failed_cleanup_capturing_agent_queue(
        db, session_factory, monkeypatch, datetime.utcnow() - timedelta(days=7)
    )
    assert queued == []


async def test_removal_is_queued_for_a_live_agent(db, session_factory, monkeypatch):
    customer, queued = await _run_failed_cleanup_capturing_agent_queue(
        db, session_factory, monkeypatch, datetime.utcnow() - timedelta(minutes=2)
    )
    assert queued == [customer.id]


def test_provisioning_no_longer_installs_the_command_agent():
    for vpn_type in ("wireguard", "l2tp"):
        script = generate_rsc_script(_token(vpn_type))
        assert f'/system script add name="{SCRIPT_NAME}"' not in script, vpn_type
        assert f'/system script remove [find name="{SCRIPT_NAME}"]' in script, vpn_type


# --- dashboard mirror of the quarantine rule ---------------------------------


def test_dashboard_quarantine_rule_matches_cleanup():
    now = datetime.utcnow()
    silent_since = now - timedelta(days=4)
    # Marked offline for 3+ days: quarantined, as before.
    assert ops_health.is_router_quarantined(False, silent_since, None, now)
    # Silent with a stale "online" flag: only once cleanup failed after it went quiet.
    assert not ops_health.is_router_quarantined(True, silent_since, None, now)
    assert not ops_health.is_router_quarantined(
        True, silent_since, None, now, silent_since - timedelta(hours=1)
    )
    assert ops_health.is_router_quarantined(
        True, silent_since, None, now, silent_since + timedelta(hours=1)
    )
    # Heard from recently: never quarantined.
    assert not ops_health.is_router_quarantined(
        False, now - timedelta(hours=1), None, now, now
    )


async def test_dashboard_loads_cleanup_failures_after_last_online(db):
    now = datetime.utcnow()
    reseller = await make_reseller(db)
    silent = await make_router(db, reseller, last_status=True, last_online_at=now - timedelta(days=4))
    recent = await make_router(
        db, reseller, ip_address="10.0.0.3", last_status=True, last_online_at=now - timedelta(hours=1)
    )
    failure = now - timedelta(hours=2)
    db.add_all([
        RouterAvailabilityCheck(router_id=silent.id, checked_at=now - timedelta(days=5),
                                is_online=False, source="expired_cleanup"),
        RouterAvailabilityCheck(router_id=silent.id, checked_at=failure,
                                is_online=False, source="expired_cleanup"),
        RouterAvailabilityCheck(router_id=silent.id, checked_at=now - timedelta(minutes=5),
                                is_online=False, source="provisioning"),
        RouterAvailabilityCheck(router_id=recent.id, checked_at=now - timedelta(minutes=10),
                                is_online=False, source="expired_cleanup"),
    ])
    await db.commit()

    failures = await ops_health.load_cleanup_failures_since_online(db, now)

    assert failures == {silent.id: failure}
