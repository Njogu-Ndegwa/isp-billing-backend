"""Problem routers: which routers cost paying customers, and did the fix work.

Pinned on the 2026-09-24 picture: kwa mwangi (router 464) lost 24 paid
deliveries in a week to an L2TP collision and was clean after moving to
WireGuard; FLASH WIFI (316) went from 54% first-try to 100% after the split.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import CustomerStatus, ProvisioningState, RouterAvailabilityCheck, SubscriptionStatus
from app.services import ops_health_problem_routers as pr
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.test_ops_health import _attempt

NOW = datetime(2026, 9, 25, 12, 0)
FAILED = ProvisioningState.FAILED
DELIVERED = ProvisioningState.ROUTER_UPDATED


def _router(rid, **kw):
    return {"id": rid, "name": f"R{rid}", "reseller": "Gifted tech", "tunnel": "l2tp",
            "management_tunnel": None, "changed_at": None, "last_online_at": NOW, **kw}


def _paid(rid, hours_ago, state=DELIVERED, tries=1):
    created = NOW - timedelta(hours=hours_ago)
    return (rid, created, state, tries, created + timedelta(seconds=10) if state == DELIVERED else None)


def test_lost_payments_in_the_last_day_need_attention():
    attempts = [_paid(1, 2, FAILED), _paid(1, 3, FAILED), _paid(1, 5, FAILED)] + [_paid(1, 4)] * 5
    out = pr.evaluate([_router(1)], [], attempts, NOW)
    row = out["routers"][0]
    assert row["state"] == "attention"
    assert row["reason"] == "3 paid customers not connected in the last 24h"
    assert row["after"]["lost"] == 3 and row["window"] == "last_24h"
    assert out["counts"] == {"attention": 1, "recovering": 0, "fixed": 0}
    assert out["paid_not_connected_24h"] == 3


def test_tunnel_move_splits_before_and_after_at_the_fix():
    moved = NOW - timedelta(days=2)
    r = _router(464, management_tunnel="wireguard", changed_at=moved, tunnel="wireguard")
    before = [_paid(464, 24 * 3 + h, FAILED) for h in range(5)]          # lost before the move
    after = [_paid(464, 24 + h) for h in range(6)]                       # clean since (1-2 days ago)
    row = pr.evaluate([r], [], before + after, NOW)["routers"][0]
    assert row["state"] == "fixed"
    assert row["window"] == "since_fix"
    assert row["fix"]["label"] == "WireGuard"
    assert row["reason"].startswith("Clean since the move to WireGuard (23 Sep 12:00 UTC): 6 payments, all connected")
    assert "before: 5 not connected" in row["reason"]
    assert row["before"]["lost"] == 5 and row["after"]["lost"] == 0


def test_better_but_not_clean_is_recovering_and_healthy_routers_are_left_out():
    was_bad = [_paid(1, 48 + h, FAILED) for h in range(5)]  # a genuinely bad week (>= 5 lost)
    one_lost_now = [_paid(1, 2, FAILED)] + [_paid(1, 3 + h) for h in range(8)]
    healthy = [_paid(2, h) for h in range(1, 30)]
    out = pr.evaluate([_router(1), _router(2)], [], was_bad + one_lost_now + healthy, NOW)
    assert [r["router_id"] for r in out["routers"]] == [1]
    assert out["routers"][0]["state"] == "recovering"
    assert out["routers"][0]["reason"].startswith("Better in the last 24h: 1 not connected")


def test_too_little_activity_after_a_fix_is_not_called_fixed():
    was_bad = [_paid(1, 48 + h, FAILED) for h in range(5)]
    row = pr.evaluate([_router(1)], [], was_bad + [_paid(1, 2)], NOW)["routers"][0]
    assert row["state"] == "recovering"
    assert row["reason"].startswith("Too little activity in the last 24h to confirm the fix")


def test_flapping_reachability_counts_drops_and_needs_attention():
    checks = []
    for i in range(20):  # alternating up/down over the last 20 hours
        checks.append((1, NOW - timedelta(hours=20 - i), i % 2 == 0))
    row = pr.evaluate([_router(1)], checks, [], NOW)["routers"][0]
    assert row["state"] == "attention"
    assert row["after"]["reach_pct"] == 50 and row["after"]["drops"] == 10
    assert row["reason"] == "Reachable 50% of the time in the last 24h (10 drops)"


def test_retrying_payments_are_not_counted_as_lost_or_first_try_failures():
    pending = [(1, NOW - timedelta(minutes=5), ProvisioningState.RETRY_PENDING, 3, None)] * 15
    out = pr.evaluate([_router(1)], [], pending, NOW)
    assert out["routers"] == []


def test_fleet_headline_compares_last_day_with_the_daily_average_before():
    attempts = [_paid(1, 2, FAILED)] * 4 + [_paid(1, 48, FAILED)] * 12
    out = pr.evaluate([_router(1)], [], attempts, NOW)
    assert out["paid_not_connected_24h"] == 4
    assert out["paid_not_connected_daily_avg_before"] == 2.0  # 12 over 6 days


@pytest.mark.asyncio
async def test_section_skips_suspended_resellers_and_caches(db):
    now = datetime.utcnow()
    active = await make_reseller(db)
    suspended = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    plan = await make_plan(db, active)
    bad = await make_router(db, active, name="lee net #2", ip_address="10.0.100.63",
                            management_tunnel="sstp", last_online_at=now,
                            management_tunnel_changed_at=now - timedelta(hours=6))
    cut_off = await make_router(db, suspended, ip_address="10.0.100.9", last_online_at=now)
    customer = await make_customer(db, active, plan, bad, status=CustomerStatus.ACTIVE)
    for r in (bad, cut_off):
        for h in (1, 2, 3):
            db.add(_attempt(customer, r, state=FAILED, created=now - timedelta(hours=h),
                            error="Failed to connect"))
    db.add(RouterAvailabilityCheck(router_id=bad.id, is_online=False, source="expired_cleanup",
                                   checked_at=now - timedelta(hours=1)))
    await db.commit()

    section = await pr.build_problem_routers_section(now)
    assert [r["router_id"] for r in section["routers"]] == [bad.id]
    row = section["routers"][0]
    assert row["state"] == "attention" and row["tunnel"] == "sstp"
    assert row["fix"]["label"] == "SSTP" and row["window"] == "since_fix"
    # The only availability row is an advisory cleanup probe, which is ignored.
    assert row["after"]["reach_pct"] is None
    assert section.get("cached") is None

    again = await pr.build_problem_routers_section(now + timedelta(minutes=2))
    assert again["cached"] is True


def test_one_bad_day_that_healed_itself_is_not_listed_but_a_fixed_router_is():
    healed = [_paid(1, 48, FAILED), _paid(1, 49, FAILED)] + [_paid(1, h) for h in range(1, 12)]
    moved = NOW - timedelta(days=1)
    fixed_router = _router(2, management_tunnel="sstp", changed_at=moved, tunnel="sstp")
    fixed = [_paid(2, 48, FAILED), _paid(2, 49, FAILED)] + [_paid(2, h) for h in range(1, 12)]
    out = pr.evaluate([_router(1), fixed_router], [], healed + fixed, NOW)
    assert [(r["router_id"], r["state"]) for r in out["routers"]] == [(2, "fixed")]


def test_routers_silent_for_the_whole_week_are_left_out_and_recent_outages_say_down():
    dead = _router(1, last_online_at=NOW - timedelta(days=9))
    down = _router(2, last_online_at=NOW - timedelta(hours=20))
    checks = [(rid, NOW - timedelta(hours=h), False) for rid in (1, 2) for h in range(1, 15)]
    out = pr.evaluate([dead, down], checks, [], NOW)
    assert [r["router_id"] for r in out["routers"]] == [2]
    assert out["routers"][0]["reason"] == "Down: no contact since 24 Sep 16:00 UTC"
