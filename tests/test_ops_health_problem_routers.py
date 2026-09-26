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


def _waiting(rid, minutes_ago, state=ProvisioningState.RETRY_PENDING, tries=3):
    return (rid, NOW - timedelta(minutes=minutes_ago), state, tries, None)


def test_a_payment_still_retrying_within_the_grace_period_is_not_a_problem():
    out = pr.evaluate([_router(1)], [], [_waiting(1, 2)] * 3 + [_paid(1, 1)] * 5, NOW)
    assert out["routers"] == []
    assert out["waiting_now"] == 0 and out["waiting_routers"] == 0


def test_retrying_payments_are_waiting_customers_not_lost_or_first_try_failures():
    out = pr.evaluate([_router(1)], [], [_waiting(1, 20)] * 15, NOW)
    row = out["routers"][0]
    assert row["state"] == "attention" and row["waiting"] == 15
    assert row["after"]["lost"] == 0 and row["after"]["first_try_pct"] is None


def test_customers_paying_into_a_dead_tunnel_top_the_list_before_any_retry_gives_up():
    # 2026-09-25 RONGAI (448): WireGuard went silent 08:05 UTC while customers kept
    # paying; 23 sat in retry_pending, none failed yet, reachability still ~90% for
    # the day -- the card showed nothing. Now it leads the list.
    went_dark = NOW - timedelta(hours=2)
    rongai = _router(448, name="RONGAI", tunnel="wireguard", last_online_at=went_dark)
    checks = [(448, NOW - timedelta(minutes=30 * i), i > 4) for i in range(1, 40)]
    attempts = ([_paid(448, h) for h in range(3, 23)]
                + [_waiting(448, m) for m in (118, 100, 75, 40, 12)]
                + [_waiting(448, 3)])  # still inside the grace period
    lossy = [_paid(2, h, FAILED) for h in (1, 2, 3)]  # another router with lost payments
    out = pr.evaluate([_router(2), rongai], checks, attempts + lossy, NOW)
    assert [r["router_id"] for r in out["routers"]] == [448, 2]
    row = out["routers"][0]
    assert row["state"] == "attention" and row["waiting"] == 5
    assert row["reason"] == ("5 paid customers waiting to be connected (oldest 1h 58m)"
                             " · no contact since 25 Sep 10:00 UTC")
    assert row["oldest_waiting_at"] == "2026-09-25T10:02:00Z"
    assert out["waiting_now"] == 5 and out["waiting_routers"] == 1
    assert out["counts"]["attention"] == 2


def test_a_router_silent_for_a_week_is_still_listed_while_customers_pay_into_it():
    dead = _router(1, last_online_at=NOW - timedelta(days=9))
    out = pr.evaluate([dead], [], [_waiting(1, 30, state=ProvisioningState.IN_PROGRESS, tries=1)], NOW)
    assert out["routers"][0]["reason"] == ("1 paid customer waiting to be connected (oldest 30 min)"
                                           " · no contact since 16 Sep 12:00 UTC")


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


# --- on-demand windows: "is it still a problem in the last hour?" -------------

HOUR = timedelta(hours=1)


def test_a_fix_shows_within_the_hour_instead_of_waiting_a_day():
    # Flagged by the 24h card for 3 lost payments this morning; two clean
    # deliveries since the fix are enough to call it fixed in a 1h window.
    attempts = [_paid(1, 5, FAILED), _paid(1, 6, FAILED), _paid(1, 7, FAILED),
                _paid(1, 0.5), _paid(1, 0.2)]
    assert pr.evaluate([_router(1)], [], attempts, NOW)["routers"][0]["state"] == "attention"
    out = pr.evaluate([_router(1)], [], attempts, NOW, window=HOUR)
    row = out["routers"][0]
    assert row["state"] == "fixed" and row["window"] == "last_window"
    assert row["reason"] == "Clean in the last 1h: 2 payments, all connected (before: 3 not connected)"
    assert out["window_hours"] == 1 and out["window_label"] == "1h"


def test_a_quiet_hour_after_a_bad_morning_is_recovering_not_fixed():
    attempts = [_paid(1, 5, FAILED), _paid(1, 6, FAILED), _paid(1, 0.5)]
    row = pr.evaluate([_router(1)], [], attempts, NOW, window=HOUR)["routers"][0]
    assert row["state"] == "recovering"
    assert row["reason"].startswith("Too little activity in the last 1h to confirm the fix")


def test_a_short_window_keeps_ignoring_a_week_old_blip():
    # Healed two days ago; the 24h card does not list it, neither does the 1h view.
    healed = [_paid(1, 48, FAILED), _paid(1, 49, FAILED)] + [_paid(1, h) for h in range(1, 12)]
    assert pr.evaluate([_router(1)], [], healed, NOW, window=HOUR)["routers"] == []


def test_short_windows_scale_the_evidence_needed_to_judge_reachability():
    checks = [(1, NOW - timedelta(minutes=m), m == 50) for m in (10, 25, 40, 50)]  # 1 of 4 online
    assert pr.evaluate([_router(1)], checks, [], NOW)["routers"] == []  # 24h needs 12 checks
    row = pr.evaluate([_router(1)], checks, [], NOW, window=HOUR)["routers"][0]
    assert row["state"] == "attention"
    assert row["reason"] == "Reachable 25% of the time in the last 1h (1 drop)"
    assert pr.thresholds_for(HOUR) == pr.Thresholds(first_try_payments=5, reach_checks=4,
                                                    evidence_payments=2, evidence_checks=4)
    assert pr.thresholds_for(timedelta(hours=72)) == pr.DEFAULT_THRESHOLDS


def test_a_window_splits_on_a_tunnel_move_only_when_the_move_is_inside_it():
    before = [_paid(1, 5, FAILED), _paid(1, 6, FAILED)]
    after = [_paid(1, 0.4), _paid(1, 0.3), _paid(1, 0.1)]
    recent_move = _router(1, management_tunnel="sstp", changed_at=NOW - timedelta(minutes=45), tunnel="sstp")
    row = pr.evaluate([recent_move], [], before + after, NOW, window=HOUR)["routers"][0]
    assert row["window"] == "since_fix" and row["state"] == "fixed"
    assert row["reason"].startswith("Clean since the move to SSTP (25 Sep 11:15 UTC)")

    old_move = _router(1, management_tunnel="sstp", changed_at=NOW - timedelta(days=2), tunnel="sstp")
    row = pr.evaluate([old_move], [], before + after, NOW, window=HOUR)["routers"][0]
    assert row["window"] == "last_window" and row["fix"]["label"] == "SSTP"
    assert row["reason"].startswith("Clean in the last 1h: 3 payments")


def test_window_headline_compares_with_the_average_window_before():
    attempts = [_paid(1, 2, FAILED)] * 3 + [_paid(1, 30, FAILED)] * 12
    out = pr.evaluate([_router(1)], [], attempts, NOW, window=timedelta(hours=6))
    assert out["paid_not_connected_window"] == 3
    assert out["paid_not_connected_avg_before"] == 0.4  # 12 over 27 six-hour windows
    assert out["paid_not_connected_24h"] == 3  # the fixed-day figures are still there
    assert out["window_label"] == "6h"
    assert pr.window_label(timedelta(hours=72)) == "3 days"


def test_window_criteria_spell_out_the_scaled_thresholds():
    rules = " ".join(pr.criteria(HOUR))
    assert "in the last 1h" in rules
    assert "once 5+ payments" in rules and "once 4+ checks" in rules
    assert "at least 2 payments or 4 checks" in rules
    assert "once 10+ payments" in " ".join(pr.criteria())
    assert "criteria" not in pr.evaluate([_router(1)], [], [], NOW)  # kept out of stored snapshots


@pytest.mark.asyncio
async def test_window_build_clamps_hours_and_shares_one_read(db, monkeypatch):
    now = datetime.utcnow()
    reads = []
    real = pr.database.async_session

    def counting():
        reads.append(1)
        return real()
    monkeypatch.setattr(pr.database, "async_session", counting)
    one = await pr.build_problem_routers_window(now, 0)
    three_days = await pr.build_problem_routers_window(now + timedelta(seconds=5), 500)
    assert one["window_hours"] == 1 and three_days["window_hours"] == 72
    assert len(reads) == 1
    await pr.build_problem_routers_window(now + timedelta(minutes=2), 6)
    assert len(reads) == 2
