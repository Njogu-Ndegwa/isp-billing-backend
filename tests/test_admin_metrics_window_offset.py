"""Tests for panning the admin dashboard charts back through time.

The charts used to be permanently anchored to `now`: `period=30d` meant "the
30 days ending today" and there was no way to ask for any other 30 days. The
`offset` parameter walks the window backwards in whole windows so the dashboard
can be dragged into the past.

The two properties that matter, and that a careless refactor would break:

* offset 0 must be byte-for-byte the old behaviour, so nothing about today's
  dashboard changes;
* window N's comparison range must be window N+1's main range -- otherwise the
  "compare" overlay silently stops meaning "vs the period before this one" as
  soon as the user pans, which is the whole point of the feature.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import SubscriptionPayment, SubscriptionPaymentStatus
from app.services.admin_metrics import (
    MAX_PERIOD_OFFSET,
    _days_period_range,
    _period_days,
    _window_meta,
    compute_customer_signups_timeseries,
    compute_subscription_revenue_history,
)
from tests.factories import make_reseller

PERIODS = ["7d", "30d", "90d", "1y"]


# ---------------------------------------------------------------------------
# Window arithmetic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("period", PERIODS)
def test_offset_zero_is_the_live_window(period):
    """Offset 0 must reproduce the original now-anchored range exactly."""
    cur_start, cur_end, prev_start, prev_end = _days_period_range(period)
    days = _period_days(period)

    assert datetime.utcnow() - cur_end < timedelta(seconds=5)
    assert cur_end - cur_start == timedelta(days=days)
    assert prev_end == cur_start
    assert cur_start - prev_start == timedelta(days=days)


@pytest.mark.parametrize("period", PERIODS)
def test_offset_one_is_the_previous_window(period):
    """Panning back one step lands on the range offset 0 called 'previous'."""
    _, _, prev_start, prev_end = _days_period_range(period, 0)
    cur_start, cur_end, _, _ = _days_period_range(period, 1)

    assert abs((cur_start - prev_start).total_seconds()) < 5
    assert abs((cur_end - prev_end).total_seconds()) < 5


@pytest.mark.parametrize("period", PERIODS)
def test_windows_tile_without_gap_or_overlap(period):
    """Each step back must butt exactly against the one in front of it."""
    days = _period_days(period)
    for offset in range(0, 5):
        cur_start, cur_end, prev_start, prev_end = _days_period_range(period, offset)
        assert cur_end - cur_start == timedelta(days=days)
        # The comparison window is always the step behind this one.
        nxt_start, nxt_end, _, _ = _days_period_range(period, offset + 1)
        assert abs((nxt_end - prev_end).total_seconds()) < 5
        assert abs((nxt_start - prev_start).total_seconds()) < 5


def test_negative_offset_is_clamped_to_the_live_window():
    """Nothing should be able to pan into the future."""
    live = _days_period_range("30d", 0)
    clamped = _days_period_range("30d", -5)
    assert abs((clamped[1] - live[1]).total_seconds()) < 5


def test_window_meta_reports_inclusive_human_bounds():
    cur_start, cur_end, _, _ = _days_period_range("30d", 1)
    meta = _window_meta("30d", 1, cur_start, cur_end)

    assert meta["offset"] == 1
    assert meta["period_days"] == 30
    assert meta["max_offset"] == MAX_PERIOD_OFFSET
    assert meta["window_start"] == cur_start.date().isoformat()
    # Inclusive: the label must not advertise a day the data stops before.
    assert meta["window_end"] == (cur_end - timedelta(microseconds=1)).date().isoformat()
    assert meta["window_label"].startswith(cur_start.strftime("%b %d"))


# ---------------------------------------------------------------------------
# Subscription revenue history
# ---------------------------------------------------------------------------

async def _pay(db, user, amount: float, when: datetime):
    db.add(SubscriptionPayment(
        user_id=user.id,
        amount=amount,
        payment_method="mpesa",
        status=SubscriptionPaymentStatus.COMPLETED,
        created_at=when,
    ))
    await db.commit()


@pytest.mark.asyncio
async def test_panned_revenue_window_excludes_the_live_window(db):
    """Money earned this month must not leak into last month's view."""
    user = await make_reseller(db, created_at=datetime.utcnow() - timedelta(days=200))
    now = datetime.utcnow()

    await _pay(db, user, 1000.0, now - timedelta(days=5))    # live window
    await _pay(db, user, 400.0, now - timedelta(days=40))    # one step back

    live = await compute_subscription_revenue_history(db, period="30d", offset=0)
    back = await compute_subscription_revenue_history(db, period="30d", offset=1)

    assert live["total_revenue"] == 1000.0
    assert back["total_revenue"] == 400.0
    assert back["offset"] == 1
    assert back["window_end"] < live["window_start"] or back["window_end"] <= live["window_start"]


@pytest.mark.asyncio
async def test_compare_overlay_follows_the_panned_window(db):
    """`previous_period` must track the window being viewed, not always today.

    Viewing the -1 window with compare on should show the -2 window behind it.
    """
    user = await make_reseller(db, created_at=datetime.utcnow() - timedelta(days=200))
    now = datetime.utcnow()

    await _pay(db, user, 400.0, now - timedelta(days=40))    # window -1
    await _pay(db, user, 250.0, now - timedelta(days=70))    # window -2

    back = await compute_subscription_revenue_history(db, period="30d", offset=1)

    assert back["total_revenue"] == 400.0
    assert back["previous_total_revenue"] == 250.0


@pytest.mark.asyncio
async def test_panned_series_covers_the_whole_window(db):
    """Empty buckets still have to be emitted, or the axis silently compresses."""
    result = await compute_subscription_revenue_history(db, period="30d", offset=2)
    assert len(result["subscription_revenue_over_time"]) >= 30
    assert result["subscription_revenue_over_time"][0]["date"] == result["window_start"]


# ---------------------------------------------------------------------------
# Customer signups
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_customer_signups_window_is_offsettable(db):
    result = await compute_customer_signups_timeseries(db, period="7d", offset=3)
    live = await compute_customer_signups_timeseries(db, period="7d", offset=0)

    assert result["offset"] == 3
    assert result["period_days"] == 7
    assert result["window_start"] < live["window_start"]
