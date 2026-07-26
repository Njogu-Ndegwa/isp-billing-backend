"""Regression tests for the admin dashboard headline metrics.

Each test pins one of the defects found in the 2026-07-26 audit of the ARPU,
Active Resellers and Churn Rate cards:

* expired free trials were counted as churn (they are failed conversions);
* the churn denominator counted resellers who signed up *during* the period;
* ARPU used a different denominator formula for the current and prior periods,
  which reported a ~+316% jump that was entirely an artefact;
* the Active Resellers trend tracked cumulative registrations, a counter that
  only ever rises, while the card value tracked live subscriptions.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    SubscriptionPayment,
    SubscriptionPaymentStatus,
    SubscriptionStatus,
)
from app.services.admin_metrics import (
    compute_arpu,
    compute_churn,
    compute_dashboard_v2_extras,
    get_growth_targets,
)
from tests.factories import make_reseller

# Every assertion below places events inside the elapsed part of the current
# month. Right at the month boundary that window is empty, so there is nothing
# meaningful to assert.
_NOW = datetime.utcnow()
pytestmark = pytest.mark.skipif(
    _NOW - datetime(_NOW.year, _NOW.month, 1) < timedelta(hours=2),
    reason="needs a few hours elapsed in the current month to place test events",
)


def _windows():
    """(cur_start, now, prev_start, mid, prev_mid) for the current month."""
    now = datetime.utcnow()
    cur_start = datetime(now.year, now.month, 1)
    prev_start = (
        datetime(now.year - 1, 12, 1) if now.month == 1
        else datetime(now.year, now.month - 1, 1)
    )
    elapsed = now - cur_start
    return cur_start, now, prev_start, cur_start + elapsed / 2, prev_start + elapsed / 2


async def _pay(db, user, amount: float, when: datetime):
    db.add(SubscriptionPayment(
        user_id=user.id,
        amount=amount,
        payment_method="mpesa",
        status=SubscriptionPaymentStatus.COMPLETED,
        created_at=when,
    ))
    await db.commit()


async def _paying_subscriber(db, *, expires: datetime, status, paid_at: datetime,
                             created: datetime, amount: float = 500.0):
    user = await make_reseller(
        db, created_at=created, subscription_status=status,
        subscription_expires_at=expires,
    )
    await _pay(db, user, amount, paid_at)
    return user


async def _trial(db, *, created: datetime, expires: datetime, status):
    return await make_reseller(
        db, created_at=created, subscription_status=status,
        subscription_expires_at=expires,
    )


# ---------------------------------------------------------------------------
# Churn
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_expired_trial_is_not_counted_as_churn(db):
    """A trial that lapsed without ever paying is a failed conversion, not churn.

    Both land in SUSPENDED, so the only thing separating them is payment history.
    """
    cur_start, now, prev_start, mid, _ = _windows()

    lapsed_payer = await _paying_subscriber(
        db, created=prev_start - timedelta(days=10), paid_at=prev_start,
        expires=mid, status=SubscriptionStatus.SUSPENDED,
    )
    await _trial(
        db, created=mid - timedelta(hours=1), expires=mid,
        status=SubscriptionStatus.SUSPENDED,
    )

    result = await compute_churn(db)

    assert result["churned_count"] == 1
    assert [r["id"] for r in result["churned_resellers"]] == [lapsed_payer.id]
    assert result["churned_resellers"][0]["reason"] == "paid_subscription_lapsed"

    assert result["trial_expiry_count"] == 1
    assert result["trial_expiries"][0]["reason"] == "trial_expired_never_paid"


@pytest.mark.asyncio
async def test_churn_denominator_excludes_mid_period_signups(db):
    """Resellers who signed up this month must not sit in the period-start base."""
    cur_start, now, prev_start, mid, _ = _windows()
    before = prev_start - timedelta(days=5)
    future = now + timedelta(days=30)

    for _ in range(2):
        await _paying_subscriber(
            db, created=before, paid_at=prev_start, expires=future,
            status=SubscriptionStatus.ACTIVE,
        )
    await _paying_subscriber(
        db, created=before, paid_at=prev_start, expires=mid,
        status=SubscriptionStatus.SUSPENDED,
    )
    for _ in range(5):
        await _trial(db, created=mid, expires=future, status=SubscriptionStatus.TRIAL)

    result = await compute_churn(db)

    # Three paying subscribers existed on the 1st; the five new trials do not
    # belong in a "at period start" figure.
    assert result["total_at_period_start"] == 3
    assert result["churned_count"] == 1
    assert result["churn_rate"] == pytest.approx(33.33, abs=0.01)
    assert result["new_resellers"] == 5


@pytest.mark.asyncio
async def test_trial_expiry_rate_cannot_exceed_100_percent(db):
    """Trials that start and expire inside the window still need a sane rate."""
    cur_start, now, prev_start, mid, _ = _windows()

    for _ in range(4):
        await _trial(
            db, created=mid - timedelta(hours=1), expires=mid,
            status=SubscriptionStatus.SUSPENDED,
        )

    result = await compute_churn(db)

    assert result["trial_expiry_count"] == 4
    assert result["trials_at_risk"] >= result["trial_expiry_count"]
    assert 0 <= result["trial_expiry_rate"] <= 100


@pytest.mark.asyncio
async def test_churn_reports_zero_without_claiming_data(db):
    """No paying cohort means "no data", not a reassuring 0% churn."""
    result = await compute_churn(db)

    assert result["churn_rate"] == 0.0
    assert result["insufficient_data"] is True


# ---------------------------------------------------------------------------
# ARPU
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_arpu_uses_one_denominator_definition_for_both_periods(db):
    """The +316% artefact: prior-period denominator swept in lapsed resellers.

    A reseller who lost access before the previous window closed was subscribed
    in neither period and must be absent from both denominators.
    """
    cur_start, now, prev_start, mid, prev_mid = _windows()
    future = now + timedelta(days=30)

    await _paying_subscriber(
        db, created=prev_start - timedelta(days=20),
        paid_at=prev_start - timedelta(days=1), expires=future,
        status=SubscriptionStatus.ACTIVE, amount=1000.0,
    )
    # Paid once, then lapsed part-way through the previous window.
    await _paying_subscriber(
        db, created=prev_start - timedelta(days=20),
        paid_at=prev_start - timedelta(days=1), expires=prev_mid,
        status=SubscriptionStatus.SUSPENDED, amount=1000.0,
    )

    result = await compute_arpu(db)

    assert result["paying_subscribers"] == 1
    assert result["previous_paying_subscribers"] == 1


@pytest.mark.asyncio
async def test_arpu_excludes_trials_from_headline_denominator(db):
    """Trials pay nothing by definition, so they must not dilute the headline."""
    cur_start, now, prev_start, mid, _ = _windows()
    future = now + timedelta(days=30)

    await _paying_subscriber(
        db, created=prev_start, paid_at=mid, expires=future,
        status=SubscriptionStatus.ACTIVE, amount=800.0,
    )
    for _ in range(3):
        await _trial(db, created=prev_start, expires=future,
                     status=SubscriptionStatus.TRIAL)

    result = await compute_arpu(db)

    assert result["paying_subscribers"] == 1
    assert result["subscribers_including_trials"] == 4
    assert result["current_arpu"] == pytest.approx(800.0)
    assert result["arpu_including_trials"] == pytest.approx(200.0)


# ---------------------------------------------------------------------------
# Active Resellers card
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_active_reseller_trend_tracks_subscriptions_not_registrations(db):
    """Registrations only ever rise; the card's trend must follow the live base."""
    cur_start, now, prev_start, mid, _ = _windows()
    future = now + timedelta(days=30)

    await _paying_subscriber(
        db, created=prev_start - timedelta(days=15),
        paid_at=prev_start - timedelta(days=10), expires=future,
        status=SubscriptionStatus.ACTIVE,
    )
    # A wave of signups this month whose trials have already lapsed.
    for _ in range(10):
        await _trial(db, created=mid - timedelta(hours=2), expires=mid,
                     status=SubscriptionStatus.SUSPENDED)

    extras = await compute_dashboard_v2_extras(db)
    deltas = extras["growth_deltas"]

    assert extras["active_subscribers_now"] == 1
    assert extras["active_subscribers_prev_month"] == 1
    assert deltas["resellers_change_percent"] == 0.0
    # The old cumulative-registration signal stays available, clearly named.
    assert deltas["registered_resellers_change_percent"] > 0


# ---------------------------------------------------------------------------
# Cross-card consistency
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_growth_target_churn_matches_the_churn_card(db):
    """One churn definition for the whole dashboard."""
    cur_start, now, prev_start, mid, _ = _windows()
    future = now + timedelta(days=30)

    await _paying_subscriber(
        db, created=prev_start, paid_at=prev_start, expires=future,
        status=SubscriptionStatus.ACTIVE,
    )
    await _paying_subscriber(
        db, created=prev_start, paid_at=prev_start, expires=mid,
        status=SubscriptionStatus.SUSPENDED,
    )

    churn = await compute_churn(db)
    targets = await get_growth_targets(db)
    churn_target = next(t for t in targets["targets"] if t["id"] == "churn_target")

    assert churn_target["current_value"] == pytest.approx(churn["churn_rate"])
