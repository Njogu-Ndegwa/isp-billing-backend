"""Frozen-wall-clock pins for the 23:59 UTC payout boundary and expiry math.

The nightly B2B job fires at 23:59 UTC and crosses midnight mid-loop. Its
dedupe window is a rolling 20h window anchored ONCE at run start
(``run_anchor = datetime.utcnow()`` in ``mpesa_b2b.run_daily_payouts``) —
NOT a per-reseller "paid today?" calendar check. The calendar version caused
the 2026-07-15 mass-skip: last night's payouts land a few minutes AFTER
midnight, so during tonight's pre-midnight minute they look like "already
paid today" and everyone silently skips.

Unlike tests/test_b2b_payout_resilience.py (which back-dates ``created_at``
by hand), these tests freeze the actual wall clock with time_machine, so the
ORM default ``created_at=datetime.utcnow`` stamps the real boundary times and
the window math is asserted against genuine frozen now — including the run
itself crossing midnight mid-loop.

time_machine (not freezegun) is deliberate: SQLAlchemy captured a direct
reference to ``datetime.utcnow`` in the column default at import time.
freezegun swaps the ``datetime`` class and misses that saved reference;
time_machine patches the clock underneath it, so the default is truly frozen.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import time_machine

from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    CustomerStatus,
    DurationUnit,
    PaymentMethod,
)
from app.services.reseller_payments import record_customer_payment
from tests.factories import make_customer, make_plan, make_reseller

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _scheduled_completed_txn(db, reseller_id: int, conversation_id: str):
    """A COMPLETED scheduled payout stamped at the CURRENT (frozen) clock —
    created_at comes from the ORM default, never hand-set."""
    txn = B2BTransaction(
        reseller_id=reseller_id,
        conversation_id=conversation_id,
        amount=100.0,
        fee=5.0,
        net_amount=95.0,
        party_a="4159825",
        party_b="247247",
        status=B2BTransactionStatus.COMPLETED,
        triggered_by="scheduled",
    )
    db.add(txn)
    await db.commit()
    await db.refresh(txn)
    return txn


def _patch_payout_env(b2b, monkeypatch, session_factory, on_payout=None):
    monkeypatch.setattr(b2b, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_DAILY_PAYOUT_ENABLED", True, raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "tester", raising=False)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=500.0))
    monkeypatch.setattr(b2b, "resolve_b2b_payment_method", AsyncMock(return_value=object()))

    attempted = []

    async def fake_payout(db_, reseller_id, payment_method, balance=None, triggered_by="manual"):
        attempted.append(reseller_id)
        if on_payout is not None:
            on_payout(reseller_id)
        return SimpleNamespace(
            status=B2BTransactionStatus.PENDING,
            amount=balance, net_amount=balance, fee=0, party_b="247247",
        )

    monkeypatch.setattr(b2b, "payout_reseller", fake_payout)
    return attempted


# ---------------------------------------------------------------------------
# 20h dedupe window at the 23:59 boundary (incident 2026-07-15)
# ---------------------------------------------------------------------------

async def test_reseller_paid_by_yesterdays_2359_run_is_paid_again_tonight(
    engine, db, session_factory, monkeypatch
):
    """Yesterday's run paid at 23:59; tonight at 23:59 the reseller is owed
    again and MUST be paid — that payout is ~24h old, outside the 20h window.

    Includes the exact mass-skip shape: yesterday's run crossed midnight, so
    one reseller's payout is stamped a few minutes into TODAY's calendar day.
    A calendar "paid today?" check skips them (the incident); the run-anchored
    rolling window must not.
    """
    from app.services import mpesa_b2b as b2b

    r_pre = await make_reseller(db)   # paid yesterday 23:59:30 (pre-midnight)
    r_post = await make_reseller(db)  # paid "yesterday" but stamped 00:03 today

    with time_machine.travel("2026-07-23 23:59:30 +0000", tick=False):
        assert datetime.utcnow() == datetime(2026, 7, 23, 23, 59, 30)
        txn = await _scheduled_completed_txn(db, r_pre.id, "AG_prev_run_premidnight")
        # The ORM default (a saved reference to datetime.utcnow) stamped the
        # frozen clock — this is why time_machine and not freezegun.
        assert txn.created_at == datetime(2026, 7, 23, 23, 59, 30)

    with time_machine.travel("2026-07-24 00:03:00 +0000", tick=False):
        # Same nightly run, landed after midnight — TODAY's calendar date.
        await _scheduled_completed_txn(db, r_post.id, "AG_prev_run_postmidnight")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)

    with time_machine.travel("2026-07-24 23:59:00 +0000", tick=False):
        # window_start = 23:59 - 20h = 03:59 today; both prior payouts predate it.
        await b2b.run_daily_payouts()

    assert sorted(attempted) == sorted([r_pre.id, r_post.id])


async def test_reseller_paid_one_hour_ago_is_not_repaid(
    engine, db, session_factory, monkeypatch
):
    """A payout from 22:59 tonight is inside the 20h window at 23:59 — the
    nightly run must dedupe it, not double-pay."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)

    with time_machine.travel("2026-07-24 22:59:00 +0000", tick=False):
        await _scheduled_completed_txn(db, r1.id, "AG_one_hour_ago")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)

    with time_machine.travel("2026-07-24 23:59:00 +0000", tick=False):
        await b2b.run_daily_payouts()

    assert attempted == []


async def test_window_stays_anchored_while_run_crosses_midnight(
    engine, db, session_factory, monkeypatch
):
    """The run starts at 23:59 and the clock rolls past midnight between
    resellers. The dedupe window is computed ONCE from run_anchor, so a
    reseller evaluated at 00:01 (new calendar day) gets the same verdict as
    one evaluated at 23:59 — both owed, both paid. A per-reseller
    "start of today" recomputation flips at midnight; this pins it out."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    r2 = await make_reseller(db)

    # Both were last paid by yesterday's run, stamped just after midnight
    # today (~23.9h before tonight's run — outside the 20h window).
    with time_machine.travel("2026-07-24 00:03:00 +0000", tick=False):
        await _scheduled_completed_txn(db, r1.id, "AG_r1_last_night")
        await _scheduled_completed_txn(db, r2.id, "AG_r2_last_night")

    traveller = time_machine.travel("2026-07-24 23:59:00 +0000", tick=False)
    frozen = traveller.start()
    try:
        # After each payout the clock jumps 2 minutes, so the second reseller
        # is evaluated at ~00:01 on 2026-07-25 — across midnight.
        attempted = _patch_payout_env(
            b2b, monkeypatch, session_factory,
            on_payout=lambda _rid: frozen.shift(timedelta(minutes=2)),
        )
        await b2b.run_daily_payouts()
    finally:
        traveller.stop()

    assert sorted(attempted) == sorted([r1.id, r2.id])


# ---------------------------------------------------------------------------
# Expiry extension in record_customer_payment with frozen now
# ---------------------------------------------------------------------------

async def test_expiry_extension_math_with_frozen_clock(engine, db):
    """Exact expiry arithmetic, provable only with a frozen clock:

    * expired customer  -> expiry = frozen_now + plan duration (exactly)
    * active customer   -> expiry = old_expiry + plan duration (stacked, not
      restarted from now)
    """
    reseller = await make_reseller(db)
    plan = await make_plan(
        db, reseller, duration_value=30, duration_unit=DurationUnit.DAYS, price=500
    )

    frozen_now = datetime(2026, 7, 24, 23, 59, 0)
    active_until = datetime(2026, 7, 26, 12, 0, 0)  # 1.5 days of paid time left

    expired_cust = await make_customer(
        db, reseller, plan,
        status=CustomerStatus.INACTIVE,
        expiry=datetime(2026, 7, 23, 23, 59, 0),  # lapsed a day before frozen_now
    )
    active_cust = await make_customer(
        db, reseller, plan,
        status=CustomerStatus.ACTIVE,
        expiry=active_until,
    )

    with time_machine.travel(frozen_now, tick=False):
        await record_customer_payment(
            db=db, customer_id=expired_cust.id, reseller_id=reseller.id,
            amount=500.0, payment_method=PaymentMethod.MOBILE_MONEY,
            days_paid_for=30,
        )
        await record_customer_payment(
            db=db, customer_id=active_cust.id, reseller_id=reseller.id,
            amount=500.0, payment_method=PaymentMethod.MOBILE_MONEY,
            days_paid_for=30,
        )

    await db.refresh(expired_cust)
    await db.refresh(active_cust)

    # Expired: restarts from the frozen wall clock — to the second.
    assert expired_cust.expiry == frozen_now + timedelta(days=30)
    assert expired_cust.status == CustomerStatus.ACTIVE

    # Active: stacks on the remaining time, does NOT restart from now.
    assert active_cust.expiry == active_until + timedelta(days=30)
    assert active_cust.status == CustomerStatus.ACTIVE
