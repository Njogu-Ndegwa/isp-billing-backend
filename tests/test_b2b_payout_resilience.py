"""run_daily_payouts must finish the whole reseller list even when one payout fails.

Production incident (2026-06-09 23:59 UTC): one reseller's payout raised, the
except block's ``db.rollback()`` expired every reseller ORM object loaded into
the shared session, and the next loop iteration's ``reseller.id`` access tried
a synchronous attribute refresh on an AsyncSession — which raised, was caught,
raised AGAIN inside the except handler (which also logs ``reseller.id``), and
killed the whole job. Every reseller after the first failure was never paid.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.db.models import B2BTransaction, B2BTransactionStatus
from tests.factories import make_reseller

pytestmark = pytest.mark.asyncio


async def _make_scheduled_txn(db, reseller_id, *, age: timedelta, conversation_id: str):
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
        created_at=datetime.utcnow() - age,
    )
    db.add(txn)
    await db.commit()
    return txn


def _patch_payout_env(b2b, monkeypatch, session_factory):
    monkeypatch.setattr(b2b, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_DAILY_PAYOUT_ENABLED", True, raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "tester", raising=False)
    monkeypatch.setattr(
        b2b, "resolve_b2b_payment_method", AsyncMock(return_value=object())
    )
    attempted = []

    async def fake_payout(db_, reseller_id, payment_method, balance=None, triggered_by="manual"):
        attempted.append(reseller_id)
        return SimpleNamespace(
            status=B2BTransactionStatus.PENDING,
            amount=balance, net_amount=balance, fee=0, party_b="247247",
        )

    monkeypatch.setattr(b2b, "payout_reseller", fake_payout)
    return attempted


async def test_one_payout_failure_does_not_abort_remaining_resellers(
    engine, db, session_factory, monkeypatch
):
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    r2 = await make_reseller(db)
    r3 = await make_reseller(db)

    # run_daily_payouts binds AsyncSessionLocal at module import — point it at
    # the test engine (same expire_on_commit=False config as production).
    monkeypatch.setattr(b2b, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_DAILY_PAYOUT_ENABLED", True, raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "tester", raising=False)

    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=500.0))
    monkeypatch.setattr(
        b2b, "resolve_b2b_payment_method", AsyncMock(return_value=object())
    )

    attempted = []

    async def fake_payout(db_, reseller_id, payment_method, balance=None, triggered_by="manual"):
        attempted.append(reseller_id)
        if len(attempted) == 1:
            raise RuntimeError("simulated Safaricom 500 mid-run")
        return SimpleNamespace(
            status=B2BTransactionStatus.PENDING,
            amount=balance,
            net_amount=balance,
            fee=0,
            party_b="247247",
        )

    monkeypatch.setattr(b2b, "payout_reseller", fake_payout)

    # Must not raise, and every reseller must still be attempted after the
    # first one fails.
    await b2b.run_daily_payouts()

    assert sorted(attempted) == sorted([r1.id, r2.id, r3.id])


async def test_reseller_paid_by_last_nights_run_is_paid_again(
    engine, db, session_factory, monkeypatch
):
    """The 23:59 run crosses midnight, so last night's payouts land just AFTER
    midnight (created_at ~24h old at the next fire). The old calendar-day
    dedupe counted them as "already paid today" during the pre-midnight minute
    and mass-skipped legitimately-owed resellers (2026-07-15 incident). The
    rolling 20h window must leave them eligible."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    # Simulates the previous night's post-midnight payout: ~24h old by the
    # time tonight's run evaluates the reseller, but same calendar day when
    # the evaluation happens in the pre-midnight minute.
    await _make_scheduled_txn(db, r1.id, age=timedelta(hours=21), conversation_id="AG_prev_night")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=500.0))

    await b2b.run_daily_payouts()

    assert attempted == [r1.id]


async def test_reseller_paid_within_window_is_skipped(
    engine, db, session_factory, monkeypatch
):
    """Double-fire protection: a scheduled payout from earlier in the same
    night (well inside the 20h window) must still dedupe."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _make_scheduled_txn(db, r1.id, age=timedelta(hours=1), conversation_id="AG_same_night")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=500.0))

    await b2b.run_daily_payouts()

    assert attempted == []


async def test_balance_of_one_is_skipped_not_failed(
    engine, db, session_factory, monkeypatch
):
    """KES 1 can never net positive after the KES 1 Kadogo fee; it must be
    skipped instead of surfacing as a failed payout."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=1.0))

    await b2b.run_daily_payouts()

    assert attempted == []
