"""run_daily_payouts must finish the whole reseller list even when one payout fails.

Production incident (2026-06-09 23:59 UTC): one reseller's payout raised, the
except block's ``db.rollback()`` expired every reseller ORM object loaded into
the shared session, and the next loop iteration's ``reseller.id`` access tried
a synchronous attribute refresh on an AsyncSession — which raised, was caught,
raised AGAIN inside the except handler (which also logs ``reseller.id``), and
killed the whole job. Every reseller after the first failure was never paid.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.db.models import B2BTransactionStatus
from tests.factories import make_reseller

pytestmark = pytest.mark.asyncio


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
