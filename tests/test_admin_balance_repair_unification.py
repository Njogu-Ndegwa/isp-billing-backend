"""Admin balance helpers and the repair-balance flow must speak the canonical
payout formula (mpesa_b2b.PAYOUT_REVENUE_FILTERS).

History: mpesa_b2b.get_unpaid_balance (the number the nightly B2B job and the
self-service withdrawal actually PAY) and the reseller statement were fixed to
exclude DIRECT-collected / non-COMPLETED / non-revenue rows. The admin module
kept its own bare MOBILE_MONEY copies (`_mpesa_revenue`, `_unpaid_balance`)
feeding the admin displays AND the repair-balance flow — which WRITES
`ResellerFinancials.balance_correction`, a term inside get_unpaid_balance.
A repair computed on the bare formula therefore corrupts the paid-out number:
e.g. a DIRECT row dated before the last payout inflates the bare raw_balance
and makes the repair UNDER-correct the canonical balance.

Safety analysis backing the unification (verified in code):
  * `_apply_repair` is the ONLY writer of balance_correction and it OVERWRITES
    (never accumulates), so re-running repair with the new formula cannot
    double-correct historical corrections — it simply recomputes the one
    correction that makes the canonical formula agree with
    payments-since-last-payout truth.
  * Both repair endpoints write only when proposed_correction > 0.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.admin_reseller_routes import (
    _apply_repair,
    _compute_repair,
    _mpesa_revenue as admin_mpesa_revenue,
    _unpaid_balance as admin_unpaid_balance,
)
from app.db.models import (
    CollectionMode,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    ResellerFinancials,
    ResellerPayout,
    ResellerTransactionCharge,
    User,
)
from app.services.mpesa_b2b import get_unpaid_balance
from tests.factories import make_reseller

pytestmark = pytest.mark.asyncio


async def _add_payment(
    db: AsyncSession,
    reseller: User,
    amount: float,
    *,
    created_at: datetime,
    payment_method: PaymentMethod = PaymentMethod.MOBILE_MONEY,
    status: PaymentStatus = PaymentStatus.COMPLETED,
    collection_mode: CollectionMode | None = None,
    counts_as_revenue: bool = True,
) -> CustomerPayment:
    payment = CustomerPayment(
        customer_id=None,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=payment_method,
        payment_date=created_at,
        created_at=created_at,
        days_paid_for=30,
        status=status,
        collection_mode=collection_mode,
        counts_as_revenue=counts_as_revenue,
    )
    db.add(payment)
    await db.commit()
    return payment


async def _add_payout(db: AsyncSession, reseller: User, amount: float, *, created_at: datetime):
    payout = ResellerPayout(
        reseller_id=reseller.id, amount=amount, payment_method="mpesa",
        created_at=created_at,
    )
    db.add(payout)
    await db.commit()
    return payout


async def _add_charge(db: AsyncSession, reseller: User, amount: float, *, created_at: datetime):
    charge = ResellerTransactionCharge(
        reseller_id=reseller.id, amount=amount, description="test charge",
        created_by=reseller.id, created_at=created_at,
    )
    db.add(charge)
    await db.commit()
    return charge


async def _messy_reseller(db: AsyncSession) -> User:
    """A reseller with every row shape the canonical filter must handle:
    normal + DIRECT + pending + comp(non-revenue) rows, a payout, a charge,
    and an existing balance correction."""
    now = datetime.utcnow()
    r = await make_reseller(db)
    await _add_payment(db, r, 500.0, created_at=now - timedelta(days=3))
    await _add_payment(  # DIRECT: reseller's own paybill — platform never held it
        db, r, 300.0, created_at=now - timedelta(days=3),
        collection_mode=CollectionMode.DIRECT,
    )
    await _add_payment(  # pending STK — not revenue yet
        db, r, 400.0, created_at=now - timedelta(days=2),
        status=PaymentStatus.PENDING,
    )
    await _add_payment(  # comp voucher shape — zero-revenue
        db, r, 200.0, created_at=now - timedelta(days=2),
        payment_method=PaymentMethod.CASH, counts_as_revenue=False,
    )
    await _add_payment(db, r, 250.0, created_at=now - timedelta(days=1))
    await _add_payout(db, r, 100.0, created_at=now - timedelta(days=2))
    await _add_charge(db, r, 25.0, created_at=now - timedelta(days=1))
    db.add(ResellerFinancials(user_id=r.id, balance_correction=50.0))
    await db.commit()
    return r


# ---------------------------------------------------------------------------
# 1. Admin display helpers == canonical payout formula
# ---------------------------------------------------------------------------

async def test_admin_unpaid_balance_equals_canonical_for_messy_reseller(db):
    r = await _messy_reseller(db)

    canonical = await get_unpaid_balance(db, r.id)
    admin_value = await admin_unpaid_balance(db, r.id)

    # Canonical revenue: 500 + 250 (DIRECT/pending/comp excluded) = 750
    # Balance: 750 + 50 correction - 100 payout - 25 charge = 675
    assert canonical == 675.0
    assert admin_value == canonical


async def test_admin_mpesa_revenue_uses_canonical_filters(db):
    r = await _messy_reseller(db)
    # 500 + 250; the DIRECT 300, pending 400 and comp 200 must not count.
    assert await admin_mpesa_revenue(db, r.id) == 750.0


# ---------------------------------------------------------------------------
# 2. Repair flow computes against the canonical number
# ---------------------------------------------------------------------------

async def test_repair_correction_restores_canonical_balance_after_deletes(db):
    """The classic corruption: pre-payout payment rows were cascade-deleted,
    so raw balance is far below the truth. The repair must compute against
    CANONICAL revenue — a DIRECT row dated before the last payout previously
    inflated the bare raw_balance and made the repair under-correct."""
    now = datetime.utcnow()
    r = await make_reseller(db)

    # DIRECT row BEFORE the last payout: never platform money. Under the old
    # bare filter it added +300 to raw_balance => correction shrank by 300.
    await _add_payment(
        db, r, 300.0, created_at=now - timedelta(days=10),
        collection_mode=CollectionMode.DIRECT,
    )
    # The payout that settled the (now-deleted) historical revenue.
    await _add_payout(db, r, 450.0, created_at=now - timedelta(days=5))
    # Post-payout revenue the platform actually holds.
    await _add_payment(db, r, 500.0, created_at=now - timedelta(days=1))

    info = await _compute_repair(db, r.id)

    # Canonical truth since last payout: 500. Canonical raw: 500 - 450 = 50.
    assert info["true_unpaid_balance"] == 500.0
    assert info["raw_balance"] == 50.0
    assert info["proposed_correction"] == 450.0
    assert info["needs_repair"] is True

    await _apply_repair(db, r.id, info["proposed_correction"])
    await db.commit()

    # The whole point of the repair: the canonical (paid-out) balance now
    # equals the payments-since-last-payout truth.
    assert await get_unpaid_balance(db, r.id) == 500.0
    assert await admin_unpaid_balance(db, r.id) == 500.0


async def test_repair_true_unpaid_excludes_direct_pending_comp_since_payout(db):
    """DIRECT/pending/comp rows since the last payout are not platform-held
    revenue: they must not appear in the repair's 'true unpaid' target."""
    now = datetime.utcnow()
    r = await make_reseller(db)

    await _add_payout(db, r, 100.0, created_at=now - timedelta(days=5))
    await _add_payment(db, r, 500.0, created_at=now - timedelta(days=1))
    await _add_payment(
        db, r, 300.0, created_at=now - timedelta(days=1),
        collection_mode=CollectionMode.DIRECT,
    )
    await _add_payment(
        db, r, 400.0, created_at=now - timedelta(days=1),
        status=PaymentStatus.PENDING,
    )
    await _add_payment(
        db, r, 200.0, created_at=now - timedelta(days=1),
        payment_method=PaymentMethod.CASH, counts_as_revenue=False,
    )

    info = await _compute_repair(db, r.id)
    assert info["true_unpaid_balance"] == 500.0


# ---------------------------------------------------------------------------
# 3. Already-correct resellers are left alone
# ---------------------------------------------------------------------------

async def test_already_correct_reseller_gets_no_correction(db):
    """Settled at last payout + fresh revenue since: raw == truth, so the
    repair proposes 0 and writes nothing — even with DIRECT/pending noise."""
    now = datetime.utcnow()
    r = await make_reseller(db)

    # Period 1: 500 revenue, settled by 450 payout + 50 charge.
    await _add_payment(db, r, 500.0, created_at=now - timedelta(days=10))
    await _add_charge(db, r, 50.0, created_at=now - timedelta(days=6))
    await _add_payout(db, r, 450.0, created_at=now - timedelta(days=5))
    # Period 2: fresh canonical revenue + non-platform noise.
    await _add_payment(db, r, 500.0, created_at=now - timedelta(days=1))
    await _add_payment(
        db, r, 300.0, created_at=now - timedelta(days=1),
        collection_mode=CollectionMode.DIRECT,
    )
    await _add_payment(
        db, r, 400.0, created_at=now - timedelta(days=1),
        status=PaymentStatus.PENDING,
    )

    balance_before = await get_unpaid_balance(db, r.id)
    assert balance_before == 500.0

    info = await _compute_repair(db, r.id)
    assert info["proposed_correction"] == 0.0
    assert info["needs_repair"] is False

    # Nothing was persisted (the endpoints only write when > 0).
    fin = (await db.execute(
        select(ResellerFinancials).where(ResellerFinancials.user_id == r.id)
    )).scalar_one_or_none()
    assert fin is None or float(fin.balance_correction or 0) == 0.0
    assert await get_unpaid_balance(db, r.id) == balance_before


async def test_repair_is_idempotent_for_previously_repaired_reseller(db):
    """balance_correction is OVERWRITTEN, not accumulated: re-running the
    repair on unchanged data recomputes the same value and the canonical
    balance does not move — no double-correction."""
    now = datetime.utcnow()
    r = await make_reseller(db)
    await _add_payout(db, r, 450.0, created_at=now - timedelta(days=5))
    await _add_payment(db, r, 500.0, created_at=now - timedelta(days=1))

    first = await _compute_repair(db, r.id)
    await _apply_repair(db, r.id, first["proposed_correction"])
    await db.commit()
    balance_after_first = await get_unpaid_balance(db, r.id)

    second = await _compute_repair(db, r.id)
    assert second["proposed_correction"] == first["proposed_correction"]
    assert second["existing_correction"] == first["proposed_correction"]
    await _apply_repair(db, r.id, second["proposed_correction"])
    await db.commit()

    assert await get_unpaid_balance(db, r.id) == balance_after_first == 500.0
