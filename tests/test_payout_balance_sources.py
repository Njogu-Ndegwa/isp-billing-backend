"""Payout-balance source invariants for get_unpaid_balance (app/services/mpesa_b2b.py).

get_unpaid_balance drives real money movement: the nightly B2B job and the
reseller self-service withdrawal both pay out exactly this number
(payout_reseller / b2b_routes). The platform only owes a reseller money the
PLATFORM actually collected on their behalf, so the revenue side must count a
CustomerPayment only when ALL of:

  * payment_method == MOBILE_MONEY   (cash/voucher money never reached us)
  * status == COMPLETED              (pending/failed/refunded is not revenue)
  * counts_as_revenue is True        (compensation vouchers are zero-revenue)
  * collection_mode is not DIRECT    (DIRECT = paid straight into the
                                      reseller's OWN paybill/till, e.g. C2B to
                                      a reseller-registered shortcode — the
                                      platform never held that money and must
                                      not pay it out a second time)

collection_mode is NULL on legacy rows and on system-credential STK payments
(only the C2B paths stamp it), so NULL must keep counting as system-collected;
excluding NULL would wipe every reseller's historical balance.
"""

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    CollectionMode,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    User,
)
from app.services.mpesa_b2b import get_unpaid_balance
from tests.factories import make_reseller


async def _add_payment(
    db: AsyncSession,
    reseller: User,
    amount: float,
    *,
    payment_method: PaymentMethod = PaymentMethod.MOBILE_MONEY,
    status: PaymentStatus = PaymentStatus.COMPLETED,
    collection_mode: CollectionMode | None = CollectionMode.SYSTEM_COLLECTED,
    counts_as_revenue: bool = True,
    reference: str | None = None,
) -> CustomerPayment:
    # customer_id is intentionally NULL — payment history legitimately outlives
    # customer deletion (SET NULL), and the balance must not depend on it.
    payment = CustomerPayment(
        customer_id=None,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=payment_method,
        payment_reference=reference,
        payment_date=datetime.utcnow(),
        days_paid_for=30,
        status=status,
        collection_mode=collection_mode,
        counts_as_revenue=counts_as_revenue,
    )
    db.add(payment)
    await db.commit()
    return payment


async def test_includes_system_collected_completed_mobile_money(db):
    reseller = await make_reseller(db)
    await _add_payment(db, reseller, 500.0)

    assert await get_unpaid_balance(db, reseller.id) == 500.0


async def test_includes_legacy_rows_with_null_collection_mode(db):
    """Legacy/STK rows have collection_mode NULL (only the C2B paths stamp it).

    NULL must count as system-collected: a strict `== SYSTEM_COLLECTED` filter
    would zero out every reseller's pre-C2B balance overnight.
    """
    reseller = await make_reseller(db)
    await _add_payment(db, reseller, 250.0, collection_mode=None)

    assert await get_unpaid_balance(db, reseller.id) == 250.0


async def test_excludes_direct_collected_payment(db):
    """C2B to a reseller-registered shortcode lands in the RESELLER's paybill.

    The platform never held that money; counting it would make the B2B job pay
    the reseller a second time out of platform funds.
    """
    reseller = await make_reseller(db)
    await _add_payment(db, reseller, 500.0, reference="PLATFORM-C2B")
    await _add_payment(
        db, reseller, 300.0,
        collection_mode=CollectionMode.DIRECT,
        reference="RESELLER-OWN-PAYBILL-C2B",
    )

    assert await get_unpaid_balance(db, reseller.id) == 500.0


async def test_excludes_non_completed_payments(db):
    reseller = await make_reseller(db)
    await _add_payment(db, reseller, 500.0)
    await _add_payment(db, reseller, 400.0, status=PaymentStatus.PENDING)
    await _add_payment(db, reseller, 100.0, status=PaymentStatus.FAILED)
    await _add_payment(db, reseller, 50.0, status=PaymentStatus.REFUNDED)

    assert await get_unpaid_balance(db, reseller.id) == 500.0


async def test_excludes_non_revenue_payments(db):
    """Compensation vouchers are zero-revenue.

    In production they are recorded as CASH (voucher_service), which the
    mobile-money filter already excludes — but the balance must respect
    counts_as_revenue on its own, not by accident of the payment method.
    """
    reseller = await make_reseller(db)
    await _add_payment(db, reseller, 500.0)
    # Real-world comp voucher shape: CASH + counts_as_revenue=False
    await _add_payment(
        db, reseller, 200.0,
        payment_method=PaymentMethod.CASH,
        collection_mode=None,
        counts_as_revenue=False,
    )
    # Defensive shape: a mobile-money row explicitly flagged as non-revenue
    await _add_payment(db, reseller, 150.0, counts_as_revenue=False)

    assert await get_unpaid_balance(db, reseller.id) == 500.0
