"""Per-router payouts: each router's earnings go to that router's own till.

Money-moving code, so the properties matter more than the happy path:

  * CONSERVATION — the per-router buckets always sum to the reseller's total
    balance. Drift here means someone is over- or under-paid.
  * NO DOUBLE PAY  — a settled bucket must not be payable again, and an
    in-flight payout must not be re-sent.
  * NO REGRESSION  — a reseller who has not split anything must behave
    byte-for-byte as before, including the double-spend guard.
  * ATTRIBUTION    — revenue sticks to the router that earned it, even after
    the customer is moved to another site.
"""

import pytest

from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    CustomerPayment,
    PaymentMethod,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    ResellerPayout,
)
from app.services.mpesa_b2b import (
    MIN_SPLIT_PAYOUT,
    get_unpaid_balance,
    get_unpaid_balance_by_router,
    has_unresolved_b2b,
    resolve_router_payout_plan,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def make_method(db, reseller, label, till):
    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_TILL,
        label=label,
        mpesa_till_number=till,
        is_active=True,
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    return pm


async def add_payment(db, reseller, amount, router_id, customer_id=None):
    payment = CustomerPayment(
        customer_id=customer_id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=1,
        router_id=router_id,
        counts_as_revenue=True,
    )
    db.add(payment)
    await db.commit()
    return payment


async def add_payout(db, reseller, amount, router_id):
    payout = ResellerPayout(
        reseller_id=reseller.id,
        amount=amount,
        payment_method="mpesa_b2b",
        router_id=router_id,
    )
    db.add(payout)
    await db.commit()
    return payout


# ---------------------------------------------------------------------------
# Conservation
# ---------------------------------------------------------------------------

async def test_buckets_sum_to_the_reseller_total(db):
    reseller = await make_reseller(db)
    site_a = await make_router(db, reseller)
    site_b = await make_router(db, reseller)

    await add_payment(db, reseller, 500, site_a.id)
    await add_payment(db, reseller, 300, site_b.id)
    await add_payment(db, reseller, 120, None)      # unattributed
    await add_payout(db, reseller, 200, site_a.id)

    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    total = await get_unpaid_balance(db, reseller.id)

    assert round(sum(buckets.values()), 2) == total
    assert buckets[site_a.id] == 300  # 500 earned - 200 already paid
    assert buckets[site_b.id] == 300
    assert buckets[None] == 120


async def test_charges_and_corrections_land_in_the_default_bucket(db):
    """Reseller-wide adjustments belong to no single site."""
    from app.db.models import ResellerFinancials, ResellerTransactionCharge

    reseller = await make_reseller(db)
    site = await make_router(db, reseller)
    await add_payment(db, reseller, 500, site.id)

    db.add(ResellerTransactionCharge(
        reseller_id=reseller.id, amount=50, description="Bank fee",
        created_by=reseller.id,
    ))
    db.add(ResellerFinancials(user_id=reseller.id, balance_correction=30))
    await db.commit()

    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    total = await get_unpaid_balance(db, reseller.id)

    assert buckets[site.id] == 500
    assert buckets[None] == -20  # +30 correction - 50 charge
    assert round(sum(buckets.values()), 2) == total


async def test_settling_a_bucket_empties_only_that_bucket(db):
    reseller = await make_reseller(db)
    site_a = await make_router(db, reseller)
    site_b = await make_router(db, reseller)
    await add_payment(db, reseller, 400, site_a.id)
    await add_payment(db, reseller, 400, site_b.id)

    await add_payout(db, reseller, 400, site_a.id)

    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    assert buckets[site_a.id] == 0
    assert buckets[site_b.id] == 400


# ---------------------------------------------------------------------------
# Attribution survives a customer moving site
# ---------------------------------------------------------------------------

async def test_revenue_stays_with_the_router_that_earned_it(db):
    """The bug this snapshot prevents: money following the customer.

    Without the snapshot, attribution would read Customer.router_id and a
    customer relocated to Site B would drag Site A's earnings to B's till.
    """
    reseller = await make_reseller(db)
    site_a = await make_router(db, reseller)
    site_b = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=100)
    customer = await make_customer(db, reseller, plan=plan, router=site_a)

    await add_payment(db, reseller, 500, site_a.id, customer_id=customer.id)

    # Customer is moved to the other site.
    customer.router_id = site_b.id
    await db.commit()

    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    assert buckets[site_a.id] == 500
    assert buckets.get(site_b.id, 0) == 0


async def test_payment_recording_stamps_the_router(db):
    """The snapshot has to actually be written, not just exist as a column."""
    from app.services.reseller_payments import record_customer_payment

    reseller = await make_reseller(db)
    site = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=100)
    customer = await make_customer(db, reseller, plan=plan, router=site)

    payment = await record_customer_payment(
        db=db, customer_id=customer.id, reseller_id=reseller.id,
        amount=100, payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=1,
    )

    assert payment.router_id == site.id


# ---------------------------------------------------------------------------
# When to split
# ---------------------------------------------------------------------------

async def test_no_split_when_the_reseller_assigned_nothing(db):
    """Existing users must keep exactly one payout."""
    reseller = await make_reseller(db)
    site = await make_router(db, reseller)
    await add_payment(db, reseller, 500, site.id)

    assert await resolve_router_payout_plan(db, reseller.id) is None


async def test_no_split_when_every_router_points_at_one_till(db):
    """Same destination fleet-wide is still a single payout — no extra fees."""
    reseller = await make_reseller(db)
    till = await make_method(db, reseller, "Only till", "1111111")
    site_a = await make_router(db, reseller, payment_method_id=till.id)
    site_b = await make_router(db, reseller, payment_method_id=till.id)
    await add_payment(db, reseller, 500, site_a.id)
    await add_payment(db, reseller, 500, site_b.id)

    assert await resolve_router_payout_plan(db, reseller.id) is None


async def test_split_when_destinations_differ(db):
    reseller = await make_reseller(db)
    till_a = await make_method(db, reseller, "Till A", "1111111")
    till_b = await make_method(db, reseller, "Till B", "2222222")
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)
    await add_payment(db, reseller, 500, site_a.id)
    await add_payment(db, reseller, 300, site_b.id)

    plan = await resolve_router_payout_plan(db, reseller.id)

    assert plan is not None
    by_router = {rid: (pm.mpesa_till_number, bal) for rid, pm, bal in plan}
    assert by_router[site_a.id] == ("1111111", 500)
    assert by_router[site_b.id] == ("2222222", 300)
    # Largest first, so the biggest balance goes out even if a later leg fails.
    assert [bal for _, _, bal in plan] == sorted(
        [bal for _, _, bal in plan], reverse=True
    )


async def test_split_plan_never_exceeds_the_total_balance(db):
    """A split must not conjure money that the reseller is not owed."""
    reseller = await make_reseller(db)
    till_a = await make_method(db, reseller, "Till A", "1111111")
    till_b = await make_method(db, reseller, "Till B", "2222222")
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)
    await add_payment(db, reseller, 500, site_a.id)
    await add_payment(db, reseller, 300, site_b.id)
    await add_payment(db, reseller, 90, None)

    plan = await resolve_router_payout_plan(db, reseller.id)
    total = await get_unpaid_balance(db, reseller.id)

    assert sum(bal for _, _, bal in plan) <= total


async def test_unattributed_revenue_goes_to_the_default_method(db):
    """Historical revenue must still be payable, to the default destination."""
    reseller = await make_reseller(db)
    till_a = await make_method(db, reseller, "Till A", "1111111")
    till_b = await make_method(db, reseller, "Till B", "2222222")
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    await make_router(db, reseller, payment_method_id=till_b.id)
    await add_payment(db, reseller, 500, site_a.id)
    await add_payment(db, reseller, 250, None)

    plan = await resolve_router_payout_plan(db, reseller.id)

    default_leg = [leg for leg in plan if leg[0] is None]
    assert len(default_leg) == 1
    assert default_leg[0][2] == 250


async def test_dust_balance_is_carried_not_dropped(db):
    """A few shillings is not worth a transfer fee, but it stays owed."""
    reseller = await make_reseller(db)
    till_a = await make_method(db, reseller, "Till A", "1111111")
    till_b = await make_method(db, reseller, "Till B", "2222222")
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)
    await add_payment(db, reseller, 500, site_a.id)
    await add_payment(db, reseller, MIN_SPLIT_PAYOUT - 1, site_b.id)

    plan = await resolve_router_payout_plan(db, reseller.id)
    assert [rid for rid, _, _ in plan] == [site_a.id]

    # Still owed afterwards — not written off.
    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    assert buckets[site_b.id] == MIN_SPLIT_PAYOUT - 1


async def test_router_without_a_usable_destination_is_left_alone(db):
    """Never guess a till to send someone's money to."""
    reseller = await make_reseller(db)
    till_a = await make_method(db, reseller, "Till A", "1111111")
    till_b = await make_method(db, reseller, "Till B", "2222222")
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)
    unassigned = await make_router(db, reseller)
    await add_payment(db, reseller, 500, site_a.id)
    await add_payment(db, reseller, 400, site_b.id)
    await add_payment(db, reseller, 300, unassigned.id)

    plan = await resolve_router_payout_plan(db, reseller.id)

    assert unassigned.id not in [rid for rid, _, _ in plan]
    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    assert buckets[unassigned.id] == 300


async def test_deactivated_destination_does_not_trigger_a_split(db):
    reseller = await make_reseller(db)
    till_a = await make_method(db, reseller, "Till A", "1111111")
    till_b = await make_method(db, reseller, "Till B", "2222222")
    till_b.is_active = False
    await db.commit()
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)
    await add_payment(db, reseller, 500, site_a.id)
    await add_payment(db, reseller, 400, site_b.id)

    assert await resolve_router_payout_plan(db, reseller.id) is None


# ---------------------------------------------------------------------------
# Double-spend guard
# ---------------------------------------------------------------------------

async def add_pending_txn(db, reseller, router_id):
    txn = B2BTransaction(
        reseller_id=reseller.id, amount=100, fee=0, net_amount=100,
        party_a="600980", party_b="1111111", command_id="BusinessBuyGoods",
        status=B2BTransactionStatus.PENDING, router_id=router_id,
    )
    db.add(txn)
    await db.commit()
    return txn


async def test_unsplit_reseller_guard_is_unchanged(db):
    """No regression for everyone who never splits."""
    reseller = await make_reseller(db)
    assert await has_unresolved_b2b(db, reseller.id) is False
    await add_pending_txn(db, reseller, None)
    assert await has_unresolved_b2b(db, reseller.id) is True


async def test_pending_router_payout_blocks_only_that_router(db):
    """What lets a split reseller be paid in one night instead of one per day."""
    reseller = await make_reseller(db)
    site_a = await make_router(db, reseller)
    site_b = await make_router(db, reseller)
    await add_pending_txn(db, reseller, site_a.id)

    assert await has_unresolved_b2b(db, reseller.id, router_id=site_a.id) is True
    assert await has_unresolved_b2b(db, reseller.id, router_id=site_b.id) is False


async def test_router_scoped_call_is_still_blocked_by_a_reseller_level_payout(db):
    """A reseller-level payout draws on the shared bucket, so it blocks all."""
    reseller = await make_reseller(db)
    site = await make_router(db, reseller)
    await add_pending_txn(db, reseller, None)

    assert await has_unresolved_b2b(db, reseller.id, router_id=site.id) is True


async def test_any_router_scoped_payout_blocks_an_unscoped_call(db):
    """The old callers must stay maximally conservative."""
    reseller = await make_reseller(db)
    site = await make_router(db, reseller)
    await add_pending_txn(db, reseller, site.id)

    assert await has_unresolved_b2b(db, reseller.id) is True
