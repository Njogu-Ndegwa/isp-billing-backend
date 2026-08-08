"""What happens to users who assigned NOTHING, on the day this deploys.

Every feature in this change is opt-in by configuration, and this file is the
evidence. It walks the three things a reseller could have left unset — plans not
tied to routers, no payment method on a router, no per-router payout — and
asserts that each behaves exactly as it did before.

It also covers the state EVERY existing reseller lands in at deploy time: a
mixed ledger, where payments made before the upgrade carry no router and
payments made after it do. That mixture must not change a single shilling of
what they are owed or where it is sent.

If any test here fails, the push is not safe for existing customers.
"""

import pytest

from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    CustomerPayment,
    PaymentMethod,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from app.services.mpesa_b2b import (
    get_unpaid_balance,
    get_unpaid_balance_by_router,
    has_unresolved_b2b,
    resolve_b2b_payment_method,
    resolve_router_payout_plan,
)
from app.services.payment_gateway import resolve_router_payment_method
from app.services.plan_cache import get_plans_cached, invalidate_plan_cache
from tests.factories import make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def legacy_payment(db, reseller, amount, router_id=None):
    """A payment row shaped like one written BEFORE this change (router_id NULL)."""
    payment = CustomerPayment(
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


# ---------------------------------------------------------------------------
# 1. Plans — nobody tied a plan to a router
# ---------------------------------------------------------------------------

async def test_existing_plans_still_appear_on_every_router(db):
    """router_ids is NULL on every pre-existing plan, meaning 'all routers'."""
    reseller = await make_reseller(db)
    site_a = await make_router(db, reseller, identity="legacy-a")
    site_b = await make_router(db, reseller, identity="legacy-b")
    hourly = await make_plan(db, reseller, name="Hourly", price=20)
    daily = await make_plan(db, reseller, name="Daily", price=100)
    await invalidate_plan_cache()

    for site in (site_a, site_b):
        plans = await get_plans_cached(db, reseller.id, router_id=site.id)
        assert {p["id"] for p in plans} == {hourly.id, daily.id}
        assert all(p["router_ids"] is None for p in plans)


async def test_adding_a_new_router_later_inherits_all_existing_plans(db):
    """A router bought next month must start selling immediately."""
    reseller = await make_reseller(db)
    await make_router(db, reseller, identity="old-site")
    plan = await make_plan(db, reseller, name="Daily", price=100)
    await invalidate_plan_cache()

    new_site = await make_router(db, reseller, identity="brand-new-site")
    plans = await get_plans_cached(db, reseller.id, router_id=new_site.id)

    assert [p["id"] for p in plans] == [plan.id]


# ---------------------------------------------------------------------------
# 2. Collection — nobody assigned a payment method to a router
# ---------------------------------------------------------------------------

async def test_router_with_no_payment_method_stays_on_the_legacy_flow(db):
    reseller = await make_reseller(db)
    site = await make_router(db, reseller)

    # None is the signal every caller already treats as "use system defaults".
    assert await resolve_router_payment_method(db, site.id) is None


# ---------------------------------------------------------------------------
# 3. Payout — nobody split anything
# ---------------------------------------------------------------------------

async def test_unsplit_reseller_gets_one_payout_to_the_same_destination(db):
    reseller = await make_reseller(db)
    await make_router(db, reseller)
    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_PAYBILL,
        label="Main paybill", mpesa_paybill_number="400200", is_active=True,
    )
    db.add(pm)
    await db.commit()
    await legacy_payment(db, reseller, 1000)

    assert await resolve_router_payout_plan(db, reseller.id) is None
    chosen = await resolve_b2b_payment_method(db, reseller.id)
    assert chosen.mpesa_paybill_number == "400200"


async def test_legacy_revenue_is_still_fully_owed(db):
    """Unattributed money must not vanish into an unpayable bucket."""
    reseller = await make_reseller(db)
    await legacy_payment(db, reseller, 750)

    total = await get_unpaid_balance(db, reseller.id)
    buckets = await get_unpaid_balance_by_router(db, reseller.id)

    assert total == 750
    assert buckets[None] == 750
    assert round(sum(buckets.values()), 2) == total


async def test_double_spend_guard_behaves_exactly_as_before(db):
    """The guard protecting existing resellers must not have been loosened."""
    reseller = await make_reseller(db)
    assert await has_unresolved_b2b(db, reseller.id) is False

    db.add(B2BTransaction(
        reseller_id=reseller.id, amount=100, fee=0, net_amount=100,
        party_a="600980", party_b="400200", status=B2BTransactionStatus.PENDING,
    ))
    await db.commit()

    assert await has_unresolved_b2b(db, reseller.id) is True


# ---------------------------------------------------------------------------
# 4. Deploy day — the mixed ledger every existing reseller will have
# ---------------------------------------------------------------------------

async def test_mixed_old_and_new_payments_do_not_change_what_is_owed(db):
    """Payments before the upgrade have no router; payments after it do.

    This is the state of every live reseller the morning after the push. The
    total owed, and where it is sent, must be identical to before.
    """
    reseller = await make_reseller(db)
    site = await make_router(db, reseller)

    await legacy_payment(db, reseller, 400)             # pre-upgrade row
    await legacy_payment(db, reseller, 600, site.id)    # post-upgrade row

    total = await get_unpaid_balance(db, reseller.id)
    buckets = await get_unpaid_balance_by_router(db, reseller.id)

    assert total == 1000
    assert round(sum(buckets.values()), 2) == total
    # Nothing was split, so it is still a single payout of the full amount.
    assert await resolve_router_payout_plan(db, reseller.id) is None


async def test_splitting_later_only_affects_money_earned_after_the_split(db):
    """A reseller who opts in keeps their historical balance on the default.

    Old revenue carries no router, so it cannot be claimed by either till —
    it stays on the default destination rather than being handed to whichever
    site happens to be listed first.
    """
    reseller = await make_reseller(db)
    till_a = ResellerPaymentMethod(
        user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Till A", mpesa_till_number="1111111", is_active=True,
    )
    till_b = ResellerPaymentMethod(
        user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Till B", mpesa_till_number="2222222", is_active=True,
    )
    db.add_all([till_a, till_b])
    await db.commit()
    await db.refresh(till_a)
    await db.refresh(till_b)

    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)

    await legacy_payment(db, reseller, 900)             # earned before opting in
    await legacy_payment(db, reseller, 500, site_a.id)  # earned after
    await legacy_payment(db, reseller, 300, site_b.id)

    plan = await resolve_router_payout_plan(db, reseller.id)
    legs = {rid: (pm.mpesa_till_number, bal) for rid, pm, bal in plan}

    assert legs[site_a.id] == ("1111111", 500)
    assert legs[site_b.id] == ("2222222", 300)
    # The historical 900 goes to the default method, not to a till that did
    # not earn it.
    assert legs[None][1] == 900
    assert sum(bal for _, _, bal in plan) == await get_unpaid_balance(db, reseller.id)


async def test_no_money_is_created_or_destroyed_by_the_split(db):
    """Conservation across a realistic mixed ledger."""
    reseller = await make_reseller(db)
    till_a = ResellerPaymentMethod(
        user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="A", mpesa_till_number="1111111", is_active=True,
    )
    till_b = ResellerPaymentMethod(
        user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="B", mpesa_till_number="2222222", is_active=True,
    )
    db.add_all([till_a, till_b])
    await db.commit()
    await db.refresh(till_a)
    await db.refresh(till_b)
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)
    orphan = await make_router(db, reseller)

    for amount, rid in [(900, None), (500, site_a.id), (300, site_b.id), (75, orphan.id)]:
        await legacy_payment(db, reseller, amount, rid)

    total = await get_unpaid_balance(db, reseller.id)
    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    plan = await resolve_router_payout_plan(db, reseller.id)

    assert round(sum(buckets.values()), 2) == total == 1775
    # The orphan router has no destination, so its 75 is not paid out yet —
    # but it is still owed, never written off.
    assert sum(bal for _, _, bal in plan) == total - 75
    assert buckets[orphan.id] == 75
