"""Where the money goes: per-router collection, and who receives the payout.

Two separate questions that are easy to conflate:

  * COLLECTION — which credentials the STK push is raised against, i.e. whose
    paybill the customer's money lands in. Resolved per router from
    routers.payment_method_id.
  * PAYOUT — which paybill/till the platform later sends the reseller's balance
    to. Resolved per RESELLER, and it does NOT look at the router assignment.

The business rule these tests lock down: assigning a paybill or till to a
router must NOT divert collection away from the platform shortcode. Only a
reseller who has supplied their own Daraja API keys collects directly. Until
then every shilling is collected by the platform and paid out afterwards.
"""

import pytest
from sqlalchemy import select

from app.db.models import (
    CollectionMode,
    MpesaTransaction,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from app.services.payment_gateway import (
    encrypt_credential,
    initiate_customer_payment,
    resolve_router_payment_method,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def make_payment_method(db, reseller, method_type, **overrides):
    defaults = dict(
        user_id=reseller.id,
        method_type=method_type,
        label=f"{method_type.value}-{reseller.id}",
        is_active=True,
    )
    defaults.update(overrides)
    pm = ResellerPaymentMethod(**defaults)
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    return pm


class StkSpy:
    """Captures what credentials the STK push was raised with."""

    def __init__(self):
        self.calls = []

    async def __call__(self, **kwargs):
        from types import SimpleNamespace

        self.calls.append(kwargs)
        return SimpleNamespace(
            checkout_request_id=f"ws_CO_{len(self.calls)}",
            merchant_request_id=f"mr_{len(self.calls)}",
        )

    @property
    def last(self):
        return self.calls[-1]


@pytest.fixture
def stk(monkeypatch):
    import app.services.mpesa as mpesa_service

    spy = StkSpy()
    monkeypatch.setattr(mpesa_service, "initiate_stk_push_direct", spy)
    return spy


# ---------------------------------------------------------------------------
# Per-router resolution
# ---------------------------------------------------------------------------

async def test_each_router_resolves_its_own_assigned_method(db):
    reseller = await make_reseller(db)
    till = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_TILL,
        label="Shop till", mpesa_till_number="5566778",
    )
    paybill = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL,
        label="Main paybill", mpesa_paybill_number="400200",
    )
    site_a = await make_router(db, reseller, payment_method_id=till.id)
    site_b = await make_router(db, reseller, payment_method_id=paybill.id)

    resolved_a = await resolve_router_payment_method(db, site_a.id)
    resolved_b = await resolve_router_payment_method(db, site_b.id)

    assert resolved_a.id == till.id
    assert resolved_a.mpesa_till_number == "5566778"
    assert resolved_b.id == paybill.id
    assert resolved_b.mpesa_paybill_number == "400200"


async def test_unassigned_router_falls_back_to_legacy(db):
    """No assignment must keep the pre-existing system flow, not error."""
    reseller = await make_reseller(db)
    site = await make_router(db, reseller)

    assert await resolve_router_payment_method(db, site.id) is None


async def test_deactivated_method_stops_being_used(db):
    """A switched-off method must not keep routing money."""
    reseller = await make_reseller(db)
    pm = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL,
        mpesa_paybill_number="400200", is_active=False,
    )
    site = await make_router(db, reseller, payment_method_id=pm.id)

    assert await resolve_router_payment_method(db, site.id) is None


# ---------------------------------------------------------------------------
# THE RULE: assigning a paybill/till must not divert collection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "method_type,fields",
    [
        (ResellerPaymentMethodType.MPESA_TILL, {"mpesa_till_number": "5566778"}),
        (ResellerPaymentMethodType.MPESA_PAYBILL, {"mpesa_paybill_number": "400200"}),
        (
            ResellerPaymentMethodType.BANK_ACCOUNT,
            {"bank_paybill_number": "247247", "bank_account_number": "0812345"},
        ),
    ],
)
async def test_assigned_paybill_or_till_does_not_collect_the_money(
    db, stk, method_type, fields
):
    """The platform still collects. The reseller's number is a payout destination.

    If this ever fails, customer money is landing in the reseller's account
    instead of the platform's, and the platform cannot reconcile or pay out.
    """
    reseller = await make_reseller(db)
    pm = await make_payment_method(db, reseller, method_type, **fields)
    site = await make_router(db, reseller, payment_method_id=pm.id)
    plan = await make_plan(db, reseller, price=100)
    customer = await make_customer(db, reseller, plan=plan, router=site)

    result = await initiate_customer_payment(
        db=db, payment_method=pm, customer=customer, router=site,
        phone="254700000000", amount=100, reference="REF1",
    )

    assert result["collection_mode"] == CollectionMode.SYSTEM_COLLECTED
    transaction = (
        await db.execute(
            select(MpesaTransaction).where(
                MpesaTransaction.checkout_request_id == result["checkout_request_id"]
            )
        )
    ).scalar_one()
    assert transaction.collection_mode == CollectionMode.SYSTEM_COLLECTED
    # No shortcode/passkey/keys passed => initiate_stk_push_direct falls back to
    # the platform's settings.MPESA_* credentials.
    assert stk.last.get("shortcode") is None
    assert stk.last.get("passkey") is None
    assert stk.last.get("consumer_key") is None
    assert stk.last.get("consumer_secret") is None
    # And specifically not the reseller's own number.
    for value in fields.values():
        assert stk.last.get("shortcode") != value


async def test_only_a_reseller_with_daraja_keys_collects_directly(db, stk):
    """The single exception — and it requires real API keys to be stored."""
    reseller = await make_reseller(db)
    pm = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        mpesa_shortcode="777777",
        mpesa_passkey_encrypted=encrypt_credential("passkey-value"),
        mpesa_consumer_key_encrypted=encrypt_credential("ck-value"),
        mpesa_consumer_secret_encrypted=encrypt_credential("cs-value"),
    )
    site = await make_router(db, reseller, payment_method_id=pm.id)
    plan = await make_plan(db, reseller, price=100)
    customer = await make_customer(db, reseller, plan=plan, router=site)

    result = await initiate_customer_payment(
        db=db, payment_method=pm, customer=customer, router=site,
        phone="254700000000", amount=100, reference="REF2",
    )

    assert result["collection_mode"] == CollectionMode.DIRECT
    transaction = (
        await db.execute(
            select(MpesaTransaction).where(
                MpesaTransaction.checkout_request_id == result["checkout_request_id"]
            )
        )
    ).scalar_one()
    assert transaction.collection_mode == CollectionMode.DIRECT
    assert stk.last["shortcode"] == "777777"
    assert stk.last["consumer_key"] == "ck-value"
    assert stk.last["consumer_secret"] == "cs-value"


async def test_two_routers_two_tills_both_still_collected_by_the_platform(db, stk):
    """The realistic setup: different tills per site, one collection account."""
    reseller = await make_reseller(db)
    till_a = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_TILL,
        label="Till A", mpesa_till_number="1111111",
    )
    till_b = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_TILL,
        label="Till B", mpesa_till_number="2222222",
    )
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)
    plan = await make_plan(db, reseller, price=100)

    for site, pm in ((site_a, till_a), (site_b, till_b)):
        customer = await make_customer(db, reseller, plan=plan, router=site)
        result = await initiate_customer_payment(
            db=db, payment_method=pm, customer=customer, router=site,
            phone="254700000000", amount=100, reference=f"REF-{site.id}",
        )
        assert result["collection_mode"] == CollectionMode.SYSTEM_COLLECTED
        assert stk.last.get("shortcode") is None


# ---------------------------------------------------------------------------
# Payout: per reseller, NOT per router
# ---------------------------------------------------------------------------

async def test_payout_destination_ignores_the_router_assignment(db):
    """Documents current behaviour, which is NOT per-router.

    A reseller with two routers pointing at two different tills has ONE payout
    destination, chosen by resolve_b2b_payment_method from their account — the
    router assignment is never consulted. The whole balance goes to whichever
    eligible method that query returns.

    If per-router payout attribution is ever wanted, this test is the anchor
    to change.
    """
    from app.services.mpesa_b2b import resolve_b2b_payment_method

    reseller = await make_reseller(db)
    till_a = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_TILL,
        label="Till A", mpesa_till_number="1111111",
    )
    till_b = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_TILL,
        label="Till B", mpesa_till_number="2222222",
    )
    site_a = await make_router(db, reseller, payment_method_id=till_a.id)
    site_b = await make_router(db, reseller, payment_method_id=till_b.id)

    chosen = await resolve_b2b_payment_method(db, reseller.id)

    assert chosen is not None
    # One destination for the whole reseller, regardless of which router earned it.
    assert chosen.id in (till_a.id, till_b.id)
    assert await resolve_router_payment_method(db, site_a.id) != chosen or \
           await resolve_router_payment_method(db, site_b.id) != chosen, (
        "at least one router's assigned method is not the payout destination"
    )


async def test_payout_only_considers_b2b_eligible_types(db):
    """Keys-based collection is not a payout destination."""
    from app.services.mpesa_b2b import resolve_b2b_payment_method

    reseller = await make_reseller(db)
    await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        mpesa_shortcode="777777",
        mpesa_passkey_encrypted=encrypt_credential("p"),
        mpesa_consumer_key_encrypted=encrypt_credential("k"),
        mpesa_consumer_secret_encrypted=encrypt_credential("s"),
    )

    assert await resolve_b2b_payment_method(db, reseller.id) is None


async def test_payout_uses_buy_goods_command_for_a_till(db):
    """A till must be paid with BusinessBuyGoods, not BusinessPayBill."""
    from app.services import mpesa_b2b

    reseller = await make_reseller(db)
    till = await make_payment_method(
        db, reseller, ResellerPaymentMethodType.MPESA_TILL,
        label="Till", mpesa_till_number="5566778",
    )

    captured = {}

    async def fake_initiate(**kwargs):
        captured.update(kwargs)
        return object()

    original = mpesa_b2b.initiate_b2b_payment
    mpesa_b2b.initiate_b2b_payment = fake_initiate
    try:
        await mpesa_b2b.payout_reseller(db, reseller.id, till, balance=500.0)
    finally:
        mpesa_b2b.initiate_b2b_payment = original

    assert captured["command_id"] == "BusinessBuyGoods"
    assert captured["party_b"] == "5566778"
    assert captured["account_reference"] == ""
