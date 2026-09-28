"""Direct settlement: customer STK payments land in the reseller's own account.

Proven live 2026-09-28: the system shortcode signed STK pushes whose PartyB
was a reseller paybill (x2) and Equity 247247 with a 13-digit account number;
all returned ResultCode 0. These tests pin the contract around that:

  * a DIRECT reseller's push pays the same destination the B2B payout would
    (PartyB + AccountReference from mpesa_b2b.payout_destination), signed by
    the system credentials, and is stamped CollectionMode.DIRECT;
  * DIRECT money never enters the payout balance (no double payout);
  * a Safaricom rejection falls back to platform collection, a gateway
    failure does not (the prompt may already be out);
  * legacy (unassigned) routers follow the reseller's default method only
    when the reseller settles directly;
  * existing accounts stay 'platform', new ones default to 'direct'.
"""

from types import SimpleNamespace

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api import b2b_routes
from app.db.database import get_db
from app.db.models import (
    CollectionMode,
    CustomerPayment,
    MpesaTransaction,
    PaymentMethod,
    PaymentStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from app.services.auth import verify_token
from app.services.direct_settlement import (
    SETTLEMENT_DIRECT,
    SETTLEMENT_PLATFORM,
    direct_received_total,
)
from app.services.mpesa import StkPushRejected
from app.services.mpesa_b2b import get_unpaid_balance
from app.services.payment_gateway import (
    initiate_customer_payment,
    resolve_collection_payment_method,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

EQUITY_ACCOUNT = "1234567890123"  # 13 digits — over the documented 12


async def make_method(db, reseller, method_type, **fields):
    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=method_type,
        label=f"{method_type.value}-{reseller.id}",
        is_active=True,
        **fields,
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    return pm


class StkSpy:
    """Stands in for initiate_stk_push_direct; can fail the first N calls."""

    def __init__(self, fail_with=None):
        self.calls = []
        self.fail_with = list(fail_with or [])

    async def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail_with:
            raise self.fail_with.pop(0)
        return SimpleNamespace(
            checkout_request_id=f"ws_CO_{len(self.calls)}",
            merchant_request_id=f"mr_{len(self.calls)}",
        )


@pytest.fixture
def stk(monkeypatch):
    import app.services.mpesa as mpesa_service

    spy = StkSpy()
    monkeypatch.setattr(mpesa_service, "initiate_stk_push_direct", spy)
    return spy


async def _pay(db, reseller, pm, router=None, reference="REF"):
    router = router or await make_router(db, reseller, payment_method_id=pm.id)
    plan = await make_plan(db, reseller, price=50)
    customer = await make_customer(db, reseller, plan=plan, router=router)
    result = await initiate_customer_payment(
        db=db, payment_method=pm, customer=customer, router=router,
        phone="254700000000", amount=50, reference=reference,
        account_reference="Test ISP",
    )
    await db.commit()
    return result


async def _txn(db, checkout_id):
    return (await db.execute(
        select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_id)
    )).scalar_one()


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

async def test_new_reseller_defaults_to_direct(db):
    reseller = await make_reseller(db)
    assert reseller.settlement_mode == SETTLEMENT_DIRECT


async def test_direct_till_pays_the_till_with_buy_goods(db, stk):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_TILL,
                           mpesa_till_number="5550001")

    result = await _pay(db, reseller, pm)

    assert result["collection_mode"] == CollectionMode.DIRECT
    call = stk.calls[-1]
    assert call["party_b"] == "5550001"
    assert call["transaction_type"] == "CustomerBuyGoodsOnline"
    assert call["account_reference"] == "Test ISP"
    # Signed by the SYSTEM credentials — no reseller shortcode/keys.
    assert call.get("shortcode") is None and call.get("consumer_key") is None
    assert (await _txn(db, result["checkout_request_id"])).collection_mode == CollectionMode.DIRECT


async def test_direct_bank_keeps_the_full_account_number(db, stk):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.BANK_ACCOUNT,
                           bank_paybill_number="247247", bank_account_number=EQUITY_ACCOUNT)

    await _pay(db, reseller, pm)

    call = stk.calls[-1]
    assert call["party_b"] == "247247"
    assert call["transaction_type"] == "CustomerPayBillOnline"
    assert call["account_reference"] == EQUITY_ACCOUNT  # not truncated to 12


async def test_direct_paybill_uses_the_payout_account_reference(db, stk):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT,
                                   organization_name="Loooooong Networks Ltd")
    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL,
                           mpesa_paybill_number=" 5550002 ")

    await _pay(db, reseller, pm)

    call = stk.calls[-1]
    assert call["party_b"] == "5550002"
    # Same reference the B2B payout sends to this paybill.
    assert call["account_reference"] == "Loooooong Networks Ltd"[:13]


async def test_bank_without_account_number_is_platform_collected(db, stk):
    """A bank could not credit anyone — the money would sit in suspense."""
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.BANK_ACCOUNT,
                           bank_paybill_number="247247", bank_account_number="")

    result = await _pay(db, reseller, pm)

    assert result["collection_mode"] == CollectionMode.SYSTEM_COLLECTED
    assert stk.calls[-1].get("party_b") is None


async def test_platform_reseller_is_unchanged(db, stk):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_PLATFORM)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_TILL,
                           mpesa_till_number="5550001")

    result = await _pay(db, reseller, pm)

    assert result["collection_mode"] == CollectionMode.SYSTEM_COLLECTED
    assert stk.calls[-1].get("party_b") is None


async def test_rejected_party_b_falls_back_to_platform_collection(db, monkeypatch):
    import app.services.mpesa as mpesa_service

    spy = StkSpy(fail_with=[StkPushRejected(400, "Invalid PartyB")])
    monkeypatch.setattr(mpesa_service, "initiate_stk_push_direct", spy)
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_TILL,
                           mpesa_till_number="5550001")

    result = await _pay(db, reseller, pm)

    assert len(spy.calls) == 2
    assert spy.calls[0]["party_b"] == "5550001"
    assert spy.calls[1].get("party_b") is None
    assert result["collection_mode"] == CollectionMode.SYSTEM_COLLECTED
    assert (await _txn(db, result["checkout_request_id"])).collection_mode == CollectionMode.SYSTEM_COLLECTED


async def test_gateway_failure_is_not_retried(db, monkeypatch):
    """A 503 may have delivered the prompt; a second push would double-charge."""
    import app.services.mpesa as mpesa_service

    spy = StkSpy(fail_with=[StkPushRejected(503, "Service Unavailable")])
    monkeypatch.setattr(mpesa_service, "initiate_stk_push_direct", spy)
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_TILL,
                           mpesa_till_number="5550001")

    with pytest.raises(StkPushRejected):
        await _pay(db, reseller, pm)
    assert len(spy.calls) == 1


# ---------------------------------------------------------------------------
# Legacy (unassigned) routers
# ---------------------------------------------------------------------------

async def test_unassigned_router_uses_default_method_when_direct(db):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.BANK_ACCOUNT,
                           bank_paybill_number="247247", bank_account_number=EQUITY_ACCOUNT)
    site = await make_router(db, reseller)

    resolved = await resolve_collection_payment_method(db, site.id)
    assert resolved is not None and resolved.id == pm.id


async def test_unassigned_router_stays_legacy_when_platform(db):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_PLATFORM)
    await make_method(db, reseller, ResellerPaymentMethodType.BANK_ACCOUNT,
                      bank_paybill_number="247247", bank_account_number=EQUITY_ACCOUNT)
    site = await make_router(db, reseller)

    assert await resolve_collection_payment_method(db, site.id) is None


async def test_unassigned_router_ignores_inactive_default_method(db):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_TILL,
                           mpesa_till_number="5550001")
    pm.is_active = False
    await db.commit()
    site = await make_router(db, reseller)

    assert await resolve_collection_payment_method(db, site.id) is None


# ---------------------------------------------------------------------------
# Accounting
# ---------------------------------------------------------------------------

async def test_direct_payments_never_enter_the_payout_balance(db):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    plan = await make_plan(db, reseller, price=50)
    customer = await make_customer(db, reseller, plan=plan)
    for mode, amount in ((CollectionMode.DIRECT, 500.0), (CollectionMode.SYSTEM_COLLECTED, 80.0)):
        db.add(CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=amount,
            payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=1,
            status=PaymentStatus.COMPLETED, collection_mode=mode,
        ))
    await db.commit()

    assert await get_unpaid_balance(db, reseller.id) == 80.0
    assert await direct_received_total(db, reseller.id) == 500.0


# ---------------------------------------------------------------------------
# Reseller API
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(b2b_routes.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return await db.get(type(user), user.id)
    monkeypatch.setattr(b2b_routes, "get_current_user", _fake)


async def test_opting_in_requires_an_eligible_method(db, client, monkeypatch):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_PLATFORM)
    _auth_as(monkeypatch, reseller)

    resp = await client.put("/api/reseller/settlement-mode", json={"settlement_mode": "direct"})
    assert resp.status_code == 400

    await make_method(db, reseller, ResellerPaymentMethodType.MPESA_TILL,
                      mpesa_till_number="5550001")
    resp = await client.put("/api/reseller/settlement-mode", json={"settlement_mode": "direct"})
    assert resp.status_code == 200 and resp.json()["settlement_mode"] == "direct"

    settings = (await client.get("/api/reseller/payout-settings")).json()
    assert settings["settlement_mode"] == "direct"
    assert settings["direct_settlement_available"] is True
    assert settings["direct_received_30d"] == 0


async def test_opting_out_is_always_allowed(db, client, monkeypatch):
    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    _auth_as(monkeypatch, reseller)

    resp = await client.put("/api/reseller/settlement-mode", json={"settlement_mode": "platform"})
    assert resp.status_code == 200

    resp = await client.put("/api/reseller/settlement-mode", json={"settlement_mode": "bogus"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Switching mid-stream, and brand-new resellers
# ---------------------------------------------------------------------------

async def _record(db, reseller, amount, mode):
    plan = await make_plan(db, reseller, price=amount)
    customer = await make_customer(db, reseller, plan=plan)
    db.add(CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id, amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=1,
        status=PaymentStatus.COMPLETED, collection_mode=mode,
    ))
    await db.commit()


async def test_switching_to_direct_keeps_the_existing_balance_owed(db, stk):
    """Money collected before the switch is still paid out; money after is not."""
    from app.services.direct_settlement import set_settlement_mode

    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_PLATFORM)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.BANK_ACCOUNT,
                           bank_paybill_number="247247", bank_account_number=EQUITY_ACCOUNT)
    await _record(db, reseller, 700.0, CollectionMode.SYSTEM_COLLECTED)

    await set_settlement_mode(db, reseller.id, SETTLEMENT_DIRECT)
    await db.commit()
    result = await _pay(db, reseller, pm, reference="AFTER")
    assert result["collection_mode"] == CollectionMode.DIRECT
    await _record(db, reseller, 50.0, CollectionMode.DIRECT)

    assert await get_unpaid_balance(db, reseller.id) == 700.0


async def test_switching_back_to_platform_collects_again(db, stk):
    from app.services.direct_settlement import set_settlement_mode

    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_DIRECT)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_TILL,
                           mpesa_till_number="5550001")
    assert (await _pay(db, reseller, pm, reference="D"))["collection_mode"] == CollectionMode.DIRECT

    await set_settlement_mode(db, reseller.id, SETTLEMENT_PLATFORM)
    await db.commit()
    result = await _pay(db, reseller, pm, reference="P")
    assert result["collection_mode"] == CollectionMode.SYSTEM_COLLECTED
    assert stk.calls[-1].get("party_b") is None


async def test_payment_in_flight_during_a_switch_keeps_its_original_mode(db):
    """The mode is snapshotted when the push is raised: a prompt sent while on
    platform and paid after the reseller switched is still platform money (it
    landed on the system paybill) and must stay in the payout balance."""
    from app.services.direct_settlement import set_settlement_mode
    from app.services.reseller_payments import resolve_mpesa_collection_mode

    reseller = await make_reseller(db, settlement_mode=SETTLEMENT_PLATFORM)
    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_TILL,
                           mpesa_till_number="5550001")
    site = await make_router(db, reseller, payment_method_id=pm.id)
    plan = await make_plan(db, reseller, price=50)
    customer = await make_customer(db, reseller, plan=plan, router=site)
    txn = MpesaTransaction(
        checkout_request_id="ws_CO_inflight", phone_number="254700000000",
        amount=50, reference="R", customer_id=customer.id,
        collection_mode=CollectionMode.SYSTEM_COLLECTED,
    )
    db.add(txn)
    await db.commit()

    await set_settlement_mode(db, reseller.id, SETTLEMENT_DIRECT)
    await db.commit()

    assert await resolve_mpesa_collection_mode(db, txn, customer) == CollectionMode.SYSTEM_COLLECTED


async def test_signup_creates_a_direct_reseller(db):
    from app.db.models import UserRole
    from app.services.auth import create_user

    user = await create_user(
        db, email="brand-new@example.com", password="x" * 12,
        role=UserRole.RESELLER, organization_name="New ISP",
    )
    assert user.settlement_mode == SETTLEMENT_DIRECT


async def test_new_direct_reseller_without_a_method_is_platform_collected_until_they_add_one(db, stk):
    reseller = await make_reseller(db)  # default: direct
    site = await make_router(db, reseller)
    assert await resolve_collection_payment_method(db, site.id) is None  # legacy path

    pm = await make_method(db, reseller, ResellerPaymentMethodType.MPESA_PAYBILL,
                           mpesa_paybill_number="5550002")
    resolved = await resolve_collection_payment_method(db, site.id)
    assert resolved is not None and resolved.id == pm.id
    result = await _pay(db, reseller, resolved, router=site)
    assert result["collection_mode"] == CollectionMode.DIRECT
    assert stk.calls[-1]["party_b"] == "5550002"
