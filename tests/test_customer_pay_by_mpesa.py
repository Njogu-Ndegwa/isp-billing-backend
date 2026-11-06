"""The "Pay by M-Pesa" card (`pay_by_mpesa`) on the customer endpoints.

What the card tells a customer to pay must be exactly what the C2B handler
matches and renews. So each case here reads the card from the API and then
feeds its paybill + account number to the real handler
(`handle_validation` / `handle_confirmation`), per customer type and
settlement mode:

- PPPoE and static IP on a platform-collected router -> platform paybill
- PPPoE on the reseller's own C2B-registered paybill -> that paybill
- direct settlement to a paybill or till (no C2B we can see) -> no paybill
- hotspot -> never (the handler records the money but authorises no device)
- outside Kenya, no plan, no Luhn-valid account number -> no card
"""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import BackgroundTasks, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.customer_routes as cr
from app.api.customer_routes import router as customer_router
from app.config import settings
from app.db.database import get_db
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    ConnectionType,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from app.services.account_numbers import luhn_check_digit
from app.services.auth import verify_token
from app.services.c2b_handler import (
    ACCEPT_RESPONSE,
    handle_confirmation,
    handle_validation,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

_SEQ = {"n": 2000000}


def _account() -> str:
    _SEQ["n"] += 1
    base = str(_SEQ["n"])
    return base + luhn_check_digit(base)


@pytest.fixture(autouse=True)
def _stub_router_calls(monkeypatch):
    async def _noop(*args, **kwargs):
        return {"ok": True}

    monkeypatch.setattr("app.services.fup.restore_normal_profile", _noop)


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(customer_router)

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
        return user
    monkeypatch.setattr(cr, "get_current_user", _fake)


async def _customer(db, reseller, router, connection_type, *, price=1500, **fields):
    plan = await make_plan(db, reseller, connection_type=connection_type, price=price)
    defaults = {"account_number": _account()}
    if connection_type == ConnectionType.PPPOE:
        defaults["pppoe_username"] = f"pppoe{_SEQ['n']}"
    if connection_type == ConnectionType.STATIC_IP:
        defaults["static_ip"] = f"10.9.0.{_SEQ['n'] % 250 + 2}"
    defaults.update(fields)
    return await make_customer(db, reseller, plan, router, **defaults)


async def _method(db, reseller, router, method_type, **fields):
    method = ResellerPaymentMethod(
        user_id=reseller.id, method_type=method_type, label="Own", is_active=True, **fields,
    )
    db.add(method)
    await db.commit()
    await db.refresh(method)
    if router is not None:
        router.payment_method_id = method.id
        await db.commit()
    return method


def _payload(card, *, trans_id, amount=None):
    return {
        "TransactionType": "Pay Bill",
        "TransID": trans_id,
        "TransTime": "20261104120000",
        "TransAmount": str(amount if amount is not None else card["amount"]),
        "BusinessShortCode": card["paybill"],
        "BillRefNumber": card["account_number"],
        "MSISDN": "254712345678",
    }


async def _card(client, customer):
    detail = (await client.get(f"/api/customers/{customer.id}")).json()
    listed = {c["id"]: c for c in (await client.get("/api/customers")).json()}
    assert listed[customer.id]["pay_by_mpesa"] == detail["pay_by_mpesa"]
    return detail["pay_by_mpesa"]


async def _status(session_factory, trans_id):
    async with session_factory() as s:
        txn = (
            await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == trans_id))
        ).scalar_one()
        return txn.status, txn.matched_customer_id


# ---------------------------------------------------------------------------
# Customers who can pay by paybill + account: the handler renews them
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pppoe_platform_collected_pays_the_platform_paybill(db, client, session_factory, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="platform")
    router = await make_router(db, reseller)
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE)
    _auth_as(monkeypatch, reseller)

    card = await _card(client, customer)

    assert card == {
        "paybill": settings.MPESA_SHORTCODE,
        "account_number": customer.account_number,
        "amount": 1500,
        "unavailable_reason": None,
    }
    assert await handle_validation(_payload(card, trans_id="V1"), db) == ACCEPT_RESPONSE
    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(_payload(card, trans_id="PB001"), db, background_tasks=BackgroundTasks())
    assert await _status(session_factory, "PB001") == (C2BTransactionStatus.PROCESSED, customer.id)


@pytest.mark.asyncio
async def test_static_ip_platform_collected_pays_the_platform_paybill(db, client, session_factory, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="platform")
    router = await make_router(db, reseller)
    customer = await _customer(db, reseller, router, ConnectionType.STATIC_IP, price=4000)
    _auth_as(monkeypatch, reseller)

    card = await _card(client, customer)

    assert card["paybill"] == settings.MPESA_SHORTCODE
    assert card["account_number"] == customer.account_number
    assert card["amount"] == 4000
    with patch("app.services.static_ip.schedule_static_provision") as provision:
        await handle_confirmation(_payload(card, trans_id="PB002"), db, background_tasks=BackgroundTasks())
    assert await _status(session_factory, "PB002") == (C2BTransactionStatus.PROCESSED, customer.id)
    provision.assert_called_once_with(customer.id)


@pytest.mark.asyncio
async def test_platform_settled_paybill_method_still_pays_the_platform_paybill(db, client, monkeypatch):
    """A reseller paid out by B2B: customers pay us, we pay the reseller."""
    reseller = await make_reseller(db, settlement_mode="platform")
    router = await make_router(db, reseller)
    await _method(db, reseller, router, ResellerPaymentMethodType.MPESA_PAYBILL, mpesa_paybill_number="600100")
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE)
    _auth_as(monkeypatch, reseller)

    card = await _card(client, customer)

    assert card["paybill"] == settings.MPESA_SHORTCODE
    assert await handle_validation(_payload(card, trans_id="V3"), db) == ACCEPT_RESPONSE


@pytest.mark.asyncio
async def test_own_c2b_registered_paybill_is_the_paybill(db, client, session_factory, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="direct")
    router = await make_router(db, reseller)
    await _method(
        db, reseller, router, ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        mpesa_shortcode="555111", c2b_registered_at=datetime.utcnow(),
    )
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE)
    _auth_as(monkeypatch, reseller)

    card = await _card(client, customer)

    assert card["paybill"] == "555111"
    assert card["account_number"] == customer.account_number
    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(_payload(card, trans_id="PB004"), db, background_tasks=BackgroundTasks())
    assert await _status(session_factory, "PB004") == (C2BTransactionStatus.PROCESSED, customer.id)


@pytest.mark.asyncio
async def test_amount_is_the_pending_plan_the_handler_will_charge(db, client, session_factory, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="platform")
    router = await make_router(db, reseller)
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE, price=1500)
    upgrade = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, price=2500)
    customer.pending_update_data = {"plan_id": upgrade.id}
    await db.commit()
    _auth_as(monkeypatch, reseller)

    card = await _card(client, customer)

    assert card["amount"] == 2500
    # The old price would fall short of the upgrade and go to Unmatched.
    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(_payload(card, trans_id="PB005"), db, background_tasks=BackgroundTasks())
    assert await _status(session_factory, "PB005") == (C2BTransactionStatus.PROCESSED, customer.id)


# ---------------------------------------------------------------------------
# No paybill + account: never show one the handler would not match
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("method_type, fields", [
    (ResellerPaymentMethodType.MPESA_PAYBILL, {"mpesa_paybill_number": "4699342"}),
    (ResellerPaymentMethodType.MPESA_TILL, {"mpesa_till_number": "5123456"}),
])
async def test_direct_settlement_to_paybill_or_till_has_no_paybill(db, client, monkeypatch, method_type, fields):
    reseller = await make_reseller(db, settlement_mode="direct")
    router = await make_router(db, reseller)
    await _method(db, reseller, router, method_type, **fields)
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE)
    _auth_as(monkeypatch, reseller)

    card = await _card(client, customer)

    assert card == {
        "paybill": None, "account_number": None, "amount": None,
        "unavailable_reason": "no_paybill",
    }


@pytest.mark.asyncio
async def test_own_paybill_without_c2b_registration_has_no_paybill(db, client, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="direct")
    router = await make_router(db, reseller)
    await _method(
        db, reseller, router, ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        mpesa_shortcode="555222", c2b_registered_at=None,
    )
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE)
    _auth_as(monkeypatch, reseller)

    assert (await _card(client, customer))["unavailable_reason"] == "no_paybill"


@pytest.mark.asyncio
async def test_own_paybill_the_handler_cannot_find_is_not_shown(db, client, session_factory, monkeypatch):
    """Saved as " 555333 ": Safaricom sends "555333", the handler's exact
    shortcode lookup misses it and rejects the payment. Don't advertise it."""
    reseller = await make_reseller(db, settlement_mode="direct")
    router = await make_router(db, reseller)
    await _method(
        db, reseller, router, ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        mpesa_shortcode=" 555333 ", c2b_registered_at=datetime.utcnow(),
    )
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE)
    _auth_as(monkeypatch, reseller)

    card = await _card(client, customer)
    detail = (await client.get(f"/api/customers/{customer.id}")).json()

    assert card["unavailable_reason"] == "no_paybill"
    assert detail["payment_paybill"] is None
    probe = _payload(
        {"paybill": "555333", "account_number": customer.account_number, "amount": 1500},
        trans_id="PB008",
    )
    await handle_confirmation(probe, db, background_tasks=BackgroundTasks())
    assert (await _status(session_factory, "PB008"))[0] == C2BTransactionStatus.REJECTED


@pytest.mark.asyncio
async def test_hotspot_customer_has_no_paybill(db, client, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="platform")
    router = await make_router(db, reseller)
    customer = await _customer(db, reseller, router, ConnectionType.HOTSPOT)
    _auth_as(monkeypatch, reseller)

    card = await _card(client, customer)

    assert card["unavailable_reason"] == "hotspot"
    assert card["paybill"] is None and card["account_number"] is None


@pytest.mark.asyncio
async def test_outside_kenya_has_no_paybill(db, client, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="platform", market_code="CM")
    router = await make_router(db, reseller)
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE)
    _auth_as(monkeypatch, reseller)

    assert (await _card(client, customer))["unavailable_reason"] == "no_paybill"


@pytest.mark.asyncio
async def test_account_number_the_handler_would_reject_is_not_shown(db, client, monkeypatch):
    """Fails Luhn, so the handler buckets it as INVALID_LUHN."""
    reseller = await make_reseller(db, settlement_mode="platform")
    router = await make_router(db, reseller)
    good = _account()
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    customer = await _customer(db, reseller, router, ConnectionType.PPPOE, account_number=bad)
    _auth_as(monkeypatch, reseller)

    assert (await _card(client, customer))["unavailable_reason"] == "no_account_number"


@pytest.mark.asyncio
async def test_missing_account_number_or_login_has_no_card(db, client, monkeypatch):
    reseller = await make_reseller(db, settlement_mode="platform")
    router = await make_router(db, reseller)
    no_account = await _customer(db, reseller, router, ConnectionType.PPPOE, account_number=None)
    no_login = await _customer(db, reseller, router, ConnectionType.PPPOE, pppoe_username=None)
    _auth_as(monkeypatch, reseller)

    assert (await _card(client, no_account))["unavailable_reason"] == "no_account_number"
    assert (await _card(client, no_login))["unavailable_reason"] == "no_pppoe_login"
