"""
Payer names from M-Pesa: hotspot customers named "Guest 1234" by the portal
take the payer's real name from the C2B copy (STK echo) of their payment.

The STK callback carries no name; the C2B confirmation carries
FirstName/MiddleName/LastName. Covers the name cleaning, both arrival orders,
that an operator-set name is never replaced, and that odd or missing names
never get in the way of the payment.
"""

from datetime import datetime
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    MpesaTransaction,
    MpesaTransactionStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from app.services.c2b_handler import parse_c2b_payload
from app.services.payer_names import (
    MAX_NAME_LENGTH,
    apply_payer_name,
    clean_payer_name,
    is_placeholder_name,
    name_from_c2b_payload,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.test_c2b_stk_echo import (  # noqa: F401  (fixtures)
    BUSINESS_NAME,
    PAYBILL,
    RECEIPT,
    _c2b_payload,
    _stk_payload,
    _valid_account,
    app,
    client,
    current_user,
    patched_provisioning,
    provision_calls,
)


# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "parts, expected",
    [
        (("JOHN", "", "KAMAU"), "John Kamau"),
        (("JOHN", "MWANGI", "KAMAU"), "John Mwangi Kamau"),
        (("  mary-jane ", None, "o'neil"), "Mary-Jane O'Neil"),
        (("McDonald", None, None), "McDonald"),
        (("JOHN", None, None), "John"),
        (("J***", "", "K***"), None),  # masked
        (("JOHN", "", "K***"), "John"),
        (("", "", ""), None),
        ((None, None, None), None),
        (("254712345678", None, None), None),  # a phone number is not a name
        (("NA", "N/A", "null"), None),
        (("Guest", "1234", None), None),  # never "rename" to a placeholder
        (("JOHN\tPAUL", "", "  OTIENO  "), "John Paul Otieno"),
        (("ZOË", None, "ÑANDÚ"), "Zoë Ñandú"),
        (("<script>", None, "alert(1)"), "Script"),
        ((12345, None, None), None),
        ((object(), {"x": 1}, "JOY"), "Joy"),  # non-text parts are ignored, never raise
    ],
)
def test_clean_payer_name(parts, expected):
    assert clean_payer_name(*parts) == expected


def test_clean_payer_name_caps_length_on_a_word_boundary():
    name = clean_payer_name("A" * 25, "B" * 25, "C" * 25)
    assert name == "A" + "a" * 24 + " " + "B" + "b" * 24  # third word would pass the cap
    long_word = clean_payer_name("X" * 500)
    assert long_word is not None and len(long_word) <= MAX_NAME_LENGTH


@pytest.mark.parametrize(
    "name, placeholder",
    [
        (None, True), ("", True), ("   ", True),
        ("Guest 1234", True), ("guest 5678", True), ("Guest", True), (" Guest 12 ", True),
        ("Guest House", False), ("John Kamau", False), ("Guest 1234 Kamau", False),
        ("Device 4A:3F:F1", False), ("254712345678", False),
    ],
)
def test_is_placeholder_name(name, placeholder):
    assert is_placeholder_name(name) is placeholder


def test_name_from_c2b_payload_and_parse():
    payload = _c2b_payload()
    payload.update(FirstName="JANE", MiddleName="", LastName="WANJIKU")
    assert name_from_c2b_payload(payload) == "Jane Wanjiku"
    assert parse_c2b_payload(payload).payer_name == "Jane Wanjiku"

    payload.pop("FirstName"), payload.pop("LastName"), payload.pop("MiddleName")
    fields = parse_c2b_payload(payload)
    assert fields is not None and fields.payer_name is None
    assert name_from_c2b_payload(None) is None
    assert name_from_c2b_payload("not a dict") is None


# ---------------------------------------------------------------------------
# End to end over HTTP
# ---------------------------------------------------------------------------


async def _seed(session_factory, *, name="Guest 5678", checkout_id="ws_CO_NAME_1"):
    async with session_factory() as s:
        reseller = await make_reseller(s, business_name=BUSINESS_NAME)
        s.add(ResellerPaymentMethod(
            user_id=reseller.id,
            method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
            label="Tembo paybill",
            is_active=True,
            mpesa_shortcode=PAYBILL,
        ))
        plan = await make_plan(s, reseller, price=50, duration_value=1, duration_unit=DurationUnit.DAYS)
        router = await make_router(s, reseller)
        customer = await make_customer(
            s, reseller, plan, router,
            status=CustomerStatus.PENDING, mac_address="AA:BB:CC:DD:EE:77", name=name,
        )
        s.add(MpesaTransaction(
            checkout_request_id=checkout_id,
            phone_number=customer.phone,
            amount=50.0,
            reference=f"customer-{customer.id}",
            customer_id=customer.id,
            status=MpesaTransactionStatus.pending,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        ))
        await s.commit()
        return reseller, customer.id, checkout_id


async def _name(session_factory, customer_id):
    async with session_factory() as s:
        return (await s.execute(select(Customer.name).where(Customer.id == customer_id))).scalar_one()


def _named_echo(first="JANE", middle="", last="WANJIKU", **kw):
    payload = _c2b_payload(**kw)
    payload.update(FirstName=first, MiddleName=middle, LastName=last)
    return payload


async def test_stk_first_then_echo_names_the_guest(session_factory, client):
    _, customer_id, checkout_id = await _seed(session_factory)
    await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    assert await _name(session_factory, customer_id) == "Guest 5678"  # STK has no name

    resp = await client.post("/api/c2b/confirmation", json=_named_echo())
    assert resp.json()["ResultCode"] == "0"

    assert await _name(session_factory, customer_id) == "Jane Wanjiku"
    async with session_factory() as s:
        txn = (await s.execute(select(C2BTransaction))).scalar_one()
        assert txn.status == C2BTransactionStatus.STK_ECHO
        assert txn.payer_name == "Jane Wanjiku"


async def test_echo_first_then_stk_names_the_guest(session_factory, client):
    _, customer_id, checkout_id = await _seed(session_factory)
    await client.post("/api/c2b/confirmation", json=_named_echo())
    assert await _name(session_factory, customer_id) == "Guest 5678"  # not matched yet

    resp = await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    assert resp.json()["ResultCode"] == 0
    assert await _name(session_factory, customer_id) == "Jane Wanjiku"


async def test_operator_set_name_is_never_replaced(session_factory, client):
    _, customer_id, checkout_id = await _seed(session_factory, name="Mama Mboga Shop")
    await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    await client.post("/api/c2b/confirmation", json=_named_echo())
    assert await _name(session_factory, customer_id) == "Mama Mboga Shop"


async def test_a_second_payer_does_not_rename_an_already_named_customer(session_factory, client):
    _, customer_id, checkout_id = await _seed(session_factory)
    await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    await client.post("/api/c2b/confirmation", json=_named_echo())

    async with session_factory() as s:
        s.add(MpesaTransaction(
            checkout_request_id="ws_CO_NAME_2", phone_number="254700000000", amount=50.0,
            reference="r2", customer_id=customer_id, status=MpesaTransactionStatus.pending,
            created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
        ))
        await s.commit()
    await client.post("/api/mpesa/callback", json=_stk_payload("ws_CO_NAME_2", receipt="UJNSECOND01"))
    await client.post(
        "/api/c2b/confirmation",
        json=_named_echo(first="PETER", last="OTIENO", trans_id="UJNSECOND01"),
    )
    assert await _name(session_factory, customer_id) == "Jane Wanjiku"


@pytest.mark.parametrize(
    "first, middle, last",
    [("", "", ""), ("J***", "", "W***"), (None, None, None), ("254712345678", "", "")],
)
async def test_missing_or_masked_names_keep_the_placeholder(session_factory, client, first, middle, last):
    _, customer_id, checkout_id = await _seed(session_factory)
    resp = await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    assert resp.json()["ResultCode"] == 0
    payload = _c2b_payload()
    for key, value in (("FirstName", first), ("MiddleName", middle), ("LastName", last)):
        if value is None:
            payload.pop(key, None)
        else:
            payload[key] = value
    resp = await client.post("/api/c2b/confirmation", json=payload)
    assert resp.json()["ResultCode"] == "0"
    assert await _name(session_factory, customer_id) == "Guest 5678"


async def test_name_failure_never_blocks_the_payment(session_factory, client, provision_calls):
    """If writing the name blows up, the customer is still paid and provisioned."""
    _, customer_id, checkout_id = await _seed(session_factory)
    await client.post("/api/c2b/confirmation", json=_named_echo())

    with patch(
        "app.services.payer_names.update", side_effect=RuntimeError("db exploded")
    ):
        resp = await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    assert resp.json()["ResultCode"] == 0
    assert resp.json()["ResultDesc"] == "Payment processed successfully"

    async with session_factory() as s:
        payments = (await s.execute(select(CustomerPayment))).scalars().all()
        assert len(payments) == 1 and payments[0].customer_id == customer_id
        txn = (await s.execute(select(C2BTransaction))).scalar_one()
        assert txn.status == C2BTransactionStatus.STK_ECHO  # echo still retired
    assert [c[0] for c in provision_calls] == ["hotspot"]
    assert await _name(session_factory, customer_id) == "Guest 5678"


async def test_name_parse_failure_never_blocks_a_c2b_confirmation(session_factory, client):
    _, customer_id, checkout_id = await _seed(session_factory)
    await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    with patch(
        "app.services.c2b_handler.name_from_c2b_payload", side_effect=lambda p: None
    ):
        resp = await client.post("/api/c2b/confirmation", json=_named_echo())
    assert resp.json()["ResultCode"] == "0"
    async with session_factory() as s:
        txn = (await s.execute(select(C2BTransaction))).scalar_one()
        assert txn.status == C2BTransactionStatus.STK_ECHO and txn.payer_name is None


async def test_genuine_paybill_payment_names_a_placeholder_customer(session_factory, client):
    async with session_factory() as s:
        reseller = await make_reseller(s, business_name=BUSINESS_NAME)
        s.add(ResellerPaymentMethod(
            user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
            label="Tembo paybill", is_active=True, mpesa_shortcode=PAYBILL,
        ))
        plan = await make_plan(
            s, reseller, price=500, duration_value=30, duration_unit=DurationUnit.DAYS,
            connection_type=ConnectionType.PPPOE,
        )
        router = await make_router(s, reseller)
        guest = await make_customer(
            s, reseller, plan, router, status=CustomerStatus.INACTIVE,
            pppoe_username="pppoe_name_1", mac_address=None, name="Guest 1111",
            account_number=_valid_account("7130011"),
        )
        named = await make_customer(
            s, reseller, plan, router, status=CustomerStatus.INACTIVE,
            pppoe_username="pppoe_name_2", mac_address=None, name="Shop Owner",
            account_number=_valid_account("7130012"),
        )
        ids = (guest.id, guest.account_number, named.id, named.account_number)

    await client.post("/api/c2b/confirmation", json=_named_echo(trans_id="UJNPB000001", bill_ref=ids[1], amount=500))
    await client.post("/api/c2b/confirmation", json=_named_echo(trans_id="UJNPB000002", bill_ref=ids[3], amount=500))
    assert await _name(session_factory, ids[0]) == "Jane Wanjiku"
    assert await _name(session_factory, ids[2]) == "Shop Owner"


async def test_apply_payer_name_ignores_bad_input(session_factory):
    assert await apply_payer_name(None, "Jane") is False
    assert await apply_payer_name(123456, "Jane") is False  # no such customer
    assert await apply_payer_name(1, None) is False
