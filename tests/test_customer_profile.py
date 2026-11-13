"""Customer register details (national ID, email, alt phone, address, install
date, notes): validation, register / edit / read, masking and privacy."""

import json
import logging
from datetime import date

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.api import customer_routes
from app.db.models import ConnectionType, Customer, CustomerEvent
from app.services import customer_profile as cp
from tests.factories import make_customer, make_plan, make_reseller, make_router

NATIONAL_ID = "30981776"  # never a substring of the factory phone numbers


def _as(monkeypatch, user):
    async def _get(token, db):
        return user
    monkeypatch.setattr(customer_routes, "get_current_user", _get)


@pytest.fixture(autouse=True)
def _no_welcome_sms(monkeypatch):
    from app.services import customer_notifications
    monkeypatch.setattr(customer_notifications, "spawn_welcome_message", lambda _id: None)


async def _seed(db, connection_type=ConnectionType.PPPOE):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=connection_type)
    router = await make_router(db, reseller)
    return reseller, plan, router


def _register(plan, router, **kw):
    base = dict(name="Wanjiru", phone="254712345678", plan_id=plan.id, router_id=router.id)
    base.update(kw)
    return customer_routes.CustomerRegisterRequest(**base)


FULL_PROFILE = dict(
    national_id=" 1234 5678 ",
    email=" Wanjiru@Example.COM ",
    alt_phone=" +254 722 000 111 ",
    address_line="House B4",
    building="Kahawa Sukari Estate",
    installation_date="2026-11-10",
    notes="Router on the second floor.\nCall before visiting.",
)


# ---------------------------------------------------------------------------
# Masking and cleaning
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, masked", [
    ("12345678", "***678"),
    ("A1234567", "***567"),
    ("AB 12-34/5", "***345"),
    ("12", "***"),
    ("", None),
    (None, None),
])
def test_mask_national_id_shows_last_three_only(raw, masked):
    assert cp.mask_national_id(raw) == masked


def test_mask_does_not_reveal_length():
    assert cp.mask_national_id("1234") == cp.mask_national_id("99999234")[:3] + "234"
    assert len(cp.mask_national_id("1234")) == len(cp.mask_national_id("123456789012"))


def test_clean_profile_normalises_values():
    out = cp.clean_profile_updates(FULL_PROFILE)
    assert out["national_id"] == "1234 5678"
    assert out["email"] == "wanjiru@example.com"
    assert out["alt_phone"] == "+254 722 000 111"
    assert out["installation_date"] == date(2026, 11, 10)
    assert out["notes"] == "Router on the second floor.\nCall before visiting."


def test_clean_profile_absent_none_and_blank():
    assert cp.clean_profile_updates({}) == {}
    assert cp.clean_profile_updates({"email": None}) == {}
    assert cp.clean_profile_updates({"email": "  ", "notes": ""}) == {"email": None, "notes": None}


def test_installation_date_accepts_iso_timestamp():
    out = cp.clean_profile_updates({"installation_date": "2026-11-10T00:00:00.000Z"})
    assert out["installation_date"] == date(2026, 11, 10)


@pytest.mark.parametrize("field, value", [
    ("email", "not-an-email"),
    ("email", "a@b"),
    ("email", "a b@example.com"),
    ("alt_phone", "abc"),
    ("alt_phone", "12345"),
    ("alt_phone", "0712 345 678 ext 9"),
    ("national_id", "1234;DROP"),
    ("national_id", "1" * 40),
    ("installation_date", "10/11/2026"),
    ("notes", "x" * (cp.NOTES_MAX + 1)),
    ("building", "x" * (cp.BUILDING_MAX + 1)),
])
def test_clean_profile_rejects_bad_values(field, value):
    with pytest.raises(HTTPException) as err:
        cp.clean_profile_updates({field: value})
    assert err.value.status_code == 400


# ---------------------------------------------------------------------------
# Register / edit / read
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("connection_type", [ConnectionType.PPPOE, ConnectionType.HOTSPOT])
async def test_register_saves_and_returns_profile(db, monkeypatch, connection_type):
    reseller, plan, router = await _seed(db, connection_type)
    _as(monkeypatch, reseller)
    extra = {"mac_address": "AA:BB:CC:DD:EE:01"} if connection_type == ConnectionType.HOTSPOT else {}

    out = await customer_routes.register_customer_api(
        _register(plan, router, **FULL_PROFILE, **extra), db, "t")

    row = await db.get(Customer, out["id"])
    assert row.national_id == "1234 5678"
    assert row.email == "wanjiru@example.com"
    assert row.alt_phone == "+254 722 000 111"
    assert row.address_line == "House B4"
    assert row.building == "Kahawa Sukari Estate"
    assert row.installation_date == date(2026, 11, 10)
    # The reseller's own form gets the full number back.
    assert out["national_id"] == "1234 5678"
    assert out["national_id_masked"] == "***678"
    assert out["installation_date"] == "2026-11-10"


@pytest.mark.asyncio
async def test_register_without_profile_still_works(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)

    out = await customer_routes.register_customer_api(_register(plan, router), db, "t")

    row = await db.get(Customer, out["id"])
    assert row.national_id is None and row.email is None and row.notes is None
    assert out["national_id_masked"] is None


@pytest.mark.asyncio
async def test_register_with_bad_email_creates_nothing(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)

    with pytest.raises(HTTPException) as err:
        await customer_routes.register_customer_api(
            _register(plan, router, email="wanjiru-at-example"), db, "t")
    assert err.value.status_code == 400
    assert (await db.execute(select(func.count(Customer.id)))).scalar_one() == 0


@pytest.mark.asyncio
async def test_edit_sets_keeps_and_clears_profile(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="w_k",
                                   email="old@example.com", building="Old Court")

    out = await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(national_id="A7654321", alt_phone="0722000111", building=""),
        db, "t")

    await db.refresh(customer)
    assert customer.national_id == "A7654321"
    assert customer.alt_phone == "0722000111"
    assert customer.building is None             # "" clears
    assert customer.email == "old@example.com"   # absent = unchanged
    assert out["customer"]["national_id"] == "A7654321"
    assert out["customer"]["building"] is None


@pytest.mark.asyncio
async def test_edit_with_bad_value_changes_nothing(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="w_k")

    with pytest.raises(HTTPException) as err:
        await customer_routes.edit_customer(
            customer.id,
            customer_routes.CustomerEditRequest(name="Renamed", email="broken"),
            db, "t")
    assert err.value.status_code == 400
    await db.refresh(customer)
    assert customer.name != "Renamed"


@pytest.mark.asyncio
async def test_edit_audit_log_never_holds_the_national_id(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="w_k")

    await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(
            national_id=NATIONAL_ID, notes="Gate code 4471", email="w@example.com"),
        db, "t")

    event = (await db.execute(select(CustomerEvent))).scalar_one()
    assert "ID / passport number changed" in event.message
    assert "notes changed" in event.message
    assert "w@example.com" in event.message
    dumped = event.message + json.dumps(event.details)
    assert NATIONAL_ID not in dumped
    assert "4471" not in dumped


@pytest.mark.asyncio
async def test_other_reseller_cannot_edit_or_read(db, monkeypatch):
    owner, plan, router = await _seed(db)
    other = await make_reseller(db)
    customer = await make_customer(db, owner, plan, router, national_id=NATIONAL_ID)
    _as(monkeypatch, other)

    with pytest.raises(HTTPException) as err:
        await customer_routes.get_customer_detail(customer.id, db, "t")
    assert err.value.status_code == 404
    with pytest.raises(HTTPException) as err:
        await customer_routes.edit_customer(
            customer.id, customer_routes.CustomerEditRequest(national_id="99999999"), db, "t")
    assert err.value.status_code == 404
    await db.refresh(customer)
    assert customer.national_id == NATIONAL_ID


@pytest.mark.asyncio
async def test_detail_returns_full_id_list_returns_masked_only(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    customer = await make_customer(
        db, reseller, plan, router, national_id=NATIONAL_ID, email="w@example.com",
        building="Kahawa Sukari", installation_date=date(2026, 11, 1), notes="note")

    detail = await customer_routes.get_customer_detail(customer.id, db, "t")
    assert detail["national_id"] == NATIONAL_ID
    assert detail["national_id_masked"] == "***776"
    assert detail["installation_date"] == "2026-11-01"

    for listing in (
        await customer_routes.get_customers_api(router_id=None, tier=None, db=db, token="t"),
    ):
        (item,) = listing
        assert "national_id" not in item
        assert item["national_id_masked"] == "***776"
        assert item["email"] == "w@example.com"
        assert item["building"] == "Kahawa Sukari"
        assert NATIONAL_ID not in json.dumps(item, default=str)


@pytest.mark.asyncio
async def test_active_list_is_masked_too(db, monkeypatch):
    from datetime import datetime, timedelta
    from app.db.models import CustomerStatus

    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    await make_customer(db, reseller, plan, router, national_id=NATIONAL_ID,
                        status=CustomerStatus.ACTIVE, expiry=datetime.utcnow() + timedelta(days=1))

    (item,) = await customer_routes.get_active_customers(router_id=None, tier=None, db=db, token="t")
    assert "national_id" not in item
    assert item["national_id_masked"] == "***776"
    assert NATIONAL_ID not in json.dumps(item, default=str)


# ---------------------------------------------------------------------------
# National-ID search
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_national_id_matches_is_scoped_and_ignores_separators(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    other = await make_reseller(db)
    other_plan = await make_plan(db, other)
    other_router = await make_router(db, other)
    mine = await make_customer(db, reseller, plan, router, national_id="1234 5678")
    passport = await make_customer(db, reseller, plan, router, national_id="AK-998877")
    await make_customer(db, reseller, plan, router)
    await make_customer(db, other, other_plan, other_router, national_id="12345678")
    _as(monkeypatch, reseller)

    assert (await customer_routes.national_id_matches("12345678", db, "t")) == {"customer_ids": [mine.id]}
    assert (await customer_routes.national_id_matches("4567", db, "t")) == {"customer_ids": [mine.id]}
    assert (await customer_routes.national_id_matches("ak 9988", db, "t")) == {"customer_ids": [passport.id]}
    # Too short to search: nothing, rather than every ID containing "12".
    assert (await customer_routes.national_id_matches("123", db, "t")) == {"customer_ids": []}
    assert (await customer_routes.national_id_matches("%%%%", db, "t")) == {"customer_ids": []}


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_national_id_never_logged(db, monkeypatch, caplog):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    caplog.set_level(logging.DEBUG)

    out = await customer_routes.register_customer_api(
        _register(plan, router, national_id=NATIONAL_ID), db, "t")
    await customer_routes.edit_customer(
        out["id"], customer_routes.CustomerEditRequest(national_id="87654321"), db, "t")

    # The app's own log lines (the test DB driver logs SQL at DEBUG; production
    # runs asyncpg at INFO, which logs no parameters).
    app_text = " | ".join(r.getMessage() for r in caplog.records if r.name.startswith("app"))
    assert app_text  # registration and edit were logged
    assert NATIONAL_ID not in app_text
    assert "87654321" not in app_text


def test_error_text_drops_sql_parameters():
    from sqlalchemy.exc import IntegrityError

    exc = IntegrityError("INSERT INTO customers ...", {"national_id": NATIONAL_ID}, Exception("dup key"))
    assert NATIONAL_ID in str(exc)
    assert NATIONAL_ID not in customer_routes._error_text(exc)
    assert "dup key" in customer_routes._error_text(exc)
