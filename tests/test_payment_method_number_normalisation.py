"""Paybill/till/account numbers are normalised when a payment method is saved.

The C2B handler finds a reseller by an exact BusinessShortCode match, so a
shortcode stored as " 555111 " rejected every payment Safaricom sent to
"555111" (seen in production on method 350). Numbers are now stored without
whitespace, numeric fields digits only, on create, on update, and for admin
subscription destinations; scripts/normalize_payment_method_numbers.py puts
existing rows through the same normaliser.
"""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api import payment_method_routes as pmr
from app.api.payment_method_routes import router as payment_method_router
from app.db.database import get_db
from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType
from app.services.auth import verify_token
from app.services.c2b_handler import _resolve_reseller_from_shortcode
from app.services.payment_numbers import InvalidNumber, normalize_fields, normalize_number
from scripts.normalize_payment_method_numbers import plan_changes
from tests.factories import make_reseller


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(payment_method_router)

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
    monkeypatch.setattr(pmr, "get_current_user", _fake)


async def _stored(session_factory, method_id):
    async with session_factory() as s:
        return (await s.execute(
            select(ResellerPaymentMethod).where(ResellerPaymentMethod.id == method_id)
        )).scalar_one()


# ---------------------------------------------------------------------------
# The normaliser
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw, expected", [
    (" 555111 ", "555111"),
    ("555 111", "555111"),
    ("\t555111\n", "555111"),
    ("555 111", "555111"),       # non-breaking space (pasted from a PDF)
    ("​555111﻿", "555111"),  # zero-width space, BOM
    ("4159-825", "4159825"),
    ("   ", None),
    ("", None),
])
def test_numeric_fields_keep_digits_only(raw, expected):
    assert normalize_number("mpesa_shortcode", raw) == expected


@pytest.mark.parametrize("raw", ["555l11", "P/B 555111", "５５５１１１"])
def test_numeric_fields_reject_anything_else(raw):
    with pytest.raises(InvalidNumber):
        normalize_number("mpesa_paybill_number", raw)


def test_bank_account_numbers_only_lose_whitespace():
    assert normalize_number("bank_account_number", " 0110 2345 678 ") == "01102345678"
    assert normalize_number("bank_account_number", "AB-1234 ") == "AB-1234"


def test_normalize_fields_reports_what_changed():
    class Row:
        mpesa_shortcode = " 555111 "
        mpesa_paybill_number = "600100"
        bank_account_number = None

    row = Row()
    assert normalize_fields(row) == {"mpesa_shortcode": (" 555111 ", "555111")}
    assert row.mpesa_shortcode == "555111"


# ---------------------------------------------------------------------------
# On save
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_stores_normalised_numbers(db, client, session_factory, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)

    paybill = await client.post("/api/payment-methods", json={
        "method_type": "mpesa_paybill", "label": "Paybill", "mpesa_paybill_number": " 600 100 ",
    })
    bank = await client.post("/api/payment-methods", json={
        "method_type": "bank_account", "label": "KCB",
        "bank_paybill_number": "522 522", "bank_account_number": " 1234 5678 90 ",
    })
    keys = await client.post("/api/payment-methods", json={
        "method_type": "mpesa_paybill_with_keys", "label": "Own",
        "mpesa_shortcode": " 555111\t", "mpesa_passkey": "pk",
        "mpesa_consumer_key": "ck", "mpesa_consumer_secret": "cs",
    })

    assert paybill.status_code == bank.status_code == keys.status_code == 200, (paybill.text, bank.text, keys.text)
    assert (await _stored(session_factory, paybill.json()["id"])).mpesa_paybill_number == "600100"
    stored_bank = await _stored(session_factory, bank.json()["id"])
    assert (stored_bank.bank_paybill_number, stored_bank.bank_account_number) == ("522522", "1234567890")
    assert (await _stored(session_factory, keys.json()["id"])).mpesa_shortcode == "555111"


@pytest.mark.asyncio
async def test_create_rejects_a_paybill_that_is_not_a_number(db, client, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/payment-methods", json={
        "method_type": "mpesa_paybill", "label": "Paybill", "mpesa_paybill_number": "600l00",
    })

    assert resp.status_code == 400
    assert "digits only" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_whitespace_only_paybill_is_still_required(db, client, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/payment-methods", json={
        "method_type": "mpesa_paybill", "label": "Paybill", "mpesa_paybill_number": "   ",
    })

    assert resp.status_code == 400
    assert "required" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_update_stores_normalised_numbers(db, client, session_factory, monkeypatch):
    reseller = await make_reseller(db)
    method = ResellerPaymentMethod(
        user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        label="Own", is_active=True, mpesa_shortcode="555111",
    )
    db.add(method)
    await db.commit()
    _auth_as(monkeypatch, reseller)

    resp = await client.put(f"/api/payment-methods/{method.id}", json={"mpesa_shortcode": " 555 222 "})
    bad = await client.put(f"/api/payment-methods/{method.id}", json={"mpesa_shortcode": "555-22x"})

    assert resp.status_code == 200, resp.text
    assert bad.status_code == 400
    assert (await _stored(session_factory, method.id)).mpesa_shortcode == "555222"


@pytest.mark.asyncio
async def test_saved_shortcode_is_found_by_the_c2b_handler(db, client, monkeypatch):
    """The point of it: what Safaricom sends matches what was saved."""
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)
    resp = await client.post("/api/payment-methods", json={
        "method_type": "mpesa_paybill_with_keys", "label": "Own",
        "mpesa_shortcode": " 555333 ", "mpesa_passkey": "pk",
        "mpesa_consumer_key": "ck", "mpesa_consumer_secret": "cs",
    })
    assert resp.status_code == 200, resp.text

    assert await _resolve_reseller_from_shortcode(db, "555333") == (reseller.id, False)


# ---------------------------------------------------------------------------
# One-off fix for rows saved before this change
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backfill_plans_only_real_changes_and_leaves_non_numbers(db):
    reseller = await make_reseller(db)
    rows = [
        ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
                              label="Spaced", is_active=True, mpesa_shortcode=" 4123456"),
        ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_PAYBILL,
                              label="Clean", is_active=True, mpesa_paybill_number="600100"),
        ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_PAYBILL,
                              label="Junk", is_active=True, mpesa_paybill_number="see notes"),
    ]
    db.add_all(rows)
    await db.commit()

    changes, rejects = plan_changes(rows)

    assert [(pm.label, diff) for pm, diff in changes] == [
        ("Spaced", {"mpesa_shortcode": (" 4123456", "4123456")}),
    ]
    assert [(pm.label, field) for pm, field, _ in rejects] == [("Junk", "mpesa_paybill_number")]


@pytest.mark.asyncio
async def test_c2b_registration_uses_and_keeps_the_normalised_shortcode(db, session_factory, monkeypatch):
    """A row saved before this change heals the moment C2B is registered."""
    from unittest.mock import AsyncMock

    from app.api import c2b_routes
    from app.api.c2b_routes import router as c2b_router

    reseller = await make_reseller(db)
    pm = ResellerPaymentMethod(
        user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        label="Own", is_active=True, mpesa_shortcode=" 600999 ",
        mpesa_consumer_key_encrypted="enc-key", mpesa_consumer_secret_encrypted="enc-secret",
    )
    db.add(pm)
    await db.commit()
    monkeypatch.setattr(c2b_routes, "get_current_user", AsyncMock(return_value=reseller))
    monkeypatch.setattr(c2b_routes, "decrypt_credential", lambda v: v.replace("enc-", ""))
    daraja = AsyncMock(return_value={"ResponseCode": "0"})
    monkeypatch.setattr(c2b_routes, "_call_daraja_registerurl", daraja)

    application = FastAPI()
    application.include_router(c2b_router)

    async def _override_get_db():
        async with session_factory() as s:
            yield s
            await s.commit()

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        resp = await c.post(f"/api/payment-methods/{pm.id}/register-c2b", json={
            "confirmation_url": "https://example.test/api/c2b/confirmation",
            "validation_url": "https://example.test/api/c2b/validation",
        })

    assert resp.status_code == 200, resp.text
    assert daraja.await_args.kwargs["shortcode"] == "600999"
    assert (await _stored(session_factory, pm.id)).mpesa_shortcode == "600999"
