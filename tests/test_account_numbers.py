"""
Unit tests for the account number generator + Luhn validator.

The Luhn check digit is what lets the C2B Validation URL reject typos
before money moves, so these tests are load-bearing for the whole feature.
If is_valid_account_number disagrees with generate_account_number, the
Validation URL will reject our own correctly-generated numbers and
real customer payments will fail.
"""

import pytest

from app.services.account_numbers import (
    ACCOUNT_NUMBER_LENGTH,
    generate_account_number,
    is_valid_account_number,
    luhn_check_digit,
    _random_account_number,
)
from app.db.models import Customer, CustomerStatus
from tests.factories import make_customer, make_plan, make_reseller, make_router

# Note: asyncio_mode=auto in pytest.ini handles async tests; no pytestmark needed.


# ---------------------------------------------------------------------------
# Luhn algorithm — known-good vectors
# ---------------------------------------------------------------------------


def test_luhn_check_digit_known_vectors():
    """Verify Luhn against published examples.

    Standard Luhn examples (the algorithm is identical to credit-card check):
    - "7992739871" → check digit "3" (full number 79927398713)
    - "1234567"    → check digit "4" (full number 12345674)
    - "0000000"    → check digit "0" (full number 00000000)
    """
    assert luhn_check_digit("7992739871") == "3"
    assert luhn_check_digit("1234567") == "4"
    assert luhn_check_digit("0000000") == "0"


def test_luhn_check_digit_rejects_non_digit():
    with pytest.raises(ValueError):
        luhn_check_digit("12345A7")


# ---------------------------------------------------------------------------
# is_valid_account_number
# ---------------------------------------------------------------------------


def test_is_valid_account_number_accepts_correct_check():
    # 12345674 = 1234567 + Luhn(1234567)=4
    assert is_valid_account_number("12345674") is True


def test_is_valid_account_number_rejects_wrong_check():
    assert is_valid_account_number("12345670") is False
    assert is_valid_account_number("12345675") is False


def test_is_valid_account_number_rejects_wrong_length():
    assert is_valid_account_number("1234567") is False
    assert is_valid_account_number("123456789") is False
    assert is_valid_account_number("") is False


def test_is_valid_account_number_rejects_non_digits():
    assert is_valid_account_number("1234567A") is False
    assert is_valid_account_number("ABCDEFGH") is False


def test_is_valid_account_number_rejects_non_string():
    assert is_valid_account_number(12345674) is False
    assert is_valid_account_number(None) is False


# ---------------------------------------------------------------------------
# _random_account_number — every output must satisfy validator
# ---------------------------------------------------------------------------


def test_random_account_number_is_always_valid_over_many_calls():
    """Generator and validator must agree. Run 1000x to catch edge cases
    (especially leading zeros from zfill)."""
    for _ in range(1000):
        n = _random_account_number()
        assert len(n) == ACCOUNT_NUMBER_LENGTH
        assert n.isdigit()
        assert is_valid_account_number(n), f"Validator rejected own output: {n!r}"


def test_random_account_number_preserves_leading_zeros():
    """zfill must produce 7-digit base, not strip leading zeros that would
    yield a < 8-char output."""
    seen_lengths = {len(_random_account_number()) for _ in range(500)}
    assert seen_lengths == {ACCOUNT_NUMBER_LENGTH}


# ---------------------------------------------------------------------------
# generate_account_number — DB collision handling
# ---------------------------------------------------------------------------


async def test_generate_account_number_unique_in_empty_db(db):
    n1 = await generate_account_number(db)
    assert is_valid_account_number(n1)


async def test_generate_account_number_avoids_existing(db, monkeypatch):
    """If the random generator collides with an existing customer's number,
    generate_account_number must retry until it finds a free one."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)

    # Seed a customer with a known account number
    taken = "12345674"
    customer = await make_customer(db, reseller, plan, router, account_number=taken)
    assert customer.account_number == taken

    # Force the random generator to first emit the taken number, then a free one
    free = "98765431"  # 9876543 + Luhn = 1
    assert is_valid_account_number(free)
    outputs = iter([taken, free])
    monkeypatch.setattr(
        "app.services.account_numbers._random_account_number",
        lambda: next(outputs),
    )

    result = await generate_account_number(db)
    assert result == free


async def test_generate_account_number_gives_up_after_max_attempts(db, monkeypatch):
    """If every attempt collides, we raise rather than loop forever."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    taken = "12345674"
    await make_customer(db, reseller, plan, router, account_number=taken)

    monkeypatch.setattr(
        "app.services.account_numbers._random_account_number",
        lambda: taken,
    )

    with pytest.raises(RuntimeError, match="unique account number"):
        await generate_account_number(db)


async def test_generated_numbers_unique_in_bulk(db):
    """Sanity check: generate a batch back-to-back, assert all unique and
    all Luhn-valid. This is the closest unit-test analogue to the backfill
    script that step 4 will introduce."""
    from sqlalchemy import select

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)

    generated = []
    for i in range(20):
        n = await generate_account_number(db)
        # Persist so the next generate_account_number sees it as taken
        await make_customer(
            db, reseller, plan, router,
            name=f"bulk-{i}",
            mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            pppoe_username=f"bulk_{i}",
            account_number=n,
        )
        generated.append(n)

    assert len(set(generated)) == 20
    for n in generated:
        assert is_valid_account_number(n)

    stored = (
        await db.execute(select(Customer.account_number).where(Customer.account_number.in_(generated)))
    ).scalars().all()
    assert set(stored) == set(generated)
