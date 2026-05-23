"""
Account number generation + validation for C2B Paybill.

Format: 8 characters, ASCII digits only. First 7 digits are a random base;
the 8th is a Luhn check digit. Globally unique across all customers (the
DB-level UNIQUE constraint is the source of truth; this module just retries
on collision when generating).

Why Luhn: lets the C2B Validation URL reject typos client-side before money
moves. A customer who fat-fingers one digit will fail Luhn locally, so
Safaricom never accepts the payment in the first place.

Why numeric-only: M-Pesa Paybill prompts on feature phones are easier to
key in with digits. Safaricom accepts up to 20 alphanumeric chars for
BillRefNumber, but 8 digits is plenty of namespace (10^7 base = 10 million
customers) and stays compact.

Usage:
    from app.services.account_numbers import generate_account_number, is_valid_account_number

    new_acct = await generate_account_number(db)  # checks DB for collisions
    if is_valid_account_number(input_from_safaricom):
        ...
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from sqlalchemy import select

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


ACCOUNT_NUMBER_LENGTH = 8
_BASE_LENGTH = ACCOUNT_NUMBER_LENGTH - 1
_MAX_GENERATION_ATTEMPTS = 20


def luhn_check_digit(base: str) -> str:
    """Compute the Luhn check digit for a numeric string `base`.

    Returns a single ASCII digit. The full number `base + check_digit` will
    satisfy is_valid_account_number().
    """
    if not base.isdigit():
        raise ValueError("Luhn base must contain only ASCII digits")

    total = 0
    # Process digits right-to-left; positions 1,3,5,... (from the right of the
    # full number, which includes the check digit at position 0) get doubled.
    # Since check_digit hasn't been appended yet, base[-1] will be at position 1
    # of the final number, so it's doubled.
    for i, ch in enumerate(reversed(base)):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return str((10 - (total % 10)) % 10)


def is_valid_account_number(value: str) -> bool:
    """True if `value` is a syntactically valid Luhn-checked account number."""
    if not isinstance(value, str):
        return False
    if len(value) != ACCOUNT_NUMBER_LENGTH:
        return False
    if not value.isdigit():
        return False
    base, check = value[:-1], value[-1]
    return luhn_check_digit(base) == check


def _random_account_number() -> str:
    """Generate one Luhn-valid account number without DB collision check."""
    base_int = secrets.randbelow(10 ** _BASE_LENGTH)
    base = str(base_int).zfill(_BASE_LENGTH)
    return base + luhn_check_digit(base)


async def generate_account_number(db: "AsyncSession") -> str:
    """Generate a Luhn-valid account number that is not yet in customers.account_number.

    Retries up to _MAX_GENERATION_ATTEMPTS times. With ~10M namespace and a
    small number of existing customers, first-try collisions are vanishingly
    rare; the retry is a safety net, not a hot path.
    """
    from app.db.models import Customer

    for _ in range(_MAX_GENERATION_ATTEMPTS):
        candidate = _random_account_number()
        existing = await db.execute(
            select(Customer.id).where(Customer.account_number == candidate)
        )
        if existing.scalar_one_or_none() is None:
            return candidate

    raise RuntimeError(
        f"Could not generate a unique account number after {_MAX_GENERATION_ATTEMPTS} attempts. "
        "Namespace may be exhausted or DB is in an unexpected state."
    )
