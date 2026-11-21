"""Normalise the numbers on a reseller payment method before they are saved.

A paybill typed as " 555111 " or "555 111" used to be stored as typed. The
C2B handler looks a payment's BusinessShortCode up with an exact match, so a
stored " 555111 " never matched what Safaricom sends ("555111"): the payment
was rejected while reminders (which trim) kept advertising the paybill.

Numeric fields (paybills, shortcodes, tills) keep digits only: whitespace of
any kind (spaces, tabs, non-breaking and zero-width spaces) and dashes are
removed, and anything else left over is rejected. Bank account numbers can
carry letters at some banks, so they only lose whitespace.
"""

from __future__ import annotations

import re
from typing import Optional

from sqlalchemy import func, or_

# \s covers ASCII and Unicode whitespace incl. NBSP; zero-width characters
# and the BOM are not whitespace to Python but are invisible in a form.
_INVISIBLE = re.compile(r"[\s​‌‍⁠﻿]+")
_DASHES = re.compile(r"[-‐-―]")

# Field name -> numeric?
NUMBER_FIELDS: dict[str, bool] = {
    "mpesa_shortcode": True,
    "mpesa_paybill_number": True,
    "mpesa_till_number": True,
    "bank_paybill_number": True,
    "bank_account_number": False,
}


class InvalidNumber(ValueError):
    def __init__(self, field: str, value: str):
        super().__init__(f"{field} must contain digits only (got {value!r})")
        self.field = field


def normalize_number(field: str, raw: Optional[str]) -> Optional[str]:
    """The stored form of ``raw`` for ``field``; None when nothing is left."""
    if raw is None:
        return None
    value = _INVISIBLE.sub("", str(raw))
    if NUMBER_FIELDS.get(field, False):
        value = _DASHES.sub("", value)
        if value and not (value.isascii() and value.isdigit()):
            raise InvalidNumber(field, str(raw))
    return value or None


def normalize_fields(obj, fields=None) -> dict[str, tuple[Optional[str], Optional[str]]]:
    """Normalise the number attributes of ``obj`` in place.

    Works on request models and ORM rows alike. Only attributes that are set
    (not None) are touched. Returns {field: (before, after)} for every value
    that changed, for logging.
    """
    changed: dict[str, tuple[Optional[str], Optional[str]]] = {}
    for field in fields or NUMBER_FIELDS:
        before = getattr(obj, field, None)
        if before is None:
            continue
        after = normalize_number(field, before)
        if after != before:
            setattr(obj, field, after)
            changed[field] = (before, after)
    return changed


# Every form a Kenyan number is stored in across the ledgers: STK rows keep
# 2547..., customers are saved as typed (07..., +254..., 254...), and some
# paybill account numbers are the bare 7... form.
_PHONE_CHARS = re.compile(r"^\+?[\d\s()\-]+$")


def phone_search_variants(raw: Optional[str]) -> list[str]:
    """The stored forms of a phone typed in any of 07…/7…/254…/+254….

    Returns [] when ``raw`` does not look like a phone number (an M-Pesa
    receipt code, a name), so callers can skip the phone match. A number
    that is not Kenyan is matched as typed, with and without a leading +.
    """
    value = (raw or "").strip()
    if not value or not _PHONE_CHARS.match(value):
        return []
    digits = re.sub(r"\D", "", value)
    national = None
    if len(digits) == 12 and digits.startswith("254"):
        national = digits[3:]
    elif len(digits) == 10 and digits.startswith("0"):
        national = digits[1:]
    elif len(digits) == 9:
        national = digits
    if national is not None and national[0] in "17":
        return ["0" + national, "254" + national, "+254" + national, national]
    if len(digits) < 9:
        return []
    return [digits, "+" + digits]


PAYMENT_SEARCH_DESCRIPTION = (
    "Find one payment by its M-Pesa code or phone: exact, case-insensitive "
    "receipt/transaction code, or the payer's phone as 07…, 7…, 254… or +254…."
)


def payment_search_condition(term: Optional[str], code_columns, phone_columns):
    """WHERE clause for one exact payment lookup, or None when ``term`` is blank.

    Matches the M-Pesa receipt code case-insensitively (``tkl3xy9q2m`` finds
    ``TKL3XY9Q2M``) and, when ``term`` reads as a phone, any of its stored
    forms (07…, 7…, 254…, +254…). Both are equality tests: a partial code
    or a name is not a match.
    """
    term = (term or "").strip()
    if not term:
        return None
    conditions = [func.upper(col) == term.upper() for col in code_columns]
    variants = phone_search_variants(term)
    if variants:
        conditions.extend(col.in_(variants) for col in phone_columns)
    return or_(*conditions)
