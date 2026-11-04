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
