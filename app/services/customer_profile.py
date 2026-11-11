"""Customer register details: the optional profile a reseller keeps per customer.

National ID / passport, email, an alternative phone, house/unit and
building/estate, the installation date and free-text notes. All optional, all
plain columns on ``customers`` (see main.py run_customer_profile_migrations).

To add a field: add the column on the model and in the startup migration, add
it to PROFILE_FIELDS with a cleaner below, and to the admin form. Everything
else (register, edit, read, audit log) reads PROFILE_FIELDS.

The national ID is personal data:
- list endpoints and exports only ever carry ``national_id_masked`` (the last
  three characters), never the number itself;
- the full number is returned only by the single-customer endpoints of the
  reseller who owns the customer (detail, register, edit);
- it is never written to a log line or to the audit log (an edit records only
  "national ID changed").
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Callable, Optional

from fastapi import HTTPException

NATIONAL_ID_MAX = 32
EMAIL_MAX = 254
PHONE_MAX = 32
ADDRESS_LINE_MAX = 200
BUILDING_MAX = 120
NOTES_MAX = 2000

# Shortest national-ID fragment the list search looks up (keeps a lookup from
# turning into "every customer whose ID contains a 1").
NATIONAL_ID_SEARCH_MIN = 4

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_CHARS_RE = re.compile(r"^\+?[0-9 ()\-]+$")
_NATIONAL_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9 /\-]*$")


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def _collapse(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def clean_national_id(value: str) -> str:
    cleaned = _collapse(value).upper()
    if len(cleaned) > NATIONAL_ID_MAX:
        raise _bad(f"ID / passport number is too long (max {NATIONAL_ID_MAX} characters)")
    if not _NATIONAL_ID_RE.match(cleaned):
        raise _bad("ID / passport number can only contain letters, digits, spaces, '/' and '-'")
    return cleaned


def clean_email(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) > EMAIL_MAX or not _EMAIL_RE.match(cleaned):
        raise _bad("Enter a valid email address, like name@example.com")
    return cleaned


def clean_phone(value: str) -> str:
    """Same treatment as the main phone field (trimmed), plus a sanity check
    that it is a phone number: digits with optional +, spaces, dashes or
    brackets, 7 to 15 digits."""
    cleaned = _collapse(value)
    digits = re.sub(r"\D", "", cleaned)
    if len(cleaned) > PHONE_MAX or not _PHONE_CHARS_RE.match(cleaned) or not 7 <= len(digits) <= 15:
        raise _bad("Enter a valid alternative phone number")
    return cleaned


def _clean_text(max_len: int, label: str) -> Callable[[str], str]:
    def clean(value: str) -> str:
        cleaned = _collapse(value)
        if len(cleaned) > max_len:
            raise _bad(f"{label} is too long (max {max_len} characters)")
        return cleaned
    return clean


def clean_notes(value: str) -> str:
    # Keep line breaks, only trim the ends.
    cleaned = value.replace("\r\n", "\n").strip()
    if len(cleaned) > NOTES_MAX:
        raise _bad(f"Notes are too long (max {NOTES_MAX} characters)")
    return cleaned


def clean_installation_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    try:
        # "2026-11-11" or a full ISO timestamp from a date picker.
        return date.fromisoformat(text[:10])
    except ValueError:
        raise _bad("Installation date must be a date like 2026-11-11") from None


# field -> cleaner. Order is the order the admin shows them in.
PROFILE_FIELDS: dict[str, Callable[[Any], Any]] = {
    "national_id": clean_national_id,
    "email": clean_email,
    "alt_phone": clean_phone,
    "address_line": _clean_text(ADDRESS_LINE_MAX, "House / unit"),
    "building": _clean_text(BUILDING_MAX, "Building / estate"),
    "installation_date": clean_installation_date,
    "notes": clean_notes,
}


def clean_profile_updates(raw: dict) -> dict:
    """Validated column values for the profile fields present in ``raw``.

    A field that is absent or None is left out (unchanged on an edit). An
    empty string clears it (stored as NULL).
    """
    out: dict = {}
    for field, cleaner in PROFILE_FIELDS.items():
        if field not in raw or raw[field] is None:
            continue
        value = raw[field]
        if isinstance(value, str) and not value.strip():
            out[field] = None
            continue
        out[field] = cleaner(value)
    return out


def mask_national_id(value: Optional[str]) -> Optional[str]:
    """``***123``: only the last three characters, never the length."""
    if not value:
        return None
    tail = re.sub(r"[^A-Za-z0-9]", "", value)[-3:]
    return f"***{tail}" if len(tail) == 3 else "***"


def normalize_id_query(value: Optional[str]) -> str:
    """What a national-ID search compares on: letters and digits, upper case."""
    return re.sub(r"[^A-Za-z0-9]", "", value or "").upper()


def profile_fields(customer, *, reveal_national_id: bool) -> dict:
    """Profile fields for an API response.

    ``reveal_national_id`` is True only on single-customer responses to the
    owning reseller; lists and exports get the masked form alone.
    """
    out = {
        "national_id_masked": mask_national_id(customer.national_id),
        "email": customer.email,
        "alt_phone": customer.alt_phone,
        "address_line": customer.address_line,
        "building": customer.building,
        "installation_date": (
            customer.installation_date.isoformat() if customer.installation_date else None
        ),
        "notes": customer.notes,
    }
    if reveal_national_id:
        out["national_id"] = customer.national_id
    return out


# Audit-log labels. national_id and notes are recorded as "changed" only.
AUDITED_PROFILE_FIELDS = (
    ("email", "email"),
    ("alt_phone", "alternative phone"),
    ("address_line", "house / unit"),
    ("building", "building / estate"),
    ("installation_date", "installation date"),
)
CHANGED_ONLY_PROFILE_FIELDS = (
    ("national_id", "ID / passport number"),
    ("notes", "notes"),
)
