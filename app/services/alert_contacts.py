"""Who receives a reseller's router status SMS alerts.

A reseller can list up to ``MAX_ALERT_PHONES`` mobile numbers
(``users.alert_phones``, a JSON list) — e.g. themselves plus a field
technician. When the list is empty the alert goes to ``users.support_phone``,
exactly as before the list existed.

Numbers are cleaned the same way as ``support_phone`` (spaces, dashes and
brackets removed, ``+`` and 7-15 digits) and, for Kenyan-market resellers, must
be a Kenyan mobile number. Two spellings of the same number ("0712 345 678",
"+254712345678") count as one recipient: duplicates are dropped after
normalisation, both when saving and when sending.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

MAX_ALERT_PHONES = 3

_SUPPORT_PHONE_RE = re.compile(r"^\+?\d{7,15}$")


def clean_phone(raw: Optional[str]) -> str:
    """The support_phone cleaning: drop spaces, dashes and brackets."""
    return re.sub(r"[\s\-()]", "", raw or "")


def _is_kenyan(user) -> bool:
    return (getattr(user, "market_code", None) or "KE").upper() == "KE"


def phone_key(raw: Optional[str]) -> Optional[str]:
    """Comparison key: the 2547XXXXXXXX form for a Kenyan mobile, else the digits."""
    from app.api.subscription_routes import normalize_kenyan_msisdn

    cleaned = clean_phone(raw)
    if not cleaned:
        return None
    kenyan = normalize_kenyan_msisdn(cleaned)
    if kenyan:
        return kenyan
    digits = re.sub(r"\D", "", cleaned)
    return digits or None


def validate_alert_phones(raw_phones: Iterable[str], user) -> list[str]:
    """Clean, validate and de-duplicate a submitted list. Raises ValueError."""
    from app.api.subscription_routes import normalize_kenyan_msisdn

    kenyan = _is_kenyan(user)
    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_phones:
        cleaned = clean_phone(raw)
        if not cleaned:
            continue
        if not _SUPPORT_PHONE_RE.match(cleaned):
            raise ValueError("Invalid phone number format")
        if kenyan and normalize_kenyan_msisdn(cleaned) is None:
            raise ValueError("Enter a Kenyan mobile number, e.g. 0712 345 678")
        key = phone_key(cleaned)
        if key in seen:
            continue
        seen.add(key)
        out.append(cleaned)
    if len(out) > MAX_ALERT_PHONES:
        raise ValueError(f"You can add up to {MAX_ALERT_PHONES} mobile numbers")
    return out


def configured_alert_phones(owner) -> list[str]:
    value = getattr(owner, "alert_phones", None)
    if not isinstance(value, list):
        return []
    return [p for p in value if isinstance(p, str) and p.strip()]


def alert_recipients(owner) -> list[str]:
    """Numbers an alert goes to, in order, de-duplicated, at most MAX_ALERT_PHONES.

    The configured list when it has any number, otherwise the support phone.
    """
    source = configured_alert_phones(owner) or [getattr(owner, "support_phone", None)]
    out: list[str] = []
    seen: set[str] = set()
    for raw in source:
        phone = (raw or "").strip()
        key = phone_key(phone)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(phone)
    return out[:MAX_ALERT_PHONES]
