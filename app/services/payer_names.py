"""
Payer names from M-Pesa payment data.

Hotspot customers created at the captive portal are named "Guest <last 4
digits of the phone>" (app/api/payment_routes.py, register-and-pay). The STK
push callback carries no name at all (its CallbackMetadata is Amount,
MpesaReceiptNumber, PhoneNumber, TransactionDate, Balance), but Safaricom's
C2B confirmation does: FirstName / MiddleName / LastName. On a paybill with
C2B URLs registered every STK push also produces a C2B copy of the same
receipt (an "STK echo", see app/services/c2b_handler.py), so that copy is
where a hotspot buyer's real name comes from.

Everything here is best-effort. A missing, masked or odd name must never stop
a payment from being recorded or a customer from getting internet:

* ``clean_payer_name`` never raises and returns None for anything unusable.
* ``apply_payer_name`` only replaces a placeholder name ("Guest 1234", blank),
  never a name an operator typed, and writes with a compare-and-set so an edit
  that lands in between is not overwritten. It runs in its own short session
  and swallows every error.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any, Mapping, Optional

from sqlalchemy import update

logger = logging.getLogger(__name__)

# Customers.name is unbounded, but a display name longer than this is noise.
MAX_NAME_LENGTH = 60
_MAX_PART_LENGTH = 30

# "Guest 1234": the portal's placeholder (last four phone digits). Matches the
# bare word too, and up to 6 digits in case the suffix ever changes.
_PLACEHOLDER_RE = re.compile(r"^\s*guest(\s+\d{1,6})?\s*$", re.IGNORECASE)

# Values Safaricom or a test till sends instead of a name.
_JUNK_PARTS = {"na", "n/a", "nil", "null", "none", "unknown", "customer", "test", "x", "-"}


def is_placeholder_name(name: Optional[str]) -> bool:
    """True for names the system generated (or nothing), which a payer's real
    name may replace. Anything else was typed by someone and is kept."""
    if name is None:
        return True
    if not isinstance(name, str):
        return False
    return not name.strip() or bool(_PLACEHOLDER_RE.match(name))


def _title_word(word: str) -> str:
    """JOHN -> John, o'neil -> O'Neil, MARY-JANE -> Mary-Jane. Mixed case as
    sent (McDonald) is left alone."""
    if not (word.isupper() or word.islower()):
        return word
    return re.sub(
        r"[^\W\d_]+",
        lambda m: m.group(0)[:1].upper() + m.group(0)[1:].lower(),
        word,
    )


def _clean_part(raw: Any) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    text = unicodedata.normalize("NFKC", raw)
    words = []
    for word in text.split():
        # Masked ("J***"), numeric or otherwise not a name: drop the word.
        if "*" in word or any(ch.isdigit() for ch in word):
            continue
        word = "".join(ch for ch in word if ch.isalpha() or ch in "'-.")
        word = word.strip("'-.")
        if not word or not any(ch.isalpha() for ch in word):
            continue
        if word.lower() in _JUNK_PARTS:
            continue
        words.append(_title_word(word[:_MAX_PART_LENGTH]))
    return " ".join(words) or None


def clean_payer_name(
    first: Any = None, middle: Any = None, last: Any = None
) -> Optional[str]:
    """Build a display name from the parts of a payer's name, or None.

    Trims, collapses spaces, drops masked/numeric/junk words, title-cases
    all-caps names and caps the length on a word boundary. Never raises.
    """
    try:
        parts = [p for p in (_clean_part(first), _clean_part(middle), _clean_part(last)) if p]
        if not parts:
            return None
        name = ""
        for word in " ".join(parts).split():
            candidate = f"{name} {word}" if name else word
            if len(candidate) > MAX_NAME_LENGTH:
                break
            name = candidate
        if not name or is_placeholder_name(name):
            return None
        return name
    except Exception:  # pragma: no cover - defensive: a name is never worth a failure
        logger.exception("[PAYER NAME] Could not clean payer name")
        return None


def name_from_c2b_payload(payload: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Payer name from a Safaricom C2B confirmation/validation payload."""
    if not isinstance(payload, Mapping):
        return None
    return clean_payer_name(
        payload.get("FirstName"), payload.get("MiddleName"), payload.get("LastName")
    )


async def apply_payer_name(customer_id: Optional[int], payer_name: Optional[str]) -> bool:
    """Name ``customer_id`` after the payer if it still has a placeholder name.

    Own short session; never raises. Returns True if the name was written.
    """
    if not customer_id or not payer_name:
        return False
    from app.db import database as _database
    from app.db.models import Customer

    try:
        async with _database.AsyncSessionLocal() as session:
            current = (
                await session.execute(
                    Customer.__table__.select()
                    .with_only_columns(Customer.name)
                    .where(Customer.id == customer_id)
                )
            ).first()
            if current is None or not is_placeholder_name(current[0]):
                return False
            condition = (
                Customer.name.is_(None) if current[0] is None else Customer.name == current[0]
            )
            result = await session.execute(
                update(Customer)
                .where(Customer.id == customer_id, condition)
                .values(name=payer_name)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
            written = (result.rowcount or 0) > 0
            if written:
                logger.info("[PAYER NAME] Named customer %s from M-Pesa payer data", customer_id)
            return written
    except Exception:
        logger.exception("[PAYER NAME] Could not apply payer name to customer %s", customer_id)
        return False
