"""Support desk snapshot helpers: ingest-token check and server-side masking.

The laptop that builds the WhatsApp support dashboard already strips phone
numbers, emails and WhatsApp JIDs. Masking again here is defence in depth: a
builder bug must not put a customer's number into the production database.
"""

import hmac
import re
from typing import Any, Optional, Tuple

# A WhatsApp address: "<digits or id>@s.whatsapp.net", "@lid", "@c.us",
# "@g.us". Matched first so the whole JID goes, not just its digits.
_JID = re.compile(
    r"[\w.+-]*@(?:s\.whatsapp\.net|lid|c\.us|g\.us)\b",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# Seven or more digits in a row (optionally "+"-prefixed): phone numbers,
# MSISDNs, account-number-like ids. ISO timestamps never have 7 contiguous
# digits; the one exemption is a bare 8-digit compact date (20261021), which
# the support agent uses inside message ids and which no phone number fits.
_LONG_DIGITS = re.compile(
    r"\+\d{7,}"
    r"|(?<![\d+])(?!20\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?!\d))\d{7,}"
)
# Phone numbers written in groups: "0712 345 678", "+254 712-345-678".
# Dates (2026-10-23) and times (13:21:51) do not fit 3-3-3.
_GROUPED_PHONE = re.compile(r"\+?(?:\d{1,3}[ -])?\d{3,4}[ -]\d{3}[ -]\d{3,4}\b")

JID_MASK = "[jid]"
EMAIL_MASK = "[email]"
NUMBER_MASK = "[number]"


def mask_text(text: str) -> Tuple[str, int]:
    """Return (masked_text, replacements)."""
    total = 0
    for pattern, replacement in (
        (_JID, JID_MASK),
        (_EMAIL, EMAIL_MASK),
        (_GROUPED_PHONE, NUMBER_MASK),
        (_LONG_DIGITS, NUMBER_MASK),
    ):
        text, n = pattern.subn(replacement, text)
        total += n
    return text, total


def mask_value(value: Any) -> Tuple[Any, int]:
    """Mask every string (keys included) in a JSON value. Returns (value, count)."""
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, list):
        out, total = [], 0
        for item in value:
            masked, n = mask_value(item)
            out.append(masked)
            total += n
        return out, total
    if isinstance(value, dict):
        out_d, total = {}, 0
        for key, item in value.items():
            masked_key, nk = mask_text(str(key))
            masked_item, nv = mask_value(item)
            out_d[masked_key] = masked_item
            total += nk + nv
        return out_d, total
    return value, 0


def configured_ingest_token(raw: Optional[str], min_length: int) -> Optional[str]:
    """The ingest token if it is set and long enough, else None (endpoint off)."""
    token = (raw or "").strip()
    if len(token) < max(1, min_length):
        return None
    return token


def bearer_token(authorization: Optional[str]) -> Optional[str]:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def ingest_token_matches(presented: Optional[str], expected: str) -> bool:
    """Constant-time comparison of the presented bearer token."""
    if not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def find_open_dennis_item(snapshot: Any, item_id: str) -> Optional[dict]:
    """The open needs_dennis work-log entry with this id in a snapshot, or None.

    "Open" is no outcome, "open" (what the page lists today) or "waiting"
    (what the inbox agent often writes for the same state).
    """
    if not isinstance(snapshot, dict):
        return None
    worklog = snapshot.get("worklog")
    entries = worklog.get("entries") if isinstance(worklog, dict) else None
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("id") != item_id:
            continue
        if entry.get("category") != "needs_dennis":
            return None
        if entry.get("outcome") not in (None, "", "open", "waiting"):
            return None
        return entry
    return None
