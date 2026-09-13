"""
First-touch acquisition attribution for reseller signups.

The marketing site captures where a visitor came from (utm_*, gclid, ttclid,
referrer, landing path) on their first landing and holds it in localStorage plus
a 90-day cookie. It rides along on the signup request so the source is stored
against the account.

Why the account and not just GA4: GA4 counts *sessions* by channel, which can
say "47 sessions from TikTok, 3 converted" but never "the reseller paying us
KES 8,000/month came from TikTok". Because billing is a share of the reseller's
revenue, the number that decides where ad budget goes is cost per shilling of
recurring revenue by channel — and that join needs the source on the user row.

Everything in here is visitor-supplied query-string data. It is echoed into
reports and the CRM, so it is treated as hostile: length-capped, control
characters stripped, key count bounded, and never coerced into anything but a
short string.
"""
from typing import Any, Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# The keys the marketing site sends today. Unknown keys are kept rather than
# rejected (bounded by MAX_KEYS) so the frontend can add a new platform's click
# id without waiting for a backend release — but known keys always win a place.
KNOWN_KEYS = (
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
    "gclid",
    "ttclid",
    "fbclid",
    "referrer",
    "landing_path",
    "seen_at",
    "last_utm_source",
)

MAX_KEYS = 24
MAX_KEY_LEN = 40
MAX_VALUE_LEN = 200

# Column widths in app/db/models.py — keep in step with them.
MAX_SOURCE_LEN = 120
MAX_CAMPAIGN_LEN = 190

# A medium (or the presence of a platform click id) that means money was spent.
PAID_MEDIUMS = {"cpc", "ppc", "paid", "paidsearch", "paid_search", "paid-search", "ads", "cpm", "cpv"}


def _clean_value(value: Any) -> Optional[str]:
    """Coerce one attribution value to a short, safe string, or drop it."""
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        return None

    # Strip control characters (including newlines) so a value can never break
    # up a log line or a CSV export.
    text = "".join(ch for ch in text if ch.isprintable()).strip()
    if not text:
        return None
    return text[:MAX_VALUE_LEN]


def sanitize_attribution(raw: Any) -> Optional[Dict[str, str]]:
    """Return a bounded, string-only copy of an attribution payload, or None.

    Never raises: a malformed payload costs us the attribution, not the signup.
    """
    if not isinstance(raw, dict) or not raw:
        return None

    cleaned: Dict[str, str] = {}
    for key in KNOWN_KEYS:
        if key in raw:
            value = _clean_value(raw[key])
            if value is not None:
                cleaned[key] = value

    for key, value in raw.items():
        if len(cleaned) >= MAX_KEYS:
            break
        if key in KNOWN_KEYS or not isinstance(key, str):
            continue
        safe_key = "".join(ch for ch in key if ch.isalnum() or ch in "_-").strip()[:MAX_KEY_LEN]
        if not safe_key or safe_key in cleaned:
            continue
        safe_value = _clean_value(value)
        if safe_value is not None:
            cleaned[safe_key] = safe_value

    return cleaned or None


def is_paid(details: Optional[Dict[str, str]]) -> bool:
    """True when the visit carries the marks of a click we paid for."""
    if not details:
        return False
    if details.get("gclid") or details.get("ttclid"):
        return True
    return (details.get("utm_medium") or "").lower() in PAID_MEDIUMS


def summarize(details: Optional[Dict[str, str]]) -> Tuple[Optional[str], Optional[str]]:
    """Pull the two indexed reporting columns out of the payload.

    Source is lowercased so `TikTok`, `tiktok` and `TIKTOK` group as one row in
    a report; the campaign keeps its case because it is the advertiser's own
    label and gets read back in Ads Manager.
    """
    if not details:
        return None, None
    source = details.get("utm_source")
    campaign = details.get("utm_campaign")
    return (
        source.lower()[:MAX_SOURCE_LEN] if source else None,
        campaign[:MAX_CAMPAIGN_LEN] if campaign else None,
    )
