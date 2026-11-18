"""Wording for automatic customer SMS, and the reseller-editable templates.

Every automatic customer message (expiry, pre-expiry reminder, payment receipt,
PPPoE welcome) has a built-in default. A reseller may replace any of them with
their own text using ``{placeholder}`` fields; the placeholders each event can
use are listed in ``EVENT_PLACEHOLDERS`` and enforced when the template is
saved.

The defaults are rendered by code rather than from a placeholder string because
they drop a whole clause when its data is missing (no paybill outside Kenya or
for a direct-settlement reseller, no reference on a cash payment). A custom
template follows the same rule: a sentence whose field is empty is left out
rather than sent half-filled ("Pay via M-Pesa Paybill , Account 123"), and a
dropped paybill sentence in a reminder or expiry notice is replaced by the same
"Please renew" line the default uses.

Pure functions only: no database, no I/O.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

EVENT_EXPIRY = "expiry"
EVENT_REMINDER = "reminder"
EVENT_RECEIPT = "payment_receipt"
EVENT_WELCOME = "welcome"

EVENTS = (EVENT_RECEIPT, EVENT_WELCOME, EVENT_REMINDER, EVENT_EXPIRY)

_COMMON = ("name", "brand", "plan", "expiry", "account", "paybill", "support_phone")

EVENT_PLACEHOLDERS: dict[str, tuple[str, ...]] = {
    EVENT_EXPIRY: _COMMON,
    EVENT_REMINDER: _COMMON,
    EVENT_RECEIPT: _COMMON + ("amount", "reference"),
    EVENT_WELCOME: _COMMON + ("username", "password"),
}

# Three SMS segments. Long enough for any sensible notice, short enough that a
# typo cannot quietly bill every customer for a page of text.
MAX_TEMPLATE_LENGTH = 480

_PLACEHOLDER = re.compile(r"\{([A-Za-z_]+)\}")

# What the settings screen shows as the starting point when a reseller chooses
# to customise a message. It is the full form of the built-in default.
DEFAULT_TEMPLATE_TEXT: dict[str, str] = {
    EVENT_RECEIPT: (
        "Payment of {amount} received. Your internet is active until {expiry}. "
        "Ref {reference}. - {brand}"
    ),
    EVENT_WELCOME: (
        "Welcome to {brand}! Username: {username} Password: {password}. "
        "Pay via M-Pesa Paybill {paybill}, Account {account} to activate."
    ),
    EVENT_REMINDER: (
        "Reminder: Your internet expires soon. Pay via M-Pesa Paybill {paybill}, "
        "Account {account} to avoid disconnection. - {brand}"
    ),
    EVENT_EXPIRY: (
        "Your internet has expired. Pay via M-Pesa Paybill {paybill}, "
        "Account {account} to restore service. - {brand}"
    ),
}

# Realistic values for previews on the settings screen.
SAMPLE_CONTEXT: dict[str, str] = {
    "name": "Jane",
    "plan": "Home 10Mbps",
    "expiry": "08 Oct, 21:00",
    "account": "12345674",
    "paybill": "600980",
    "support_phone": "0712345678",
    "amount": "KES 1,500",
    "reference": "QJK3ABCD12",
    "username": "jane_home",
    "password": "x7Kp2mQa",
}


# ---------------------------------------------------------------------------
# Custom templates
# ---------------------------------------------------------------------------

def placeholders_in(body: str) -> list[str]:
    return list(dict.fromkeys(_PLACEHOLDER.findall(body or "")))


def validate_template(event: str, body: str) -> str | None:
    """Return a user-facing error for an invalid template, or None."""
    if event not in EVENT_PLACEHOLDERS:
        return f"Unknown message type '{event}'"
    text = (body or "").strip()
    if not text:
        return "Message text cannot be empty"
    if len(text) > MAX_TEMPLATE_LENGTH:
        return f"Message text must be at most {MAX_TEMPLATE_LENGTH} characters"
    allowed = set(EVENT_PLACEHOLDERS[event])
    unknown = [name for name in placeholders_in(text) if name not in allowed]
    if unknown:
        listed = ", ".join("{" + name + "}" for name in unknown)
        return (
            f"{listed} cannot be used in this message. Available: "
            + ", ".join("{" + name + "}" for name in EVENT_PLACEHOLDERS[event])
        )
    return None


# Fields that are always filled (build_context gives them a fallback), so a
# sentence holding one is never dropped.
_ALWAYS_FILLED = frozenset({"name", "brand", "plan"})

# Sentence boundaries: end punctuation followed by space, or a line break. The
# separator is captured so the reseller's spacing and line breaks survive.
_SENTENCE_BREAK = re.compile(r"((?<=[.!?]) +|\s*\n\s*)")

# What the default says instead of the paybill line when there is none.
_RENEW_INSTEAD = {
    EVENT_REMINDER: "Please renew to avoid disconnection.",
    EVENT_EXPIRY: "Please renew to restore service.",
}
# The ending of the default's payment sentence, for a till in its place.
_PAY_PURPOSE = {
    EVENT_REMINDER: "to avoid disconnection",
    EVENT_EXPIRY: "to restore service",
    EVENT_WELCOME: "to activate",
}


def _instead_of_paybill(event: str | None, context: dict[str, str]) -> str | None:
    """The sentence that replaces a paybill sentence that cannot be filled."""
    if context.get("till") and event in _PAY_PURPOSE:
        return f"{_payment_instruction(context)} {_PAY_PURPOSE[event]}."
    return _RENEW_INSTEAD.get(event)


def _has_empty_field(sentence: str, context: dict[str, str]) -> bool:
    return any(
        key in context and key not in _ALWAYS_FILLED and not context[key]
        for key in _PLACEHOLDER.findall(sentence)
    )


def render_custom(body: str, context: dict[str, str], event: str | None = None) -> str:
    """Fill a reseller template. Unknown fields are left as typed.

    A sentence that uses a field with no value is dropped, as the defaults do,
    so customers never get "Pay via M-Pesa Paybill , Account 123" or "Ref .".
    """

    def _fill(match: re.Match) -> str:
        key = match.group(1)
        if key not in context:
            return match.group(0)
        return context[key] or ""

    parts = _SENTENCE_BREAK.split(body.strip())
    kept: list[str] = []
    renew_added = False
    for index in range(0, len(parts), 2):
        sentence = parts[index]
        separator = parts[index + 1] if index + 1 < len(parts) else ""
        if _has_empty_field(sentence, context):
            renew = _instead_of_paybill(event, context)
            if renew and "{paybill}" in sentence and not renew_added:
                kept.append(renew + (separator or " "))
                renew_added = True
            continue
        kept.append(sentence + separator)

    text = _PLACEHOLDER.sub(_fill, "".join(kept))
    text = re.sub(r"[ \t]{2,}", " ", text).strip()
    if not text:
        # Every sentence needed a missing field: the default is better than
        # an empty message.
        return _DEFAULTS[event](context) if event in _DEFAULTS else ""
    return text


def custom_template(templates, event: str) -> str | None:
    """The reseller's saved template for `event`, or None for the default."""
    if not isinstance(templates, dict):
        return None
    value = templates.get(event)
    if not isinstance(value, str) or not value.strip():
        return None
    if validate_template(event, value) is not None:
        # Saved before a placeholder was withdrawn, or hand-edited: fall back
        # to the default rather than sending a broken message.
        return None
    return value


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

def brand_name(reseller) -> str:
    name = (
        getattr(reseller, "business_name", None)
        or getattr(reseller, "organization_name", None)
        or "Your internet provider"
    )
    return name.strip()


_PLACEHOLDER_NAMES = {"guest", "device", "customer", "user", "unknown"}


def friendly_name(raw: str | None) -> str:
    """First name for a greeting, or 'Customer' when the name is a placeholder.

    Hotspot customers are often stored under their phone number or MAC address,
    which reads badly in "Hi 254712345678".
    """
    first = (raw or "").strip().split(" ")[0] if raw else ""
    if not first or ":" in first or sum(ch.isdigit() for ch in first) >= 4:
        return "Customer"
    # The captive portal names self-registered customers "Guest 5364" or
    # "Device 4A:3F:F1"; those are labels, not names.
    if first.lower() in _PLACEHOLDER_NAMES:
        return "Customer"
    return first


def format_amount(amount: float | int | None, currency: str | None) -> str:
    value = float(amount or 0)
    number = f"{value:,.0f}" if value.is_integer() else f"{value:,.2f}"
    return f"{(currency or 'KES').upper()} {number}"


def format_local_time(moment: datetime | None, tz_name: str | None) -> str:
    """'08 Oct, 21:00' in the reseller's market timezone. DB times are naive UTC."""
    if moment is None:
        return ""
    aware = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    try:
        local = aware.astimezone(ZoneInfo(tz_name or "Africa/Nairobi"))
    except ZoneInfoNotFoundError:
        local = aware
    return local.strftime("%d %b, %H:%M")


def build_context(
    *,
    reseller,
    tz_name: str | None,
    customer_name: str | None = None,
    plan_name: str | None = None,
    expiry: datetime | None = None,
    account_number: str | None = None,
    paybill: str | None = None,
    support_phone: str | None = None,
    amount: str | None = None,
    reference: str | None = None,
    username: str | None = None,
    password: str | None = None,
    till: str | None = None,
) -> dict[str, str]:
    return {
        "name": friendly_name(customer_name),
        "brand": brand_name(reseller),
        "plan": (plan_name or "internet plan").strip(),
        "expiry": format_local_time(expiry, tz_name),
        "account": (account_number or "").strip(),
        "paybill": (paybill or "").strip(),
        "support_phone": (support_phone or "").strip(),
        "amount": amount or "",
        "reference": (reference or "").strip(),
        "username": (username or "").strip(),
        "password": password or "",
        # Not a template placeholder: a Buy Goods till replaces the paybill
        # sentence (see render_custom and _payment_instruction).
        "till": (till or "").strip(),
    }


# ---------------------------------------------------------------------------
# Built-in defaults
# ---------------------------------------------------------------------------

def _payment_instruction(context: dict[str, str]) -> str | None:
    if context.get("paybill") and context.get("account"):
        return f"Pay via M-Pesa Paybill {context['paybill']}, Account {context['account']}"
    if context.get("till"):
        return f"Pay via M-Pesa Buy Goods Till {context['till']}"
    return None


def default_expiry(context: dict[str, str]) -> str:
    payment = _payment_instruction(context)
    brand = context["brand"]
    if payment:
        return f"Your internet has expired. {payment} to restore service. - {brand}"
    return f"Your internet package has expired. Please renew to restore service. - {brand}"


def default_reminder(context: dict[str, str]) -> str:
    payment = _payment_instruction(context)
    brand = context["brand"]
    if payment:
        return (
            f"Reminder: Your internet expires soon. {payment} to avoid "
            f"disconnection. - {brand}"
        )
    return (
        "Reminder: Your internet package will expire soon. "
        f"Please renew to avoid disconnection. - {brand}"
    )


def default_receipt(context: dict[str, str]) -> str:
    text = f"Payment of {context['amount']} received. Your internet"
    text += f" is active until {context['expiry']}." if context["expiry"] else " is active."
    if context["reference"]:
        text += f" Ref {context['reference']}."
    return f"{text} - {context['brand']}"


def default_welcome(context: dict[str, str]) -> str:
    # Kept to one SMS (160 chars) for typical brand and username lengths.
    text = (
        f"Welcome to {context['brand']}! Username: {context['username']} "
        f"Password: {context['password']}."
    )
    payment = _payment_instruction(context)
    if payment:
        text += f" {payment} to activate."
    return text


_DEFAULTS = {
    EVENT_EXPIRY: default_expiry,
    EVENT_REMINDER: default_reminder,
    EVENT_RECEIPT: default_receipt,
    EVENT_WELCOME: default_welcome,
}


def render(event: str, context: dict[str, str], templates=None) -> str:
    """The message for `event`: the reseller's template if set, else the default."""
    custom = custom_template(templates, event)
    if custom is not None:
        return render_custom(custom, context, event)
    return _DEFAULTS[event](context)
