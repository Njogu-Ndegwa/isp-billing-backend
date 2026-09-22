"""PayAfrica -> us notification when a card subscription payment succeeds.

PayAfrica accepts a per-checkout ``webhook_url`` and calls it after payment,
the way Safaricom calls our M-Pesa callback. It does not (yet) document a
signature, so the URL itself carries the proof: it embeds an HMAC of the
payment id with our own SECRET_KEY. Only PayAfrica ever receives that URL, so
a caller who has it is either PayAfrica or someone PayAfrica leaked it to.

Belt and braces before any activation:
  * the token must match the payment id in the path;
  * the payment must still be pending and be a card payment;
  * the amount and currency in the payload must match our payment;
  * when PAYSTACK_SECRET_KEY is configured, the payment is additionally
    verified against Paystack and the payload is only a trigger.

The payload shape isn't documented yet, so parsing is tolerant and every
delivery is logged in full (no secrets in it) to confirm the real format.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

_SUCCESS_VALUES = {
    "success", "successful", "completed", "complete", "paid",
    "payment.completed", "payment.succeeded", "charge.success",
}
_FAILURE_VALUES = {"failed", "failure", "reversed", "cancelled", "canceled", "payment.failed"}


def webhook_token(payment_id: int) -> str:
    """Unguessable token for this payment, derived from SECRET_KEY."""
    return hmac.new(
        settings.SECRET_KEY.encode(), f"payafrica-webhook:{payment_id}".encode(), hashlib.sha256
    ).hexdigest()[:32]


def valid_token(payment_id: int, token: str | None) -> bool:
    return bool(token) and hmac.compare_digest(webhook_token(payment_id), token.strip())


def webhook_url_for(payment_id: int) -> str | None:
    """Public URL PayAfrica should call for this payment (None if disabled)."""
    base = (settings.PAYAFRICA_WEBHOOK_BASE_URL or "").strip().rstrip("/")
    if not base:
        return None
    return f"{base}/api/payafrica/webhook/{payment_id}/{webhook_token(payment_id)}"


def _walk(payload: Any):
    """Yield every dict in a nested payload, outermost first."""
    if isinstance(payload, dict):
        yield payload
        for value in payload.values():
            yield from _walk(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _walk(item)


def _first(payload: Any, keys: tuple[str, ...]):
    for node in _walk(payload):
        for key in keys:
            if key in node and node[key] not in (None, ""):
                return node[key]
    return None


def extract_outcome(payload: Any) -> str:
    """'success', 'failed' or 'unknown' from an undocumented payload."""
    # An explicit status decides on its own: a body that says "failed" or
    # "pending" must never be read as success because the event happens to be
    # payment.completed. The event name is used only when no status is given.
    explicit = _first(payload, ("status", "payment_status", "transaction_status", "state"))
    values = [explicit] if explicit is not None else [_first(payload, ("event",))]
    for value in values:
        text = str(value or "").strip().lower()
        if text in _SUCCESS_VALUES:
            return "success"
        if text in _FAILURE_VALUES:
            return "failed"
    return "unknown"


def amount_matches(payload: Any, expected_amount: float, expected_currency: str) -> bool:
    """True when the payload's amount/currency match our payment.

    The amount may arrive in major units (10) or minor units (1000); both are
    accepted. A currency in the payload must match; a missing one is allowed
    because the payment id already pins the checkout.
    """
    # The live PayAfrica relay uses ``amount_subunits`` (1000 for USD 10).
    # Keep it distinct from the older/undocumented amount fields so a value of
    # 10 subunits can never be mistaken for USD 10.
    raw_subunits = _first(payload, ("amount_subunits",))
    if raw_subunits is not None:
        try:
            amount_subunits = float(str(raw_subunits).replace(",", ""))
        except (TypeError, ValueError):
            return False
        amount_ok = abs(amount_subunits - expected_amount * 100) <= 0.01
    else:
        raw = _first(payload, ("amount", "amount_paid", "value", "requested_amount"))
        if raw is None:
            return False
        try:
            amount = float(str(raw).replace(",", ""))
        except (TypeError, ValueError):
            return False
        # Older relay payloads have used both major and minor units under the
        # generic ``amount`` key, so retain support for both there.
        amount_ok = (
            abs(amount - expected_amount) <= 0.01
            or abs(amount - expected_amount * 100) <= 0.01
        )

    if not amount_ok:
        return False

    currency = _first(payload, ("currency", "currency_code"))
    if currency and str(currency).strip().upper() != expected_currency.upper():
        return False
    return True


def safe_headers(headers) -> dict:
    """Header snapshot for the log: useful for spotting a signature header."""
    interesting = ("content-type", "user-agent", "x-payafrica-signature", "x-signature",
                   "x-webhook-signature", "x-paystack-signature", "x-request-id")
    return {k: v for k, v in headers.items() if k.lower() in interesting}
