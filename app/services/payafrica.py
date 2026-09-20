"""PayAfrica client for card payments through its Paystack hosted checkout.

``POST /api/v1/paystack/initialize`` creates a Paystack checkout that settles
to PayAfrica and returns the link the payer opens. Amounts are in MAJOR units
(``10`` with ``USD`` shows "Pay USD 10" on the checkout page).

PayAfrica does not yet expose a status lookup or a signed webhook for these
checkouts, so nothing here can prove a payment succeeded. Card payments are
confirmed by an admin (``POST /api/admin/subscriptions/payments/{id}/confirm-card``)
and never from the browser redirect back to ``callback_url``, which anyone
can forge.

Docs: https://api.payafrica.org/docs
"""

from __future__ import annotations

import logging
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

PAYAFRICA_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
SUPPORTED_CURRENCIES = ("KES", "USD")


class PayAfricaAPIError(RuntimeError):
    """A provider error safe to log or return to the reseller."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def normalize_amount(amount: Any) -> float:
    try:
        value = Decimal(str(amount))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid payment amount: {amount!r}") from exc
    if not value.is_finite() or value <= 0:
        raise ValueError("Card payment amount must be greater than zero")
    return float(value.quantize(Decimal("0.01")))


def _provider_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"PayAfrica request failed with HTTP {response.status_code}"
    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("message") or payload.get("error")
        if detail:
            return str(detail)[:500]
    return f"PayAfrica request failed with HTTP {response.status_code}"


async def initialize_card_checkout(
    *,
    amount: Any,
    currency: str,
    customer_email: str,
    reference: str,
    callback_url: str | None = None,
    webhook_url: str | None = None,
) -> dict:
    """Create a Paystack checkout; returns ``payment_url`` and PayAfrica's ``reference``."""
    currency = (currency or "").upper()
    if currency not in SUPPORTED_CURRENCIES:
        raise ValueError(f"Card payments support {', '.join(SUPPORTED_CURRENCIES)} only")

    payload = {
        "amount": normalize_amount(amount),
        "currency": currency,
        "customer_email": customer_email,
        "reference": reference,
    }
    if callback_url:
        payload["callback_url"] = callback_url
    # Server-to-server notification when the payment succeeds. PayAfrica only
    # accepts destinations it has registered, so callers must be ready for a
    # rejection (see initialize_card_checkout_with_fallback).
    if webhook_url:
        payload["webhook_url"] = webhook_url

    base_url = settings.PAYAFRICA_BASE_URL.rstrip("/")
    async with httpx.AsyncClient(timeout=PAYAFRICA_TIMEOUT) as client:
        response = await client.post(
            f"{base_url}/api/v1/paystack/initialize",
            headers={"Accept": "application/json"},
            json=payload,
        )

    if response.status_code != 200:
        message = _provider_message(response)
        logger.error(
            "PayAfrica card checkout failed: status=%s reference=%s message=%s",
            response.status_code, reference, message,
        )
        raise PayAfricaAPIError(message, status_code=response.status_code)

    data = response.json()
    if not data.get("payment_url") or not data.get("reference"):
        raise PayAfricaAPIError("PayAfrica response did not include a checkout link")
    if data.get("external_reference") and data["external_reference"] != reference:
        raise PayAfricaAPIError("PayAfrica echoed a different reference")
    logger.info(
        "PayAfrica card checkout created: reference=%s payafrica_reference=%s",
        reference, data["reference"],
    )
    return data


# PayAfrica only accepts callback_url on origins it has allow-listed. Until
# ours is added, fall back so the payment itself still goes through; the
# payer then lands on PayAfrica's page instead of ours after paying.
PAYAFRICA_OWN_CALLBACK = "https://payafrica.org/payments"


def _rejects_field(error: "PayAfricaAPIError", field: str) -> bool:
    """True when PayAfrica refused this optional field, for any reason.

    Seen in the wild: "callback_url origin is not trusted by PayAfrica",
    "webhook_url must be a registered HTTPS PayAfrica relay destination", and
    pydantic's "URL host invalid". Any of them means: drop the field and keep
    the payment going.
    """
    return error.status_code == 422 and field in str(error).lower()


def _is_untrusted_callback(error: "PayAfricaAPIError") -> bool:
    return _rejects_field(error, "callback_url")


def _is_unregistered_webhook(error: "PayAfricaAPIError") -> bool:
    return _rejects_field(error, "webhook_url")


async def initialize_card_checkout_with_fallback(
    *,
    amount: Any,
    currency: str,
    customer_email: str,
    reference: str,
    callback_url: str | None,
    webhook_url: str | None = None,
) -> tuple[dict, str | None, str | None]:
    """Create the checkout, dropping whichever of callback_url / webhook_url
    PayAfrica refuses, so an unregistered URL never blocks the payment.

    Returns (checkout, callback_url_used, webhook_url_used).
    """
    callbacks: list[str | None] = list(dict.fromkeys([callback_url, None, PAYAFRICA_OWN_CALLBACK]))
    callback_index = 0
    webhook = webhook_url
    last_error: PayAfricaAPIError | None = None

    # At most one drop per field, so this terminates.
    for _ in range(len(callbacks) + 1):
        if callback_index >= len(callbacks):
            break
        candidate = callbacks[callback_index]
        try:
            checkout = await initialize_card_checkout(
                amount=amount,
                currency=currency,
                customer_email=customer_email,
                reference=reference,
                callback_url=candidate,
                webhook_url=webhook,
            )
            if candidate != callback_url:
                logger.warning(
                    "PayAfrica rejected callback origin %r; checkout %s created with callback %r",
                    callback_url, reference, candidate,
                )
            return checkout, candidate, webhook
        except PayAfricaAPIError as exc:
            last_error = exc
            if webhook and _is_unregistered_webhook(exc):
                logger.warning(
                    "PayAfrica has not registered webhook %r; checkout %s continues without it",
                    webhook, reference,
                )
                webhook = None
                continue
            if _is_untrusted_callback(exc):
                callback_index += 1
                continue
            raise
    assert last_error is not None
    raise last_error
