"""Paystack verification for card subscription payments.

Card checkouts are created through PayAfrica (app/services/payafrica.py) on a
Paystack account. With that account's secret key configured
(``PAYSTACK_SECRET_KEY``), we can ask Paystack directly whether a checkout was
paid and verify Paystack's signed webhooks, so card payments activate
automatically instead of waiting for an admin.

The secret key only ever lives in the server environment. Never log it.

Docs: https://paystack.com/docs/api/transaction/#verify
      https://paystack.com/docs/payments/webhooks/
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from decimal import Decimal

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

PAYSTACK_TIMEOUT = httpx.Timeout(20.0, connect=10.0)


class PaystackError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def is_configured() -> bool:
    return bool((settings.PAYSTACK_SECRET_KEY or "").strip())


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY.strip()}",
        "Accept": "application/json",
    }


def to_minor_units(amount) -> int:
    """Paystack amounts are in the currency's minor unit (cents for USD)."""
    return int((Decimal(str(amount)) * 100).quantize(Decimal("1")))


async def verify_transaction(reference: str) -> dict | None:
    """Return Paystack's transaction ``data`` for ``reference``, or None if
    Paystack doesn't know that reference."""
    if not is_configured():
        raise PaystackError("PAYSTACK_SECRET_KEY is not configured")
    base = settings.PAYSTACK_BASE_URL.rstrip("/")
    async with httpx.AsyncClient(timeout=PAYSTACK_TIMEOUT) as client:
        response = await client.get(
            f"{base}/transaction/verify/{reference}", headers=_headers()
        )
    if response.status_code == 404:
        return None
    if response.status_code == 400:
        # Paystack answers "Transaction reference not found" with a 400.
        try:
            message = str(response.json().get("message", ""))
        except ValueError:
            message = ""
        if "not found" in message.lower():
            return None
    if response.status_code != 200:
        raise PaystackError(
            f"Paystack verify failed with HTTP {response.status_code}",
            status_code=response.status_code,
        )
    payload = response.json()
    if not payload.get("status"):
        return None
    return payload.get("data") or None


def valid_webhook_signature(raw_body: bytes, signature: str | None) -> bool:
    """Paystack signs webhooks with HMAC-SHA512 of the raw body using the
    account's secret key (header ``x-paystack-signature``)."""
    if not is_configured() or not signature:
        return False
    expected = hmac.new(
        settings.PAYSTACK_SECRET_KEY.strip().encode(), raw_body, hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(expected, signature.strip())
