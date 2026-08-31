"""Fapshi Cameroon collection API client.

Only server-side code calls this module. API credentials are supplied by the
reseller payment-method record and are never returned to the captive portal.

Docs: https://docs.fapshi.com/en/api-reference/endpoint/direct-pay
"""

from __future__ import annotations

import logging
import re
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

logger = logging.getLogger(__name__)

FAPSHI_BASE_URLS = {
    "sandbox": "https://sandbox.fapshi.com",
    "live": "https://live.fapshi.com",
}
FAPSHI_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class FapshiAPIError(RuntimeError):
    """A safe provider error suitable for logging or an API error response."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def normalize_environment(environment: str | None) -> str:
    value = (environment or "sandbox").strip().lower()
    if value not in FAPSHI_BASE_URLS:
        raise ValueError("Fapshi environment must be 'sandbox' or 'live'")
    return value


def normalize_cameroon_phone(phone: str) -> str:
    """Return the local 9-digit number Fapshi expects (for example 670000000)."""
    if not phone:
        raise ValueError("Phone number is required")

    digits = re.sub(r"\D", "", phone)
    if digits.startswith("00237"):
        digits = digits[5:]
    elif digits.startswith("237"):
        digits = digits[3:]
    elif len(digits) == 10 and digits.startswith("0"):
        digits = digits[1:]

    if len(digits) != 9 or not digits.startswith("6"):
        raise ValueError(
            "Enter a valid Cameroon mobile number (for example 670000000 or +237670000000)"
        )
    return digits


def normalize_xaf_amount(amount: Any) -> int:
    """Validate Fapshi's integer-XAF, minimum-100 amount contract."""
    try:
        value = Decimal(str(amount))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid payment amount: {amount!r}") from exc

    if not value.is_finite() or value != value.to_integral_value():
        raise ValueError("Fapshi amounts must be whole XAF values")
    amount_xaf = int(value)
    if amount_xaf < 100:
        raise ValueError("Fapshi requires a minimum payment of 100 XAF")
    return amount_xaf


def _headers(api_user: str, api_key: str) -> dict[str, str]:
    if not api_user or not api_key:
        raise ValueError("Fapshi API User and API Key are required")
    return {
        "apiuser": api_user,
        "apikey": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _provider_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"Fapshi request failed with HTTP {response.status_code}"

    if isinstance(payload, dict):
        detail = payload.get("message") or payload.get("error") or payload.get("detail")
        if detail:
            return str(detail)[:500]
    return f"Fapshi request failed with HTTP {response.status_code}"


async def initiate_direct_payment(
    *,
    api_user: str,
    api_key: str,
    environment: str,
    amount: Any,
    phone: str,
    name: str | None,
    user_id: str,
    external_id: str,
    message: str | None = None,
) -> dict:
    """Send a Direct Pay prompt and return Fapshi's accepted transaction."""
    env = normalize_environment(environment)
    payload = {
        "amount": normalize_xaf_amount(amount),
        "phone": normalize_cameroon_phone(phone),
        # Omitting ``medium`` lets Fapshi detect MTN vs Orange from the number.
        "name": (name or "Customer")[:100],
        "userId": user_id,
        "externalId": external_id,
        "message": (message or "Internet package payment")[:160],
    }

    async with httpx.AsyncClient(timeout=FAPSHI_TIMEOUT) as client:
        response = await client.post(
            f"{FAPSHI_BASE_URLS[env]}/direct-pay",
            headers=_headers(api_user, api_key),
            json=payload,
        )

    if response.status_code != 200:
        provider_message = _provider_message(response)
        logger.error(
            "Fapshi Direct Pay failed: status=%s external_id=%s message=%s",
            response.status_code,
            external_id,
            provider_message,
        )
        raise FapshiAPIError(provider_message, status_code=response.status_code)

    data = response.json()
    if not data.get("transId"):
        raise FapshiAPIError("Fapshi response did not include a transaction ID")
    logger.info("Fapshi Direct Pay accepted: trans_id=%s", data["transId"])
    return data


async def get_payment_status(
    *,
    api_user: str,
    api_key: str,
    environment: str,
    trans_id: str,
) -> dict:
    """Fetch the authoritative status of a Fapshi transaction."""
    env = normalize_environment(environment)
    async with httpx.AsyncClient(timeout=FAPSHI_TIMEOUT) as client:
        response = await client.get(
            f"{FAPSHI_BASE_URLS[env]}/payment-status/{trans_id}",
            headers=_headers(api_user, api_key),
        )
    if response.status_code != 200:
        raise FapshiAPIError(
            _provider_message(response), status_code=response.status_code
        )
    return response.json()


async def get_service_balance(
    *, api_user: str, api_key: str, environment: str
) -> dict:
    """Read the service balance; used as the non-mutating credential test."""
    env = normalize_environment(environment)
    async with httpx.AsyncClient(timeout=FAPSHI_TIMEOUT) as client:
        response = await client.get(
            f"{FAPSHI_BASE_URLS[env]}/balance",
            headers=_headers(api_user, api_key),
        )
    if response.status_code != 200:
        raise FapshiAPIError(
            _provider_message(response), status_code=response.status_code
        )
    return response.json()
