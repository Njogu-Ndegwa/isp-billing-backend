"""
MTN Mobile Money (Collection) integration.

Implements the subset of the MTN MoMo Open API that we need to collect bill
payments from customers:

  * POST /collection/token/                 -> OAuth access token
  * POST /collection/v1_0/requesttopay      -> initiate a pull payment
  * GET  /collection/v1_0/requesttopay/{id} -> poll status

Credentials live per-reseller on ``ResellerPaymentMethod`` (API User UUID, API
Key, Primary Subscription Key, target environment, base URL, currency).  All
secrets are decrypted by the caller before invoking the helpers below.

Reference: https://momodeveloper.mtn.com/api-documentation/
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
from typing import Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# In-process cache of access tokens, keyed by (api_user, base_url).
# Each entry is (token, epoch_expiry_seconds). MTN tokens are valid ~3600s;
# we expire ours 60s early to avoid edge-of-window failures.
_TOKEN_CACHE: dict[Tuple[str, str], Tuple[str, float]] = {}
_TOKEN_CACHE_LOCK = asyncio.Lock()
_TOKEN_EARLY_REFRESH_SECONDS = 60

DEFAULT_SANDBOX_BASE_URL = "https://sandbox.momodeveloper.mtn.com"


def _format_amount(amount) -> str:
    """
    Render an amount exactly how MTN expects it in the JSON body: a string with
    no trailing decimal noise.  ``1000.0`` → ``"1000"`` and ``1000.5`` → ``"1000.50"``.
    """
    try:
        value = float(amount)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid amount: {amount!r}")
    if value < 0:
        raise ValueError(f"Amount must be non-negative: {amount!r}")
    if value == int(value):
        return str(int(value))
    return f"{value:.2f}"


# ---------------------------------------------------------------------------
# MSISDN helpers
# ---------------------------------------------------------------------------

_MSISDN_STRIP_RE = re.compile(r"[^\d]")


def normalize_msisdn(phone: str) -> str:
    """
    Normalise a phone number for MTN: digits only, no leading ``+``.

    MTN's API validates MSISDN per ITU-T E.164, so we expect ``<country><sub>``
    with no separators or leading zeros.  We do not attempt to infer a country
    code — callers must supply a fully-qualified international number.
    """
    if not phone:
        raise ValueError("Phone number is required")
    digits = _MSISDN_STRIP_RE.sub("", phone)
    if not digits:
        raise ValueError(f"Invalid phone number: {phone!r}")
    # Most MTN MSISDNs are 10-15 digits; sandbox test numbers are 11-12 digits.
    if not (8 <= len(digits) <= 15):
        raise ValueError(f"Phone number has invalid length: {digits}")
    return digits


# ---------------------------------------------------------------------------
# Access tokens
# ---------------------------------------------------------------------------

async def get_access_token(
    *,
    api_user: str,
    api_key: str,
    subscription_key: str,
    base_url: str,
) -> str:
    """
    Fetch (or reuse) an OAuth access token for the collection product.

    MTN requires HTTP Basic auth with ``<api_user>:<api_key>`` plus the
    subscription key header.  The response is::

        { "access_token": "...", "token_type": "access_token", "expires_in": 3600 }

    Tokens are cached in-process keyed by (api_user, base_url); concurrent
    callers hitting a cache miss are serialized behind a lock so we only
    request one token per key at a time.
    """
    cache_key = (api_user, base_url)
    now = time.time()

    cached = _TOKEN_CACHE.get(cache_key)
    if cached and cached[1] - _TOKEN_EARLY_REFRESH_SECONDS > now:
        return cached[0]

    async with _TOKEN_CACHE_LOCK:
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached[1] - _TOKEN_EARLY_REFRESH_SECONDS > now:
            return cached[0]

        basic = base64.b64encode(f"{api_user}:{api_key}".encode()).decode()
        headers = {
            "Authorization": f"Basic {basic}",
            "Ocp-Apim-Subscription-Key": subscription_key,
        }

        url = f"{base_url.rstrip('/')}/collection/token/"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(url, headers=headers)

        if response.status_code != 200:
            logger.error(
                "MTN MoMo token request failed: %s %s", response.status_code, response.text
            )
            response.raise_for_status()

        data = response.json()
        access_token = data.get("access_token")
        if not access_token:
            raise RuntimeError(f"MTN MoMo token response missing access_token: {data}")

        # ``expires_in`` is seconds; fall back to 1 hour if missing.
        expires_in = int(data.get("expires_in") or 3600)
        _TOKEN_CACHE[cache_key] = (access_token, now + expires_in)
        logger.info(
            "MTN MoMo token acquired (user=%s, base=%s, expires_in=%ss)",
            api_user, base_url, expires_in,
        )
        return access_token


def invalidate_access_token(api_user: str, base_url: str) -> None:
    """Drop a cached token (e.g. after a 401 from a downstream call)."""
    _TOKEN_CACHE.pop((api_user, base_url), None)


# ---------------------------------------------------------------------------
# RequestToPay
# ---------------------------------------------------------------------------

async def initiate_request_to_pay(
    *,
    reference_id: str,
    amount: float,
    currency: str,
    phone: str,
    external_id: str,
    payer_message: str,
    payee_note: str,
    target_environment: str,
    base_url: str,
    api_user: str,
    api_key: str,
    subscription_key: str,
    callback_url: Optional[str] = None,
) -> None:
    """
    Initiate a pull payment from the given MSISDN.

    Returns ``None`` on success (MTN responds ``202 Accepted`` with an empty
    body).  Raises ``httpx.HTTPStatusError`` on any non-2xx response.

    The caller is responsible for persisting a ``MtnMomoTransaction`` with the
    supplied ``reference_id`` in PENDING state before (or after) this call.
    """
    access_token = await get_access_token(
        api_user=api_user,
        api_key=api_key,
        subscription_key=subscription_key,
        base_url=base_url,
    )

    url = f"{base_url.rstrip('/')}/collection/v1_0/requesttopay"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Reference-Id": reference_id,
        "X-Target-Environment": target_environment,
        "Ocp-Apim-Subscription-Key": subscription_key,
        "Content-Type": "application/json",
    }
    if callback_url:
        headers["X-Callback-Url"] = callback_url

    body = {
        "amount": _format_amount(amount),
        "currency": currency,
        "externalId": external_id,
        "payer": {
            "partyIdType": "MSISDN",
            "partyId": normalize_msisdn(phone),
        },
        "payerMessage": (payer_message or "")[:160],
        "payeeNote": (payee_note or "")[:160],
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, headers=headers, json=body)

    # 202 Accepted is the happy path; some gateways return 200.
    if response.status_code in (200, 202):
        logger.info(
            "MTN MoMo requesttopay accepted: reference_id=%s, amount=%s %s, env=%s",
            reference_id, amount, currency, target_environment,
        )
        return

    # Treat 401 as a stale-token signal so the next call refreshes.
    if response.status_code == 401:
        invalidate_access_token(api_user, base_url)

    logger.error(
        "MTN MoMo requesttopay failed: %s %s (reference_id=%s)",
        response.status_code, response.text, reference_id,
    )
    response.raise_for_status()


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

async def check_request_to_pay_status(
    reference_id: str,
    *,
    target_environment: str,
    base_url: str,
    api_user: str,
    api_key: str,
    subscription_key: str,
) -> dict:
    """
    Fetch the current state of a previously-initiated RequestToPay.

    Response shape (abridged)::

        {
            "amount": "1000",
            "currency": "EUR",
            "externalId": "...",
            "payer": { "partyIdType": "MSISDN", "partyId": "..." },
            "status": "SUCCESSFUL" | "PENDING" | "FAILED",
            "financialTransactionId": "...",
            "reason": { "code": "...", "message": "..." }
        }

    Returns the raw JSON dict so callers can branch on ``status`` / ``reason``.
    """
    access_token = await get_access_token(
        api_user=api_user,
        api_key=api_key,
        subscription_key=subscription_key,
        base_url=base_url,
    )

    url = f"{base_url.rstrip('/')}/collection/v1_0/requesttopay/{reference_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Target-Environment": target_environment,
        "Ocp-Apim-Subscription-Key": subscription_key,
    }

    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 401:
        invalidate_access_token(api_user, base_url)

    response.raise_for_status()
    data = response.json()
    logger.info(
        "MTN MoMo status for %s: %s",
        reference_id, data.get("status"),
    )
    return data
