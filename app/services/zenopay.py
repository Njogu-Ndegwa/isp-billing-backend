"""
ZenoPay Tanzania integration.

Handles mobile money payments for Tanzanian operators (M-Pesa TZ, Airtel Money,
Tigo Pesa, Halopesa) via the ZenoPay gateway.

API docs: https://docs.zenopay.net/introduction/
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

ZENOPAY_BASE_URL = "https://zenoapi.com/api"


async def initiate_zenopay_payment(
    api_key: str,
    order_id: str,
    phone: str,
    amount: float,
    name: str,
    email: str,
    webhook_url: Optional[str] = None,
) -> dict:
    """
    Initiate a mobile money payment via ZenoPay.

    The customer receives a push notification on their phone to authorize the
    payment. Results are delivered asynchronously via the webhook_url.
    """
    payload = {
        "order_id": order_id,
        "buyer_email": email,
        "buyer_name": name,
        "buyer_phone": phone,
        "amount": int(amount),
    }
    if webhook_url:
        payload["webhook_url"] = webhook_url

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{ZENOPAY_BASE_URL}/payments/mobile_money_tanzania",
            json=payload,
            headers=headers,
        )

        if response.status_code != 200:
            logger.error(
                "ZenoPay API error %s: %s", response.status_code, response.text
            )

        response.raise_for_status()
        data = response.json()

        if data.get("status") == "error":
            raise Exception(f"ZenoPay error: {data.get('message', 'Unknown error')}")

        logger.info("ZenoPay payment initiated: order_id=%s", order_id)
        return data


async def check_zenopay_order_status(api_key: str, order_id: str) -> dict:
    """
    Query ZenoPay for the current status of a payment order.

    ZenoPay returns::

        {
          "result": "SUCCESS",
          "data": [{ "order_id": "...", "payment_status": "COMPLETED", ... }]
        }

    This function returns the first item from ``data[]`` with top-level
    fields merged in, or the raw response if parsing fails.
    """
    headers = {"x-api-key": api_key}

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(
            f"{ZENOPAY_BASE_URL}/payments/order-status",
            params={"order_id": order_id},
            headers=headers,
        )
        response.raise_for_status()
        raw = response.json()
        logger.info("ZenoPay order status for %s: %s", order_id, raw.get("result"))

        data_list = raw.get("data")
        if isinstance(data_list, list) and data_list:
            order_data = data_list[0]
            order_data["api_result"] = raw.get("result")
            order_data["api_message"] = raw.get("message")
            return order_data

        return raw


def validate_zenopay_webhook(headers: dict, expected_api_key: str) -> bool:
    """
    Verify that a ZenoPay webhook request is authentic by checking
    the x-api-key header against the reseller's stored key.
    """
    received_key = headers.get("x-api-key", "")
    return received_key == expected_api_key
