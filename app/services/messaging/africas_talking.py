"""Africa's Talking bulk SMS provider."""

import logging
from typing import Optional

import httpx

from app.services.messaging.base import MessagingProvider, SendResult

logger = logging.getLogger(__name__)


class AfricasTalkingProvider(MessagingProvider):
    name = "africastalking"

    def __init__(self, username: str, api_key: str, base_url: str):
        self.username = username
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        if not recipients:
            return []
        data = {
            "username": self.username,
            "to": ",".join(recipients),
            "message": body,
        }
        if sender_id:
            data["from"] = sender_id
        headers = {
            "apiKey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        url = f"{self.base_url}/version1/messaging"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, data=data, headers=headers)
            resp.raise_for_status()
            payload = resp.json()

        recs = (payload.get("SMSMessageData", {}) or {}).get("Recipients", []) or []
        results: list[SendResult] = []
        for r in recs:
            status = (r.get("status") or "").strip()
            mid = r.get("messageId")
            if mid in (None, "", "None"):
                mid = None
            results.append(SendResult(
                recipient=r.get("number", ""),
                success=status.lower() == "success",
                provider_message_id=mid,
                status=status,
                error=None if status.lower() == "success" else status,
                cost=r.get("cost"),
            ))
        if not results:
            results = [SendResult(recipient=n, success=False,
                                  status="no_response", error="no_response")
                       for n in recipients]
        return results
