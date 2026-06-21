"""TalkSASA bulk SMS provider."""

import logging
from typing import Any

import httpx

from app.services.messaging.base import MessagingProvider, SendResult

logger = logging.getLogger(__name__)


class TalksasaProvider(MessagingProvider):
    name = "talksasa"

    def __init__(self, api_token: str, base_url: str):
        self.api_token = api_token
        self.base_url = base_url.rstrip("/")

    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        if not recipients:
            return []
        if not self.api_token:
            return [
                SendResult(
                    recipient=recipient,
                    success=False,
                    status="missing_api_token",
                    error="missing_api_token",
                )
                for recipient in recipients
            ]
        if not sender_id:
            return [
                SendResult(
                    recipient=recipient,
                    success=False,
                    status="missing_sender_id",
                    error="missing_sender_id",
                )
                for recipient in recipients
            ]

        payload = {
            "recipient": ",".join(recipients),
            "sender_id": sender_id,
            "type": "plain",
            "message": body,
        }
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        url = f"{self.base_url}/sms/send"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            response_payload = resp.json()

        return self._parse_response(response_payload, recipients)

    def _parse_response(
        self, payload: dict[str, Any], recipients: list[str]
    ) -> list[SendResult]:
        if payload.get("status") == "error":
            message = str(payload.get("message") or "provider_error")
            return [
                SendResult(
                    recipient=recipient,
                    success=False,
                    status="error",
                    error=message[:255],
                )
                for recipient in recipients
            ]

        data = payload.get("data")
        rows = (
            data
            if isinstance(data, list)
            else [data]
            if isinstance(data, dict)
            else []
        )
        results = [self._result_from_row(row) for row in rows]
        results = [result for result in results if result.recipient]
        if results:
            return self._align_recipients(results, recipients)

        status = str(payload.get("status") or "success")
        return [
            SendResult(
                recipient=recipient,
                success=status.lower() == "success",
                status=status,
                error=None if status.lower() == "success" else status,
            )
            for recipient in recipients
        ]

    def _result_from_row(self, row: dict[str, Any]) -> SendResult:
        recipient = str(
            row.get("recipient")
            or row.get("to")
            or row.get("phone")
            or row.get("number")
            or ""
        )
        status = str(row.get("status") or "")
        error = row.get("error") or row.get("message")
        success = status.lower() in {
            "success",
            "sent",
            "queued",
            "accepted",
            "delivered",
        }
        if status.lower() in {"error", "failed", "rejected", "undelivered"}:
            success = False
        message_id = (
            row.get("uid")
            or row.get("message_id")
            or row.get("messageId")
            or row.get("id")
        )
        if message_id in (None, "", "None"):
            message_id = None
        return SendResult(
            recipient=recipient,
            success=success,
            provider_message_id=str(message_id) if message_id is not None else None,
            status=status or None,
            error=None if success else str(error or status or "failed")[:255],
            cost=str(row.get("cost")) if row.get("cost") is not None else None,
        )

    def _align_recipients(
        self, results: list[SendResult], recipients: list[str]
    ) -> list[SendResult]:
        originals = {self._phone_key(recipient): recipient for recipient in recipients}
        used: set[str] = set()
        for result in results:
            if result.recipient in recipients:
                used.add(result.recipient)
                continue
            original = originals.get(self._phone_key(result.recipient))
            if original and original not in used:
                result.recipient = original
                used.add(original)
        return results

    def _phone_key(self, phone: str) -> str:
        return "".join(ch for ch in phone if ch.isdigit())
