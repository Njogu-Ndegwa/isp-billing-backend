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

        prepared: list[tuple[str, str]] = []
        results: list[SendResult] = []
        for recipient in recipients:
            formatted = self._format_recipient(recipient)
            if not formatted:
                results.append(
                    SendResult(
                        recipient=recipient,
                        success=False,
                        status="invalid_recipient",
                        error="invalid_recipient",
                    )
                )
                continue
            prepared.append((recipient, formatted))

        if not prepared:
            return results

        payload = {
            "recipient": ",".join(formatted for _, formatted in prepared),
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
            try:
                response_payload = resp.json()
            except ValueError:
                response_payload = {"status": "error", "message": resp.text}
            if resp.status_code >= 400:
                if len(prepared) > 1:
                    results.extend(
                        await self._send_individual(
                            client, url, headers, prepared, body, sender_id
                        )
                    )
                    return results
                message = (
                    response_payload.get("message")
                    if isinstance(response_payload, dict)
                    else None
                ) or f"HTTP {resp.status_code}"
                return [
                    SendResult(
                        recipient=prepared[0][0],
                        success=False,
                        status=f"http_{resp.status_code}",
                        error=str(message)[:255],
                    )
                ]

        parsed = self._parse_response(
            response_payload, [original for original, _ in prepared]
        )
        return results + parsed

    async def _send_individual(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        prepared: list[tuple[str, str]],
        body: str,
        sender_id: str,
    ) -> list[SendResult]:
        results: list[SendResult] = []
        for original, formatted in prepared:
            payload = {
                "recipient": formatted,
                "sender_id": sender_id,
                "type": "plain",
                "message": body,
            }
            try:
                resp = await client.post(url, json=payload, headers=headers)
                try:
                    response_payload = resp.json()
                except ValueError:
                    response_payload = {"status": "error", "message": resp.text}
            except Exception as exc:
                results.append(
                    SendResult(
                        recipient=original,
                        success=False,
                        status="network_error",
                        error=str(exc)[:255],
                    )
                )
                continue

            if resp.status_code >= 400:
                message = (
                    response_payload.get("message")
                    if isinstance(response_payload, dict)
                    else None
                ) or f"HTTP {resp.status_code}"
                results.append(
                    SendResult(
                        recipient=original,
                        success=False,
                        status=f"http_{resp.status_code}",
                        error=str(message)[:255],
                    )
                )
                continue

            results.extend(self._parse_response(response_payload, [original]))
        return results

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
        provider_message_id = None
        provider_status = status
        if isinstance(data, dict):
            provider_message_id = (
                data.get("queue_uid")
                or data.get("uid")
                or data.get("message_id")
                or data.get("id")
            )
            provider_status = str(data.get("status") or status)
        success = status.lower() == "success" and provider_status.lower() not in {
            "error",
            "failed",
            "rejected",
            "undelivered",
        }
        return [
            SendResult(
                recipient=recipient,
                success=success,
                provider_message_id=(
                    str(provider_message_id)
                    if provider_message_id not in (None, "", "None")
                    else None
                ),
                status=provider_status,
                error=None if success else str(payload.get("message") or provider_status)[:255],
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

    def _format_recipient(self, phone: str | None) -> str:
        digits = "".join(ch for ch in (phone or "") if ch.isdigit())
        if not digits:
            return ""
        if digits.startswith("00") and len(digits) > 2:
            digits = digits[2:]
        if digits.startswith("0") and len(digits) == 10:
            return "254" + digits[1:]
        if len(digits) == 9 and digits[0] in {"1", "7"}:
            return "254" + digits
        return digits
