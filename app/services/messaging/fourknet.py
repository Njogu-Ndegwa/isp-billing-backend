"""4K Net SMS (sms.4knet.co.ke) bulk SMS provider.

Wire format (https://sms.4knet.co.ke/docs): bearer API key, JSON POST to
`/sms/send-bulk` with at most 100 recipients per request:

    POST {base_url}/sms/send-bulk
    Authorization: Bearer <api_key>
    {"recipients": ["254712345678", ...], "message": "...", "sender_id": "..."}

    {"success": true, "message": "Bulk SMS sent: 2 successful, 0 failed",
     "statistics": {...}, "units_used": 2, "total_cost": 0.58, "new_balance": 92.13,
     "results": [{"recipient": "254712345678", "message_id": "8f2c...", "success": true}]}

Errors are plain HTTP: 400 {"error": "..."}, 401 bad or missing key, 429 rate
limited (60 requests per minute per key, all endpoints). `sender_id` is
optional on their side: without it the account's default sender ID is used.

Results are matched back to recipients by phone number (the vendor
normalises numbers to 254...). Each request carries an Idempotency-Key so a
retried chunk is not sent twice.
"""

import asyncio
import logging
import uuid
from typing import Any

import httpx

from app.core.runtime_mode import require_external_side_effects_enabled
from app.services.messaging.base import (
    BalanceResult,
    MessagingProvider,
    ProviderField,
    ProviderSpec,
    SendResult,
    parse_amount,
)

logger = logging.getLogger(__name__)

# The bulk endpoint documents a maximum of 100 recipients per call.
_MAX_PER_REQUEST = 100
# 60 requests/minute per key: stay under it when one send needs many chunks.
_CHUNK_PAUSE_SECONDS = 1.1


class FourKNetProvider(MessagingProvider):
    name = "fourknet"
    supports_balance = True

    def __init__(self, api_key: str, base_url: str = "https://sms.4knet.co.ke/api/v1"):
        self.api_key = api_key
        self.base_url = (base_url or "").rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def get_balance(self) -> BalanceResult:
        """GET /balance — read-only, sends no message.

        {"success": true, "sms_balance": 92.13, "default_sender_id": "...",
         "sms_cost_per_unit": 0.29}
        """
        missing = self._missing_config()
        if missing:
            return BalanceResult(ok=False, error=missing)
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(f"{self.base_url}/balance", headers=self._headers())
        except Exception as exc:
            return BalanceResult(ok=False, error=f"network_error: {exc}"[:255])
        try:
            data = resp.json()
        except ValueError:
            return BalanceResult(ok=False, raw=(resp.text or "")[:255],
                                 error=f"bad_response (HTTP {resp.status_code})")
        raw = str(data)[:255]
        if resp.status_code >= 400 or not isinstance(data, dict) or data.get("success") is False:
            status = f"http_{resp.status_code}"
            return BalanceResult(ok=False, raw=raw,
                                 error=f"{status}: {self._error_text(data) or 'request rejected'}"[:255])
        for key in ("sms_balance", "balance", "credit"):
            if key in data:
                amount, unit = parse_amount(data[key])
                if amount is not None:
                    return BalanceResult(ok=True, balance=amount, unit=unit, raw=raw)
        return BalanceResult(ok=False, raw=raw, error="bad_response: no balance field")

    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        if not recipients:
            return []
        require_external_side_effects_enabled("4K Net SMS delivery")
        missing = self._missing_config()
        if missing:
            return self._all_failed(recipients, missing, missing)

        results: list[SendResult] = []
        prepared: list[tuple[str, str]] = []
        for recipient in recipients:
            formatted = self._format_recipient(recipient)
            if not formatted:
                results.append(SendResult(recipient=recipient, success=False,
                                          status="invalid_recipient", error="invalid_recipient"))
                continue
            prepared.append((recipient, formatted))
        if not prepared:
            return results

        url = f"{self.base_url}/sms/send-bulk"
        async with httpx.AsyncClient(timeout=30) as client:
            for start in range(0, len(prepared), _MAX_PER_REQUEST):
                if start:
                    await asyncio.sleep(_CHUNK_PAUSE_SECONDS)
                chunk = prepared[start:start + _MAX_PER_REQUEST]
                results.extend(await self._send_chunk(client, url, chunk, body, sender_id))
        return results

    async def _send_chunk(
        self, client: httpx.AsyncClient, url: str, chunk: list[tuple[str, str]],
        body: str, sender_id: str,
    ) -> list[SendResult]:
        payload: dict[str, Any] = {"recipients": [f for _, f in chunk], "message": body}
        if sender_id:
            payload["sender_id"] = sender_id
        headers = {**self._headers(), "Idempotency-Key": uuid.uuid4().hex}
        originals = [original for original, _ in chunk]
        try:
            resp = await client.post(url, json=payload, headers=headers)
        except Exception as exc:
            return self._all_failed(originals, "network_error", str(exc)[:255])
        try:
            data = resp.json()
        except ValueError:
            data = {"error": (resp.text or "")[:255]}

        if resp.status_code >= 400:
            # Keep the code and the vendor's own reason: failure_reasons.classify
            # reads both (http_401 -> credentials, http_429 -> sending limit, and a
            # 400's text such as "insufficient balance" or "invalid ... number").
            status = f"http_{resp.status_code}"
            reason = self._error_text(data) or "request rejected"
            return self._all_failed(originals, status, f"{status}: {reason}")
        return self._parse_response(data, chunk)

    def _parse_response(self, data: Any, chunk: list[tuple[str, str]]) -> list[SendResult]:
        originals = [original for original, _ in chunk]
        rows = data.get("results") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            if isinstance(data, dict) and data.get("success") is False:
                reason = self._error_text(data) or "rejected"
                return self._all_failed(originals, "rejected", reason)
            return self._all_failed(originals, "bad_response", "bad_response")

        by_phone = {self._phone_key(formatted): original for original, formatted in chunk}
        matched: dict[str, SendResult] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = self._phone_key(self._format_recipient(str(row.get("recipient") or row.get("phone") or "")))
            original = by_phone.get(key)
            if original is None or key in matched:
                continue
            if row.get("success") is True:
                message_id = row.get("message_id") or row.get("bytewave_uid")
                matched[key] = SendResult(recipient=original, success=True,
                                          provider_message_id=str(message_id) if message_id else None,
                                          status="success")
            else:
                reason = self._error_text(row) or "failed"
                matched[key] = SendResult(recipient=original, success=False,
                                          status="failed", error=reason[:255])

        return [
            matched.get(self._phone_key(formatted)) or SendResult(
                recipient=original, success=False, status="no_result",
                error="Gateway returned no result for this recipient",
            )
            for original, formatted in chunk
        ]

    def _error_text(self, payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        for key in ("error", "message", "detail"):
            value = payload.get(key)
            if value:
                return str(value)
        return ""

    def _missing_config(self) -> str:
        if not self.api_key:
            return "missing_api_key"
        if not self.base_url:
            return "missing_base_url"
        return ""

    def _all_failed(self, recipients: list[str], status: str, error: str) -> list[SendResult]:
        return [SendResult(recipient=r, success=False, status=status, error=error[:255])
                for r in recipients]

    def _phone_key(self, phone: str) -> str:
        return "".join(ch for ch in (phone or "") if ch.isdigit())

    def _format_recipient(self, phone: str | None) -> str:
        """Normalize to 2547XXXXXXXX / 2541XXXXXXXX. 4K Net accepts Kenyan numbers only."""
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


SPEC = ProviderSpec(
    name="fourknet",
    label="4K Net SMS",
    factory=FourKNetProvider,
    sender_id_hint="Sender ID approved on your 4K Net account; leave empty to use the account default",
    docs_url="https://sms.4knet.co.ke/docs",
    countries=["KE"],
    fields=[
        ProviderField(
            "api_key", "API key", secret=True, required=True,
            help="From the 4K Net dashboard, Developer page.",
        ),
        ProviderField(
            "base_url", "API base URL", required=True,
            default="https://sms.4knet.co.ke/api/v1",
        ),
    ],
)
