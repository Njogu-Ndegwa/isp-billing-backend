"""TextSMS Kenya (textsms.co.ke) bulk SMS provider.

Wire format: JSON POST to `/api/services/sendbulk/`, credentials repeated
inside every message object, at most 20 messages per request. The response
carries one entry per message, so results are genuinely per-recipient:

    {"responses": [
        {"respose-code": 200, "response-description": "Success",
         "mobile": "254733123456", "messageid": 75085465,
         "clientsmsid": "1234", "networkid": "2"},
        {"respose-code": 1006, "response-description": "Invalid credentials",
         "mobile": "0755123456", "clientsmsid": "1236"}
    ]}

Two quirks worth knowing:

  * The code key is spelled "respose-code" in the vendor's own responses.
    Both spellings are accepted in case they ever fix it.
  * Successful entries echo `mobile` normalised to 254..., failed ones echo it
    as sent. Each message carries a `clientsmsid`, and results are matched on
    that first, falling back to the phone number.
"""

import itertools
import logging
import time
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

# The bulk endpoint documents "up to 20 bulk messages in one single call".
_MAX_PER_REQUEST = 20

_SUCCESS_CODE = 200

# Documented response codes, mapped to the short status stored on the row.
_CODE_STATUS = {
    1001: "invalid_sender_id",
    1002: "network_not_allowed",
    1003: "invalid_recipient",
    1004: "low_credits",
    1005: "system_error",
    1006: "invalid_credentials",
    1007: "system_error",
    1008: "system_error",
    1009: "unsupported_data_type",
    1010: "unsupported_request_type",
    4090: "internal_error",
    4091: "missing_partner_id",
    4092: "missing_api_key",
    4093: "account_not_found",
}

# clientsmsid only has to be unique within one request for matching, but the
# vendor may also use it to drop repeats, so keep it unique across requests.
_client_ids = itertools.count(int(time.time() * 1000) % 1_000_000_000)


class TextSmsProvider(MessagingProvider):
    name = "textsms"
    supports_balance = True

    def __init__(
        self,
        api_key: str,
        partner_id: str,
        base_url: str = "https://sms.textsms.co.ke",
    ):
        self.api_key = api_key
        self.partner_id = partner_id
        self.base_url = (base_url or "").rstrip("/")

    async def get_balance(self) -> BalanceResult:
        """POST /api/services/getbalance/ — read-only, sends no message.

        The vendor (an Advanta-platform white label) answers
        {"response-code": 200, "credit": "800.00", "partner-id": "..."} on
        success and the usual bare code + description on refusal. The credit
        key is read loosely in case this deployment names it differently.
        """
        missing = self._missing_config()
        if missing:
            return BalanceResult(ok=False, error=missing)
        url = f"{self.base_url}/api/services/getbalance/"
        payload = {"apikey": self.api_key, "partnerID": self.partner_id}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    url, json=payload,
                    headers={"Content-Type": "application/json",
                             "Accept": "application/json"},
                )
        except Exception as exc:
            return BalanceResult(ok=False, error=f"network_error: {exc}"[:255])
        try:
            data = resp.json()
        except ValueError:
            return BalanceResult(ok=False, raw=(resp.text or "")[:255],
                                 error=f"bad_response (HTTP {resp.status_code})")
        raw = str(data)[:255]
        if isinstance(data, dict) and isinstance(data.get("responses"), list) and data["responses"]:
            data = data["responses"][0]
        if not isinstance(data, dict):
            return BalanceResult(ok=False, raw=raw, error="bad_response")

        code = self._code(data)
        if resp.status_code >= 400 or (code is not None and code != _SUCCESS_CODE):
            status = _CODE_STATUS.get(code, f"error_{code}") if code is not None else f"http_{resp.status_code}"
            return BalanceResult(ok=False, raw=raw,
                                 error=(self._description(data) or status)[:255])

        for key in ("credit", "credits", "balance", "credit-balance", "account-balance"):
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
        require_external_side_effects_enabled("TextSMS delivery")
        missing = self._missing_config()
        if missing:
            return self._all_failed(recipients, missing, missing)
        if not sender_id:
            return self._all_failed(recipients, "missing_sender_id", "missing_sender_id")

        results: list[SendResult] = []
        prepared: list[tuple[str, str]] = []
        for recipient in recipients:
            formatted = self._format_recipient(recipient)
            if not formatted:
                results.append(SendResult(
                    recipient=recipient,
                    success=False,
                    status="invalid_recipient",
                    error="invalid_recipient",
                ))
                continue
            prepared.append((recipient, formatted))

        if not prepared:
            return results

        url = f"{self.base_url}/api/services/sendbulk/"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=30) as client:
            for start in range(0, len(prepared), _MAX_PER_REQUEST):
                chunk = prepared[start:start + _MAX_PER_REQUEST]
                results.extend(
                    await self._send_chunk(client, url, headers, chunk, body, sender_id)
                )
        return results

    async def _send_chunk(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        chunk: list[tuple[str, str]],
        body: str,
        sender_id: str,
    ) -> list[SendResult]:
        by_client_id: dict[str, tuple[str, str]] = {}
        smslist = []
        for original, formatted in chunk:
            client_id = str(next(_client_ids))
            by_client_id[client_id] = (original, formatted)
            smslist.append({
                "partnerID": self.partner_id,
                "apikey": self.api_key,
                "pass_type": "plain",
                "clientsmsid": client_id,
                "mobile": formatted,
                "message": body,
                "shortcode": sender_id,
            })
        payload = {"count": len(smslist), "smslist": smslist}

        originals = [original for original, _ in chunk]
        try:
            resp = await client.post(url, json=payload, headers=headers)
        except Exception as exc:
            return self._all_failed(originals, "network_error", str(exc)[:255])
        try:
            response_payload = resp.json()
        except ValueError:
            response_payload = {"response-description": (resp.text or "")[:255]}

        if resp.status_code >= 400:
            reason = self._description(response_payload) or f"HTTP {resp.status_code}"
            return self._all_failed(originals, f"http_{resp.status_code}", reason)

        return self._parse_response(response_payload, by_client_id)

    def _parse_response(
        self, payload: Any, by_client_id: dict[str, tuple[str, str]]
    ) -> list[SendResult]:
        originals = [original for original, _ in by_client_id.values()]
        rows = payload.get("responses") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            # A request-level rejection (bad credentials, no partner ID) comes
            # back as one bare code rather than a responses list.
            code = self._code(payload)
            if code is not None and code != _SUCCESS_CODE:
                status = _CODE_STATUS.get(code, f"error_{code}")
                reason = self._description(payload) or status
                return self._all_failed(originals, status, reason)
            return self._all_failed(originals, "bad_response", "bad_response")

        by_phone = {
            self._phone_key(formatted): client_id
            for client_id, (_, formatted) in by_client_id.items()
        }
        matched: dict[str, SendResult] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            client_id = str(row.get("clientsmsid") or "")
            if client_id not in by_client_id or client_id in matched:
                client_id = by_phone.get(
                    self._phone_key(self._format_recipient(str(row.get("mobile") or ""))),
                    "",
                )
            if not client_id or client_id in matched:
                continue
            matched[client_id] = self._result_from_row(row, by_client_id[client_id][0])

        return [
            matched.get(client_id) or SendResult(
                recipient=original,
                success=False,
                status="no_result",
                error="Gateway returned no result for this recipient",
            )
            for client_id, (original, _) in by_client_id.items()
        ]

    def _result_from_row(self, row: dict, recipient: str) -> SendResult:
        code = self._code(row)
        if code == _SUCCESS_CODE:
            message_id = row.get("messageid")
            return SendResult(
                recipient=recipient,
                success=True,
                provider_message_id=(
                    str(message_id) if message_id not in (None, "", "None") else None
                ),
                status="success",
            )
        status = _CODE_STATUS.get(code, f"error_{code}") if code is not None else "error"
        return SendResult(
            recipient=recipient,
            success=False,
            status=status,
            error=(self._description(row) or status)[:255],
        )

    def _code(self, payload: Any) -> int | None:
        if not isinstance(payload, dict):
            return None
        raw = payload.get("respose-code", payload.get("response-code"))
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    def _description(self, payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        for key in ("response-description", "message", "error"):
            value = payload.get(key)
            if value:
                return str(value)
        return ""

    def _missing_config(self) -> str:
        if not self.api_key:
            return "missing_api_key"
        if not self.partner_id:
            return "missing_partner_id"
        if not self.base_url:
            return "missing_base_url"
        return ""

    def _all_failed(
        self, recipients: list[str], status: str, error: str
    ) -> list[SendResult]:
        return [
            SendResult(recipient=r, success=False, status=status, error=error[:255])
            for r in recipients
        ]

    def _phone_key(self, phone: str) -> str:
        return "".join(ch for ch in (phone or "") if ch.isdigit())

    def _format_recipient(self, phone: str | None) -> str:
        """Normalize to MSISDN without '+'. Kenyan local forms get a 254 prefix."""
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
    name="textsms",
    label="TextSMS Kenya",
    factory=TextSmsProvider,
    sender_id_hint="Sender ID approved on your TextSMS account, e.g. TextSMS",
    docs_url="https://textsms.co.ke/bulk-sms-api/",
    countries=["KE"],
    fields=[
        ProviderField(
            "api_key", "API key", secret=True, required=True,
            help="From the TextSMS dashboard, under API settings.",
        ),
        ProviderField(
            "partner_id", "Partner ID", required=True,
            help="Shown next to the API key in the TextSMS dashboard.",
        ),
        ProviderField(
            "base_url", "API base URL", required=True,
            default="https://sms.textsms.co.ke",
        ),
    ],
)
