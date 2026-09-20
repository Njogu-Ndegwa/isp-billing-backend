"""HostPinnacle Kenya bulk SMS provider.

HostPinnacle (smsportal.hostpinnacle.co.ke) is a white-label of the
SMSGatewayCenter enterprise platform, so the wire format is that platform's:
form-encoded POST, credentials in the body, one comma-separated `mobile`
list per request, JSON back.

Two details vary between deployments of that platform, and HostPinnacle's own
API reference sits behind a portal login, so both are exposed as config rather
than hardcoded:

  * `send_path` — "/SMSApi/send" on HostPinnacle, "/SMSApi/rest/send" upstream
  * `send_method` — "quick" on HostPinnacle, "simpleMsg" upstream

If a tenant's portal turns out to use the other variant, it is a settings
change on their provider account, not a code change. Use the admin test-send
endpoint to confirm against a live account.

The response is per-request, not per-recipient: the platform reports one
transaction plus an `invalidMobile` list of the numbers it rejected. We fan
that back out to one SendResult per recipient so the caller's accounting and
credit refunds stay per-recipient like every other provider.
"""

import logging
from typing import Any

import httpx

from app.services.messaging.base import (
    MessagingProvider,
    ProviderField,
    ProviderSpec,
    SendResult,
)

logger = logging.getLogger(__name__)

# Platform statusCode 900 and HTTP-style 200 both mean accepted.
_OK_STATUS_CODES = {"200", "900"}


class HostPinnacleProvider(MessagingProvider):
    name = "hostpinnacle"

    def __init__(
        self,
        userid: str,
        password: str,
        base_url: str = "https://smsportal.hostpinnacle.co.ke",
        api_key: str = "",
        send_path: str = "/SMSApi/send",
        send_method: str = "quick",
        msg_type: str = "text",
        duplicate_check: str = "true",
    ):
        self.userid = userid
        self.password = password
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self.send_path = "/" + (send_path or "").strip("/")
        self.send_method = send_method
        self.msg_type = msg_type
        self.duplicate_check = duplicate_check

    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        if not recipients:
            return []
        missing = self._missing_config()
        if missing:
            return self._all_failed(recipients, missing, missing)
        if not sender_id:
            return self._all_failed(recipients, "missing_sender_id", "missing_sender_id")

        prepared: list[tuple[str, str]] = []
        results: list[SendResult] = []
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

        data = {
            "userid": self.userid,
            "password": self.password,
            "senderid": sender_id,
            "mobile": ",".join(formatted for _, formatted in prepared),
            "msg": body,
            "msgType": self.msg_type,
            "sendMethod": self.send_method,
            "duplicatecheck": self.duplicate_check,
            "output": "json",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apikey"] = self.api_key

        url = f"{self.base_url}{self.send_path}"
        originals = [original for original, _ in prepared]
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(url, data=data, headers=headers)
                try:
                    payload = resp.json()
                except ValueError:
                    payload = {"status": "error", "reason": (resp.text or "")[:255]}
        except Exception as exc:
            return results + self._all_failed(originals, "network_error", str(exc)[:255])

        if resp.status_code >= 400:
            reason = self._reason(payload) or f"HTTP {resp.status_code}"
            return results + self._all_failed(
                originals, f"http_{resp.status_code}", reason
            )

        return results + self._parse_response(payload, prepared)

    def _missing_config(self) -> str:
        if not self.userid:
            return "missing_userid"
        if not self.password:
            return "missing_password"
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

    def _reason(self, payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        for key in ("reason", "message", "description", "error"):
            value = payload.get(key)
            if value:
                return str(value)
        return ""

    def _parse_response(
        self, payload: Any, prepared: list[tuple[str, str]]
    ) -> list[SendResult]:
        originals = [original for original, _ in prepared]
        if not isinstance(payload, dict):
            return self._all_failed(originals, "bad_response", "bad_response")

        status = str(payload.get("status") or "").lower()
        status_code = str(payload.get("statusCode") or "")
        reason = self._reason(payload) or status or "failed"
        transaction_id = payload.get("transactionId") or None
        if transaction_id in ("", "None"):
            transaction_id = None

        accepted = status == "success" or status_code in _OK_STATUS_CODES
        if not accepted:
            return self._all_failed(originals, status or "error", reason)

        # The batch was accepted; the platform still names numbers it rejected,
        # either flat (`invalidMobile`) or inside the per-message `sms` array.
        invalid = self._invalid_keys(payload)

        results: list[SendResult] = []
        for original, formatted in prepared:
            if self._phone_key(formatted) in invalid:
                results.append(SendResult(
                    recipient=original,
                    success=False,
                    status="invalid_recipient",
                    error="invalid_recipient",
                ))
                continue
            results.append(SendResult(
                recipient=original,
                success=True,
                provider_message_id=str(transaction_id) if transaction_id else None,
                status=status or "success",
            ))
        return results

    def _invalid_keys(self, payload: dict) -> set[str]:
        raw: list[Any] = []
        flat = payload.get("invalidMobile")
        if isinstance(flat, str):
            raw.extend(flat.split(","))
        elif isinstance(flat, list):
            raw.extend(flat)
        rows = payload.get("sms")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                nested = row.get("invalidMobile")
                if isinstance(nested, str):
                    raw.extend(nested.split(","))
                elif isinstance(nested, list):
                    raw.extend(nested)
        return {self._phone_key(str(v)) for v in raw if str(v).strip()}

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
    name="hostpinnacle",
    label="HostPinnacle Kenya",
    factory=HostPinnacleProvider,
    sender_id_hint="Approved alphanumeric sender ID, e.g. DUKESTOP",
    docs_url="https://smsportal.hostpinnacle.co.ke/docs/api/",
    countries=["KE"],
    fields=[
        ProviderField("userid", "Portal username", required=True),
        ProviderField("password", "Portal password", secret=True, required=True),
        ProviderField(
            "base_url", "API base URL", required=True,
            default="https://smsportal.hostpinnacle.co.ke",
        ),
        ProviderField(
            "api_key", "API key", secret=True, required=False,
            help="Optional. Sent as the 'apikey' header when the account uses one.",
        ),
        ProviderField(
            "send_path", "Send endpoint path", required=True, default="/SMSApi/send",
            help="/SMSApi/send on HostPinnacle; /SMSApi/rest/send on some deployments.",
        ),
        ProviderField(
            "send_method", "Send method", required=True, default="quick",
            help="'quick' on HostPinnacle; 'simpleMsg' on some deployments.",
        ),
        ProviderField(
            "msg_type", "Message type", required=True, default="text",
            help="'text' for GSM-7, 'unicode' for messages with non-GSM characters.",
        ),
        ProviderField(
            "duplicate_check", "Duplicate check", required=False, default="true",
            help="'true' lets the gateway drop identical repeat sends.",
        ),
    ],
)
