"""Africa's Talking bulk SMS provider."""

import logging

import httpx

from app.services.messaging.base import (
    BalanceResult,
    MessagingProvider,
    ProviderField,
    ProviderSpec,
    SendResult,
    parse_amount,
)
from app.core.runtime_mode import require_external_side_effects_enabled

logger = logging.getLogger(__name__)


class AfricasTalkingProvider(MessagingProvider):
    name = "africastalking"
    supports_balance = True

    def __init__(self, username: str, api_key: str, base_url: str):
        self.username = username
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    async def get_balance(self) -> BalanceResult:
        """GET /version1/user — {"UserData": {"balance": "KES 1785.50"}}. Read-only."""
        url = f"{self.base_url}/version1/user"
        headers = {"apiKey": self.api_key, "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, params={"username": self.username},
                                        headers=headers)
        except Exception as exc:
            return BalanceResult(ok=False, error=f"network_error: {exc}"[:255])
        raw = (resp.text or "")[:255]
        if resp.status_code >= 400:
            # AT answers a bad key with 401 and a plain-text explanation.
            return BalanceResult(ok=False, raw=raw,
                                 error=(raw or f"http_{resp.status_code}")[:255])
        try:
            data = resp.json()
        except ValueError:
            return BalanceResult(ok=False, raw=raw, error="bad_response")
        user_data = data.get("UserData") if isinstance(data, dict) else None
        amount, unit = parse_amount((user_data or {}).get("balance"))
        if amount is None:
            return BalanceResult(ok=False, raw=raw, error="bad_response: no balance field")
        return BalanceResult(ok=True, balance=amount, unit=unit, raw=raw)

    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        if not recipients:
            return []
        require_external_side_effects_enabled("Africa's Talking SMS delivery")
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


SPEC = ProviderSpec(
    name="africastalking",
    label="Africa's Talking",
    factory=AfricasTalkingProvider,
    sender_id_hint="Registered alphanumeric sender ID, or blank for the shared pool",
    docs_url="https://developers.africastalking.com/docs/sms/overview",
    countries=["KE", "UG", "TZ", "RW", "NG", "MW"],
    fields=[
        ProviderField("username", "Username", required=True,
                      help="'sandbox' for the test environment."),
        ProviderField("api_key", "API key", secret=True, required=True),
        ProviderField("base_url", "API base URL", required=True,
                      default="https://api.africastalking.com"),
    ],
)
