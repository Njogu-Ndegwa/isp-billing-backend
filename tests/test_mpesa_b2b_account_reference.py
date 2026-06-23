from unittest.mock import AsyncMock

import pytest

from tests.factories import make_reseller

pytestmark = pytest.mark.asyncio


async def test_initiate_b2b_payment_sends_full_account_reference(db, monkeypatch):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    account_reference = "12345678901230"
    captured = {}

    class FakeResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {
                "ResponseCode": "0",
                "ConversationID": "conv-001",
                "OriginatorConversationID": "orig-001",
            }

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json, headers):
            captured["url"] = url
            captured["payload"] = json
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr(b2b, "_get_access_token", AsyncMock(return_value="token"))
    monkeypatch.setattr(b2b, "generate_security_credential", lambda: "credential")
    monkeypatch.setattr(b2b.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(b2b.settings, "MPESA_SHORTCODE", "600980", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "initiator", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_RESULT_URL", "https://example.com/result", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_TIMEOUT_URL", "https://example.com/timeout", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_ENVIRONMENT", "sandbox", raising=False)

    txn = await b2b.initiate_b2b_payment(
        db=db,
        reseller_id=reseller.id,
        amount=1000,
        party_b="522522",
        account_reference=account_reference,
        fee=10,
    )

    assert captured["payload"]["AccountReference"] == account_reference
    assert captured["payload"]["AccountReference"].endswith("0")
    assert txn.account_reference == account_reference
