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


async def test_bank_account_payout_uses_saved_account_number_exactly(db, monkeypatch):
    from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    account_number = "05007313786150"
    captured = {}

    payment_method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.BANK_ACCOUNT,
        label="I&M",
        is_active=True,
        bank_paybill_number="542542",
        bank_account_number=account_number,
    )
    db.add(payment_method)
    await db.commit()
    await db.refresh(payment_method)

    class FakeResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {
                "ResponseCode": "0",
                "ConversationID": "conv-bank-001",
                "OriginatorConversationID": "orig-bank-001",
            }

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json, headers):
            captured["payload"] = json
            return FakeResponse()

    monkeypatch.setattr(b2b, "_get_access_token", AsyncMock(return_value="token"))
    monkeypatch.setattr(b2b, "generate_security_credential", lambda: "credential")
    monkeypatch.setattr(b2b.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(b2b.settings, "MPESA_SHORTCODE", "600980", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "initiator", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_RESULT_URL", "https://example.com/result", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_TIMEOUT_URL", "https://example.com/timeout", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_ENVIRONMENT", "sandbox", raising=False)

    txn = await b2b.payout_reseller(
        db=db,
        reseller_id=reseller.id,
        payment_method=payment_method,
        balance=309,
    )

    assert captured["payload"]["PartyB"] == "542542"
    assert captured["payload"]["AccountReference"] == account_number
    assert txn.account_reference == account_number


async def test_failed_b2b_payment_blank_provider_ids_are_stored_as_null(db, monkeypatch):
    from app.db.models import B2BTransactionStatus
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)

    class FakeResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {
                "ResponseCode": "1",
                "ResponseDescription": "Rejected before queueing",
                "ConversationID": "",
                "OriginatorConversationID": "   ",
            }

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json, headers):
            return FakeResponse()

    monkeypatch.setattr(b2b, "_get_access_token", AsyncMock(return_value="token"))
    monkeypatch.setattr(b2b, "generate_security_credential", lambda: "credential")
    monkeypatch.setattr(b2b.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(b2b.settings, "MPESA_SHORTCODE", "600980", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "initiator", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_RESULT_URL", "https://example.com/result", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_TIMEOUT_URL", "https://example.com/timeout", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_ENVIRONMENT", "sandbox", raising=False)

    first = await b2b.initiate_b2b_payment(
        db=db,
        reseller_id=reseller.id,
        amount=309,
        party_b="542542",
        account_reference="05007313786150",
        fee=5,
    )
    second = await b2b.initiate_b2b_payment(
        db=db,
        reseller_id=reseller.id,
        amount=309,
        party_b="542542",
        account_reference="05007313786150",
        fee=5,
    )

    assert first.status == B2BTransactionStatus.FAILED
    assert second.status == B2BTransactionStatus.FAILED
    assert first.conversation_id is None
    assert first.originator_conversation_id is None
    assert second.conversation_id is None
    assert second.originator_conversation_id is None

    assert await b2b.process_b2b_result(db, {"Result": {"ResultCode": "0"}}) is None
