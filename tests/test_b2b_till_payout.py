"""Buy Goods till payouts (added 2026-07-21).

A merchant till is a different B2B receiver than a paybill: CommandID
BusinessBuyGoods, RecieverIdentifierType 2, and NO AccountReference (tills
have no accounts; Safaricom mishandles unexpected fields). Sending the
paybill command to a till is the SFC_IC0003 "Receiver party is invalid"
failure that till-number resellers hit every night before this existed.
"""

from unittest.mock import AsyncMock

import pytest

from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType
from tests.factories import make_reseller

pytestmark = pytest.mark.asyncio


def _fake_safaricom(monkeypatch, b2b, captured):
    class FakeResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {
                "ResponseCode": "0",
                "ConversationID": "conv-till-001",
                "OriginatorConversationID": "orig-till-001",
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
            return FakeResponse()

    monkeypatch.setattr(b2b, "_get_access_token", AsyncMock(return_value="token"))
    monkeypatch.setattr(b2b, "generate_security_credential", lambda: "credential")
    monkeypatch.setattr(b2b.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(b2b.settings, "MPESA_SHORTCODE", "600980", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "initiator", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_RESULT_URL", "https://example.com/result", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_TIMEOUT_URL", "https://example.com/timeout", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_ENVIRONMENT", "sandbox", raising=False)


async def test_till_payout_uses_business_buy_goods(db, monkeypatch):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Duka till",
        is_active=True,
        mpesa_till_number="9285575",
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)

    captured = {}
    _fake_safaricom(monkeypatch, b2b, captured)

    txn = await b2b.payout_reseller(db, reseller.id, pm, balance=1000.0)

    payload = captured["payload"]
    assert payload["CommandID"] == "BusinessBuyGoods"
    assert payload["RecieverIdentifierType"] == "2"
    assert payload["SenderIdentifierType"] == "4"
    assert payload["PartyB"] == "9285575"
    # Tills have no accounts — the key must be absent, not empty.
    assert "AccountReference" not in payload
    assert txn.command_id == "BusinessBuyGoods"
    assert txn.party_b == "9285575"


async def test_paybill_payout_still_uses_business_paybill(db, monkeypatch):
    """Guard: the till path must not change paybill/bank behavior."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.BANK_ACCOUNT,
        label="Equity",
        is_active=True,
        bank_paybill_number="247247",
        bank_account_number="1520186200177",
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)

    captured = {}
    _fake_safaricom(monkeypatch, b2b, captured)

    txn = await b2b.payout_reseller(db, reseller.id, pm, balance=1000.0)

    payload = captured["payload"]
    assert payload["CommandID"] == "BusinessPayBill"
    assert payload["RecieverIdentifierType"] == "4"
    assert payload["AccountReference"] == "1520186200177"
    assert txn.command_id == "BusinessPayBill"


async def test_till_method_is_b2b_eligible(db):
    """resolve_b2b_payment_method must pick up an active till method, so the
    nightly job pays till resellers automatically."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    db.add(ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Duka till",
        is_active=True,
        mpesa_till_number="1234567",
    ))
    await db.commit()

    pm = await b2b.resolve_b2b_payment_method(db, reseller.id)
    assert pm is not None
    assert ResellerPaymentMethodType(pm.method_type) == ResellerPaymentMethodType.MPESA_TILL


async def test_till_without_number_raises(db, monkeypatch):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Broken till",
        is_active=True,
        mpesa_till_number=None,
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)

    with pytest.raises(ValueError, match="no destination paybill/till"):
        await b2b.payout_reseller(db, reseller.id, pm, balance=500.0)
