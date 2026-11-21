"""Daraja free-text safety for B2B payouts.

26 Oct incident: a payment method labelled "I&M" produced Remarks
"Payout to I&M"; Safaricom answered with an all-empty ack and the payout was
marked FAILED with a blank reason, every night for ~4 weeks. Reseller 666,
labelled "IM", paid out fine to the same paybill.
"""

from unittest.mock import AsyncMock

import pytest

from app.db.models import B2BTransactionStatus
from tests.factories import make_reseller


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Payout to I&M", "Payout to IM"),
        ("Payout to I & M", "Payout to I M"),
        ("Payout to I\tM\n", "Payout to IM"),
        ("Payout to KCB/Equity (main)", "Payout to KCBEquity main"),
        ("Payout to   Co-op   Bank ", "Payout to Coop Bank"),
        ("Payout to Mpesa Till 123456", "Payout to Mpesa Till 123456"),
        ("Payout to Café", "Payout to Caf"),
        ("&&&", "Payout"),
        ("", "Payout"),
        (None, "Payout"),
    ],
)
def test_sanitize_daraja_text(raw, expected):
    from app.services.mpesa_b2b import sanitize_daraja_text

    assert sanitize_daraja_text(raw) == expected


def test_sanitize_daraja_text_caps_at_100_without_trailing_space():
    from app.services.mpesa_b2b import sanitize_daraja_text

    out = sanitize_daraja_text("Payout to " + "A" * 89 + " B" + "C" * 50)
    assert len(out) <= 100
    assert out == out.strip()


def _patch_env(b2b, monkeypatch, ack, captured):
    class FakeResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return ack

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


async def _make_im_method(db, reseller, label="I&M"):
    from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType

    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.BANK_ACCOUNT,
        label=label,
        is_active=True,
        bank_paybill_number="542542",
        bank_account_number="05007313786150",
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    return pm


OK_ACK = {
    "ResponseCode": "0",
    "ResponseDescription": "Accept the service request successfully.",
    "ConversationID": "AG_20261026_conv",
    "OriginatorConversationID": "orig-im-1",
}

EMPTY_ACK = {
    "OriginatorConversationID": "",
    "ConversationID": "",
    "ResponseCode": "",
    "ResponseDescription": "",
}


@pytest.mark.asyncio
async def test_im_label_payout_sends_clean_remarks(db, monkeypatch):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    pm = await _make_im_method(db, reseller)
    captured = {}
    _patch_env(b2b, monkeypatch, OK_ACK, captured)

    # The real payout path builds remarks=f"Payout to {payment_method.label}".
    txn = await b2b.payout_reseller(db, reseller.id, pm, balance=1000)

    payload = captured["payload"]
    assert payload["Remarks"] == "Payout to IM"
    # Identifiers are never touched by the sanitiser.
    assert payload["AccountReference"] == "05007313786150"
    assert payload["PartyB"] == "542542"
    assert txn.remarks == "Payout to IM"
    assert txn.status == B2BTransactionStatus.PENDING
    assert txn.conversation_id == "AG_20261026_conv"
    # The stored display label keeps what the reseller typed.
    await db.refresh(pm)
    assert pm.label == "I&M"


@pytest.mark.asyncio
async def test_normal_label_unchanged(db, monkeypatch):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    captured = {}
    _patch_env(b2b, monkeypatch, OK_ACK, captured)

    txn = await b2b.initiate_b2b_payment(
        db=db,
        reseller_id=reseller.id,
        amount=1000,
        party_b="542542",
        account_reference="05007313786150",
        remarks="Payout to IM",
        fee=10,
    )

    assert captured["payload"]["Remarks"] == "Payout to IM"
    assert txn.status == B2BTransactionStatus.PENDING
    assert txn.result_desc is None


@pytest.mark.asyncio
async def test_empty_ack_marks_failed_with_readable_reason(db, monkeypatch):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    captured = {}
    _patch_env(b2b, monkeypatch, EMPTY_ACK, captured)

    txn = await b2b.initiate_b2b_payment(
        db=db,
        reseller_id=reseller.id,
        amount=1000,
        party_b="542542",
        account_reference="05007313786150",
        remarks="Payout to IM",
        fee=10,
    )

    assert txn.status == B2BTransactionStatus.FAILED
    assert txn.result_desc == b2b.EMPTY_ACK_DESC
    assert "empty response" in txn.result_desc
    assert txn.conversation_id is None


@pytest.mark.asyncio
async def test_gateway_error_body_reason_is_kept(db, monkeypatch):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    captured = {}
    ack = {
        "requestId": "abc",
        "errorCode": "400.002.02",
        "errorMessage": "Bad Request - Invalid Remarks",
    }
    _patch_env(b2b, monkeypatch, ack, captured)

    txn = await b2b.initiate_b2b_payment(
        db=db,
        reseller_id=reseller.id,
        amount=1000,
        party_b="542542",
        account_reference="05007313786150",
        fee=10,
    )

    assert txn.status == B2BTransactionStatus.FAILED
    assert txn.result_desc == "400.002.02 Bad Request - Invalid Remarks"


@pytest.mark.asyncio
async def test_rejection_with_description_unchanged(db, monkeypatch):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    captured = {}
    ack = {"ResponseCode": "2001", "ResponseDescription": "The initiator information is invalid."}
    _patch_env(b2b, monkeypatch, ack, captured)

    txn = await b2b.initiate_b2b_payment(
        db=db,
        reseller_id=reseller.id,
        amount=1000,
        party_b="542542",
        account_reference="05007313786150",
        fee=10,
    )

    assert txn.status == B2BTransactionStatus.FAILED
    assert txn.result_code == "2001"
    assert txn.result_desc == "The initiator information is invalid."
