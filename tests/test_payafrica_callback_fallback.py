"""PayAfrica rejects callback_url on origins it hasn't allow-listed (prod
2026-09-19: 422 "callback_url origin is not trusted by PayAfrica"). The
checkout must still be created, falling back to no callback, then to
PayAfrica's own page; other errors must not be retried."""

import pytest

import app.services.payafrica as payafrica
from app.services.payafrica import PayAfricaAPIError, initialize_card_checkout_with_fallback

OURS = "https://bitwavetechnologies.com/settings/subscription?card=returned"
UNTRUSTED = PayAfricaAPIError("callback_url origin is not trusted by PayAfrica", status_code=422)


def _stub(monkeypatch, outcomes, webhooks=None):
    calls = []
    webhooks = webhooks if webhooks is not None else []

    async def _fake(**kwargs):
        calls.append(kwargs["callback_url"])
        webhooks.append(kwargs.get("webhook_url"))
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(payafrica, "initialize_card_checkout", _fake)
    return calls


async def _create(webhook_url=None):
    checkout, callback, webhook = await initialize_card_checkout_with_fallback(
        amount=10, currency="USD", customer_email="r@example.com",
        reference="SUBCARD-1-x", callback_url=OURS, webhook_url=webhook_url,
    )
    return checkout, callback, webhook


@pytest.mark.asyncio
async def test_trusted_callback_used_as_is(monkeypatch):
    calls = _stub(monkeypatch, [{"payment_url": "u", "reference": "PAF-1"}])
    checkout, used, webhook = await _create()
    assert calls == [OURS] and used == OURS and webhook is None and checkout["reference"] == "PAF-1"


@pytest.mark.asyncio
async def test_untrusted_callback_retries_without_it(monkeypatch):
    calls = _stub(monkeypatch, [UNTRUSTED, {"payment_url": "u", "reference": "PAF-2"}])
    checkout, used, _ = await _create()
    assert calls == [OURS, None] and used is None and checkout["reference"] == "PAF-2"


@pytest.mark.asyncio
async def test_falls_back_to_payafricas_own_page(monkeypatch):
    calls = _stub(monkeypatch, [UNTRUSTED, UNTRUSTED, {"payment_url": "u", "reference": "PAF-3"}])
    _, used, _ = await _create()
    assert calls == [OURS, None, payafrica.PAYAFRICA_OWN_CALLBACK]
    assert used == payafrica.PAYAFRICA_OWN_CALLBACK


@pytest.mark.asyncio
async def test_other_errors_are_not_retried(monkeypatch):
    calls = _stub(monkeypatch, [PayAfricaAPIError("amount too small", status_code=422)])
    with pytest.raises(PayAfricaAPIError):
        await _create()
    assert calls == [OURS]


@pytest.mark.asyncio
async def test_gives_up_after_all_candidates(monkeypatch):
    calls = _stub(monkeypatch, [UNTRUSTED, UNTRUSTED, UNTRUSTED])
    with pytest.raises(PayAfricaAPIError):
        await _create()
    assert len(calls) == 3


UNREGISTERED_WEBHOOK = PayAfricaAPIError(
    "webhook_url must be a registered HTTPS PayAfrica relay destination", status_code=422)
WH = "https://isp.bitwavetechnologies.net/api/payafrica/webhook/1/abc"


@pytest.mark.asyncio
async def test_webhook_sent_when_accepted(monkeypatch):
    webhooks = []
    calls = _stub(monkeypatch, [{"payment_url": "u", "reference": "PAF-4"}], webhooks)
    _, callback, webhook = await _create(WH)
    assert calls == [OURS] and webhooks == [WH]
    assert callback == OURS and webhook == WH


@pytest.mark.asyncio
async def test_unregistered_webhook_is_dropped_but_payment_proceeds(monkeypatch):
    webhooks = []
    calls = _stub(monkeypatch, [UNREGISTERED_WEBHOOK, {"payment_url": "u", "reference": "PAF-5"}], webhooks)
    _, callback, webhook = await _create(WH)
    # Same callback retried, this time without the webhook.
    assert calls == [OURS, OURS] and webhooks == [WH, None]
    assert callback == OURS and webhook is None


@pytest.mark.asyncio
async def test_both_rejected_drops_each_once(monkeypatch):
    webhooks = []
    calls = _stub(monkeypatch, [UNREGISTERED_WEBHOOK, UNTRUSTED, {"payment_url": "u", "reference": "PAF-6"}], webhooks)
    _, callback, webhook = await _create(WH)
    assert calls == [OURS, OURS, None] and webhooks == [WH, None, None]
    assert callback is None and webhook is None


INVALID_CALLBACK_HOST = PayAfricaAPIError(
    "[{'loc': ['body', 'callback_url'], 'msg': 'URL host invalid, top level domain required'}]",
    status_code=422)


@pytest.mark.asyncio
async def test_any_callback_rejection_is_dropped(monkeypatch):
    """A localhost callback fails pydantic validation, not the trust check;
    the payment must still go through (caught in local end-to-end testing)."""
    calls = _stub(monkeypatch, [INVALID_CALLBACK_HOST, {"payment_url": "u", "reference": "PAF-7"}])
    _, callback, _ = await _create()
    assert calls == [OURS, None] and callback is None
