"""PayAfrica rejects callback_url on origins it hasn't allow-listed (prod
2026-09-19: 422 "callback_url origin is not trusted by PayAfrica"). The
checkout must still be created, falling back to no callback, then to
PayAfrica's own page; other errors must not be retried."""

import pytest

import app.services.payafrica as payafrica
from app.services.payafrica import PayAfricaAPIError, initialize_card_checkout_with_fallback

OURS = "https://bitwavetechnologies.com/settings/subscription?card=returned"
UNTRUSTED = PayAfricaAPIError("callback_url origin is not trusted by PayAfrica", status_code=422)


def _stub(monkeypatch, outcomes):
    calls = []

    async def _fake(**kwargs):
        calls.append(kwargs["callback_url"])
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(payafrica, "initialize_card_checkout", _fake)
    return calls


async def _create():
    return await initialize_card_checkout_with_fallback(
        amount=10, currency="USD", customer_email="r@example.com",
        reference="SUBCARD-1-x", callback_url=OURS,
    )


@pytest.mark.asyncio
async def test_trusted_callback_used_as_is(monkeypatch):
    calls = _stub(monkeypatch, [{"payment_url": "u", "reference": "PAF-1"}])
    checkout, used = await _create()
    assert calls == [OURS] and used == OURS and checkout["reference"] == "PAF-1"


@pytest.mark.asyncio
async def test_untrusted_callback_retries_without_it(monkeypatch):
    calls = _stub(monkeypatch, [UNTRUSTED, {"payment_url": "u", "reference": "PAF-2"}])
    checkout, used = await _create()
    assert calls == [OURS, None] and used is None and checkout["reference"] == "PAF-2"


@pytest.mark.asyncio
async def test_falls_back_to_payafricas_own_page(monkeypatch):
    calls = _stub(monkeypatch, [UNTRUSTED, UNTRUSTED, {"payment_url": "u", "reference": "PAF-3"}])
    _, used = await _create()
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
