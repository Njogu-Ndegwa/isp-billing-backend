"""Safaricom calls over a lossy link (Hetzner DE -> Safaricom KE, 2026-09-29).

About 1 in 8 payment prompts failed with a blank "handshake operation timed
out": the OAuth token was fetched for every STK push and the 5 s connect
timeout was too tight. These tests pin the behaviour that fixed it:

* the token is reused until shortly before it expires (per credential pair);
* a failed CONNECTION is retried (the request never left, so no double prompt);
* a read timeout / HTTP error is never retried (Safaricom may have acted on it);
* a token Safaricom rejects as invalid is refreshed once and the push resent.
"""
import httpx
import pytest

from app.config import settings
from app.services import mpesa

TOKEN_URL = "/oauth/v1/generate"
STK_URL = "/mpesa/stkpush/v1/processrequest"
STK_OK = {"CheckoutRequestID": "ws_CO_1", "MerchantRequestID": "m-1", "ResponseCode": "0"}


class FakeSafaricom:
    """Scripted responses per path; each entry is a Response or an exception."""

    def __init__(self, token_script=(), stk_script=()):
        self.token_script = list(token_script)
        self.stk_script = list(stk_script)
        self.calls = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((path, request.headers.get("Authorization", "")))
        script = self.token_script if path == TOKEN_URL else self.stk_script
        item = script.pop(0) if len(script) > 1 else script[0]
        if isinstance(item, Exception):
            raise item
        return item

    def count(self, path):
        return sum(1 for p, _ in self.calls if p == path)


def _token(value="tok-1", expires_in="3599"):
    return httpx.Response(200, json={"access_token": value, "expires_in": expires_in})


@pytest.fixture
def safaricom(monkeypatch):
    mpesa.reset_token_cache()
    monkeypatch.setattr(settings, "MPESA_ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "MPESA_CONSUMER_KEY", "key-a")
    monkeypatch.setattr(settings, "MPESA_CONSUMER_SECRET", "secret-a")
    monkeypatch.setattr(settings, "MPESA_SHORTCODE", "174379")
    monkeypatch.setattr(settings, "MPESA_PASSKEY", "pk")
    monkeypatch.setattr(settings, "MPESA_CALLBACK_URL", "https://example.test/cb")
    monkeypatch.setattr(mpesa, "require_external_side_effects_enabled", lambda *_a, **_k: None)
    monkeypatch.setattr(mpesa, "CONNECT_RETRY_BACKOFF_SECONDS", 0)
    fake = FakeSafaricom()
    monkeypatch.setattr(mpesa, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)))
    yield fake
    mpesa.reset_token_cache()


async def _push():
    return await mpesa.initiate_stk_push_direct("254700000001", 10, "REF1")


@pytest.mark.asyncio
async def test_token_is_reused_across_pushes(safaricom):
    safaricom.token_script = [_token()]
    safaricom.stk_script = [httpx.Response(200, json=STK_OK)]
    for _ in range(3):
        assert (await _push()).checkout_request_id == "ws_CO_1"
    assert safaricom.count(TOKEN_URL) == 1          # was 3: one per push
    assert safaricom.count(STK_URL) == 3


@pytest.mark.asyncio
async def test_token_cache_is_per_credential_pair(safaricom):
    safaricom.token_script = [_token("tok-a"), _token("tok-b")]
    assert await mpesa.get_access_token() == "tok-a"
    assert await mpesa.get_access_token(consumer_key="key-b", consumer_secret="secret-b") == "tok-b"
    assert await mpesa.get_access_token() == "tok-a"
    assert safaricom.count(TOKEN_URL) == 2


@pytest.mark.asyncio
async def test_expired_token_is_refetched(safaricom, monkeypatch):
    safaricom.token_script = [_token("old"), _token("new")]
    clock = {"t": 1000.0}
    monkeypatch.setattr(mpesa.time, "monotonic", lambda: clock["t"])
    assert await mpesa.get_access_token() == "old"
    clock["t"] += 3599 - mpesa.TOKEN_REFRESH_MARGIN_SECONDS - 1
    assert await mpesa.get_access_token() == "old"   # still inside its life
    clock["t"] += 2
    assert await mpesa.get_access_token() == "new"   # refreshed before Safaricom expires it


@pytest.mark.asyncio
async def test_credential_test_bypasses_the_cache(safaricom):
    safaricom.token_script = [_token("t1"), _token("t2")]
    await mpesa.get_access_token()
    assert await mpesa.get_access_token(use_cache=False) == "t2"


@pytest.mark.asyncio
async def test_connect_timeout_on_token_is_retried(safaricom):
    safaricom.token_script = [httpx.ConnectTimeout("handshake timed out"), httpx.ConnectError("reset"), _token()]
    assert await mpesa.get_access_token() == "tok-1"
    assert safaricom.count(TOKEN_URL) == 3


@pytest.mark.asyncio
async def test_token_gives_up_after_the_retries_with_a_named_error(safaricom):
    safaricom.token_script = [httpx.ConnectTimeout("handshake timed out")]
    with pytest.raises(Exception) as exc:
        await mpesa.get_access_token()
    assert "ConnectTimeout" in str(exc.value.detail)             # no longer a blank message
    assert safaricom.count(TOKEN_URL) == 1 + mpesa.CONNECT_RETRIES


@pytest.mark.asyncio
async def test_stk_connect_failure_is_retried_once_sent_once(safaricom):
    safaricom.token_script = [_token()]
    safaricom.stk_script = [httpx.ConnectTimeout("handshake timed out"), httpx.Response(200, json=STK_OK)]
    assert (await _push()).checkout_request_id == "ws_CO_1"
    assert safaricom.count(STK_URL) == 2


@pytest.mark.asyncio
async def test_stk_read_timeout_is_never_retried(safaricom):
    # The request reached Safaricom: resending could prompt the customer twice.
    safaricom.token_script = [_token()]
    safaricom.stk_script = [httpx.ReadTimeout("no answer")]
    with pytest.raises(Exception):
        await _push()
    assert safaricom.count(STK_URL) == 1


@pytest.mark.asyncio
async def test_stk_http_rejection_is_not_retried(safaricom):
    safaricom.token_script = [_token()]
    safaricom.stk_script = [httpx.Response(400, json={"errorMessage": "Invalid PhoneNumber"})]
    with pytest.raises(mpesa.StkPushRejected):
        await _push()
    assert safaricom.count(STK_URL) == 1


@pytest.mark.asyncio
async def test_invalid_token_is_refreshed_and_the_push_resent_once(safaricom):
    safaricom.token_script = [_token("stale"), _token("fresh")]
    safaricom.stk_script = [
        httpx.Response(404, json={"errorCode": "404.001.03", "errorMessage": "Invalid Access Token"}),
        httpx.Response(200, json=STK_OK),
    ]
    assert (await _push()).checkout_request_id == "ws_CO_1"
    auths = [a for p, a in safaricom.calls if p == STK_URL]
    assert auths == ["Bearer stale", "Bearer fresh"]
