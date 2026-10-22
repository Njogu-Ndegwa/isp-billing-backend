import httpx
import pytest

from app.services.messaging import registry
from app.services.messaging import fourknet as fourknet_module
from app.services.messaging.failure_reasons import classify
from app.services.messaging.fourknet import FourKNetProvider


def _client(responder, captured):
    class _FakeResponse:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
            self.text = str(payload)

        def json(self):
            if isinstance(self._payload, Exception):
                raise self._payload
            return self._payload

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            captured.append({"method": "POST", "url": url, "json": json, "headers": headers})
            status, payload = responder(json)
            return _FakeResponse(status, payload)

        async def get(self, url, headers=None):
            captured.append({"method": "GET", "url": url, "headers": headers})
            status, payload = responder(None)
            return _FakeResponse(status, payload)

    return _FakeClient


def _provider():
    return FourKNetProvider(api_key="key123", base_url="https://sms.example/api/v1/")


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch):
    monkeypatch.setattr(fourknet_module, "_CHUNK_PAUSE_SECONDS", 0)


def test_registry_discovers_fourknet():
    registry.reset_cache()
    spec = registry.get_spec("fourknet")
    assert spec.label == "4K Net SMS"
    assert spec.secret_keys() == {"api_key"}
    assert spec.validate({}) == ["API key is required"]
    provider = spec.build({"api_key": " k \n"})
    assert isinstance(provider, FourKNetProvider)
    assert provider.api_key == "k"
    assert provider.base_url == "https://sms.4knet.co.ke/api/v1"
    assert "fourknet" in registry.provider_names()


@pytest.mark.asyncio
async def test_posts_bulk_with_bearer_key_and_maps_per_recipient(monkeypatch):
    captured = []

    def responder(body):
        return 200, {
            "success": True,
            "message": "Bulk SMS sent: 1 successful, 1 failed",
            "results": [
                {"recipient": "254712345678", "message_id": "abc123", "success": True},
                {"recipient": "254700000000", "success": False, "error": "Invalid phone number"},
            ],
        }

    monkeypatch.setattr(httpx, "AsyncClient", _client(responder, captured))
    results = await _provider().send_bulk(["0712345678", "+254700000000"], "Hello", "BITWAVE")

    assert len(captured) == 1
    req = captured[0]
    assert req["url"] == "https://sms.example/api/v1/sms/send-bulk"
    assert req["headers"]["Authorization"] == "Bearer key123"
    assert req["headers"]["Idempotency-Key"]
    assert req["json"] == {"recipients": ["254712345678", "254700000000"],
                           "message": "Hello", "sender_id": "BITWAVE"}
    assert [r.recipient for r in results] == ["0712345678", "+254700000000"]
    assert results[0].success and results[0].provider_message_id == "abc123"
    assert not results[1].success
    assert classify(results[1].error).code == classify("invalid phone").code


@pytest.mark.asyncio
async def test_empty_sender_id_uses_account_default(monkeypatch):
    captured = []
    monkeypatch.setattr(httpx, "AsyncClient", _client(
        lambda body: (200, {"success": True, "results": [
            {"recipient": "254712345678", "message_id": "x", "success": True}]}), captured))
    results = await _provider().send_bulk(["0712345678"], "Hi", "")
    assert "sender_id" not in captured[0]["json"]
    assert results[0].success


@pytest.mark.asyncio
async def test_chunks_at_100_recipients(monkeypatch):
    captured = []

    def responder(body):
        return 200, {"success": True, "results": [
            {"recipient": r, "message_id": r[-4:], "success": True} for r in body["recipients"]]}

    monkeypatch.setattr(httpx, "AsyncClient", _client(responder, captured))
    phones = [f"07{n:08d}" for n in range(250)]
    results = await _provider().send_bulk(phones, "Hi", "S")
    assert [len(c["json"]["recipients"]) for c in captured] == [100, 100, 50]
    assert len({c["headers"]["Idempotency-Key"] for c in captured}) == 3
    assert len(results) == 250 and all(r.success for r in results)


@pytest.mark.asyncio
@pytest.mark.parametrize("status,payload,expected", [
    (401, {"error": "Unauthorized"}, "INVALID_CREDENTIALS"),
    (429, {"error": "Too Many Requests"}, "SENDING_LIMIT"),
    (400, {"error": "Insufficient balance"}, "LOW_BALANCE"),
    (400, {"error": "Recipient must be a valid Kenyan phone number."}, "INVALID_RECIPIENT"),
])
async def test_http_errors_fail_every_recipient_with_classifiable_reason(monkeypatch, status, payload, expected):
    from app.services.messaging import failure_reasons
    monkeypatch.setattr(httpx, "AsyncClient", _client(lambda body: (status, payload), []))
    results = await _provider().send_bulk(["0712345678", "0712345679"], "Hi", "S")
    assert all(not r.success for r in results)
    assert all(r.status == f"http_{status}" for r in results)
    assert classify(results[0].error) is getattr(failure_reasons, expected)


@pytest.mark.asyncio
async def test_missing_result_row_is_reported_not_assumed_sent(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", _client(
        lambda body: (200, {"success": True, "results": [
            {"recipient": "254712345678", "message_id": "x", "success": True}]}), []))
    results = await _provider().send_bulk(["0712345678", "0799999999"], "Hi", "S")
    assert results[0].success
    assert not results[1].success and results[1].status == "no_result"


@pytest.mark.asyncio
async def test_invalid_and_missing_config(monkeypatch):
    calls = []
    monkeypatch.setattr(httpx, "AsyncClient", _client(lambda body: (200, {}), calls))
    results = await FourKNetProvider(api_key="").send_bulk(["0712345678"], "Hi", "S")
    assert results[0].status == "missing_api_key" and not calls
    results = await _provider().send_bulk(["", "abc"], "Hi", "S")
    assert all(r.status == "invalid_recipient" for r in results) and not calls


@pytest.mark.asyncio
async def test_balance(monkeypatch):
    captured = []
    monkeypatch.setattr(httpx, "AsyncClient", _client(lambda body: (200, {
        "success": True, "sms_balance": 92.13, "default_sender_id": "X", "sms_cost_per_unit": 0.29}), captured))
    bal = await _provider().get_balance()
    assert captured[0]["method"] == "GET" and captured[0]["url"] == "https://sms.example/api/v1/balance"
    assert bal.ok and bal.balance == 92.13

    monkeypatch.setattr(httpx, "AsyncClient", _client(lambda body: (401, {"error": "Unauthorized"}), []))
    bal = await _provider().get_balance()
    assert not bal.ok and "http_401" in bal.error
