import httpx
import pytest

from app.services.messaging import registry
from app.services.messaging.textsms import TextSmsProvider


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
            captured.append({"url": url, "json": json, "headers": headers})
            status, payload = responder(json)
            return _FakeResponse(status, payload)

    return _FakeClient


def _provider():
    return TextSmsProvider(api_key="key123", partner_id="77",
                           base_url="https://sms.example/")


def _ok_row(msg):
    return {"respose-code": 200, "response-description": "Success",
            "mobile": msg["mobile"], "messageid": 9000 + int(msg["clientsmsid"]) % 1000,
            "clientsmsid": msg["clientsmsid"], "networkid": "1"}


def test_registry_discovers_textsms():
    registry.reset_cache()
    spec = registry.get_spec("textsms")
    assert spec.label == "TextSMS Kenya"
    assert spec.secret_keys() == {"api_key"}
    assert spec.validate({"api_key": "k"}) == ["Partner ID is required"]
    provider = spec.build({"api_key": "k", "partner_id": "1"})
    assert isinstance(provider, TextSmsProvider)
    assert provider.base_url == "https://sms.textsms.co.ke"


@pytest.mark.asyncio
async def test_posts_bulk_payload_and_maps_per_recipient(monkeypatch):
    captured = []

    def responder(body):
        first, second = body["smslist"]
        return 200, {"responses": [
            _ok_row(first),
            {"respose-code": 1003, "response-description": "Invalid mobile number",
             "mobile": "0700000000", "clientsmsid": second["clientsmsid"]},
        ]}

    monkeypatch.setattr(httpx, "AsyncClient", _client(responder, captured))
    results = await _provider().send_bulk(
        ["0712345678", "+254700000000"], "Hello", "BITWAVE"
    )

    assert len(captured) == 1
    req = captured[0]
    assert req["url"] == "https://sms.example/api/services/sendbulk/"
    assert req["json"]["count"] == 2
    msg = req["json"]["smslist"][0]
    assert msg["apikey"] == "key123"
    assert msg["partnerID"] == "77"
    assert msg["shortcode"] == "BITWAVE"
    assert msg["message"] == "Hello"
    assert msg["pass_type"] == "plain"
    assert [m["mobile"] for m in req["json"]["smslist"]] == ["254712345678", "254700000000"]

    ok, bad = results
    assert ok.recipient == "0712345678" and ok.success is True
    assert ok.provider_message_id is not None
    assert bad.recipient == "+254700000000" and bad.success is False
    assert bad.status == "invalid_recipient"
    assert bad.error == "Invalid mobile number"


@pytest.mark.asyncio
async def test_matches_by_phone_when_client_id_missing(monkeypatch):
    captured = []

    def responder(body):
        rows = []
        for m in reversed(body["smslist"]):
            row = _ok_row(m)
            row.pop("clientsmsid")
            rows.append(row)
        return 200, {"responses": rows}

    monkeypatch.setattr(httpx, "AsyncClient", _client(responder, captured))
    results = await _provider().send_bulk(["0711111111", "0722222222"], "Hi", "S")
    assert [r.recipient for r in results] == ["0711111111", "0722222222"]
    assert all(r.success for r in results)


@pytest.mark.asyncio
async def test_chunks_requests_at_twenty(monkeypatch):
    captured = []

    def responder(body):
        return 200, {"responses": [_ok_row(m) for m in body["smslist"]]}

    monkeypatch.setattr(httpx, "AsyncClient", _client(responder, captured))
    recipients = [f"07{i:08d}" for i in range(45)]
    results = await _provider().send_bulk(recipients, "Hi", "S")
    assert [r["json"]["count"] for r in captured] == [20, 20, 5]
    assert [r.recipient for r in results] == recipients
    assert all(r.success for r in results)
    client_ids = [m["clientsmsid"] for r in captured for m in r["json"]["smslist"]]
    assert len(set(client_ids)) == 45


@pytest.mark.asyncio
async def test_request_level_error_fails_whole_chunk(monkeypatch):
    captured = []
    monkeypatch.setattr(httpx, "AsyncClient", _client(
        lambda body: (200, {"response-code": 1006,
                            "response-description": "Invalid credentials"}),
        captured,
    ))
    results = await _provider().send_bulk(["0711111111", "0722222222"], "Hi", "S")
    assert [r.success for r in results] == [False, False]
    assert {r.status for r in results} == {"invalid_credentials"}
    assert results[0].error == "Invalid credentials"


@pytest.mark.asyncio
async def test_low_credits_reported_per_recipient(monkeypatch):
    captured = []

    def responder(body):
        return 200, {"responses": [
            {"respose-code": 1004, "response-description": "Low bulk credits",
             "mobile": m["mobile"], "clientsmsid": m["clientsmsid"]}
            for m in body["smslist"]
        ]}

    monkeypatch.setattr(httpx, "AsyncClient", _client(responder, captured))
    results = await _provider().send_bulk(["0711111111"], "Hi", "S")
    assert results[0].success is False
    assert results[0].status == "low_credits"


@pytest.mark.asyncio
async def test_missing_row_is_failed_not_dropped(monkeypatch):
    captured = []
    monkeypatch.setattr(httpx, "AsyncClient", _client(
        lambda body: (200, {"responses": [_ok_row(body["smslist"][0])]}), captured,
    ))
    results = await _provider().send_bulk(["0711111111", "0722222222"], "Hi", "S")
    assert len(results) == 2
    assert results[0].success is True
    assert results[1].success is False and results[1].status == "no_result"


@pytest.mark.asyncio
async def test_http_error_fails_chunk(monkeypatch):
    captured = []
    monkeypatch.setattr(httpx, "AsyncClient", _client(
        lambda body: (500, ValueError("not json")), captured,
    ))
    results = await _provider().send_bulk(["0711111111"], "Hi", "S")
    assert results[0].success is False
    assert results[0].status == "http_500"


@pytest.mark.asyncio
async def test_invalid_recipient_and_missing_config_make_no_request(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("no HTTP call expected")

    monkeypatch.setattr(httpx, "AsyncClient", _boom)
    results = await _provider().send_bulk(["abc"], "Hi", "S")
    assert results[0].status == "invalid_recipient"

    no_key = TextSmsProvider(api_key="", partner_id="1")
    results = await no_key.send_bulk(["0711111111"], "Hi", "S")
    assert results[0].status == "missing_api_key"

    results = await _provider().send_bulk(["0711111111"], "Hi", "")
    assert results[0].status == "missing_sender_id"

    assert await _provider().send_bulk([], "Hi", "S") == []
