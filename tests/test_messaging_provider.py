import httpx
import pytest

from app.services.messaging import get_provider
from app.services.messaging.africas_talking import AfricasTalkingProvider
from app.services.messaging.base import SendResult
from app.services.messaging.talksasa import TalksasaProvider


def test_factory_returns_africas_talking(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "SMS_PROVIDER", "africastalking")
    provider = get_provider()
    assert isinstance(provider, AfricasTalkingProvider)


def test_factory_returns_talksasa(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "SMS_PROVIDER", "talksasa")
    monkeypatch.setattr(settings, "TALKSASA_API_TOKEN", "token")
    monkeypatch.setattr(settings, "TALKSASA_BASE_URL", "https://api.example/v3")
    provider = get_provider()
    assert isinstance(provider, TalksasaProvider)


def test_default_sender_id_is_provider_aware(monkeypatch):
    from app.config import settings
    from app.services.messaging import default_sender_id, resolve_sender_id
    monkeypatch.setattr(settings, "SMS_SENDER_ID", "")
    monkeypatch.setattr(settings, "SMS_PROVIDER", "talksasa")
    monkeypatch.setattr(settings, "TALKSASA_SENDER_ID", "TALKSASA")
    monkeypatch.setattr(settings, "AT_SENDER_ID", "ATBRAND")
    assert default_sender_id() == "TALKSASA"
    assert resolve_sender_id("DBBRAND") == "DBBRAND"

    monkeypatch.setattr(settings, "SMS_SENDER_ID", "GLOBAL")
    assert default_sender_id() == "GLOBAL"
    assert resolve_sender_id("DBBRAND") == "GLOBAL"


def test_factory_unknown_provider_raises(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "SMS_PROVIDER", "nope")
    with pytest.raises(ValueError):
        get_provider()


@pytest.mark.asyncio
async def test_africas_talking_parses_per_recipient(monkeypatch):
    captured = {}

    class _FakeResponse:
        status_code = 201
        def raise_for_status(self): pass
        def json(self):
            return {"SMSMessageData": {"Recipients": [
                {"number": "+254712345678", "status": "Success",
                 "messageId": "ATXid_1", "cost": "KES 0.8000"},
                {"number": "+254700000000", "status": "Failed",
                 "messageId": "None", "cost": "0"},
            ]}}

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, data=None, headers=None):
            captured["url"] = url
            captured["data"] = data
            captured["headers"] = headers
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = AfricasTalkingProvider(username="sandbox", api_key="key",
                                      base_url="https://api.example")
    results = await provider.send_bulk(
        ["+254712345678", "+254700000000"], "Hi", "BRAND"
    )
    assert captured["data"]["username"] == "sandbox"
    assert captured["data"]["to"] == "+254712345678,+254700000000"
    assert captured["data"]["from"] == "BRAND"
    assert captured["headers"]["apiKey"] == "key"
    by_num = {r.recipient: r for r in results}
    assert by_num["+254712345678"].success is True
    assert by_num["+254712345678"].provider_message_id == "ATXid_1"
    assert by_num["+254700000000"].success is False


@pytest.mark.asyncio
async def test_empty_recipients_makes_no_request(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("must not open an HTTP client for empty recipients")
    monkeypatch.setattr(httpx, "AsyncClient", _boom)
    provider = AfricasTalkingProvider(username="u", api_key="k",
                                      base_url="https://api.example")
    assert await provider.send_bulk([], "Hi", "BRAND") == []


@pytest.mark.asyncio
async def test_missing_recipients_payload_falls_back_to_failed(monkeypatch):
    class _FakeResponse:
        status_code = 201
        def raise_for_status(self): pass
        def json(self):
            return {"SMSMessageData": {}}   # no Recipients key

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, data=None, headers=None):
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = AfricasTalkingProvider(username="u", api_key="k",
                                      base_url="https://api.example")
    results = await provider.send_bulk(["+254712345678"], "Hi", "BRAND")
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].status == "no_response"


@pytest.mark.asyncio
async def test_talksasa_posts_json_with_bearer_token(monkeypatch):
    captured = {}

    class _FakeResponse:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {
                "status": "success",
                "data": [
                    {
                        "uid": "sms_1",
                        "recipient": "+254712345678",
                        "status": "sent",
                        "cost": 1,
                    },
                    {
                        "uid": "sms_2",
                        "recipient": "254700000000",
                        "status": "failed",
                        "message": "Invalid recipient",
                    },
                ],
            }

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = TalksasaProvider(api_token="token|with-pipe",
                                base_url="https://api.example/v3/")

    results = await provider.send_bulk(
        ["254712345678", "254700000000"], "Hi", "BRAND"
    )

    assert captured["url"] == "https://api.example/v3/sms/send"
    assert captured["json"] == {
        "recipient": "254712345678,254700000000",
        "sender_id": "BRAND",
        "type": "plain",
        "message": "Hi",
    }
    assert captured["headers"]["Authorization"] == "Bearer token|with-pipe"
    assert captured["headers"]["Accept"] == "application/json"
    by_num = {r.recipient: r for r in results}
    assert by_num["254712345678"].success is True
    assert by_num["254712345678"].provider_message_id == "sms_1"
    assert by_num["254700000000"].success is False
    assert by_num["254700000000"].error == "Invalid recipient"


@pytest.mark.asyncio
async def test_talksasa_normalizes_common_kenyan_phone_formats(monkeypatch):
    captured = {}

    class _FakeResponse:
        status_code = 200
        def json(self):
            return {
                "status": "success",
                "data": {"queue_uid": "queue-1", "status": "accepted"},
            }

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            captured["json"] = json
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = TalksasaProvider(api_token="token", base_url="https://api.example/v3")
    results = await provider.send_bulk(["0712345678", "+254700000000"], "Hi", "BRAND")

    assert captured["json"]["recipient"] == "254712345678,254700000000"
    assert [r.recipient for r in results] == ["0712345678", "+254700000000"]
    assert all(r.success for r in results)


@pytest.mark.asyncio
async def test_talksasa_bulk_4xx_falls_back_to_single_recipient_sends(monkeypatch):
    calls = []

    class _FakeResponse:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
            self.text = str(payload)
        def json(self):
            return self._payload

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            calls.append(json)
            if len(calls) == 1:
                return _FakeResponse(404, {
                    "status": "error",
                    "message": "000 is a invalid phone number",
                })
            if json["recipient"] == "999":
                return _FakeResponse(404, {
                    "status": "error",
                    "message": "999 is a invalid phone number",
                })
            return _FakeResponse(200, {
                "status": "success",
                "data": {"queue_uid": "queue-1", "status": "accepted"},
            })

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = TalksasaProvider(api_token="token", base_url="https://api.example/v3")
    results = await provider.send_bulk(["999", "0712345678"], "Hi", "BRAND")

    assert [call["recipient"] for call in calls] == [
        "999,254712345678",
        "999",
        "254712345678",
    ]
    by_recipient = {r.recipient: r for r in results}
    assert by_recipient["999"].success is False
    assert by_recipient["999"].error == "999 is a invalid phone number"
    assert by_recipient["0712345678"].success is True


@pytest.mark.asyncio
async def test_talksasa_error_payload_marks_all_recipients_failed(monkeypatch):
    class _FakeResponse:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"status": "error", "message": "Insufficient balance"}

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = TalksasaProvider(api_token="token", base_url="https://api.example/v3")
    results = await provider.send_bulk(["254712345678"], "Hi", "BRAND")
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error == "Insufficient balance"


@pytest.mark.asyncio
async def test_talksasa_accepted_queue_marks_all_recipients_sent(monkeypatch):
    class _FakeResponse:
        status_code = 202
        def json(self):
            return {
                "status": "success",
                "message": "Your SMS is being processed and will be delivered",
                "data": {
                    "queue_uid": "queue-1",
                    "status": "accepted",
                    "recipients_count": 2,
                },
            }

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = TalksasaProvider(api_token="token", base_url="https://api.example/v3")
    results = await provider.send_bulk(["254700000001", "254700000002"], "Hi", "BRAND")
    assert [r.success for r in results] == [True, True]
    assert {r.provider_message_id for r in results} == {"queue-1"}
    assert {r.status for r in results} == {"accepted"}


@pytest.mark.asyncio
async def test_talksasa_http_error_body_marks_all_recipients_failed(monkeypatch):
    class _FakeResponse:
        status_code = 404
        text = '{"status":"error","message":"Sender ID information not found"}'
        def json(self):
            return {"status": "error", "message": "Sender ID information not found"}

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = TalksasaProvider(api_token="token", base_url="https://api.example/v3")
    results = await provider.send_bulk(["254700000001"], "Hi", "BRAND")
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].status == "http_404"
    assert results[0].error == "Sender ID information not found"


@pytest.mark.asyncio
async def test_talksasa_missing_credentials_makes_no_request(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("must not open an HTTP client without credentials")

    monkeypatch.setattr(httpx, "AsyncClient", _boom)
    provider = TalksasaProvider(api_token="", base_url="https://api.example/v3")
    results = await provider.send_bulk(["254712345678"], "Hi", "BRAND")
    assert results[0].success is False
    assert results[0].error == "missing_api_token"
