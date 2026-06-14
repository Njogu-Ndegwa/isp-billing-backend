import httpx
import pytest

from app.services.messaging import get_provider
from app.services.messaging.africas_talking import AfricasTalkingProvider
from app.services.messaging.base import SendResult


def test_factory_returns_africas_talking(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "SMS_PROVIDER", "africastalking")
    provider = get_provider()
    assert isinstance(provider, AfricasTalkingProvider)


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
