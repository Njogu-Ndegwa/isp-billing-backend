"""Register C2B: Safaricom failures must reach the reseller as readable text.

The API sits behind Cloudflare, which replaces origin 502/504 responses with
its own page (no CORS headers), so the dashboard showed only "Failed to fetch".
The registerurl helper now answers 422/503 with a plain-string detail and logs
Safaricom's status and body. No real Safaricom call is made: httpx is routed
through a MockTransport and the OAuth token is stubbed.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api import c2b_routes
from app.api.c2b_routes import _call_daraja_registerurl, router as c2b_router
from app.db.database import get_db
from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType
from app.services.auth import verify_token
from tests.factories import make_reseller

_REAL_ASYNC_CLIENT = httpx.AsyncClient
_KEY = "ck-should-never-be-logged"
_SECRET = "cs-should-never-be-logged"
_TOKEN = "token-should-never-be-logged"


def _route_safaricom(monkeypatch, handler):
    """Send the helper's httpx calls to ``handler`` instead of the network."""
    calls = []

    def _handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    def _client(**kwargs):
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(_handler), **kwargs)

    monkeypatch.setattr(c2b_routes.httpx, "AsyncClient", _client)
    return calls


@pytest.fixture(autouse=True)
def _stub_token_and_shadow(monkeypatch):
    monkeypatch.setattr(c2b_routes, "require_external_side_effects_enabled", lambda _op: None)
    monkeypatch.setattr(c2b_routes, "get_access_token", AsyncMock(return_value=_TOKEN))


async def _register(**overrides):
    kwargs = dict(
        shortcode="600999",
        consumer_key=_KEY,
        consumer_secret=_SECRET,
        confirmation_url="https://example.test/api/c2b/confirmation",
        validation_url="https://example.test/api/c2b/validation",
    )
    kwargs.update(overrides)
    return await _call_daraja_registerurl(**kwargs)


def _assert_no_secrets(caplog):
    for secret in (_KEY, _SECRET, _TOKEN):
        assert secret not in caplog.text


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def test_safaricom_500_with_error_message_becomes_readable_422(monkeypatch, caplog):
    body = {
        "requestId": "abc-123",
        "errorCode": "500.003.1001",
        "errorMessage": "Urls are already registered",
    }
    _route_safaricom(monkeypatch, lambda req: httpx.Response(500, json=body))

    with caplog.at_level(logging.WARNING, logger="app.api.c2b_routes"):
        with pytest.raises(HTTPException) as exc:
            await _register()

    assert exc.value.status_code == 422
    assert isinstance(exc.value.detail, str)
    assert exc.value.detail == (
        "Safaricom rejected C2B registration (500): Urls are already registered"
    )
    # Safaricom's status and body are logged for support, credentials are not.
    assert "600999" in caplog.text
    assert "safaricom_status=500" in caplog.text
    assert "Urls are already registered" in caplog.text
    _assert_no_secrets(caplog)


async def test_falls_back_to_response_description_then_raw_text(monkeypatch):
    _route_safaricom(
        monkeypatch,
        lambda req: httpx.Response(400, json={"ResponseDescription": "Invalid ShortCode"}),
    )
    with pytest.raises(HTTPException) as exc:
        await _register()
    assert exc.value.status_code == 422
    assert exc.value.detail == "Safaricom rejected C2B registration (400): Invalid ShortCode"

    _route_safaricom(monkeypatch, lambda req: httpx.Response(503, text="Service Unavailable"))
    with pytest.raises(HTTPException) as exc:
        await _register()
    assert exc.value.status_code == 422
    assert exc.value.detail == "Safaricom rejected C2B registration (503): Service Unavailable"


async def test_timeout_returns_readable_503(monkeypatch, caplog):
    def _timeout(request):
        raise httpx.ReadTimeout("timed out", request=request)

    _route_safaricom(monkeypatch, _timeout)
    with caplog.at_level(logging.WARNING, logger="app.api.c2b_routes"):
        with pytest.raises(HTTPException) as exc:
            await _register()

    assert exc.value.status_code == 503
    assert isinstance(exc.value.detail, str)
    assert "did not respond in time" in exc.value.detail
    _assert_no_secrets(caplog)


async def test_transport_error_returns_readable_503(monkeypatch):
    def _refused(request):
        raise httpx.ConnectError("connection refused", request=request)

    _route_safaricom(monkeypatch, _refused)
    with pytest.raises(HTTPException) as exc:
        await _register()

    assert exc.value.status_code == 503
    assert "Could not reach Safaricom" in exc.value.detail


async def test_token_failure_returns_readable_422(monkeypatch, caplog):
    monkeypatch.setattr(
        c2b_routes,
        "get_access_token",
        AsyncMock(side_effect=HTTPException(status_code=500, detail="Failed to get M-Pesa access token: boom")),
    )
    calls = _route_safaricom(monkeypatch, lambda req: httpx.Response(200, json={}))
    with caplog.at_level(logging.WARNING, logger="app.api.c2b_routes"):
        with pytest.raises(HTTPException) as exc:
            await _register()

    assert exc.value.status_code == 422
    assert "consumer key and secret" in exc.value.detail
    assert calls == []
    _assert_no_secrets(caplog)


async def test_success_returns_safaricom_body_unchanged(monkeypatch):
    body = {
        "OriginatorCoversationID": "7619-37765134-1",
        "ResponseCode": "0",
        "ResponseDescription": "success",
    }
    calls = _route_safaricom(monkeypatch, lambda req: httpx.Response(200, json=body))

    result = await _register()

    assert result == body
    assert len(calls) == 1
    assert calls[0].url.path == "/mpesa/c2b/v2/registerurl"
    assert calls[0].headers["Authorization"] == f"Bearer {_TOKEN}"


# ---------------------------------------------------------------------------
# Reseller route
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def client(session_factory):
    app = FastAPI()
    app.include_router(c2b_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[verify_token] = lambda: "test-token"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _seed_method(db):
    reseller = await make_reseller(db)
    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        label="Paybill",
        mpesa_shortcode="600999",
        mpesa_consumer_key_encrypted="enc-key",
        mpesa_consumer_secret_encrypted="enc-secret",
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    await db.refresh(reseller)
    return reseller, pm


async def test_reseller_route_returns_422_string_detail_and_does_not_mark_registered(
    db, client, monkeypatch
):
    reseller, pm = await _seed_method(db)
    pm_id = pm.id
    monkeypatch.setattr(c2b_routes, "get_current_user", AsyncMock(return_value=reseller))
    monkeypatch.setattr(c2b_routes, "decrypt_credential", lambda v: v.replace("enc-", ""))
    _route_safaricom(
        monkeypatch,
        lambda req: httpx.Response(500, json={"errorMessage": "Urls are already registered"}),
    )

    resp = await client.post(
        f"/api/payment-methods/{pm_id}/register-c2b",
        json={
            "confirmation_url": "https://example.test/api/c2b/confirmation",
            "validation_url": "https://example.test/api/c2b/validation",
        },
    )

    assert resp.status_code == 422
    assert resp.json() == {
        "detail": "Safaricom rejected C2B registration (500): Urls are already registered"
    }
    db.expire_all()
    row = (
        await db.execute(select(ResellerPaymentMethod).where(ResellerPaymentMethod.id == pm_id))
    ).scalar_one()
    assert row.c2b_registered_at is None


async def test_reseller_route_success_marks_registered(db, client, monkeypatch):
    reseller, pm = await _seed_method(db)
    pm_id = pm.id
    monkeypatch.setattr(c2b_routes, "get_current_user", AsyncMock(return_value=reseller))
    monkeypatch.setattr(c2b_routes, "decrypt_credential", lambda v: v.replace("enc-", ""))
    body = {"ResponseCode": "0", "ResponseDescription": "success"}
    _route_safaricom(monkeypatch, lambda req: httpx.Response(200, json=body))

    resp = await client.post(
        f"/api/payment-methods/{pm_id}/register-c2b",
        json={
            "confirmation_url": "https://example.test/api/c2b/confirmation",
            "validation_url": "https://example.test/api/c2b/validation",
        },
    )

    assert resp.status_code == 200
    assert resp.json() == body
    db.expire_all()
    row = (
        await db.execute(select(ResellerPaymentMethod).where(ResellerPaymentMethod.id == pm_id))
    ).scalar_one()
    assert row.c2b_registered_at is not None
