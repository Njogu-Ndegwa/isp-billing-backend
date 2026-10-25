"""Unhandled errors must reach the browser as a readable 500, not "NetworkError".

25 Oct 2026: Generate Vouchers raised an unhandled exception; the 500 left
without CORS headers (ServerErrorMiddleware sits outside CORSMiddleware), so
the browser hid it and the reseller saw "NetworkError when attempting to fetch
resource". See app/core/error_handlers.py.
"""

import logging

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.error_handlers import install_unhandled_error_handler

ALLOWED = "https://isp.example.com"
DISALLOWED = "https://evil.example.net"

RESTRICTED_CORS = dict(
    allow_origins=[ALLOWED],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class _Body(BaseModel):
    quantity: int


def _build_app(cors_options) -> FastAPI:
    """Same layering as main.py: CORSMiddleware + the catch-all handler."""
    app = FastAPI()
    app.add_middleware(CORSMiddleware, **cors_options)
    install_unhandled_error_handler(app, cors_options)

    @app.get("/boom")
    async def boom():
        raise RuntimeError("voucher generation exploded")

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    @app.get("/http-error")
    async def http_error():
        raise HTTPException(status_code=409, detail="Router busy")

    @app.post("/validate")
    async def validate(body: _Body):
        return body

    return app


def _client(cors_options) -> TestClient:
    # ServerErrorMiddleware re-raises after sending the response (that is how
    # the server logs the traceback); don't let the test client re-raise it.
    return TestClient(_build_app(cors_options), raise_server_exceptions=False)


def test_unhandled_error_is_500_json_with_cors_for_allowed_origin():
    resp = _client(RESTRICTED_CORS).get("/boom", headers={"Origin": ALLOWED})

    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    assert resp.headers["access-control-allow-origin"] == ALLOWED
    assert resp.headers["access-control-allow-credentials"] == "true"
    assert "origin" in resp.headers.get("vary", "").lower()
    # The exception text never leaks to the client.
    assert "exploded" not in resp.text


def test_unhandled_error_has_no_allow_origin_for_disallowed_origin():
    resp = _client(RESTRICTED_CORS).get("/boom", headers={"Origin": DISALLOWED})

    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    assert "access-control-allow-origin" not in resp.headers


def test_unhandled_error_without_origin_has_no_cors_headers():
    resp = _client(RESTRICTED_CORS).get("/boom")

    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    assert "access-control-allow-origin" not in resp.headers


@pytest.mark.parametrize("origin", [ALLOWED, DISALLOWED, None])
def test_error_headers_match_what_cors_middleware_gives_a_success(origin):
    """The 500's CORS headers are exactly the ones a 200 gets: never wider."""
    client = _client(RESTRICTED_CORS)
    headers = {"Origin": origin} if origin else {}

    def cors_headers(resp):
        return {k: v for k, v in resp.headers.items() if k.startswith("access-control-")}

    assert cors_headers(client.get("/boom", headers=headers)) == cors_headers(
        client.get("/ok", headers=headers)
    )


def test_http_exception_and_validation_unchanged():
    client = _client(RESTRICTED_CORS)

    resp = client.get("/http-error", headers={"Origin": ALLOWED})
    assert resp.status_code == 409
    assert resp.json() == {"detail": "Router busy"}
    assert resp.headers["access-control-allow-origin"] == ALLOWED

    resp = client.post("/validate", json={"quantity": "lots"}, headers={"Origin": ALLOWED})
    assert resp.status_code == 422
    assert resp.json()["detail"][0]["loc"] == ["body", "quantity"]


def test_traceback_still_reaches_the_server(caplog):
    """The exception still propagates past the handler, so uvicorn logs the traceback."""
    client = TestClient(_build_app(RESTRICTED_CORS), raise_server_exceptions=True)
    with caplog.at_level(logging.ERROR, logger="app.core.error_handlers"):
        with pytest.raises(RuntimeError, match="voucher generation exploded"):
            client.get("/boom", headers={"Origin": ALLOWED})
    assert any("GET /boom" in r.getMessage() for r in caplog.records)


def test_production_app_uses_its_own_cors_options_for_errors():
    """main.app: the handler is registered and wired to the live CORS config."""
    import main

    assert Exception in main.app.exception_handlers

    cors = [m for m in main.app.user_middleware if m.cls is CORSMiddleware]
    assert len(cors) == 1
    assert dict(cors[0].kwargs) == main.CORS_OPTIONS

    # The live config ("*" + credentials) applied to an erroring route.
    resp = _client(main.CORS_OPTIONS).get("/boom", headers={"Origin": ALLOWED})
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    ok = _client(main.CORS_OPTIONS).get("/ok", headers={"Origin": ALLOWED})
    assert resp.headers["access-control-allow-origin"] == ok.headers["access-control-allow-origin"]
