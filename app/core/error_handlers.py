"""Catch-all 500 handler whose response the browser can actually read.

Why this exists (25 Oct 2026): a reseller pressing Generate Vouchers saw only
"NetworkError when attempting to fetch resource". The backend had raised an
unhandled exception, and Starlette turns those into a 500 in
ServerErrorMiddleware -- the OUTERMOST layer, outside CORSMiddleware. So the
500 left without any Access-Control-Allow-Origin header, the browser refused
to hand it to the admin app, and the reseller got a generic network error
instead of "something went wrong on our side".

A handler registered for ``Exception`` runs in that same outer layer, so it
does not get CORS headers for free either. This module runs the 500 response
through a CORSMiddleware built from the SAME options as the app's real one,
so the error carries exactly the headers a successful response would -- for
allowed origins only, using Starlette's own origin logic, never wider.

Scope is deliberately narrow:
  * Only exceptions nothing else handled reach here. HTTPException and
    RequestValidationError keep their own handlers and are untouched.
  * Success responses never pass through this code.
  * The traceback is still logged as before: ServerErrorMiddleware re-raises
    after sending our response, and uvicorn logs it ("Exception in ASGI
    application"). We add one line naming the request so it is easy to find.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.middleware.cors import CORSMiddleware
from starlette.types import Receive, Scope, Send

logger = logging.getLogger(__name__)

INTERNAL_ERROR_BODY = {"detail": "Internal server error"}


class _CORSAwareJSONResponse(JSONResponse):
    """A JSONResponse that adds CORS headers the way CORSMiddleware would."""

    def __init__(
        self, content: Any, status_code: int, cors_options: Mapping[str, Any]
    ) -> None:
        super().__init__(content=content, status_code=status_code)
        self._cors_options = dict(cors_options)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request_headers = Headers(scope=scope)
        if "origin" not in request_headers:
            # Not a cross-origin browser request: CORSMiddleware adds nothing here either.
            await super().__call__(scope, receive, send)
            return
        # Wrap this very response in a CORSMiddleware with the app's options and
        # use the middleware's own simple-request path: it adds its configured
        # headers and mirrors the Origin only when that origin is allowed. (Not
        # its __call__: that would answer a preflight-shaped request with a
        # preflight 200 instead of this 500.)
        cors = CORSMiddleware(super().__call__, **self._cors_options)
        await cors.simple_response(scope, receive, send, request_headers=request_headers)


def install_unhandled_error_handler(app: FastAPI, cors_options: Mapping[str, Any]) -> None:
    """Register the catch-all 500 handler on ``app``.

    ``cors_options`` must be the exact kwargs passed to the app's
    ``app.add_middleware(CORSMiddleware, ...)`` so the two can never drift.
    """

    options = dict(cors_options)
    CORSMiddleware(None, **options)  # fail at startup, not mid-error, on a bad option

    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.error(
            "Unhandled %s on %s %s -> 500 (traceback follows from the server)",
            type(exc).__name__,
            request.method,
            request.url.path,
        )
        return _CORSAwareJSONResponse(INTERNAL_ERROR_BODY, status_code=500, cors_options=options)

    app.add_exception_handler(Exception, unhandled_exception_handler)
