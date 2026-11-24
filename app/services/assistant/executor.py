"""Run one API request for the assistant, in-process, as the caller.

The request goes through the whole app -- every middleware (View-as guard,
staff guard and activity log, shadow-mode guard) and the route's own auth --
exactly as if the dashboard had sent it, with the caller's own bearer token.
Nothing here grants anything: what the person cannot do on the dashboard
fails here with the same 401/403.

No DB session is held here; the inner request opens and closes its own.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.config import settings
from app.services.assistant.caller import Caller

ASSISTANT_HEADER = "X-Bitwave-Assistant"


@dataclass
class ApiResult:
    status: int
    data: Any = None              # parsed JSON, or None
    text: Optional[str] = None    # non-JSON body (shortened)
    content_type: str = ""
    elapsed_ms: int = 0
    error: Optional[str] = None   # transport-level failure

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    def detail(self) -> str:
        """The backend's own error message, for the model and the screen."""
        if self.error:
            return self.error
        d = self.data
        if isinstance(d, dict):
            msg = d.get("detail") or d.get("message") or d.get("error")
            if isinstance(msg, list):  # FastAPI validation errors
                parts = []
                for item in msg[:6]:
                    if isinstance(item, dict):
                        loc = ".".join(str(x) for x in item.get("loc", [])[1:])
                        parts.append(f"{loc}: {item.get('msg')}" if loc else str(item.get("msg")))
                return "; ".join(parts) or f"HTTP {self.status}"
            if isinstance(msg, dict):
                return json.dumps(msg, default=str)[:500]
            if msg:
                return str(msg)[:500]
        if self.text:
            return self.text[:300]
        return f"HTTP {self.status}"


async def call_api(app, caller: Caller, method: str, path: str,
                   query: Optional[dict] = None, body: Any = None) -> ApiResult:
    headers = {
        "Authorization": caller.authorization,
        "User-Agent": f"{caller.user_agent} BitwaveAssistant/1".strip()[:250],
        ASSISTANT_HEADER: "1",
        "Accept": "application/json",
    }
    if caller.ip:
        headers["X-Forwarded-For"] = caller.ip
        headers["CF-Connecting-IP"] = caller.ip
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://assistant.internal",
            timeout=settings.ASSISTANT_CALL_TIMEOUT_SECONDS,
        ) as client:
            kwargs: dict = {"headers": headers}
            if query:
                kwargs["params"] = {k: v for k, v in query.items() if v is not None}
            if body is not None and method.upper() != "GET":
                kwargs["json"] = body
            response = await client.request(method.upper(), path, **kwargs)
    except httpx.TimeoutException:
        return ApiResult(status=504, error="The request took too long and was stopped.",
                         elapsed_ms=int((time.monotonic() - started) * 1000))
    except Exception as exc:  # the app itself failed to answer
        return ApiResult(status=500, error=f"The request failed: {type(exc).__name__}",
                         elapsed_ms=int((time.monotonic() - started) * 1000))

    elapsed = int((time.monotonic() - started) * 1000)
    ctype = response.headers.get("content-type", "")
    if "json" in ctype:
        try:
            return ApiResult(status=response.status_code, data=response.json(),
                             content_type=ctype, elapsed_ms=elapsed)
        except ValueError:
            pass
    if ctype.startswith("text/") and "csv" not in ctype:
        return ApiResult(status=response.status_code, text=response.text[:4000],
                         content_type=ctype, elapsed_ms=elapsed)
    size = len(response.content)
    return ApiResult(
        status=response.status_code,
        data={"_file": True, "content_type": ctype or "unknown", "bytes": size,
              "_note": "This returns a file, which the chat cannot hand over yet. Read the same "
                       "figures with a list or summary action and draw them instead."},
        content_type=ctype, elapsed_ms=elapsed,
    )
