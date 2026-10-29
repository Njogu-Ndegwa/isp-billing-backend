"""Tunnel HTTP to an access point THROUGH the customer's MikroTik.

Our server has no route to the hotspot LAN where the AP lives, but the router
does. RouterOS ``/tool fetch`` can make an HTTP request from the router and
hand us back the response body (``output=user`` + ``as-value`` returns a row
with ``data``/``status``/``duration``). This module turns an :class:`ApRequest`
into that fetch command, sends it over our existing MikroTik API session, and
returns the body -- so an adapter can drive the AP without us ever touching the
hotspot LAN directly.

Cookies: ``/tool fetch`` does NOT expose the AP's ``Set-Cookie`` response
header, so we cannot read a server-issued session id. Two things make a session
work anyway, and both are used:

* the AP sees every request coming from the same source (the MikroTik's LAN
  address), and the Tenda firmware ties a session to that source; and
* on several Tenda builds the session cookie is derived from the credentials
  (CVE-2026-22082), so the adapter can hand us a deterministic ``Cookie`` to
  send on every request.

This is the part most in need of bench confirmation (see the PR checklist). The
transport is intentionally thin and fully faked in tests.

SAFETY: this only ever issues ``/tool fetch`` against the AP's address. It never
changes the MikroTik's own configuration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from app.services.ap_adapters import ApRequest

logger = logging.getLogger(__name__)

# ROS fetch returns a trap on non-2xx; a Tenda login answers 302, which we must
# not treat as a hard failure.
FETCH_TIMEOUT_HINT = "10s"


@dataclass
class FetchResponse:
    ok: bool
    status: Optional[int]
    body: str
    error: Optional[str] = None
    redirected: bool = False


def _redirect_error(message: str) -> bool:
    text = (message or "").lower()
    return "302" in text or "301" in text or "redirect" in text or "moved" in text


def _status_from_error(message: str) -> Optional[int]:
    text = (message or "")
    for code in ("301", "302", "303", "307", "400", "401", "403", "404", "500", "502", "503"):
        if code in text:
            return int(code)
    return None


class RouterFetchHttpClient:
    """HTTP client whose requests ride RouterOS ``/tool fetch``.

    ``api`` is a connected MikroTik API object (``send_command``); ``base_host``
    is the AP's IP. ``cookie`` is set after a successful login and attached to
    every later request.
    """

    def __init__(self, api, base_host: str, *, scheme: str = "http",
                 header_fields: Optional[List[str]] = None):
        self.api = api
        self.base_host = base_host
        self.scheme = scheme
        self.cookie: Optional[str] = None
        self._extra_headers = header_fields or []

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.scheme}://{self.base_host}{path}"

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> str:
        fields: List[str] = list(self._extra_headers)
        if self.cookie:
            fields.append(f"Cookie: {self.cookie}")
        if extra:
            for key, value in extra.items():
                fields.append(f"{key}: {value}")
        return ",".join(fields)

    def request(self, req: ApRequest) -> FetchResponse:
        params: Dict[str, str] = {
            "url": self._url(req.path),
            "mode": self.scheme,
            "http-method": req.method.lower(),
            "output": "user",
            "as-value": "",
            "check-certificate": "no",
        }
        header_extra: Dict[str, str] = {}
        if req.method.lower() == "post":
            params["http-data"] = urlencode(req.data or {})
            header_extra["Content-Type"] = "application/x-www-form-urlencoded"
        headers = self._headers(header_extra)
        if headers:
            params["http-header-field"] = headers

        result = self.api.send_command("/tool/fetch", params)
        if result.get("error"):
            message = str(result.get("error"))
            if _redirect_error(message):
                # A 3xx (e.g. the login redirect) is a reachable server, not a
                # failure. ROS gives us no body for it.
                return FetchResponse(ok=True, status=_status_from_error(message) or 302,
                                     body="", redirected=True)
            return FetchResponse(ok=False, status=_status_from_error(message),
                                 body="", error=message)

        rows = result.get("data") or []
        row = rows[0] if rows else {}
        body = row.get("data", "") or ""
        status_text = str(row.get("status", "")).lower()
        ok = status_text in ("", "finished", "finished.") or "finish" in status_text
        return FetchResponse(ok=ok, status=200 if ok else None, body=body,
                             error=None if ok else status_text or "fetch did not finish")

    def login(self, attempt_post_data: Dict[str, str], login_path: str,
              cookie: Optional[str]) -> FetchResponse:
        # Send the cookie the firmware expects (if any) ON the login too, then
        # keep it for later requests.
        if cookie:
            self.cookie = cookie
        return self.request(ApRequest("post", login_path, attempt_post_data))


def parse_json_body(body: str) -> Any:
    """Best-effort JSON parse of a Tenda goform reply. Returns None on garbage."""
    if not body:
        return None
    text = body.strip()
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        # Some firmware prefixes/suffixes the JSON; grab the first {...}.
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start:end + 1])
            except (ValueError, TypeError):
                return None
        return None


def reply_ok(body: str) -> bool:
    """A Tenda write succeeded when its JSON reply carries errCode 0."""
    data = parse_json_body(body)
    if isinstance(data, dict):
        for key in ("errCode", "errcode", "error", "ret", "result"):
            if key in data:
                try:
                    return int(data[key]) == 0
                except (TypeError, ValueError):
                    return str(data[key]).lower() in ("0", "ok", "success", "true")
    # Reboot and some setters answer with an empty 200 body.
    return data is None and body.strip() == ""
