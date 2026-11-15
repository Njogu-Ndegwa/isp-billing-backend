"""Tunnel HTTP to an access point THROUGH the customer's MikroTik.

Our server has no route to the hotspot LAN where the AP lives, but the router
does. RouterOS ``/tool fetch`` can make an HTTP request from the router and
hand us back the response body (``output=user`` + ``as-value`` returns a row
with ``data``/``status``/``duration``). This module turns an :class:`ApRequest`
into that fetch command, sends it over our existing MikroTik API session, and
returns the body -- so an adapter can drive the AP without us ever touching the
hotspot LAN directly.

Login requests capture response headers. RouterOS 7.19.6 includes Set-Cookie
in the redirect trap when output=user-with-headers is used; successful HTTP
responses carry the headers in data. Cookies stay in this single-device client
and never enter public results or logs. Redirects are not followed, so neither
credentials nor cookies can be forwarded to a different host.

SAFETY: this only ever issues ``/tool fetch`` against the AP's address. It never
changes the MikroTik's own configuration.
"""

from __future__ import annotations

import json
import logging
import re
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
    location: Optional[str] = None


def _redirect_error(message: str) -> bool:
    return _status_from_error(message) in (301, 302, 303, 307, 308)


def _status_from_error(message: str) -> Optional[int]:
    text = re.sub(r'(?i)(Set-Cookie|Location):\s*"[^"\r\n]*"', "", message or "")
    for code in ("301", "302", "303", "307", "308", "400", "401", "403", "404", "500", "502", "503"):
        if re.search(rf"\b{code}\b", text):
            return int(code)
    return None


class RouterFetchHttpClient:
    """HTTP client whose requests ride RouterOS ``/tool fetch``.

    ``api`` is a connected MikroTik API object (``send_command``); ``base_host``
    is the AP's IP. ``cookie`` is set after a successful login and attached to
    every later request.
    """

    def __init__(self, api, base_host: str, *, scheme: str = "http",
                 port: Optional[int] = None,
                 header_fields: Optional[List[str]] = None):
        self.api = api
        self.base_host = base_host
        self.scheme = scheme
        # Optional non-default web port. A hotspot-LAN AP answers on 80 (port
        # left None -> no ":port" in the URL, unchanged behaviour); a PPPoE CPE
        # answers on its remote-management port (often 8888), passed here.
        try:
            self.port: Optional[int] = int(port) if port else None
        except (TypeError, ValueError):
            self.port = None
        self.cookie: Optional[str] = None
        self._extra_headers = header_fields or []

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        host = self.base_host
        if self.port and self.port != 80:
            host = f"{self.base_host}:{self.port}"
        return f"{self.scheme}://{host}{path}"

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> str:
        fields: List[str] = list(self._extra_headers)
        if self.cookie:
            fields.append(f"Cookie: {self.cookie}")
        if extra:
            for key, value in extra.items():
                fields.append(f"{key}: {value}")
        return ",".join(fields)

    def _accept_cookies(self, headers: List[str]) -> None:
        cookies = {}
        for item in (self.cookie or "").split("; "):
            if "=" in item:
                name, value = item.split("=", 1)
                cookies[name] = value
        for header in headers:
            pair = header.split(";", 1)[0].strip()
            name, sep, value = pair.partition("=")
            # Reject header injection and RouterOS header-list delimiters.
            if (sep and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                    and len(value) <= 4096
                    and not re.search(r'[\x00-\x20\x7f,;"\\]', value)):
                if value:
                    cookies[name] = value
                else:
                    cookies.pop(name, None)
        self.cookie = "; ".join(f"{k}={v}" for k, v in cookies.items()) or None

    def has_cookie(self, name: str) -> bool:
        return any(p.partition("=")[0] == name for p in (self.cookie or "").split("; "))

    def request(self, req: ApRequest, *, capture_headers: bool = False) -> FetchResponse:
        params: Dict[str, str] = {
            "url": self._url(req.path),
            "mode": self.scheme,
            "http-method": req.method.lower(),
            "output": "user-with-headers" if capture_headers else "user",
            "as-value": "",
            "check-certificate": "no",
            "http-max-redirect-count": "0",
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
            self._accept_cookies(re.findall(r'Set-Cookie:\s*"([^"\r\n]*)"', message, re.I))
            location_match = re.search(r'Location:\s*"([^"\r\n]*)"', message, re.I)
            location = location_match.group(1) if location_match else None
            if _redirect_error(message):
                # A 3xx (e.g. the login redirect) is a reachable server, not a
                # failure. ROS gives us no body for it.
                return FetchResponse(ok=True, status=_status_from_error(message) or 302,
                                     body="", redirected=True, location=location)
            # RouterOS traps can contain session cookies and redirect queries.
            # Keep the cause, never the raw HTTP header values.
            message = re.sub(r'(?i)(Set-Cookie|Location):\s*"[^"\r\n]*"',
                             r'\1: [redacted]', message)
            return FetchResponse(ok=False, status=_status_from_error(message),
                                 body="", error=message)

        # RouterOS may stream progress rows (connecting, downloading) before the
        # one that carries the result, so the last row is the outcome.
        rows = result.get("data") or []
        row = rows[-1] if rows else {}
        body = row.get("data", "") or ""
        location = None
        if capture_headers and body.startswith("HTTP/"):
            parts = re.split(r"\r?\n\r?\n", body, maxsplit=1)
            if len(parts) == 2:
                head, body = parts
                self._accept_cookies(re.findall(r"(?im)^Set-Cookie:\s*([^\r\n]*)", head))
                match = re.search(r"(?im)^Location:\s*([^\r\n]*)", head)
                location = match.group(1) if match else None
        status_text = str(row.get("status", "")).lower()
        ok = status_text in ("", "finished", "finished.") or "finish" in status_text
        return FetchResponse(ok=ok, status=200 if ok else None, body=body,
                             error=None if ok else status_text or "fetch did not finish",
                             location=location)

    def login(self, attempt_post_data: Dict[str, str], login_path: str,
              cookie: Optional[str]) -> FetchResponse:
        # Send the cookie the firmware expects (if any) ON the login too, then
        # keep it for later requests.
        self.cookie = cookie  # discard any earlier failed attempt's session
        return self.request(ApRequest("post", login_path, attempt_post_data), capture_headers=True)


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
