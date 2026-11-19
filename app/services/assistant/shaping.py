"""Make API results safe and small enough for the chat.

Two views of every result:

* ``for_model`` -- what the language model reads (and what is stored in the
  conversation): secrets masked, long lists cut to a sample with the total,
  long strings cut, overall size bounded.
* ``for_screen`` -- what the chat draws as a table or card: secrets masked
  too (they never travel through the chat), but far larger limits.

Requests are checked the other way round: ``secret_fields`` finds secret
values the model tried to send, which the agent refuses -- passwords and keys
are typed on the dashboard page, not into a chat.
"""
from __future__ import annotations

import json
from typing import Any

MASK = "•••• (hidden — open the page to see it)"

_SECRET_PARTS = (
    "password", "passwd", "passkey", "secret", "api_key", "apikey", "private_key",
    "consumer_key", "credential_value", "auth_token", "access_token", "refresh_token",
    "session_token", "bearer", "jwt", "webfig_password",
)
_SECRET_EXACT = frozenset({"token", "pin", "otp", "shared_secret", "psk", "pre_shared_key"})


def is_secret_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    k = key.lower()
    if k in _SECRET_EXACT or k.endswith("_token") or k.endswith("_secret") or k.endswith("_password"):
        return True
    return any(part in k for part in _SECRET_PARTS)


def mask(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (MASK if is_secret_key(k) and v not in (None, "", [], {}) else mask(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v) for v in value]
    return value


def secret_fields(value: Any, prefix: str = "") -> list[str]:
    """Paths of non-empty secret-looking fields in a request body or query."""
    found: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            here = f"{prefix}.{k}" if prefix else str(k)
            if is_secret_key(k) and v not in (None, "", [], {}):
                found.append(here)
            else:
                found.extend(secret_fields(v, here))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found.extend(secret_fields(v, f"{prefix}[{i}]"))
    return found


def _cut(value: Any, *, max_list: int, max_str: int, depth: int = 0, max_depth: int = 7) -> Any:
    if depth > max_depth:
        return "…"
    if isinstance(value, dict):
        return {k: _cut(v, max_list=max_list, max_str=max_str, depth=depth + 1, max_depth=max_depth)
                for k, v in value.items()}
    if isinstance(value, list):
        items = [_cut(v, max_list=max_list, max_str=max_str, depth=depth + 1, max_depth=max_depth)
                 for v in value[:max_list]]
        if len(value) > max_list:
            items.append({"_note": f"{len(value) - max_list} more items not shown "
                                   f"({len(value)} in total). Narrow with filters or paging."})
        return items
    if isinstance(value, str) and len(value) > max_str:
        return value[:max_str] + f"… ({len(value)} characters)"
    return value


def _size(value: Any) -> int:
    return len(json.dumps(value, default=str, ensure_ascii=False))


def for_model(data: Any, limit_chars: int = 14000) -> Any:
    data = mask(data)
    for max_list, max_str in ((30, 400), (15, 240), (8, 160), (4, 120), (2, 80)):
        shaped = _cut(data, max_list=max_list, max_str=max_str)
        if _size(shaped) <= limit_chars:
            return shaped
    text = json.dumps(shaped, default=str, ensure_ascii=False)
    return {"_note": "Result too large; showing the start only.", "start": text[:limit_chars]}


def for_screen(data: Any, limit_chars: int = 180_000) -> Any:
    data = mask(data)
    for max_list, max_str in ((300, 2000), (120, 800), (50, 300)):
        shaped = _cut(data, max_list=max_list, max_str=max_str, max_depth=9)
        if _size(shaped) <= limit_chars:
            return shaped
    return {"_note": "Too large to show here. Open the page for the full list."}


def to_json_text(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))
