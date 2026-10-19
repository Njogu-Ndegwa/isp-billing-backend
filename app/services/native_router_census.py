"""Decode the native check-in census into the existing data-only protocol."""
from __future__ import annotations

import csv
import io
import json
import re

_IDENTITY = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELDS = {"users": "name", "checkin_users": "name", "bindings": "mac-address",
           "checkin_bindings": "mac-address", "queues": "name", "others": "mac-address"}


def _column(value: object, column: str, limit: int) -> list[str]:
    if not isinstance(value, dict) or set(value) != {"count", "data"}:
        raise ValueError("invalid native census column")
    count, data = value["count"], value["data"]
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= limit or not isinstance(data, str):
        raise ValueError("invalid native census count")
    if count == 0 and data == "":
        return []
    # Native DSV has no terminal line ending. Preserve a final empty MAC cell.
    parsed = list(csv.reader(io.StringIO(data + "\n"), strict=True))
    if not parsed or parsed[0] != [column] or len(parsed) != count + 1:
        raise ValueError("incomplete native census")
    result = []
    for row in parsed[1:]:
        if not row:
            row = [""]
        if len(row) != 1 or any(c in row[0] for c in "\r\n&=,"):
            raise ValueError("invalid native census cell")
        result.append(row[0])
    return result


def native_census_as_legacy(raw: bytes, *, max_body: int, max_macs: int, max_others: int) -> bytes:
    if len(raw) > max_body:
        raise ValueError("body too large")
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid native census JSON") from exc
    if not isinstance(body, dict) or type(body.get("v")) is not int or body["v"] != 3:
        raise ValueError("unsupported native census")
    identity, census = body.get("id"), body.get("census")
    if not isinstance(identity, str) or not _IDENTITY.fullmatch(identity):
        raise ValueError("missing or invalid identity")
    if not isinstance(census, dict) or set(census) != set(_FIELDS):
        raise ValueError("incomplete native census")
    data = {name: _column(census[name], column, max_macs) for name, column in _FIELDS.items()}
    users = [x for x in data["users"] if len(x) == 17]
    bindings = [x for x in data["bindings"] if len(x) == 17]
    queues = set(data["queues"])
    checkin_bindings = [x for x in data["checkin_bindings"] if len(x) == 17]
    queue_missing = [x for x in checkin_bindings if "plan_" + x.replace(":", "") not in queues]
    checkin = checkin_bindings + [x for x in data["checkin_users"] if len(x) == 17]
    others = [x for x in data["others"] if len(x) == 17][:max_others]
    # Only scalar identifiers pass into the established parser. It remains the
    # authority for MAC validation, subsets, deduplication and delivery version.
    text = (f"v=3&id={identity}&n={len(users) + len(bindings)}&macs={','.join(bindings + users)}"
            f"&q={','.join(queue_missing)}&c={','.join(checkin)}&o={','.join(others)}")
    return text.encode("ascii")
