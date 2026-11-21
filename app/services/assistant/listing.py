"""Narrowing any list the assistant reads: filter, sort and cut by the rows' own fields.

The API's lists each have a few server filters (status, router, dates). People ask
for much more ("customers on Weekly 300", "payments over 1,000 this week", "routers
with more than 50 online"), and adding a server filter per question is the hardcoded
road. Instead the assistant reads the list and narrows it here, on any field the rows
carry (dotted for nested ones: ``plan.name``), before anything is drawn. So what
reaches the screen is exactly what was asked for.

A field no row has is an error, never ignored: an ignored filter is how "active
customers" once came back with the inactive ones too.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Optional

OPS = ("eq", "ne", "in", "not_in", "contains", "not_contains", "gt", "gte", "lt", "lte", "empty", "not_empty")
MAX_RULES = 6
# keys that name a page's list in an envelope ({"data": [...], "total": 9})
_LIST_KEYS = ("data", "items", "results", "rows", "customers", "transactions", "users", "routers", "plans", "vouchers")

WHERE_SCHEMA = {
    "type": "array",
    "maxItems": MAX_RULES,
    "description": (
        "Narrow the list this read returns to what was asked, on any field of its rows (dotted for nested: "
        "plan.name, router.name). All rules must hold. Use it whenever the action has no query filter "
        "for what the person asked, e.g. [{\"field\": \"plan.name\", \"op\": \"eq\", \"value\": \"Weekly 300\"}], "
        "[{\"field\": \"amount\", \"op\": \"gte\", \"value\": 1000}], "
        "[{\"field\": \"expiry\", \"op\": \"lt\", \"value\": \"now+48h\"}]. Dates take ISO times or now, now+3d, now-12h."),
    "items": {
        "type": "object",
        "properties": {
            "field": {"type": "string"},
            "op": {"type": "string", "enum": list(OPS)},
            "value": {},
        },
        "required": ["field", "op"],
        "additionalProperties": False,
    },
}
SORT_SCHEMA = {
    "type": "object",
    "description": "Order the rows by one field, e.g. {\"field\": \"amount\", \"desc\": true}.",
    "properties": {"field": {"type": "string"}, "desc": {"type": "boolean"}},
    "required": ["field"],
    "additionalProperties": False,
}
LIMIT_SCHEMA = {"type": "integer", "minimum": 1, "maximum": 500,
                "description": "Keep only the first N rows (after where and sort): a top 10."}


class ListingError(ValueError):
    """Said back to the model: it asked for something the rows cannot answer."""


def find_list(data: Any) -> tuple[Optional[list], Optional[str]]:
    """The list of records in a result, and the key it sits under (None for a bare list)."""
    if isinstance(data, list):
        return (data, None) if all(isinstance(r, dict) for r in data) else (None, None)
    if not isinstance(data, dict):
        return None, None
    lists = {k: v for k, v in data.items()
             if isinstance(v, list) and v and all(isinstance(r, dict) for r in v)}
    for key in _LIST_KEYS:
        if key in lists:
            return lists[key], key
    if lists:
        key = max(lists, key=lambda k: len(lists[k]))
        return lists[key], key
    for key in _LIST_KEYS:
        if isinstance(data.get(key), list):
            return data[key], key   # an empty list
    return None, None


_MISSING = object()


def _get(row: dict, field: str) -> Any:
    value: Any = row
    for part in field.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return _MISSING
    return value


_REL = re.compile(r"^now\s*(?:([+-])\s*(\d+(?:\.\d+)?)\s*([mhdw]))?$", re.I)
_UNIT = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def _as_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or len(value) < 3:
        return None
    m = _REL.match(value.strip())
    if m:
        now = datetime.now(timezone.utc)
        if not m.group(1):
            return now
        delta = timedelta(**{_UNIT[m.group(3).lower()]: float(m.group(2))})
        return now + delta if m.group(1) == "+" else now - delta
    if not re.match(r"^\d{4}-\d{2}-\d{2}", value):
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # the API's naive times are UTC
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.replace(",", "").strip())
        except ValueError:
            return None
    return None


def _text(value: Any) -> str:
    return str(value).strip().lower() if value is not None else ""


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return _text(a) == _text(b)   # True ~ "true"
    na, nb = _as_number(a), _as_number(b)
    if na is not None and nb is not None:
        return na == nb
    return _text(a) == _text(b)


def _order(a: Any, b: Any) -> Optional[int]:
    """-1, 0, 1 comparing a row's value with the rule's, as times, then numbers, then text."""
    ta, tb = _as_time(a), _as_time(b)
    if ta is not None and tb is not None:
        return (ta > tb) - (ta < tb)
    na, nb = _as_number(a), _as_number(b)
    if na is not None and nb is not None:
        return (na > nb) - (na < nb)
    if a is None or b is None:
        return None
    sa, sb = _text(a), _text(b)
    return (sa > sb) - (sa < sb)


def _holds(row: dict, rule: dict) -> bool:
    value = _get(row, rule["field"])
    op, want = rule["op"], rule.get("value")
    if value is _MISSING:
        value = None
    empty = value is None or value == "" or value == [] or value == {}
    if op == "empty":
        return empty
    if op == "not_empty":
        return not empty
    if op in ("in", "not_in"):
        options = want if isinstance(want, list) else [want]
        hit = any(_same(value, w) for w in options)
        return hit if op == "in" else not hit
    if op in ("contains", "not_contains"):
        hay = " ".join(map(_text, value)) if isinstance(value, list) else _text(value)
        hit = _text(want) in hay
        return hit if op == "contains" else not hit
    if op == "eq":
        return _same(value, want)
    if op == "ne":
        return not _same(value, want)
    c = _order(value, want)
    if c is None:
        return False
    return {"gt": c > 0, "gte": c >= 0, "lt": c < 0, "lte": c <= 0}[op]


def _check_rules(rows: list, where: Any) -> list[dict]:
    if where is None:
        return []
    if isinstance(where, dict):
        where = [where]
    if not isinstance(where, list) or len(where) > MAX_RULES:
        raise ListingError(f"where must be a list of at most {MAX_RULES} rules")
    rules = []
    for rule in where:
        if not isinstance(rule, dict) or not isinstance(rule.get("field"), str) or rule.get("op") not in OPS:
            raise ListingError(f"each where rule needs a field and an op ({', '.join(OPS)})")
        if rule["op"] not in ("empty", "not_empty") and "value" not in rule:
            raise ListingError(f"where rule on {rule['field']} needs a value")
        rules.append(rule)
    return rules


def _fields_of(rows: list) -> list[str]:
    seen: dict[str, None] = {}
    for r in rows[:20]:
        for k, v in r.items():
            seen.setdefault(k, None)
            if isinstance(v, dict):
                for kk in v:
                    seen.setdefault(f"{k}.{kk}", None)
    return list(seen)


def narrow(data: Any, where: Any = None, sort: Any = None, limit: Any = None) -> tuple[Any, Optional[dict]]:
    """``data`` with its list narrowed, and a note for the model (None when nothing was asked)."""
    if where is None and sort is None and limit is None:
        return data, None
    rows, key = find_list(data)
    if rows is None:
        raise ListingError("This result is not a list of records, so where/sort/limit do not apply; leave them out.")
    rules = _check_rules(rows, where)
    known = _fields_of(rows)
    for name in [r["field"] for r in rules] + ([sort["field"]] if isinstance(sort, dict) and sort.get("field") else []):
        if rows and all(_get(r, name) is _MISSING for r in rows):
            raise ListingError(
                f"No row has a field '{name}'. The rows' fields are: {', '.join(known[:40])}.")
    kept = [r for r in rows if all(_holds(r, rule) for rule in rules)]
    if isinstance(sort, dict) and sort.get("field"):
        field, desc = sort["field"], bool(sort.get("desc"))
        present = [r for r in kept if _get(r, field) not in (_MISSING, None)]
        absent = [r for r in kept if _get(r, field) in (_MISSING, None)]
        import functools

        def cmp(a, b):
            c = _order(_get(a, field), _get(b, field))
            return c or 0
        present.sort(key=functools.cmp_to_key(cmp), reverse=desc)
        kept = present + absent   # rows without the value go last either way
    if limit is not None:
        try:
            n = max(1, min(500, int(limit)))
        except (TypeError, ValueError):
            raise ListingError("limit must be a whole number")
        kept = kept[:n]

    if key is None:
        out: Any = kept
    else:
        out = {**data, key: kept}
        for k in ("total", "count", "total_count", "total_items"):
            if isinstance(out.get(k), int):
                out[k] = len(kept)
        out.pop("total_pages", None)
    note = {"rows_read": len(rows), "rows_kept": len(kept)}
    if isinstance(data, dict) and isinstance(data.get("total_pages"), int) and data["total_pages"] > 1:
        note["warning"] = ("Only this page was narrowed: the list has more pages. Read it without page/per_page "
                           "(or use a server filter) to cover everything.")
    return out, note
