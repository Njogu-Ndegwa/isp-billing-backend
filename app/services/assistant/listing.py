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

from contextvars import ContextVar
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
        "[{\"field\": \"expiry\", \"op\": \"lt\", \"value\": \"now+48h\"}]. Dates take ISO times, now, now+3d, now-12h, "
        "or calendar moments in the person's own timezone: today_start, today_end, tomorrow_start, tomorrow_end, "
        "yesterday_start, yesterday_end, week_start (Monday), month_start, last_month_start, year_start, each "
        "with an optional offset (today_start-2d). Time ending today: [{\"field\": \"expiry\", \"op\": \"gt\", "
        "\"value\": \"today_start\"}, {\"field\": \"expiry\", \"op\": \"lte\", \"value\": \"today_end\"}]."),
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
    # did_you_mean: close matches beside an empty search result, never the result itself
    lists = {k: v for k, v in data.items()
             if k != "did_you_mean" and isinstance(v, list) and v and all(isinstance(r, dict) for r in v)}
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


_ANCHORS = ("now", "today_start", "today_end", "tomorrow_start", "tomorrow_end", "yesterday_start",
            "yesterday_end", "week_start", "month_start", "last_month_start", "year_start")
_REL = re.compile(r"^(" + "|".join(sorted(_ANCHORS, key=len, reverse=True)) +
                  r")\s*(?:([+-])\s*(\d+(?:\.\d+)?)\s*([mhdw]))?$", re.I)
_UNIT = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def _midnight(local: datetime, days: int) -> datetime:
    """Local midnight `days` days from `local`'s day, safe across a clock change."""
    day = local.replace(hour=12, minute=0, second=0, microsecond=0) + timedelta(days=days)
    return day.replace(hour=0).astimezone(local.tzinfo) if local.tzinfo else day.replace(hour=0)


def anchor_time(name: str, now: Optional[datetime] = None, tz_name: Optional[str] = None) -> datetime:
    """A calendar moment ("today_end") as an aware UTC time, the day counted in `tz_name`."""
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    name = name.lower()
    if name == "now":
        return now
    try:
        zone = ZoneInfo(tz_name) if tz_name else timezone.utc
    except ZoneInfoNotFoundError:
        zone = timezone.utc
    local = now.astimezone(zone)
    days = {"today_start": 0, "today_end": 1, "tomorrow_start": 1, "tomorrow_end": 2,
            "yesterday_start": -1, "yesterday_end": 0}
    if name in days:
        moment = _midnight(local, days[name])
    elif name == "week_start":
        moment = _midnight(local, -local.weekday())
    elif name == "month_start":
        moment = _midnight(local, 1 - local.day)
    elif name == "last_month_start":
        first = _midnight(local, 1 - local.day)
        moment = _midnight(first - timedelta(days=1), 1 - (first - timedelta(days=1)).day)
    elif name == "year_start":
        moment = _midnight(local, 1 - local.timetuple().tm_yday)
    else:
        raise ValueError(name)
    return moment.astimezone(timezone.utc)


# Within one narrow() each distinct text is read as a time once: a 3,000-row sort compares
# every value many times, and "today_end" would otherwise be worked out per row.
_TIMES: ContextVar[Optional[dict]] = ContextVar("listing_times", default=None)


def _as_time(value: Any, tz_name: Optional[str] = None) -> Optional[datetime]:
    if not isinstance(value, str) or len(value) < 3:
        return None
    memo = _TIMES.get()
    if memo is None:
        return _parse_time(value, tz_name)
    if value not in memo:
        memo[value] = _parse_time(value, tz_name)
    return memo[value]


def _parse_time(value: str, tz_name: Optional[str]) -> Optional[datetime]:
    m = _REL.match(value.strip())
    if m:
        base = anchor_time(m.group(1), tz_name=tz_name)
        if not m.group(2):
            return base
        delta = timedelta(**{_UNIT[m.group(4).lower()]: float(m.group(3))})
        return base + delta if m.group(2) == "+" else base - delta
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


def _order(a: Any, b: Any, tz_name: Optional[str] = None) -> Optional[int]:
    """-1, 0, 1 comparing a row's value with the rule's, as times, then numbers, then text."""
    ta, tb = _as_time(a, tz_name), _as_time(b, tz_name)
    if ta is not None and tb is not None:
        return (ta > tb) - (ta < tb)
    na, nb = _as_number(a), _as_number(b)
    if na is not None and nb is not None:
        return (na > nb) - (na < nb)
    if a is None or b is None:
        return None
    sa, sb = _text(a), _text(b)
    return (sa > sb) - (sa < sb)


def _sort_key(value: Any) -> tuple:
    t = _as_time(value)
    if t is not None:
        return (0, t.timestamp(), "")
    n = _as_number(value)
    if n is not None:
        return (1, n, "")
    return (2, 0.0, _text(value))


def _holds(row: dict, rule: dict, tz_name: Optional[str] = None) -> bool:
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
    c = _order(value, want, tz_name)
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


def narrow(data: Any, where: Any = None, sort: Any = None, limit: Any = None,
           tz_name: Optional[str] = None) -> tuple[Any, Optional[dict]]:
    """``data`` with its list narrowed, and a note for the model (None when nothing was asked).
    Calendar moments in rules (today_end, month_start) are days in ``tz_name``."""
    token = _TIMES.set({})
    try:
        return _narrow(data, where, sort, limit, tz_name)
    finally:
        _TIMES.reset(token)


def _narrow(data: Any, where: Any, sort: Any, limit: Any, tz_name: Optional[str]) -> tuple[Any, Optional[dict]]:
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
    kept = [r for r in rows if all(_holds(r, rule, tz_name) for rule in rules)]
    if isinstance(sort, dict) and sort.get("field"):
        field, desc = sort["field"], bool(sort.get("desc"))
        present = [r for r in kept if _get(r, field) not in (_MISSING, None)]
        absent = [r for r in kept if _get(r, field) in (_MISSING, None)]
        # one key per row (times, then numbers, then text), not a parse per comparison
        present.sort(key=lambda r: _sort_key(_get(r, field)), reverse=desc)
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


# ---- reading every page --------------------------------------------------------------

MAX_PAGES = 40
MAX_ROWS = 5000
_SIZE_KEYS = ("per_page", "page_size", "size")


def next_page(param_names: set, query: Optional[dict], data: Any, rows_so_far: int,
              page_rows: int) -> Optional[dict]:
    """The query for the page after this one, or None when this was the last.

    Narrowing a list must see all of it: "customers whose time ends today" read from the
    first page of 50 would quietly miss the rest. Both paging styles are followed:
    page/per_page (stops at total_pages, a total, or a short page) and limit/offset
    (stops at has_more false or a short page)."""
    q = dict(query or {})
    if page_rows == 0:
        return None
    meta = data if isinstance(data, dict) else {}
    if meta.get("has_more") is False:
        return None
    total = next((meta[k] for k in ("total", "total_count", "total_items", "count")
                  if isinstance(meta.get(k), int) and not isinstance(meta.get(k), bool)), None)
    if total is not None and rows_so_far >= total:
        return None
    if "page" in param_names:
        page = meta.get("page") if isinstance(meta.get("page"), int) else int(q.get("page") or 1)
        pages = meta.get("total_pages") if isinstance(meta.get("total_pages"), int) else None
        if pages is not None:
            if page >= pages:
                return None
        elif total is None and meta.get("has_more") is not True:
            size_key = next((k for k in _SIZE_KEYS if k in q or isinstance(meta.get(k), int)), None)
            size = q.get(size_key) or meta.get(size_key) if size_key else None
            # no total and no page count: a full page may have more after it
            if not size or page_rows < int(size):
                return None
        q["page"] = page + 1
        return q
    if "offset" in param_names:
        limit = q.get("limit") or meta.get("limit")
        if meta.get("has_more") is not True and (not limit or page_rows < int(limit)):
            return None
        q["offset"] = int(q.get("offset") or 0) + page_rows
        return q
    return None


def bigger_pages(params: list, query: Optional[dict], first: Any, page_rows: int) -> Optional[dict]:
    """When a long list was read in small pages, the first-page query with the largest page
    the action allows; None when the page is already that size or there is no more."""
    names = {p["name"] for p in params}
    if next_page(names, query, first, page_rows, page_rows) is None:
        return None
    q = dict(query or {})
    for p in params:
        if p["name"] not in (*_SIZE_KEYS, "limit"):
            continue
        schema = p.get("schema") or {}
        top = schema.get("maximum") or next((s.get("maximum") for s in schema.get("anyOf", []) if s.get("maximum")), None)
        if not top or (q.get(p["name"]) and int(q[p["name"]]) >= top) or page_rows >= top:
            continue
        q[p["name"]] = int(top)
        q.pop("offset", None)
        if "page" in names:
            q["page"] = 1
        return q
    return None


def partial_read(params: list, query: Optional[dict], data: Any) -> Optional[str]:
    """Why one read's list is not the whole list (one page of more, a full limit, an offset),
    or None when it is all of it. Figures over its rows then say they cover only those rows."""
    rows, _ = find_list(data)
    if not rows:
        return None
    meta = data if isinstance(data, dict) else {}
    q = query or {}
    names = {p["name"]: p for p in params}
    total = next((meta[k] for k in ("total", "total_count", "total_items", "count")
                  if isinstance(meta.get(k), int) and not isinstance(meta.get(k), bool)), None)
    pages = meta.get("total_pages") if isinstance(meta.get("total_pages"), int) else None
    if (pages and pages > 1) or (total is not None and total > len(rows)):
        return (f"this read is one page of {len(rows)} rows" + (f" out of {total} rows" if total else "")
                + (f" in {pages} pages" if pages and pages > 1 else ""))
    if meta.get("has_more") is True:
        return f"there are more rows after these {len(rows)}"
    offset = q.get("offset")
    if "offset" in names and offset and int(offset) > 0:
        return f"the first {int(offset)} rows were skipped (offset {int(offset)})"
    if "limit" in names:
        limit = q.get("limit") or (names["limit"].get("schema") or {}).get("default")
        if limit and len(rows) >= int(limit):
            return f"one read returns at most {int(limit)} rows and this one is full"
    return None


def join_pages(first: Any, rows: list) -> Any:
    """The first page's result carrying every page's rows."""
    if isinstance(first, list):
        return rows
    _, key = find_list(first)
    out = {**first, key: rows}
    for k in ("total_pages", "page", "has_more", "offset"):
        out.pop(k, None)
    return out
