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


_STATUS_KEYS = ("status", "state")
_AMOUNT_KEYS = ("amount", "total_amount", "amount_paid", "revenue", "price", "total")
_LABEL_KEYS = ("date", "day", "period", "label", "name", "created_at")


def _num(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _money(value: float) -> Any:
    value = round(value, 2)
    return int(value) if value == int(value) else value


def list_totals(rows: list, partial: str | None = None) -> dict | None:
    """Server-side figures over every row of a list of records, for when the model sees only a few.

    Always the row count. Rows with a code-like status (a few short values) get count and, when
    they have an amount, the sum per status; like /api/mpesa/transactions/summary, a row with
    counts_as_revenue false is counted but its money is kept apart. Rows without a status get
    sum, highest and lowest of each number field (ids aside), so "the best day" is the server's."""
    if not rows or not all(isinstance(r, dict) for r in rows):
        return None
    out: dict = {"rows": len(rows)}
    status_key = next((k for k in _STATUS_KEYS if any(isinstance(r.get(k), str) for r in rows)), None)
    if status_key:
        values = {r.get(status_key) for r in rows}
        if len(values) > 12 or any(isinstance(v, str) and len(v) > 32 for v in values) \
                or any(v is not None and not isinstance(v, str) for v in values):
            status_key = None
    amount_key = next((k for k in _AMOUNT_KEYS if any(_num(r.get(k)) is not None for r in rows)), None)
    if status_key:
        by: dict = {}
        apart = {"rows": 0, "amount": 0.0}
        for r in rows:
            entry = by.setdefault(str(r.get(status_key) or "none"), {"rows": 0, **({"amount": 0.0} if amount_key else {})})
            entry["rows"] += 1
            amount = _num(r.get(amount_key)) if amount_key else None
            if amount is None:
                continue
            if r.get("counts_as_revenue") is False:
                apart["rows"] += 1
                apart["amount"] += amount
            else:
                entry["amount"] += amount
        for entry in by.values():
            if "amount" in entry:
                entry["amount"] = _money(entry["amount"])
        out["by_status"] = dict(sorted(by.items()))
        if apart["rows"]:
            out["not_counted_as_revenue"] = {"rows": apart["rows"], "amount": _money(apart["amount"])}
    else:
        label_key = next((k for k in _LABEL_KEYS if any(isinstance(r.get(k), str) for r in rows)), None)
        fields = [k for k in rows[0] if k != "id" and not k.endswith("_id") and _num(rows[0].get(k)) is not None]
        for key in fields[:6]:
            numbered = [(r, _num(r.get(key))) for r in rows if _num(r.get(key)) is not None]
            high = max(numbered, key=lambda p: p[1])
            low = min(numbered, key=lambda p: p[1])
            fig = {"sum": _money(sum(v for _, v in numbered)), "highest": _money(high[1])}
            if label_key:
                fig["highest_at"] = high[0].get(label_key)
            fig["lowest"] = _money(low[1])
            if label_key:
                fig["lowest_at"] = low[0].get(label_key)
            out[key] = fig
    if partial:
        out["partial"] = (f"{partial}: these figures cover only the rows read, not the whole list. For whole "
                          "figures read the summary action (e.g. /api/mpesa/transactions/summary) or filter.")
    return out


def _with_totals(shaped: Any, data: Any, partial: str | None) -> Any:
    """Put list_totals on the closing note of the result's own list(s) when they were cut."""
    def attach(cut: Any, whole: Any) -> Any:
        if not (isinstance(cut, list) and isinstance(whole, list) and cut and len(cut) - 1 < len(whole)
                and isinstance(cut[-1], dict) and "_note" in cut[-1]):
            return cut
        totals = list_totals(whole, partial)
        if totals is None:
            return cut
        n, t = len(cut) - 1, len(whole)
        note = (f"Showing the first {n} of {t} rows. list_totals holds figures over all {t} rows: take any "
                f"total, count, best or worst from it, never by adding up the rows shown.")
        if partial:
            note += " This read is not the whole list (see list_totals.partial)."
        return [*cut[:-1], {"_note": note, "list_totals": totals}]
    if isinstance(shaped, list):
        return attach(shaped, data)
    if isinstance(shaped, dict) and isinstance(data, dict):
        return {k: attach(v, data.get(k)) for k, v in shaped.items()}
    return shaped


def for_model(data: Any, limit_chars: int = 14000, partial: str | None = None) -> Any:
    data = mask(data)
    for max_list, max_str in ((30, 400), (15, 240), (8, 160), (4, 120), (2, 80)):
        shaped = _cut(data, max_list=max_list, max_str=max_str)
        if _size(shaped) <= limit_chars:
            return _with_totals(shaped, data, partial)
    text = json.dumps(shaped, default=str, ensure_ascii=False)
    out = {"_note": "Result too large; showing the start only.", "start": text[:limit_chars]}
    totals = list_totals(data, partial) if isinstance(data, list) else None
    return {**out, "list_totals": totals} if totals else out


def for_screen(data: Any, limit_chars: int = 180_000) -> Any:
    data = mask(data)
    for max_list, max_str in ((300, 2000), (120, 800), (50, 300)):
        shaped = _cut(data, max_list=max_list, max_str=max_str, max_depth=9)
        if _size(shaped) <= limit_chars:
            return shaped
    return {"_note": "Too large to show here. Open the page for the full list."}


def to_json_text(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))
