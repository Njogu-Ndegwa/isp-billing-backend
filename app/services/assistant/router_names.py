"""Routers on one account that share a name, marked so the model can tell them apart.

Older accounts can have two routers with the same name (CR-1123-F9). In a router
list each row then gets ``same_name_as``: the other routers with that name, by id,
identity and status. Only what the model reads is marked; the API result is not changed.
"""

from typing import Any


def _key(name: Any) -> str:
    return " ".join(str(name or "").split()).casefold()


def _is_router(row: Any) -> bool:
    return isinstance(row, dict) and "name" in row and "identity" in row and "id" in row


def _mark_list(rows: list) -> list:
    groups: dict[str, list] = {}
    for row in rows:
        if _is_router(row):
            groups.setdefault(_key(row.get("name")), []).append(row)
    shared = {id(r): group for group in groups.values() if len(group) > 1 for r in group}
    if not shared:
        return [mark_shared_names(r) for r in rows]
    out = []
    for row in rows:
        group = shared.get(id(row))
        marked = mark_shared_names(row)
        if group:
            marked = {**marked, "same_name_as": [
                {"id": o.get("id"), "identity": o.get("identity"), "status": o.get("status")}
                for o in group if o is not row
            ]}
        out.append(marked)
    return out


def mark_shared_names(data: Any) -> Any:
    """A copy of ``data`` where routers sharing a name in a list carry ``same_name_as``."""
    if isinstance(data, list):
        return _mark_list(data) if any(isinstance(r, (dict, list)) for r in data) else data
    if isinstance(data, dict):
        return {k: mark_shared_names(v) if isinstance(v, (dict, list)) else v for k, v in data.items()}
    return data
