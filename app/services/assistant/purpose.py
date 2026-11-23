"""The one field a form card was opened for ("add her phone", "set the speed", "rename").

The model names it with call_api's ``purpose``. The card shows that field first and
marked, with ``original`` (what the record holds now, as the form shows it), and the
page keeps Confirm off until it holds something else. The server checks the same on
Confirm, so a card opened to add a phone never saves "ok" without one (CR-1123-B9).
"""
from __future__ import annotations

import re
from typing import Any, Optional

from app.services.assistant.catalog import local_input


def mark_purpose(form: list[dict], name: str, context: Optional[dict], editing: bool,
                 tz: Optional[str]) -> Optional[list[dict]]:
    """The form with the purpose field first and marked; None when it is not one of the form's fields."""
    field = next((f for f in form if f.get("name") == name), None)
    if field is None or field.get("kind") == "password" or field.get("when"):
        return None  # a password never comes back to be compared; a field that may be hidden cannot be the point
    original = context.get(name) if editing and isinstance(context, dict) else None
    if field.get("kind") == "datetime" and original is not None:
        original = local_input(original, tz) or original
    marked = {**field, "purpose": True, "original": original}
    return [marked] + [f for f in form if f is not field]


def _plain(value: Any, field: dict) -> Any:
    if value is None:
        return ""
    if isinstance(value, list):
        return sorted(str(v).strip() for v in value if str(v).strip())
    if isinstance(value, bool):
        return value
    if field.get("kind") == "boolean":
        return str(value).strip().lower() in ("true", "1", "yes", "on")
    text = str(value).strip()
    if field.get("format") == "phone":
        return re.sub(r"[\s().-]", "", text)
    if field.get("kind") in ("integer", "number", "select") and text:
        try:
            number = float(text.replace(",", ""))
            return int(number) if number.is_integer() else number
        except ValueError:
            return text.lower() if field.get("kind") == "select" else text
    return text


def purpose_problem(field: dict, typed: Optional[dict], body: Any) -> Optional[str]:
    """Why this Confirm must not run (the purpose field empty or as it was), or None."""
    name = field["name"]
    if isinstance(typed, dict) and name in typed:
        now = typed[name]
    else:
        now = body.get(name) if isinstance(body, dict) else None
    label = str(field.get("label") or name)
    now_plain = _plain(now, field)
    if now_plain in ("", []) and field.get("kind") != "boolean":
        return (f"Not run yet: this form was opened to set {label}, and {label} is still empty. "
                f"Type it on the card, then tap Confirm.")
    if now_plain == _plain(field.get("original"), field):
        return (f"Not run yet: this form was opened to change {label}, and {label} is unchanged. "
                f"Type the new {label.lower()} on the card, then tap Confirm.")
    return None
