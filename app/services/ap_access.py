"""Who may use remote access-point control.

Gated by ``settings.AP_CONTROL_ENABLED_FOR`` so the feature can ship and deploy
while still being bench-tested: default ``"admins"`` restricts it to Bitwave
platform admins; ``"all"`` opens it to every owner/staff who already holds the
router permissions (``routers.view`` / ``routers.manage``). Independent of the
permission check -- both must pass.
"""

from __future__ import annotations

from typing import Any

from app.config import settings

SCOPE_ADMINS = "admins"
SCOPE_ALL = "all"


def ap_control_scope() -> str:
    scope = str(getattr(settings, "AP_CONTROL_ENABLED_FOR", SCOPE_ADMINS) or SCOPE_ADMINS).strip().lower()
    return SCOPE_ALL if scope == SCOPE_ALL else SCOPE_ADMINS


def _role_value(role: Any) -> str:
    if role is None:
        return ""
    return getattr(role, "value", None) or str(role)


def ap_control_allowed(role: Any) -> bool:
    """True when a user with this role may use AP control under the current scope."""
    if ap_control_scope() == SCOPE_ALL:
        return True
    return _role_value(role).lower() == "admin"
