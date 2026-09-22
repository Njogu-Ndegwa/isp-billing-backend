"""Fail-closed runtime controls for migration and disaster-recovery stacks.

``SHADOW_MODE`` is deliberately broader than a scheduler toggle.  A shadow
application may read its restored database and serve safe diagnostics, but it
must not become a second billing writer or operate customer routers/providers.
"""

from app.config import settings


class ShadowModeBlockedError(RuntimeError):
    """Raised before an operation that is unsafe in shadow mode."""


_SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_SHADOW_SAFE_POST_PATHS = frozenset({"/api/auth/login"})
_ROUTEROS_READ_ACTIONS = frozenset(
    {
        "export",
        "get",
        "monitor",
        "monitor-traffic",
        "ping",
        "print",
        "traceroute",
    }
)


def shadow_mode_enabled() -> bool:
    return bool(getattr(settings, "SHADOW_MODE", False))


def scheduler_enabled() -> bool:
    """Honor the current kill switch and the legacy Hetzner candidate alias."""
    return bool(getattr(settings, "RUN_SCHEDULER", True)) and bool(
        getattr(settings, "SCHEDULER_ENABLED", True)
    )


def runtime_mode_name() -> str:
    if shadow_mode_enabled():
        return "shadow"
    return "active" if scheduler_enabled() else "standby"


def shadow_http_request_allowed(method: str, path: str) -> bool:
    """Allow reads plus the login endpoint, which is read-only in shadow mode."""
    normalized_method = (method or "").upper()
    normalized_path = (path or "").rstrip("/") or "/"
    return (
        normalized_method in _SAFE_HTTP_METHODS
        or (
            normalized_method == "POST"
            and normalized_path in _SHADOW_SAFE_POST_PATHS
        )
    )


def require_external_side_effects_enabled(operation: str) -> None:
    if shadow_mode_enabled():
        raise ShadowModeBlockedError(
            f"{operation} is disabled while SHADOW_MODE is active"
        )


def routeros_command_is_read_only(command: str) -> bool:
    normalized = (command or "").strip().lower().rstrip("/")
    if not normalized.startswith("/"):
        return False
    action = normalized.rsplit("/", 1)[-1]
    return action in _ROUTEROS_READ_ACTIONS


def shadow_routeros_command_blocked(command: str) -> bool:
    return shadow_mode_enabled() and not routeros_command_is_read_only(command)
