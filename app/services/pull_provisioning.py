"""Outbound pull-provisioning channel (opt-in per router).

When a paid hotspot user cannot be pushed to a flaky/Starlink-fed router over the
WireGuard tunnel, the app renders the provisioning as an idempotent RouterOS script
and hands it to the secondary-server pull service. The router fetches and applies it
on its next outbound check-in, so the customer gets online even while the tunnel is
down. The queue + serving live on the secondary server; the old box only makes the
brief outbound handoff here.

SECURITY: the rendered script is executed by the router, so every value that comes
from customer data is either strictly whitelist-validated (username, MAC, rate,
time) or escaped for RouterOS double-quoted strings (password, comment). Anything
that fails validation raises, so a malformed/hostile value is never embedded.
"""
from __future__ import annotations

import os
import re
import logging

logger = logging.getLogger(__name__)

# --- config (env, with safe defaults matching the current POC service) ---
PULL_SERVICE_URL = os.environ.get("PULL_SERVICE_URL", "http://35.170.199.141:8443").rstrip("/")
PULL_SERVICE_TOKEN = os.environ.get("PULL_SERVICE_TOKEN", "")
PULL_HANDOFF_TIMEOUT = float(os.environ.get("PULL_HANDOFF_TIMEOUT", "8"))

# --- strict validators for structured fields ---
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
_RATE_RE = re.compile(r"^\d+[KMG]?/\d+[KMG]?$")
_TIME_RE = re.compile(r"^[0-9wdhms:]{1,20}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9._/-]{1,72}$")
_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


def _require(value, rx: re.Pattern, name: str) -> str:
    v = str(value or "").strip()
    if not rx.match(v):
        raise ValueError(f"pull-provisioning: unsafe {name}={value!r}")
    return v


def _normalize_mac(mac) -> str:
    m = str(mac or "").strip().upper().replace("-", ":")
    if not _MAC_RE.match(m):
        raise ValueError(f"pull-provisioning: unsafe mac={mac!r}")
    return m


def _ros_quote(s) -> str:
    """Escape a value for a RouterOS double-quoted string: backslash, quote and the
    variable-expansion '$' are escaped; control chars (incl. CR/LF) are stripped so a
    value can never break out of its quotes or inject a new command."""
    s = str(s or "")
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    s = "".join(ch for ch in s if ord(ch) >= 0x20)
    return s[:120]


def render_hotspot_provision_rsc(
    *, username: str, password: str, mac_address: str,
    rate_limit: str, time_limit: str, comment: str = "",
    expires_at: int | None = None,
) -> str:
    """Render an idempotent RouterOS script that provisions one hotspot user exactly
    like ``MikroTikAPI.add_customer_bypass_mode`` (profile -> user -> bypassed
    ip-binding). Re-applying is a no-op, so the router may safely fetch it repeatedly.
    Raises ValueError on any value that fails validation.

    ``expires_at`` (unix seconds) is emitted as a leading ``# PULL-EXPIRES`` comment.
    RouterOS ignores ``#`` lines on import, but the pull service reads it and STOPS
    serving the command once the customer's plan has expired — so a delivered command
    can never keep re-granting access past the paid window (the free-internet bug)."""
    user = _require(username, _USERNAME_RE, "username")
    mac = _normalize_mac(mac_address)
    rate = _require(rate_limit, _RATE_RE, "rate_limit")
    uptime = _require(time_limit, _TIME_RE, "time_limit")
    profile = _require("plan_" + rate.replace("/", "_"), _PROFILE_RE, "profile")
    pw = _ros_quote(password)
    cm = _ros_quote(comment)

    header = []
    if expires_at is not None:
        exp = int(expires_at)
        if exp > 0:
            header.append(f"# PULL-EXPIRES {exp}")

    return "\n".join(header + [
        f"# pull-provisioning hotspot user {user}",
        "/ip hotspot user profile",
        (f':if ([:len [find name="{profile}"]] = 0) do={{ add name="{profile}" '
         f'rate-limit="{rate}" }} else={{ set [find name="{profile}"] rate-limit="{rate}" }}'),
        "/ip hotspot user",
        (f':if ([:len [find name="{user}"]] = 0) do={{ add name="{user}" password="{pw}" '
         f'profile="{profile}" limit-uptime="{uptime}" comment="{cm}" }} '
         f'else={{ set [find name="{user}"] password="{pw}" profile="{profile}" '
         f'limit-uptime="{uptime}" comment="{cm}" }}'),
        "/ip hotspot ip-binding",
        (f':if ([:len [find mac-address="{mac}"]] = 0) do={{ add mac-address="{mac}" '
         f'type=bypassed comment="{cm}" }} else={{ set [find mac-address="{mac}"] '
         f'type=bypassed comment="{cm}" }}'),
        "",
    ])


_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _safe_key(key: str) -> str:
    """A per-command key (so concurrent users don't overwrite each other). Falls back
    to a sanitized form if the raw key has unsafe chars."""
    k = re.sub(r"[^A-Za-z0-9._-]", "_", str(key or "cmd"))[:64] or "cmd"
    return k


async def handoff_to_pull_service(identity: str, key: str, rsc: str) -> dict:
    """POST a rendered script to the secondary-server pull service so `identity` fetches
    it under `key` (one slot per user, no overwrite). Must be called with NO DB session
    held (network I/O). Never raises on transport error — the app's retry tries again."""
    import httpx
    ident = _require(identity, _KEY_RE, "identity")
    url = f"{PULL_SERVICE_URL}/pull/set/{ident}/{_safe_key(key)}"
    try:
        async with httpx.AsyncClient(timeout=PULL_HANDOFF_TIMEOUT) as client:
            resp = await client.post(
                url, content=rsc.encode("utf-8"),
                headers={"X-Pull-Token": PULL_SERVICE_TOKEN, "Content-Type": "text/plain"},
            )
        ok = 200 <= resp.status_code < 300
        if not ok:
            logger.warning("pull handoff for %s/%s got HTTP %s", ident, key, resp.status_code)
        return {"ok": ok, "status": resp.status_code}
    except Exception as e:
        logger.warning("pull handoff for %s/%s failed: %s", ident, key, e)
        return {"ok": False, "error": str(e)}


async def clear_pull_service(identity: str, key: str) -> dict:
    """Tell the pull service one user's command has been applied; stop serving it."""
    import httpx
    ident = _require(identity, _KEY_RE, "identity")
    url = f"{PULL_SERVICE_URL}/pull/clear/{ident}/{_safe_key(key)}"
    try:
        async with httpx.AsyncClient(timeout=PULL_HANDOFF_TIMEOUT) as client:
            resp = await client.post(url, headers={"X-Pull-Token": PULL_SERVICE_TOKEN})
        return {"ok": 200 <= resp.status_code < 300, "status": resp.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}
