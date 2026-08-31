"""RouterOS-safe hotspot command rendering plus retired pull-service helpers.

The main app's durable ``router_commands`` outbox now uses the renderer below.
The old secondary-server handoff functions remain only for rollback compatibility;
the paid provisioning path no longer calls them.

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
    lb_enabled: bool = False,
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
    lb_timeout_seconds = 60
    if lb_enabled:
        total = 0
        for amount, unit in re.findall(r"(\d+)([wdhms])", uptime.lower()):
            total += int(amount) * {
                "w": 604800,
                "d": 86400,
                "h": 3600,
                "m": 60,
                "s": 1,
            }[unit]
        lb_timeout_seconds = max(60, min(21_000_000, total or 60))

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
        # Capture the address before removing the unauthorized host entry, then
        # force an immediate hotspot re-evaluation so a just-paid device does
        # not remain trapped on the portal until it reconnects.
        f':local bwClientIp ""',
        f':local bwHost [/ip hotspot host find mac-address="{mac}"]',
        ':if ([:len $bwHost] > 0) do={ :set bwClientIp [/ip hotspot host get [:pick $bwHost 0] address] }',
        f':if ([:len $bwClientIp] = 0) do={{ :local bwLease [/ip dhcp-server lease find mac-address="{mac}"]; '
        ':if ([:len $bwLease] > 0) do={ :set bwClientIp [/ip dhcp-server lease get [:pick $bwLease 0] active-address]; '
        ':if ([:len $bwClientIp] = 0) do={ :set bwClientIp [/ip dhcp-server lease get [:pick $bwLease 0] address] } } }',
        f':do {{ /ip hotspot active remove [find mac-address="{mac}"] }} on-error={{}}',
        f':do {{ /ip hotspot host remove [find mac-address="{mac}"] }} on-error={{}}',
        # Bypassed bindings do not reliably inherit hotspot profile limits.
        # Match the direct path with a per-IP queue plus FastTrack exclusions.
        f':do {{ /queue simple remove [find name="plan_{user}"] }} on-error={{}}',
        ':if ([:len $bwClientIp] > 0) do={',
        f'    /queue simple add name="plan_{user}" target=($bwClientIp . "/32") max-limit="{rate}" '
        f'comment="MAC:{mac}|Plan rate limit"',
        '    :local bwFastTrack [/ip firewall filter find chain=forward action=fasttrack-connection disabled=no]',
        '    :if ([:len $bwFastTrack] > 0) do={',
        '        :if ([:len [/ip firewall address-list find list="isp_queue_limited_clients" address=$bwClientIp]] = 0) do={',
        '            /ip firewall address-list add list="isp_queue_limited_clients" address=$bwClientIp comment="Managed by ISP Billing queue sync"',
        '        }',
        '        :do { /ip firewall filter remove [find comment="ISP_BILLING_QUEUE_BYPASS_SRC"] } on-error={}',
        '        :do { /ip firewall filter remove [find comment="ISP_BILLING_QUEUE_BYPASS_DST"] } on-error={}',
        '        /ip firewall filter add chain=forward action=accept src-address-list="isp_queue_limited_clients" '
        'comment="ISP_BILLING_QUEUE_BYPASS_SRC" place-before=[:pick $bwFastTrack 0]',
        '        /ip firewall filter add chain=forward action=accept dst-address-list="isp_queue_limited_clients" '
        'comment="ISP_BILLING_QUEUE_BYPASS_DST" place-before=[:pick $bwFastTrack 0]',
        '    }',
        *(
            [
                f'    :do {{ /ip firewall address-list remove [find list="LB_PAID" address=$bwClientIp] }} on-error={{}}',
                f'    /ip firewall address-list add list="LB_PAID" address=$bwClientIp '
                f'timeout={lb_timeout_seconds}s comment="PAID:{mac}"',
            ]
            if lb_enabled
            else []
        ),
        '}',
        ':foreach bwQueue in=[/queue simple find] do={',
        '    :local bwQueueName [/queue simple get $bwQueue name]',
        '    :if (([:pick $bwQueueName 0 3] = "hs-") or '
        '(([:pick $bwQueueName 0 4] = "<hs-") and ([:pick $bwQueueName ([:len $bwQueueName] - 1) [:len $bwQueueName]] = ">"))) do={',
        '        :do { /queue simple remove $bwQueue } on-error={}',
        '    }',
        '}',
        f':if ([:len [/ip hotspot user find name="{user}"]] = 0) do={{ :error "hotspot user missing" }}',
        f':if ([:len [/ip hotspot ip-binding find mac-address="{mac}" type=bypassed]] = 0) do={{ :error "bypass binding missing" }}',
        f':if (([:len $bwClientIp] > 0) and ([:len [/queue simple find name="plan_{user}"]] = 0)) do={{ :error "rate queue missing" }}',
        *(
            [
                f':if (([:len $bwClientIp] > 0) and ([:len [/ip firewall address-list find list="LB_PAID" address=$bwClientIp]] = 0)) do={{ :error "LB_PAID missing" }}',
            ]
            if lb_enabled
            else []
        ),
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
