"""Hotspot MAC-login enforcement (pilot, 2026-09-28).

The default hotspot delivery gives a paid device a ``bypassed`` ip-binding and
a static ``plan_<MAC>`` simple queue aimed at the device's IP at payment time.
That leaks speed in several ways: the queue goes stale when DHCP hands the
device a new IP, FastTrack skips the queue, the queue sync can't keep up, and
any broader queue higher in the list takes the traffic first.

On routers listed in ``HOTSPOT_MAC_LOGIN_ROUTER_IDS`` a paid device is instead
a real hotspot user named after its MAC (``AA:BB:CC:DD:EE:FF``), and the
hotspot server profile has ``login-by`` including ``mac``. When the device
shows up, RouterOS logs it in by MAC with no portal, and the user profile's
``rate-limit`` makes RouterOS create a dynamic ``<hotspot-...>`` queue for the
session. That queue follows the session (and so the device's current IP),
sits above static queues, and goes away on logout. This is how PHPNuxBill and
RADIUS-based systems (Splynx) enforce speed.

Rules this module keeps:

* A MAC-login user IS access: a leftover user means free internet. Users are
  tagged ``MACLOGIN|MAC:<mac>|T:<epoch>`` so every cleanup path can find them
  by MAC, and :func:`reconcile_router` deletes any tagged user whose MAC is not
  a paid customer (after a grace, so a payment in flight is never undone).
* FastTrack skips hotspot dynamic queues exactly as it skips static ones, so
  the router gets one accept rule pair (established/related traffic in or out
  of the hotspot interfaces) placed before the first FastTrack rule. The rules
  are only ever added or moved, never removed and re-added (a remove/re-add
  gap FastTracks every live connection until it closes).
* Router functions take a connected ``MikroTikAPI`` and do no DB work.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from app.config import settings
from app.services.mikrotik_api import normalize_mac_address, parse_speed_to_mikrotik

logger = logging.getLogger("hotspot_mac_login")

COMMENT_PREFIX = "MACLOGIN|"
HOTSPOT_CLIENT_IFACE_LIST = "ISP_HOTSPOT_CLIENTS"
NO_FASTTRACK_IN_COMMENT = "ISP_BILLING_HOTSPOT_NO_FASTTRACK_IN"
NO_FASTTRACK_OUT_COMMENT = "ISP_BILLING_HOTSPOT_NO_FASTTRACK_OUT"

# A tagged user younger than this is never treated as an orphan: the sync may
# have read the paid-customer list just before a payment committed.
ORPHAN_GRACE_SECONDS = 15 * 60
# The payment path makes sure login-by=mac and the FastTrack exemption exist
# before creating a user, so a router nobody converted (a new router, or one
# offline during the rollout) works from its first payment. Checked at most
# once per router per this many seconds per process.
SETUP_RECHECK_SECONDS = 30 * 60
_setup_checked_at: Dict[str, float] = {}
# Per reconcile run, cap the users (re)written so a big router can't hold its
# lock for long; the rest roll over to the next run.
MAX_PROVISIONS_PER_RECONCILE = 40

CMD_DELAY = 0.05
# Two sessions per MAC-login user. The user is locked to its MAC
# (mac-address=), so the second session can only be the same device: when a
# phone gets a new IP while its old session is still alive (keepalive 2m), the
# new IP's MAC login is refused with shared-users=1 ("no more sessions are
# allowed") and RouterOS never retries it, leaving a paid customer at the portal
# (router 256, 2026-09-29: 40 min).
MAC_LOGIN_SHARED_USERS = "2"
# Per reconcile run, paid devices stuck at the portal whose host entry is
# cleared so RouterOS retries their MAC login.
MAX_UNSTICK_PER_RECONCILE = 20

_MAC_NAME_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_T_RE = re.compile(r"\|T:(\d{9,11})")


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def _ids(raw) -> frozenset[int]:
    return frozenset(int(p.strip()) for p in str(raw or "").split(",") if p.strip().isdigit())


def mac_login_router_ids() -> frozenset[int]:
    """The explicitly listed router ids (empty when the list is "all")."""
    return _ids(getattr(settings, "HOTSPOT_MAC_LOGIN_ROUTER_IDS", ""))


def mac_login_all_routers() -> bool:
    return str(getattr(settings, "HOTSPOT_MAC_LOGIN_ROUTER_IDS", "") or "").strip().lower() == "all"


def mac_login_enabled(router_id: Optional[int]) -> bool:
    """Is this router on MAC login?

    Listed, or the list is "all", or its id is at least
    HOTSPOT_MAC_LOGIN_MIN_ROUTER_ID (new routers); never when excluded.
    """
    if router_id is None:
        return False
    try:
        rid = int(router_id)
    except (TypeError, ValueError):
        return False
    if rid in _ids(getattr(settings, "HOTSPOT_MAC_LOGIN_EXCLUDE_ROUTER_IDS", "")):
        return False
    if mac_login_all_routers() or rid in mac_login_router_ids():
        return True
    try:
        floor = int(getattr(settings, "HOTSPOT_MAC_LOGIN_MIN_ROUTER_ID", 0) or 0)
    except (TypeError, ValueError):
        floor = 0
    return floor > 0 and rid >= floor


def mac_login_username(mac_address: str) -> str:
    """RouterOS sends the MAC as ``AA:BB:CC:DD:EE:FF`` for login-by=mac."""
    return normalize_mac_address(mac_address).upper()


def profile_name_for_rate(rate_limit: str) -> str:
    """Same naming as bypass provisioning, so existing plan profiles are reused."""
    return f"plan_{rate_limit.replace('/', '_')}"


def build_user_comment(mac_address: str, note: str = "", now: Optional[float] = None,
                       expiry: Optional[datetime] = None) -> str:
    mac = mac_login_username(mac_address)
    stamp = int(now if now is not None else time.time())
    parts = [f"{COMMENT_PREFIX}MAC:{mac}", f"T:{stamp}"]
    if expiry is not None:
        try:
            # The rounded-UP UTC second, like the bindings' EXP: the router
            # reaper enforces it (a naive datetime is UTC, whatever the host TZ).
            from app.services.router_expiry import expiry_second

            parts.append(f"EXP:{expiry_second(expiry)}")
        except Exception:
            pass
    if note:
        # RouterOS comments are single-line; keep ours short and pipe-safe.
        parts.append(str(note).replace("|", "/").replace("\n", " ")[:80])
    return "|".join(parts)


def is_mac_login_user(user: Dict[str, Any]) -> bool:
    return str(user.get("comment", "") or "").startswith(COMMENT_PREFIX)


def user_created_at(user: Dict[str, Any]) -> Optional[int]:
    match = _T_RE.search(str(user.get("comment", "") or ""))
    return int(match.group(1)) if match else None


def mac_of_user(user: Dict[str, Any]) -> Optional[str]:
    name = str(user.get("name", "") or "")
    if _MAC_NAME_RE.match(name):
        return name.upper()
    return None


def hotspot_user_is_for_mac(user: Dict[str, Any], mac_address: str) -> bool:
    """True for any hotspot user this app created for ``mac_address``.

    Covers the bypass-era user (``AABBCCDDEEFF``) and the MAC-login user
    (``AA:BB:CC:DD:EE:FF``, tagged with the MAC in its comment). Every removal
    path must use this: a MAC-login user left behind logs the device straight
    back in.
    """
    try:
        mac = normalize_mac_address(mac_address).upper()
    except Exception:
        return False
    compact = mac.replace(":", "")
    name = str(user.get("name", "") or "").strip().upper()
    if name in (compact, mac):
        return True
    comment = str(user.get("comment", "") or "").upper()
    return f"{COMMENT_PREFIX}MAC:{mac}" in comment


def _ok(result: Dict[str, Any]) -> bool:
    return bool(result.get("success")) or "error" not in result


def _data(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return (result.get("data") or []) if result.get("success") else []


# --------------------------------------------------------------------------
# Router setup (idempotent)
# --------------------------------------------------------------------------

def ensure_router_setup(api) -> Dict[str, Any]:
    """Enable MAC login on the hotspot and keep hotspot traffic off FastTrack.

    Safe to call on every reconcile: it only writes when something is missing.
    """
    out: Dict[str, Any] = {"success": True, "profiles_updated": [], "fasttrack": None}

    servers_res = api.send_command("/ip/hotspot/print")
    if not servers_res.get("success"):
        return {"error": f"hotspot server read failed: {servers_res.get('error')}"}
    servers = [s for s in _data(servers_res) if str(s.get("disabled", "false")).lower() != "true"]
    if not servers:
        return {"error": "no enabled hotspot server"}
    profile_names = {s.get("profile") for s in servers if s.get("profile")}
    interfaces = sorted({s.get("interface") for s in servers if s.get("interface")})

    profiles_res = api.send_command("/ip/hotspot/profile/print")
    if not profiles_res.get("success"):
        return {"error": f"hotspot profile read failed: {profiles_res.get('error')}"}
    for profile in _data(profiles_res):
        if profile.get("name") not in profile_names:
            continue
        login_by = [x for x in str(profile.get("login-by", "") or "").split(",") if x]
        if "mac" in login_by:
            continue
        new_login_by = ",".join(login_by + ["mac"])
        result = api.send_command("/ip/hotspot/profile/set", {
            "numbers": profile.get(".id"),
            "login-by": new_login_by,
        })
        if not _ok(result):
            return {"error": f"enable login-by=mac on {profile.get('name')}: {result.get('error')}"}
        out["profiles_updated"].append({"profile": profile.get("name"), "login-by": new_login_by})
        logger.warning("[MAC-LOGIN] %s: login-by now %s", profile.get("name"), new_login_by)

    # Plan profiles: allow a second session for the same device (see
    # MAC_LOGIN_SHARED_USERS). Covers profiles made by payments, the reconcile
    # and the check-in applier alike.
    out["shared_users_set"] = []
    for up in _data(api.send_command("/ip/hotspot/user/profile/print")):
        name = str(up.get("name", ""))
        if not name.startswith("plan_") or str(up.get("shared-users", "")) == MAC_LOGIN_SHARED_USERS:
            continue
        if _ok(api.send_command("/ip/hotspot/user/profile/set", {
                "numbers": up.get(".id"), "shared-users": MAC_LOGIN_SHARED_USERS})):
            out["shared_users_set"].append(name)

    out["fasttrack"] = ensure_hotspot_fasttrack_exemption(api, interfaces)
    if out["fasttrack"].get("error"):
        out["success"] = False
        out["error"] = out["fasttrack"]["error"]
    return out


def ensure_hotspot_fasttrack_exemption(api, interfaces: Iterable[str]) -> Dict[str, Any]:
    """Accept established/related hotspot traffic before any FastTrack rule.

    Interface based (not per-IP address lists), so a device's new IP is covered
    the moment it gets it. Adds or moves the two rules; never removes them.
    """
    interfaces = [i for i in interfaces if i]
    out: Dict[str, Any] = {"success": True, "added": [], "moved": [], "members_added": []}

    lists = _data(api.send_command("/interface/list/print"))
    if not any(l.get("name") == HOTSPOT_CLIENT_IFACE_LIST for l in lists):
        res = api.send_command("/interface/list/add", {
            "name": HOTSPOT_CLIENT_IFACE_LIST,
            "comment": "Managed by ISP Billing: hotspot client interfaces",
        })
        if not _ok(res):
            return {"error": f"interface list add failed: {res.get('error')}"}

    members = _data(api.send_command("/interface/list/member/print"))
    have = {m.get("interface") for m in members if m.get("list") == HOTSPOT_CLIENT_IFACE_LIST}
    for iface in interfaces:
        if iface in have:
            continue
        res = api.send_command("/interface/list/member/add", {
            "list": HOTSPOT_CLIENT_IFACE_LIST, "interface": iface,
        })
        if not _ok(res):
            return {"error": f"interface list member {iface} failed: {res.get('error')}"}
        out["members_added"].append(iface)

    rules_res = api.send_command_optimized(
        "/ip/firewall/filter/print",
        proplist=[".id", "chain", "action", "disabled", "comment"],
    )
    if not rules_res.get("success"):
        return {"error": f"firewall filter read failed: {rules_res.get('error')}"}
    rules = _data(rules_res)

    def first_fasttrack_index() -> Optional[int]:
        for i, r in enumerate(rules):
            if (r.get("chain") == "forward" and r.get("action") == "fasttrack-connection"
                    and str(r.get("disabled", "false")).lower() != "true"):
                return i
        return None

    ft_index = first_fasttrack_index()
    out["fasttrack_enabled"] = ft_index is not None
    if ft_index is None:
        return out
    ft_id = rules[ft_index].get(".id")

    wanted = (
        (NO_FASTTRACK_IN_COMMENT, "in-interface-list"),
        (NO_FASTTRACK_OUT_COMMENT, "out-interface-list"),
    )
    for comment, field in wanted:
        index = next((i for i, r in enumerate(rules) if r.get("comment") == comment), None)
        if index is None:
            res = api.send_command("/ip/firewall/filter/add", {
                "chain": "forward",
                "action": "accept",
                "connection-state": "established,related",
                field: HOTSPOT_CLIENT_IFACE_LIST,
                "comment": comment,
                "place-before": ft_id,
            })
            if not _ok(res):
                return {"error": f"add {comment} failed: {res.get('error')}"}
            out["added"].append(comment)
        elif index > ft_index:
            res = api.send_command("/ip/firewall/filter/move", {
                "numbers": rules[index].get(".id"),
                "destination": ft_id,
            })
            if not _ok(res):
                return {"error": f"move {comment} failed: {res.get('error')}"}
            out["moved"].append(comment)
        elif str(rules[index].get("disabled", "false")).lower() == "true":
            api.send_command("/ip/firewall/filter/enable", {"numbers": rules[index].get(".id")})
    return out


def flush_fasttracked_connections(api) -> Dict[str, Any]:
    """Drop connections already FastTracked, so the new limits apply to them.

    A FastTracked connection stays FastTracked until it closes. Run once when a
    router is converted; the affected apps simply reconnect.
    """
    res = api.send_command_optimized(
        "/ip/firewall/connection/print", proplist=[".id", "fasttrack"],
    )
    if not res.get("success"):
        return {"error": res.get("error")}
    removed = 0
    for conn in _data(res):
        if str(conn.get("fasttrack", "false")).lower() == "true" and conn.get(".id"):
            if _ok(api.send_command("/ip/firewall/connection/remove", {"numbers": conn[".id"]})):
                removed += 1
    return {"success": True, "removed": removed}


# --------------------------------------------------------------------------
# Per-customer
# --------------------------------------------------------------------------

def _ensure_profile(api, rate_limit: str, cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    profile = profile_name_for_rate(rate_limit)
    if cache is not None and profile in cache:
        return cache[profile]
    # Written only when missing or different: rate-limit plus the second
    # session for the same device (MAC_LOGIN_SHARED_USERS).
    existing = next((p for p in _data(api.send_command("/ip/hotspot/user/profile/print"))
                     if p.get("name") == profile), None)
    wanted = {"rate-limit": rate_limit, "shared-users": MAC_LOGIN_SHARED_USERS}
    if existing is None:
        result = api.send_command("/ip/hotspot/user/profile/add", {"name": profile, **wanted})
    elif any(str(existing.get(k, "")) != v for k, v in wanted.items()):
        result = api.send_command("/ip/hotspot/user/profile/set", {"numbers": existing.get(".id"), **wanted})
    else:
        result = {"success": True, "unchanged": True}
    result = dict(result or {})
    if not _ok(result):
        result["error"] = result.get("error") or "profile write failed"
    result["profile"] = profile
    if cache is not None:
        cache[profile] = result
    return result


def _kick(api, mac: str, *, hosts: bool = True) -> Dict[str, int]:
    """Remove the MAC's active session (and host entry) so login re-runs now."""
    kicked = {"sessions_removed": 0, "hosts_removed": 0}
    for session in _data(api.get_hotspot_active_minimal()):
        if session.get("mac-address") and normalize_mac_address(session["mac-address"]).upper() == mac:
            if _ok(api.send_command("/ip/hotspot/active/remove", {"numbers": session.get(".id")})):
                kicked["sessions_removed"] += 1
    if hosts:
        for host in _data(api.get_hotspot_hosts_minimal()):
            if host.get("mac-address") and normalize_mac_address(host["mac-address"]).upper() == mac:
                if _ok(api.send_command("/ip/hotspot/host/remove", {"numbers": host.get(".id")})):
                    kicked["hosts_removed"] += 1
    return kicked


def _remove_legacy_bypass(api, mac: str) -> Dict[str, int]:
    """Drop this MAC's bypassed binding and static plan queue (bypass era)."""
    compact = mac.replace(":", "")
    removed = {"bindings": 0, "queues": 0}
    for binding in _data(api.send_command("/ip/hotspot/ip-binding/print")):
        b_mac = binding.get("mac-address")
        if (b_mac and normalize_mac_address(b_mac).upper() == mac
                and str(binding.get("type", "")).lower() == "bypassed"):
            if _ok(api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding.get(".id")})):
                removed["bindings"] += 1
    for queue in _data(api.send_command("/queue/simple/print")):
        if str(queue.get("dynamic", "false")).lower() == "true":
            continue
        name = str(queue.get("name", ""))
        comment = str(queue.get("comment", "")).upper()
        if name in (f"plan_{compact}", f"queue_{compact}") or f"MAC:{mac}" in comment:
            if _ok(api.send_command("/queue/simple/remove", {"numbers": queue.get(".id")})):
                removed["queues"] += 1
    return removed


def provision_customer(
    api,
    mac_address: str,
    bandwidth_limit: str,
    note: str = "",
    expiry: Optional[datetime] = None,
    profile_cache: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Make ``mac_address`` a MAC-login hotspot user on its plan's profile.

    Result keys mirror ``MikroTikAPI.add_customer_bypass_mode`` so the
    provisioning pipeline's error extraction works unchanged.
    """
    try:
        mac = mac_login_username(mac_address)
        rate_limit = parse_speed_to_mikrotik(bandwidth_limit)
        setup_result = _ensure_setup_recently(api)
        profile_result = _ensure_profile(api, rate_limit, profile_cache)
        if profile_result.get("error"):
            return {"error": f"profile: {profile_result['error']}", "profile_result": profile_result}
        profile = profile_result["profile"]
        time.sleep(CMD_DELAY)

        comment = build_user_comment(mac, note, expiry=expiry)
        users = api.send_command_optimized(
            "/ip/hotspot/user/print",
            proplist=[".id", "name", "profile", "comment", "disabled", "mac-address"],
        )
        if not users.get("success"):
            return {"error": f"hotspot user read failed: {users.get('error')}"}
        existing = next((u for u in _data(users) if str(u.get("name", "")).upper() == mac), None)

        if existing:
            user_result = api.send_command("/ip/hotspot/user/set", {
                "numbers": existing.get(".id"),
                "password": "",
                "profile": profile,
                "mac-address": mac,
                "limit-uptime": "0s",
                "disabled": "no",
                "comment": comment,
            })
        else:
            user_result = api.send_command("/ip/hotspot/user/add", {
                "name": mac,
                "password": "",
                "profile": profile,
                "mac-address": mac,
                "comment": comment,
            })
        if not _ok(user_result):
            return {"error": f"hotspot user write failed: {user_result.get('error')}",
                    "hotspot_user_result": user_result}
        time.sleep(CMD_DELAY)

        legacy = _remove_legacy_bypass(api, mac)
        time.sleep(CMD_DELAY)
        # A live session keeps the rate it logged in with, and a host that was
        # bypassed keeps that state until it is re-evaluated: kick both so the
        # device logs in by MAC now, on the new profile.
        kicked = _kick(api, mac)

        return {
            "success": True,
            "mode": "mac_login",
            "message": f"{mac} provisioned for MAC login on {profile}",
            "user_details": {
                "username": mac,
                "mac_address": mac,
                "bandwidth_limit": bandwidth_limit,
                "rate_limit": rate_limit,
                "profile": profile,
            },
            "profile_result": profile_result,
            "hotspot_user_result": user_result,
            "legacy_removed": legacy,
            "kick_result": kicked,
            "setup_result": setup_result,
            "queue_result": {"skipped": True, "message": "router-managed dynamic hotspot queue"},
        }
    except Exception as exc:
        logger.error("[MAC-LOGIN] provision %s failed: %s", mac_address, exc)
        return {"error": str(exc)}


def _ensure_setup_recently(api) -> Dict[str, Any]:
    """Run ensure_router_setup unless this router passed it recently.

    Never fails the payment: a setup error is logged and returned, and the
    user is still created (the reconcile retries the setup).
    """
    key = f"{getattr(api, 'host', '')}:{getattr(api, 'port', '')}"
    now = time.monotonic()
    checked = _setup_checked_at.get(key)
    if checked is not None and now - checked < SETUP_RECHECK_SECONDS:
        return {"skipped": "checked recently"}
    try:
        result = ensure_router_setup(api)
    except Exception as exc:  # pragma: no cover - defensive
        result = {"error": str(exc)}
    if result.get("error"):
        logger.warning("[MAC-LOGIN] router %s setup at payment time failed: %s", key, result["error"])
    else:
        _setup_checked_at[key] = now
    return result


def verify_customer(api, mac_address: str) -> Dict[str, Any]:
    mac = mac_login_username(mac_address)
    user = api.get_hotspot_user_by_name(mac)
    if user.get("error"):
        return {"error": f"Hotspot user lookup failed: {user['error']}"}
    if not user.get("found"):
        return {"error": f"MAC-login user {mac} not found after provisioning"}
    return {"success": True, "hotspot_user": user.get("data")}


def set_customer_rate(api, mac_address: str, bandwidth_limit: str) -> Dict[str, Any]:
    """Move an existing MAC-login user to another rate (FUP throttle/restore)."""
    mac = mac_login_username(mac_address)
    rate_limit = parse_speed_to_mikrotik(bandwidth_limit)
    profile_result = _ensure_profile(api, rate_limit)
    if profile_result.get("error"):
        return {"error": f"profile: {profile_result['error']}"}
    user = api.get_hotspot_user_by_name(mac)
    if user.get("error") or not user.get("found"):
        return {"error": user.get("error") or f"MAC-login user {mac} not found"}
    result = api.send_command("/ip/hotspot/user/set", {
        "numbers": user["data"].get(".id"),
        "profile": profile_result["profile"],
        "disabled": "no",
    })
    if not _ok(result):
        return {"error": result.get("error")}
    kicked = _kick(api, mac, hosts=False)
    return {"success": True, "profile": profile_result["profile"], "kick_result": kicked}


def block_customer(api, mac_address: str) -> Dict[str, Any]:
    """Disable the MAC-login user and end its session (FUP block)."""
    mac = mac_login_username(mac_address)
    user = api.get_hotspot_user_by_name(mac)
    if user.get("error") or not user.get("found"):
        return {"error": user.get("error") or f"MAC-login user {mac} not found"}
    result = api.send_command("/ip/hotspot/user/set", {
        "numbers": user["data"].get(".id"), "disabled": "yes",
    })
    if not _ok(result):
        return {"error": result.get("error")}
    return {"success": True, "kick_result": _kick(api, mac, hosts=False)}


def remove_customer(api, mac_address: str) -> Dict[str, Any]:
    """Delete the MAC-login user and end its session (revert / orphan)."""
    mac = mac_login_username(mac_address)
    removed = 0
    for user in _data(api.send_command("/ip/hotspot/user/print")):
        if is_mac_login_user(user) and hotspot_user_is_for_mac(user, mac):
            if _ok(api.send_command("/ip/hotspot/user/remove", {"numbers": user.get(".id")})):
                removed += 1
    kicked = _kick(api, mac, hosts=False)
    return {"success": True, "users_removed": removed, "kick_result": kicked}


# --------------------------------------------------------------------------
# Reconcile (runs from the scheduled queue sync for MAC-login routers)
# --------------------------------------------------------------------------

def reconcile_router(api, customers_data: List[Dict[str, Any]], now: Optional[float] = None) -> Dict[str, Any]:
    """Bring one MAC-login router in line with its paid customers.

    ``customers_data`` is the complete list of active paid hotspot customers on
    this router (the queue sync's list: ``mac_address``, ``plan_speed``
    already throttled for FUP, ``fup_action``). Only called when that list was
    read successfully; an empty or partial list must never reach here.
    """
    now = time.time() if now is None else now
    summary: Dict[str, Any] = {
        "setup": None, "provisioned": 0, "already_ok": 0, "blocked_skipped": 0,
        "on_bypass": 0, "orphans_removed": 0, "unstuck": 0, "errors": [],
    }
    setup = ensure_router_setup(api)
    summary["setup"] = setup
    if setup.get("error"):
        summary["errors"].append(f"setup: {setup['error']}")

    users_res = api.send_command_optimized(
        "/ip/hotspot/user/print",
        proplist=[".id", "name", "profile", "comment", "disabled"],
    )
    if not users_res.get("success"):
        summary["errors"].append(f"user read failed: {users_res.get('error')}")
        return summary
    users = _data(users_res)
    user_by_name = {str(u.get("name", "")).upper(): u for u in users}

    wanted: Dict[str, Dict[str, Any]] = {}
    for cust in customers_data:
        try:
            wanted[mac_login_username(cust["mac_address"])] = cust
        except Exception:
            continue

    bypassed_macs = set()
    for binding in _data(api.send_command("/ip/hotspot/ip-binding/print")):
        if binding.get("mac-address") and str(binding.get("type", "")).lower() == "bypassed":
            bypassed_macs.add(normalize_mac_address(binding["mac-address"]).upper())

    # Paid devices on the network but not logged in: RouterOS tries a MAC
    # login once, when it first sees a host; if that failed (the user did not
    # exist yet, or a session limit), clearing the host makes it try again.
    stuck_hosts: Dict[str, List[str]] = {}
    active_macs = {
        normalize_mac_address(a["mac-address"]).upper()
        for a in _data(api.get_hotspot_active_minimal()) if a.get("mac-address")
    }
    for host in _data(api.get_hotspot_hosts_minimal()):
        hm = host.get("mac-address")
        if not hm or not host.get(".id"):
            continue
        hm = normalize_mac_address(hm).upper()
        if (str(host.get("authorized", "false")).lower() != "true"
                and str(host.get("bypassed", "false")).lower() != "true"
                and hm not in active_macs):
            stuck_hosts.setdefault(hm, []).append(host[".id"])

    profile_cache: Dict[str, Any] = {}
    budget = MAX_PROVISIONS_PER_RECONCILE
    unstick_budget = MAX_UNSTICK_PER_RECONCILE
    for mac, cust in wanted.items():
        if str(cust.get("fup_action") or "").lower() == "block":
            summary["blocked_skipped"] += 1
            continue
        if not cust.get("plan_speed"):
            continue
        profile = profile_name_for_rate(parse_speed_to_mikrotik(cust["plan_speed"]))
        user = user_by_name.get(mac)
        if user is None and mac in bypassed_macs:
            # Still on the bypass path (not converted yet, or delivered by a
            # path that only knows bypass). Converting is the convert script's
            # call, so a router can be moved one device at a time.
            summary["on_bypass"] += 1
            continue
        healthy = (
            user is not None
            and user.get("profile") == profile
            and str(user.get("disabled", "false")).lower() != "true"
            and mac not in bypassed_macs
        )
        if healthy:
            summary["already_ok"] += 1
            if mac in stuck_hosts and unstick_budget > 0:
                unstick_budget -= 1
                for host_id in stuck_hosts[mac]:
                    api.send_command("/ip/hotspot/host/remove", {"numbers": host_id})
                summary["unstuck"] += 1
                logger.warning("[MAC-LOGIN] paid %s was at the portal; host cleared for a new MAC login", mac)
            continue
        if budget <= 0:
            continue
        budget -= 1
        result = provision_customer(api, mac, cust["plan_speed"], note="reconcile",
                                    expiry=cust.get("expiry"), profile_cache=profile_cache)
        if result.get("error"):
            summary["errors"].append(f"{mac}: {result['error']}")
        else:
            summary["provisioned"] += 1

    for user in users:
        if not is_mac_login_user(user):
            continue
        mac = mac_of_user(user)
        if not mac or mac in wanted:
            continue
        created = user_created_at(user)
        if created is not None and now - created < ORPHAN_GRACE_SECONDS:
            continue
        if _ok(api.send_command("/ip/hotspot/user/remove", {"numbers": user.get(".id")})):
            summary["orphans_removed"] += 1
            _kick(api, mac, hosts=False)
            logger.warning("[MAC-LOGIN] removed unpaid MAC-login user %s", mac)
        else:
            summary["errors"].append(f"orphan {mac}: remove failed")
    return summary
