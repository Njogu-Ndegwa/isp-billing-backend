"""Reseller block list for hotspot devices (feedback board post 14).

A reseller can stop one device (by MAC) from using the hotspot at all, the
login page included, with a RouterOS ``/ip hotspot ip-binding`` entry of
``type=blocked``. The router binding is the only record: no DB table.

Every block we write carries ``BLOCK_TAG`` in its comment. Code that removes or
rewrites ip-bindings (expiry cleanup, safety nets, payment delivery, FUP,
force-remove, ...) calls ``is_reseller_block`` and leaves such a binding alone,
so a blocked device stays blocked until the reseller unblocks it, even if it
pays. The comment never holds ``EXP:``/``USER:`` or a MAC (``safe_reason``
drops colons), so the router-side expiry reaper and the MAC/username matchers
never mistake it for a paid customer's binding.

The sync helpers below talk to the router; callers run them in a thread after
closing their DB session (AGENTS.md, Database Session Discipline).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.protected_devices import is_protected_device
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

logger = logging.getLogger(__name__)

BLOCK_TAG = "BW-RESELLER-BLOCK"
BINDINGS = "/ip/hotspot/ip-binding"
_REASON_MAX = 60
_STAMP_FMT = "%Y%m%dT%H%MZ"
# Payment delivery's error for a blocked device (shown as the attempt's last_error).
BLOCKED_DELIVERY_ERROR = "Device is blocked by the reseller on this router; unblock it to deliver"
# Not a device: refuse outright.
_NOT_A_DEVICE = {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}


def is_reseller_block(binding: Optional[Dict[str, Any]]) -> bool:
    """True for an ip-binding a reseller added with the block endpoint."""
    return bool(binding) and BLOCK_TAG in str(binding.get("comment") or "")


def safe_reason(reason: Optional[str]) -> str:
    """Letters, digits, spaces and . , ' _ - only, at most 60 characters."""
    text = re.sub(r"[^A-Za-z0-9 .,'_-]+", " ", str(reason or ""))
    return re.sub(r"\s+", " ", text).strip()[:_REASON_MAX]


def block_comment(reason: Optional[str], now: Optional[datetime] = None) -> str:
    stamp = (now or datetime.utcnow()).strftime(_STAMP_FMT)
    return f"{BLOCK_TAG}|{safe_reason(reason)}|{stamp}"


def parse_block(binding: Dict[str, Any]) -> Dict[str, Any]:
    parts = str(binding.get("comment") or "").split("|")
    reason = parts[1] if len(parts) > 1 else ""
    blocked_at = None
    if len(parts) > 2:
        try:
            blocked_at = datetime.strptime(parts[2], _STAMP_FMT).isoformat() + "Z"
        except ValueError:
            blocked_at = None
    mac = binding.get("mac-address") or ""
    return {
        "mac_address": normalize_mac_address(mac) if mac else "",
        "reason": reason or None,
        "blocked_at": blocked_at,
        "disabled": str(binding.get("disabled", "false")).lower() == "true",
    }


def is_blockable_mac(mac: str) -> bool:
    return normalize_mac_address(mac) not in _NOT_A_DEVICE


def _rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(result, dict) and result.get("success"):
        return result.get("data") or []
    return []


def _same_mac(row: Dict[str, Any], mac: str) -> bool:
    value = row.get("mac-address")
    return bool(value) and normalize_mac_address(value) == mac


def _api(router_info: dict) -> MikroTikAPI:
    return MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )


def _protected_reason(api: MikroTikAPI, mac: str) -> Optional[str]:
    """Why this MAC must not be blocked (router port / infrastructure), or None."""
    for iface in _rows(api.send_command("/interface/print")):
        if _same_mac(iface, mac):
            return f"{mac} is the router's own port {iface.get('name', '')}".strip()
    for arp in _rows(api.send_command("/ip/arp/print")):
        if _same_mac(arp, mac) and is_protected_device(
            ip_address=arp.get("address", ""), interface=arp.get("interface", ""),
        ):
            return (f"{mac} ({arp.get('address', '')} on {arp.get('interface', '')}) is a "
                    "management/infrastructure device")
    return None


def _neutralise_user_expiry(api: MikroTikAPI, mac: str) -> int:
    """Turn ``EXP:`` into ``EXX:`` on this device's hotspot users.

    Routers on reaper script v4 remove EVERY ip-binding of a MAC whose
    MAC-login user (``MACLOGIN|...|EXP:``) is due, which would take the block
    off. ``EXX:`` is the reaper's own "forgotten" marker; the server cleanup
    still removes the user when the customer expires.
    """
    compact = mac.replace(":", "")
    changed = 0
    for user in _rows(api.send_command("/ip/hotspot/user/print")):
        name = str(user.get("name", "")).upper()
        comment = str(user.get("comment") or "")
        if name in (mac, compact) and "EXP:" in comment and user.get(".id"):
            res = api.send_command("/ip/hotspot/user/set", {
                "numbers": user[".id"], "comment": comment.replace("EXP:", "EXX:"),
            })
            if not res.get("error"):
                changed += 1
    return changed


def _kick(api: MikroTikAPI, mac: str) -> int:
    kicked = 0
    for menu in ("/ip/hotspot/active", "/ip/hotspot/host"):
        for row in _rows(api.send_command(f"{menu}/print")):
            if _same_mac(row, mac) and row.get(".id"):
                if not api.send_command(f"{menu}/remove", {"numbers": row[".id"]}).get("error"):
                    kicked += 1
    return kicked


def block_mac_sync(router_info: dict, mac_address: str, reason: Optional[str] = None) -> Dict[str, Any]:
    mac = normalize_mac_address(mac_address)
    api = _api(router_info)
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        protected = _protected_reason(api, mac)
        if protected:
            return {"error": "protected_device", "detail": f"Cannot block {protected}."}

        listed = api.send_command(f"{BINDINGS}/print")
        if not listed.get("success"):
            return {"error": "router_error", "detail": listed.get("error") or "Could not read ip-bindings"}
        bindings = listed.get("data") or []
        comment = block_comment(reason)
        existing = next((b for b in bindings if _same_mac(b, mac)), None)

        if existing and existing.get(".id"):
            action = "updated" if is_reseller_block(existing) else "converted"
            res = api.send_command(f"{BINDINGS}/set", {
                "numbers": existing[".id"], "type": "blocked", "comment": comment, "disabled": "no",
            })
            if res.get("error"):
                return {"error": "router_error", "detail": res["error"]}
            first = bindings[0].get(".id")
            if first and first != existing[".id"]:
                # Top of the table, ahead of any address-based bypass.
                api.send_command(f"{BINDINGS}/move", {"numbers": existing[".id"], "destination": first})
        else:
            action = "added"
            args = {"mac-address": mac, "type": "blocked", "comment": comment}
            if bindings and bindings[0].get(".id"):
                args["place-before"] = bindings[0][".id"]
            res = api.send_command(f"{BINDINGS}/add", args)
            if res.get("error"):
                return {"error": "router_error", "detail": res["error"]}

        users_changed = _neutralise_user_expiry(api, mac)
        kicked = _kick(api, mac)
        logger.info("[HOTSPOT-BLOCK] %s %s on %s (kicked %s)", action, mac, router_info.get("ip"), kicked)
        return {"success": True, "action": action, "mac_address": mac, "reason": safe_reason(reason) or None,
                "sessions_ended": kicked, "users_expiry_untagged": users_changed}
    finally:
        api.disconnect()


def unblock_mac_sync(router_info: dict, mac_address: str) -> Dict[str, Any]:
    mac = normalize_mac_address(mac_address)
    api = _api(router_info)
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        listed = api.send_command(f"{BINDINGS}/print")
        if not listed.get("success"):
            return {"error": "router_error", "detail": listed.get("error") or "Could not read ip-bindings"}
        removed = 0
        for b in listed.get("data") or []:
            if _same_mac(b, mac) and is_reseller_block(b) and b.get(".id"):
                res = api.send_command(f"{BINDINGS}/remove", {"numbers": b[".id"]})
                if res.get("error"):
                    return {"error": "router_error", "detail": res["error"]}
                removed += 1
        if not removed:
            return {"error": "not_blocked"}
        # Clear the stale host row so the device gets the login page at once.
        for host in _rows(api.send_command("/ip/hotspot/host/print")):
            if _same_mac(host, mac) and host.get(".id"):
                api.send_command("/ip/hotspot/host/remove", {"numbers": host[".id"]})
        logger.info("[HOTSPOT-BLOCK] unblocked %s on %s", mac, router_info.get("ip"))
        return {"success": True, "mac_address": mac, "removed": removed}
    finally:
        api.disconnect()


def list_blocks_sync(router_info: dict) -> Dict[str, Any]:
    api = _api(router_info)
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        listed = api.send_command(f"{BINDINGS}/print")
        if not listed.get("success"):
            return {"error": "router_error", "detail": listed.get("error") or "Could not read ip-bindings"}
        return {"success": True, "blocked": [parse_block(b) for b in listed.get("data") or []
                                             if is_reseller_block(b)]}
    finally:
        api.disconnect()
