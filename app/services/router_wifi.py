"""Read and rename the hotspot Wi-Fi name (SSID) on a reseller's MikroTik.

Same rules the support workers' rename script used by hand since October,
now behind a dashboard endpoint:

* Only access-point interfaces are renamed. A station/client interface can be
  the router's internet uplink; renaming it makes the router hunt for a
  network that does not exist and takes the whole site offline (the 22 Oct
  Dreamplug lesson).
* Only interfaces that serve the hotspot: a port of the bridge the hotspot
  server runs on (or the hotspot interface itself). A Wi-Fi in some other
  bridge, or in none, is left alone.
* Only enabled master interfaces. Virtual APs keep their own names.
* Only the SSID changes. Security profile, password, band, channel: untouched.
* The result is read back from the router; a rename that did not stick is
  reported as not verified.

Covers legacy ``/interface wireless`` (RouterOS 6, and RouterOS 7 boards on the
wireless package) and the RouterOS 7 ``/interface wifi`` package (and its
7.12-and-older name ``wifiwave2``).

Everything here is synchronous and talks to the router through an object with
``send_command`` (MikroTikAPI in production, a fake in tests). Run it through
``run_with_guard`` with no DB session open.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SSID_MAX_LEN = 32  # 802.11 limit (bytes; we only accept ASCII so chars == bytes)

# Modes that broadcast to customers. Anything else may be the router's uplink.
AP_MODES = frozenset({"ap-bridge", "bridge", "ap"})

# Our provisioning names the hotspot bridge "bridge"; used when the router has
# no hotspot server to read the bridge from.
DEFAULT_HOTSPOT_BRIDGE = "bridge"

# (menu, ssid key used by /set) per Wi-Fi package.
MENU_WIRELESS = "/interface/wireless"
MENU_WIFI = "/interface/wifi"
MENU_WIFIWAVE2 = "/interface/wifiwave2"
WIFI_MENUS = (MENU_WIRELESS, MENU_WIFI, MENU_WIFIWAVE2)

# Why an interface is not renamed (stable codes for the frontend and tests).
REASON_DISABLED = "disabled"
REASON_CLIENT_MODE = "client_mode"
REASON_NOT_HOTSPOT = "not_hotspot"
REASON_VIRTUAL = "virtual"

# Rate limit per router: a rename drops every Wi-Fi client, so a few per hour
# is plenty for a reseller fixing a typo, and stops a stuck retry loop.
RENAME_LIMIT = 5
RENAME_WINDOW_SECONDS = 3600


class InvalidSsid(ValueError):
    pass


def validate_ssid(value: Optional[str]) -> str:
    """The SSID a reseller typed, or InvalidSsid with a message they can act on.

    Printable ASCII only: older RouterOS builds and many phones show anything
    else as garbage. 1-32 characters, no leading/trailing spaces.
    """
    ssid = (value or "").strip()
    if not ssid:
        raise InvalidSsid("Type a Wi-Fi name.")
    bad = sorted({ch for ch in ssid if not (0x20 <= ord(ch) < 0x7F)})
    if bad:
        raise InvalidSsid(
            "Use only English letters, numbers, spaces and common symbols in the Wi-Fi name "
            f"(not allowed: {' '.join(bad)})."
        )
    if len(ssid) > SSID_MAX_LEN:
        raise InvalidSsid(f"A Wi-Fi name can be at most {SSID_MAX_LEN} characters (this one is {len(ssid)}).")
    return ssid


# ---------------------------------------------------------------------------
# Per-router "one rename at a time" claim + rate limit
# ---------------------------------------------------------------------------

@dataclass
class RenameClaim:
    router_id: int
    started: bool = False


_claims: Dict[int, RenameClaim] = {}
_history: Dict[int, Deque[float]] = {}
_guard = threading.Lock()


def try_claim(router_id: int) -> Optional[RenameClaim]:
    """Claim the router for one rename; None if one is already running.

    A thread-safe dict (like port_restart) so a request that times out keeps
    the claim until its worker thread has finished talking to the router.
    """
    with _guard:
        if router_id in _claims:
            return None
        claim = RenameClaim(router_id=router_id)
        _claims[router_id] = claim
        return claim


def begin_claim(claim: RenameClaim) -> bool:
    with _guard:
        if _claims.get(claim.router_id) is not claim:
            return False
        claim.started = True
        return True


def release_claim(claim: RenameClaim) -> None:
    with _guard:
        if _claims.get(claim.router_id) is claim:
            del _claims[claim.router_id]


def abandon_if_not_started(claim: RenameClaim) -> None:
    with _guard:
        if not claim.started and _claims.get(claim.router_id) is claim:
            del _claims[claim.router_id]


def rename_in_progress(router_id: int) -> bool:
    with _guard:
        return router_id in _claims


def rate_limit_wait(router_id: int, now: Optional[float] = None) -> int:
    """Seconds until another rename is allowed on this router (0 = allowed)."""
    now = time.monotonic() if now is None else now
    with _guard:
        hist = _history.get(router_id)
        if not hist:
            return 0
        while hist and now - hist[0] >= RENAME_WINDOW_SECONDS:
            hist.popleft()
        if len(hist) < RENAME_LIMIT:
            return 0
        return max(1, int(RENAME_WINDOW_SECONDS - (now - hist[0])) + 1)


def record_rename(router_id: int, now: Optional[float] = None) -> None:
    now = time.monotonic() if now is None else now
    with _guard:
        _history.setdefault(router_id, deque()).append(now)


def reset_state() -> None:
    """Tests only."""
    with _guard:
        _claims.clear()
        _history.clear()


# ---------------------------------------------------------------------------
# Reading the router
# ---------------------------------------------------------------------------

def _rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(result.get("data") or []) if result.get("success") else []


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "yes")


class RouterStateError(Exception):
    pass


def _hotspot_attachments(api) -> Tuple[set, Dict[str, str]]:
    """(interfaces the hotspot serves, interface -> bridge). Fails closed when
    the bridge ports cannot be read: without them we cannot tell a hotspot AP
    from an uplink."""
    hotspot = {r.get("interface") for r in _rows(api.send_command("/ip/hotspot/print")) if r.get("interface")}
    if not hotspot:
        hotspot = {DEFAULT_HOTSPOT_BRIDGE}
    ports = api.send_command("/interface/bridge/port/print")
    if not ports.get("success"):
        raise RouterStateError("Could not read the router's bridge ports: " + str(ports.get("error") or "unknown error"))
    bridge_of = {r.get("interface"): r.get("bridge") for r in _rows(ports) if r.get("interface")}
    return hotspot, bridge_of


def _wifi_profiles(api, menu: str) -> Dict[str, Dict[str, Any]]:
    """RouterOS 7 wifi: /interface/wifi/configuration rows by name, for
    interfaces that take their SSID/mode from a configuration profile."""
    return {r.get("name"): r for r in _rows(api.send_command(menu + "/configuration/print")) if r.get("name")}


def _describe(menu: str, row: Dict[str, Any], profiles: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    if menu == MENU_WIRELESS:
        ssid = row.get("ssid")
        mode = row.get("mode") or "ap-bridge"
    else:
        profile = profiles.get(row.get("configuration") or "") or {}
        ssid = row.get("configuration.ssid") or row.get("ssid") or profile.get("ssid")
        mode = row.get("configuration.mode") or row.get("mode") or profile.get("mode") or "ap"
    return {
        "id": row.get(".id"),
        "name": row.get("name"),
        "menu": menu.rsplit("/", 1)[-1],
        "ssid": ssid,
        "mode": mode,
        "disabled": _is_true(row.get("disabled")),
        "running": _is_true(row.get("running")),
        "virtual": bool(row.get("master-interface")),
    }


def read_wifi(api) -> Dict[str, Any]:
    """Every Wi-Fi interface the router has, each marked renameable or not.

    ``has_wireless`` is False when no Wi-Fi menu answers (hEX, RB4011, CCR,
    RB5009...): the Wi-Fi then comes from a separate access point.
    """
    hotspot, bridge_of = _hotspot_attachments(api)
    interfaces: List[Dict[str, Any]] = []
    has_wireless = False
    for menu in WIFI_MENUS:
        res = api.send_command(menu + "/print")
        if not res.get("success"):
            continue
        rows = _rows(res)
        if not rows:
            continue
        has_wireless = True
        profiles = _wifi_profiles(api, menu) if menu != MENU_WIRELESS else {}
        for row in rows:
            item = _describe(menu, row, profiles)
            item["bridge"] = bridge_of.get(item["name"])
            in_hotspot = item["name"] in hotspot or (item["bridge"] in hotspot)
            if item["disabled"]:
                reason = REASON_DISABLED
            elif item["virtual"]:
                reason = REASON_VIRTUAL
            elif item["mode"] not in AP_MODES:
                reason = REASON_CLIENT_MODE
            elif not in_hotspot:
                reason = REASON_NOT_HOTSPOT
            else:
                reason = None
            item["renameable"] = reason is None
            item["reason"] = reason
            item["_menu_path"] = menu
            interfaces.append(item)
    return {"has_wireless": has_wireless, "interfaces": interfaces}


def _public(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in item.items() if not k.startswith("_") and k != "id"}


# ---------------------------------------------------------------------------
# Entry points (sync; run through run_with_guard)
# ---------------------------------------------------------------------------

def _make_api(router_info: Dict[str, Any], api_factory):
    if api_factory is None:
        from app.services.mikrotik_api import MikroTikAPI
        api_factory = MikroTikAPI
    return api_factory(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=12,
        connect_timeout=5,
    )


def _connect(router_info, api_factory):
    api = _make_api(router_info, api_factory)
    if not api.connect():
        return None, {"error": "connect_failed",
                      "message": getattr(api, "last_connect_error", None) or "Failed to connect to router"}
    return api, None


def _disconnect(api) -> None:
    try:
        api.disconnect()
    except Exception:
        pass


NO_WIRELESS_MESSAGE = (
    "This router has no built-in Wi-Fi, so the Wi-Fi name comes from a separate access point "
    "(for example a Tenda). Change the name on that access point."
)
NONE_ELIGIBLE_MESSAGE = (
    "No hotspot Wi-Fi on this router can be renamed safely: every Wi-Fi interface is turned off, "
    "a client/uplink, a virtual AP, or outside the hotspot network."
)


def read_wifi_sync(router_info: Dict[str, Any], *, api_factory=None) -> Dict[str, Any]:
    """Current Wi-Fi names for the dashboard. Read-only."""
    api, err = _connect(router_info, api_factory)
    if err:
        return err
    try:
        state = read_wifi(api)
        current = sorted({i["ssid"] for i in state["interfaces"] if i["renameable"] and i["ssid"]})
        return {
            "success": True,
            "has_wireless": state["has_wireless"],
            "ssids": current,
            "interfaces": [_public(i) for i in state["interfaces"]],
        }
    except RouterStateError as exc:
        return {"error": "state_unreadable", "message": str(exc)}
    finally:
        _disconnect(api)


def rename_wifi_sync(
    router_info: Dict[str, Any],
    new_ssid: str,
    claim: Optional[RenameClaim] = None,
    *,
    api_factory=None,
) -> Dict[str, Any]:
    """Set ``new_ssid`` on every renameable hotspot AP interface, then read back.

    Returns {"success": True, "verified": bool, "interfaces": [...], "skipped": [...]}
    or {"error": code, "message": ...}. ``new_ssid`` must already be validated.
    """
    if claim is not None and not begin_claim(claim):
        return {"error": "cancelled", "message": "The request expired before it started."}
    try:
        api, err = _connect(router_info, api_factory)
        if err:
            return err
        try:
            try:
                state = read_wifi(api)
            except RouterStateError as exc:
                return {"error": "state_unreadable", "message": str(exc)}
            if not state["has_wireless"]:
                return {"error": "no_wireless", "message": NO_WIRELESS_MESSAGE}
            targets = [i for i in state["interfaces"] if i["renameable"]]
            skipped = [_public(i) for i in state["interfaces"] if not i["renameable"]]
            if not targets:
                return {"error": "no_eligible_wifi", "message": NONE_ELIGIBLE_MESSAGE, "skipped": skipped}

            results = []
            for item in targets:
                out = {"name": item["name"], "menu": item["menu"], "ssid_before": item["ssid"]}
                if item["ssid"] != new_ssid:
                    key = "ssid" if item["_menu_path"] == MENU_WIRELESS else "configuration.ssid"
                    res = api.send_command(item["_menu_path"] + "/set", {".id": item["id"], key: new_ssid})
                    out["set_error"] = None if res.get("success") else str(res.get("error") or "set failed")
                results.append(out)

            # Verify by reading back.
            try:
                after = {(i["_menu_path"], i["name"]): i["ssid"] for i in read_wifi(api)["interfaces"]}
            except RouterStateError:
                after = {}
            for item, out in zip(targets, results):
                out["ssid_after"] = after.get((item["_menu_path"], item["name"]))
                out["verified"] = out["ssid_after"] == new_ssid
            verified = all(o["verified"] for o in results)
            return {"success": True, "verified": verified, "ssid": new_ssid,
                    "interfaces": results, "skipped": skipped}
        finally:
            _disconnect(api)
    finally:
        if claim is not None:
            release_claim(claim)
