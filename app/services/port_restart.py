"""Restart the device behind one MikroTik LAN port by bouncing that port.

Resellers hang Tenda (and other) access points off their MikroTik. When one
freezes, the fix on site is to pull its cable. This module does the same thing
remotely without ever logging into the access point:

* the port has PoE out and is powering something -> power-cycle the PoE
  (RouterOS ``power-cycle`` when the version has it, else poe-out off, wait,
  back to the exact previous setting);
* otherwise -> disable the interface, wait, enable it again.

The original state is always put back, including when something fails between
the two steps (retries with a fresh API connection if the first one dropped).

Hard guards refuse the ports that would cut the router off from the internet
or from us: ether1 and anything carrying the default route, a DHCP client or a
PPPoE client (plus load-balancer WANs), the management tunnel interface, the
interface our API session arrives on, anything that is not ethernet, and any
port that is not in a hotspot / plain / PPPoE / dual LAN. The same evaluation
backs the read-only eligibility list the dashboard uses to grey out buttons,
so the UI and the endpoint can never disagree.

Everything here is synchronous and talks to the router through an object with
``send_command`` / ``send_command_optimized`` (MikroTikAPI in production, a
fake in tests). Run it through ``run_with_guard`` with no DB session open.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

logger = logging.getLogger(__name__)

POE_OFF_SECONDS = 8
BOUNCE_SECONDS = 5
RESTORE_ATTEMPTS = 3

# Bridges our own port features create for customer LANs.
KNOWN_LAN_BRIDGES = frozenset({"bridge", "bridge-plain", "bridge-pppoe", "bridge-dual"})

METHOD_POE_POWER_CYCLE = "poe_power_cycle"
METHOD_POE_TOGGLE = "poe_toggle"
METHOD_INTERFACE_BOUNCE = "interface_bounce"

METHOD_LABELS = {
    METHOD_POE_POWER_CYCLE: "PoE power-cycle",
    METHOD_POE_TOGGLE: "PoE off/on",
    METHOD_INTERFACE_BOUNCE: "port disable/enable",
}

# Refusal codes (stable, for the frontend and tests).
REASON_NOT_FOUND = "not_found"
REASON_NOT_ETHERNET = "not_ethernet"
REASON_WAN = "wan"
REASON_MANAGEMENT = "management"
REASON_API_INGRESS = "api_ingress"
REASON_NOT_LAN = "not_lan"
REASON_DISABLED = "disabled"


# ---------------------------------------------------------------------------
# Per-router "one restart at a time" claim
# ---------------------------------------------------------------------------

@dataclass
class RestartClaim:
    router_id: int
    started: bool = False


_claims: Dict[int, RestartClaim] = {}
_claims_guard = threading.Lock()


def try_claim(router_id: int) -> Optional[RestartClaim]:
    """Claim the router for one port restart; None if one is already running.

    A thread-safe dict rather than an asyncio.Lock on purpose: if the request
    times out, the worker thread keeps running until it has put the port back,
    and the claim must stay held until then. The thread releases it.
    """
    with _claims_guard:
        if router_id in _claims:
            return None
        claim = RestartClaim(router_id=router_id)
        _claims[router_id] = claim
        return claim


def release_claim(claim: RestartClaim) -> None:
    with _claims_guard:
        if _claims.get(claim.router_id) is claim:
            del _claims[claim.router_id]


def begin_claim(claim: RestartClaim) -> bool:
    """Called by the worker thread before touching the router. False when the
    request already gave up on this claim (thread started too late)."""
    with _claims_guard:
        if _claims.get(claim.router_id) is not claim:
            return False
        claim.started = True
        return True


def abandon_if_not_started(claim: RestartClaim) -> None:
    """Called by the request after run_with_guard returns. Drops the claim only
    if the worker never began; a running worker releases it itself."""
    with _claims_guard:
        if not claim.started and _claims.get(claim.router_id) is claim:
            del _claims[claim.router_id]


def restart_in_progress(router_id: int) -> bool:
    with _claims_guard:
        return router_id in _claims


def reset_claims() -> None:
    """Tests only."""
    with _claims_guard:
        _claims.clear()


# ---------------------------------------------------------------------------
# Reading the router
# ---------------------------------------------------------------------------

class RouterStateError(Exception):
    pass


def _rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(result.get("data") or []) if result.get("success") else []


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "yes")


def read_port_state(api) -> Dict[str, Any]:
    """Every RouterOS table the guards need. Raises RouterStateError when a
    table the guards depend on cannot be read (fail closed)."""

    def required(command: str, **kwargs) -> List[Dict[str, Any]]:
        if kwargs:
            result = api.send_command_optimized(command, **kwargs)
        else:
            result = api.send_command(command)
        if not result.get("success"):
            raise RouterStateError(
                f"Could not read {command} from the router: {result.get('error') or 'no answer'}"
            )
        return _rows(result)

    def optional(command: str) -> Optional[List[Dict[str, Any]]]:
        result = api.send_command(command)
        return _rows(result) if result.get("success") else None

    return {
        "interfaces": required("/interface/print"),
        "bridge_ports": required("/interface/bridge/port/print"),
        "routes": required("/ip/route/print", query="?dst-address=0.0.0.0/0"),
        "addresses": required("/ip/address/print"),
        "dhcp_clients": required("/ip/dhcp-client/print"),
        "pppoe_clients": required("/interface/pppoe-client/print"),
        "vlans": optional("/interface/vlan/print") or [],
        "active_users": required("/user/active/print"),
        "hotspot_servers": optional("/ip/hotspot/print") or [],
        "pppoe_servers": optional("/interface/pppoe-server/server/print") or [],
        # Boards without PoE have no such menu; None means "no PoE here".
        "poe": optional("/interface/ethernet/poe/print"),
    }


# ---------------------------------------------------------------------------
# Guard evaluation (pure)
# ---------------------------------------------------------------------------

@dataclass
class PortVerdict:
    name: str
    eligible: bool
    reason_code: Optional[str] = None
    reason: Optional[str] = None
    method: Optional[str] = None  # "poe" or "bounce" when eligible
    poe_out: Optional[str] = None
    bridge: Optional[str] = None
    interface_id: Optional[str] = None
    poe_id: Optional[str] = None

    def public(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "eligible": self.eligible,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "method": self.method,
            "poe_out": self.poe_out,
            "bridge": self.bridge,
        }


@dataclass
class _Topology:
    by_name: Dict[str, Dict[str, Any]]
    bridge_names: Set[str]
    bridge_of: Dict[str, str]
    members_of: Dict[str, List[str]]
    vlan_parent: Dict[str, str]
    pppoe_client_parent: Dict[str, str]
    wan: Dict[str, str] = field(default_factory=dict)          # physical port -> why
    management: Set[str] = field(default_factory=set)
    management_logical: Set[str] = field(default_factory=set)
    api_ingress: Set[str] = field(default_factory=set)


_IFACE_TOKEN = re.compile(r"(?:%|via\s+)([A-Za-z0-9_.\-<>]+)")


def _expand_physical(topo: _Topology, name: str, _seen: Optional[Set[str]] = None) -> Set[str]:
    """Physical (and intermediate) interfaces underneath a logical one."""
    seen = _seen if _seen is not None else set()
    if not name or name in seen:
        return set()
    seen.add(name)
    out = {name}
    if name in topo.pppoe_client_parent:
        out |= _expand_physical(topo, topo.pppoe_client_parent[name], seen)
    if name in topo.vlan_parent:
        out |= _expand_physical(topo, topo.vlan_parent[name], seen)
    if name in topo.bridge_names:
        for member in topo.members_of.get(name, []):
            out |= _expand_physical(topo, member, seen)
    return out


def _networks(addresses: Iterable[Dict[str, Any]]):
    for row in addresses:
        if _is_true(row.get("disabled")) or _is_true(row.get("invalid")):
            continue
        try:
            iface = ipaddress.ip_interface(str(row.get("address", "")).strip())
        except ValueError:
            continue
        yield iface, row.get("interface", "")


def _interfaces_for_ip(addresses, ip_text: str) -> Set[str]:
    try:
        ip = ipaddress.ip_address(str(ip_text).strip())
    except ValueError:
        return set()
    return {name for iface, name in _networks(addresses) if name and ip in iface.network}


def _interfaces_owning_ip(addresses, ip_text: str) -> Set[str]:
    try:
        ip = ipaddress.ip_address(str(ip_text).strip())
    except ValueError:
        return set()
    return {name for iface, name in _networks(addresses) if name and iface.ip == ip}


def _build_topology(state: Dict[str, Any], router_ip: str, lb_wan_ports: Iterable[str]) -> _Topology:
    interfaces = state["interfaces"]
    by_name = {row.get("name", ""): row for row in interfaces if row.get("name")}
    bridge_names = {name for name, row in by_name.items() if row.get("type") == "bridge"}
    bridge_of: Dict[str, str] = {}
    members_of: Dict[str, List[str]] = {}
    for row in state["bridge_ports"]:
        iface, bridge = row.get("interface", ""), row.get("bridge", "")
        if iface and bridge:
            bridge_of[iface] = bridge
            members_of.setdefault(bridge, []).append(iface)
            bridge_names.add(bridge)
    vlan_parent = {
        row.get("name", ""): row.get("interface", "")
        for row in state.get("vlans") or [] if row.get("name")
    }
    pppoe_client_parent = {
        row.get("name", ""): row.get("interface", "")
        for row in state["pppoe_clients"] if row.get("name")
    }
    topo = _Topology(
        by_name=by_name,
        bridge_names=bridge_names,
        bridge_of=bridge_of,
        members_of=members_of,
        vlan_parent=vlan_parent,
        pppoe_client_parent=pppoe_client_parent,
    )

    def mark_wan(logical: str, why: str) -> None:
        for name in _expand_physical(topo, logical):
            topo.wan.setdefault(name, why)

    # Convention on every Bitwave router: ether1 is the uplink.
    mark_wan("ether1", "ether1 is the internet (WAN) port")

    for row in state["routes"]:
        if str(row.get("dst-address", "")).strip() != "0.0.0.0/0" or _is_true(row.get("disabled")):
            continue
        why = "this port carries the router's internet (default route)"
        candidates: Set[str] = set()
        for key in ("gateway", "immediate-gw", "gateway-status", "vrf-interface"):
            value = str(row.get(key) or "")
            candidates.update(_IFACE_TOKEN.findall(value))
            for part in re.split(r"[,\s]+", value):
                part = part.split("%")[0]
                if part in by_name or part in bridge_names or part in pppoe_client_parent:
                    candidates.add(part)
                else:
                    candidates.update(_interfaces_for_ip(state["addresses"], part))
        for name in candidates:
            mark_wan(name, why)

    for row in state["dhcp_clients"]:
        if not _is_true(row.get("disabled")) and row.get("interface"):
            mark_wan(row["interface"], "this port gets the router's internet address (DHCP client)")
    for row in state["pppoe_clients"]:
        if not _is_true(row.get("disabled")) and row.get("interface"):
            mark_wan(row["interface"], "this port dials the router's internet (PPPoE client)")
    for port in lb_wan_ports or []:
        mark_wan(str(port), "this port is an internet line in load balancing")

    # The management tunnel: whatever holds the address we connect to.
    for logical in _interfaces_owning_ip(state["addresses"], router_ip):
        topo.management_logical.add(logical)
        topo.management |= _expand_physical(topo, logical)

    # Where our API session(s) come in from.
    for row in state["active_users"]:
        if not str(row.get("via", "")).lower().startswith("api"):
            continue
        for logical in _interfaces_for_ip(state["addresses"], row.get("address", "")):
            topo.api_ingress |= _expand_physical(topo, logical)

    return topo


def _lan_attachment(state: Dict[str, Any], topo: _Topology, name: str) -> Optional[str]:
    """Name of the customer LAN this port belongs to, or None."""
    hotspot_ifaces = {
        row.get("interface", "") for row in state.get("hotspot_servers") or []
        if not _is_true(row.get("disabled"))
    }
    pppoe_ifaces = {
        row.get("interface", "") for row in state.get("pppoe_servers") or []
        if not _is_true(row.get("disabled"))
    }
    bridge = topo.bridge_of.get(name)
    if bridge:
        if bridge in KNOWN_LAN_BRIDGES or bridge in hotspot_ifaces or bridge in pppoe_ifaces:
            return bridge
        return None
    if name in hotspot_ifaces or name in pppoe_ifaces:
        return name  # server bound straight to the port (direct PPPoE)
    return None


def evaluate_port(
    state: Dict[str, Any],
    name: str,
    *,
    router_ip: str,
    lb_wan_ports: Iterable[str] = (),
    topology: Optional[_Topology] = None,
) -> PortVerdict:
    topo = topology or _build_topology(state, router_ip, lb_wan_ports)
    row = topo.by_name.get(name)
    if row is None:
        return PortVerdict(name, False, REASON_NOT_FOUND, "This port does not exist on the router.")

    bridge = topo.bridge_of.get(name)
    verdict = PortVerdict(name, False, bridge=bridge, interface_id=row.get(".id"))

    def refuse(code: str, reason: str) -> PortVerdict:
        verdict.reason_code, verdict.reason = code, reason
        return verdict

    if name in topo.management_logical or name in topo.management:
        return refuse(REASON_MANAGEMENT, "This is the router's management connection to Bitwave; restarting it would cut the router off.")
    if row.get("type") != "ether":
        return refuse(REASON_NOT_ETHERNET, "Only ethernet ports can be restarted.")
    if name in topo.wan:
        return refuse(REASON_WAN, f"Internet port, not restarted: {topo.wan[name]}.")
    if name in topo.api_ingress:
        return refuse(REASON_API_INGRESS, "Bitwave reaches the router through this port; restarting it would cut the connection.")
    if _lan_attachment(state, topo, name) is None:
        return refuse(REASON_NOT_LAN, "This port is not in a hotspot, plain or PPPoE LAN.")
    if _is_true(row.get("disabled")):
        return refuse(REASON_DISABLED, "This port is turned off on the router.")

    poe_rows = state.get("poe")
    poe_row = next((r for r in poe_rows or [] if r.get("name") == name), None)
    poe_out = (poe_row or {}).get("poe-out")
    verdict.poe_out = poe_out
    verdict.eligible = True
    if poe_row is not None and poe_out and poe_out != "off":
        verdict.method = "poe"
        verdict.poe_id = poe_row.get(".id") or name
    else:
        verdict.method = "bounce"
    return verdict


def evaluate_all_ethernet(state: Dict[str, Any], *, router_ip: str, lb_wan_ports: Iterable[str] = ()) -> List[PortVerdict]:
    topo = _build_topology(state, router_ip, lb_wan_ports)
    return [
        evaluate_port(state, name, router_ip=router_ip, topology=topo)
        for name, row in topo.by_name.items()
        if row.get("type") == "ether"
    ]


# ---------------------------------------------------------------------------
# Performing the restart
# ---------------------------------------------------------------------------

def _ok(result: Dict[str, Any]) -> bool:
    return bool(result.get("success"))


def _restore(api, reconnect: Callable[[], bool], command: str, args: Dict[str, str], sleep) -> Optional[str]:
    """Run the restore command, reconnecting between attempts. None on success."""
    last_error = None
    for attempt in range(RESTORE_ATTEMPTS):
        try:
            if attempt and not reconnect():
                last_error = "could not reconnect to the router"
                sleep(1)
                continue
            result = api.send_command(command, args)
            if _ok(result):
                return None
            last_error = result.get("error") or "router rejected the command"
        except Exception as exc:  # the socket can die mid-restore
            last_error = str(exc)
        sleep(1)
    return last_error


def _find(rows: Optional[List[Dict[str, Any]]], name: str) -> Optional[Dict[str, Any]]:
    return next((r for r in rows or [] if r.get("name") == name), None)


def _poe_restart(api, reconnect, verdict: PortVerdict, sleep, off_seconds: int) -> Dict[str, Any]:
    original = verdict.poe_out or "auto-on"
    target = verdict.poe_id or verdict.name

    cycle = api.send_command(
        "/interface/ethernet/poe/power-cycle",
        {"numbers": target, "duration": f"{off_seconds}s"},
    )
    if _ok(cycle):
        sleep(off_seconds + 2)
        check = api.send_command("/interface/ethernet/poe/print")
        row = _find(_rows(check), verdict.name) if _ok(check) else None
        now = (row or {}).get("poe-out")
        if now is not None and now != original:
            # power-cycle never edits the setting, but put it back if anything did.
            err = _restore(api, reconnect, "/interface/ethernet/poe/set",
                           {"numbers": target, "poe-out": original}, sleep)
            if err:
                return {"error": "restore_failed", "method": METHOD_POE_POWER_CYCLE,
                        "message": f"PoE on {verdict.name} may still be off: {err}"}
        return {"success": True, "method": METHOD_POE_POWER_CYCLE, "restored": True,
                "poe_out": original, "off_seconds": off_seconds}

    logger.info("[port-restart] power-cycle unavailable on %s (%s); toggling poe-out",
                verdict.name, cycle.get("error"))
    off = api.send_command("/interface/ethernet/poe/set", {"numbers": target, "poe-out": "off"})
    if not _ok(off):
        # Nothing changed on the router; safe to stop here.
        return {"error": "command_failed", "method": METHOD_POE_TOGGLE,
                "message": f"Router refused to switch PoE off on {verdict.name}: {off.get('error')}"}
    restore_error = None
    try:
        sleep(off_seconds)
    finally:
        restore_error = _restore(api, reconnect, "/interface/ethernet/poe/set",
                                 {"numbers": target, "poe-out": original}, sleep)
    if restore_error:
        return {"error": "restore_failed", "method": METHOD_POE_TOGGLE,
                "message": f"PoE on {verdict.name} may still be off: {restore_error}"}
    return {"success": True, "method": METHOD_POE_TOGGLE, "restored": True,
            "poe_out": original, "off_seconds": off_seconds}


def _bounce_restart(api, reconnect, verdict: PortVerdict, sleep, off_seconds: int) -> Dict[str, Any]:
    target = verdict.interface_id or verdict.name
    off = api.send_command("/interface/disable", {"numbers": target})
    if not _ok(off):
        return {"error": "command_failed", "method": METHOD_INTERFACE_BOUNCE,
                "message": f"Router refused to turn off {verdict.name}: {off.get('error')}"}
    restore_error = None
    try:
        sleep(off_seconds)
    finally:
        restore_error = _restore(api, reconnect, "/interface/enable", {"numbers": target}, sleep)
    if restore_error:
        return {"error": "restore_failed", "method": METHOD_INTERFACE_BOUNCE,
                "message": f"{verdict.name} may still be turned off: {restore_error}"}
    return {"success": True, "method": METHOD_INTERFACE_BOUNCE, "restored": True,
            "off_seconds": off_seconds}


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


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


def restart_options_sync(router_info: Dict[str, Any], *, api_factory=None) -> Dict[str, Any]:
    """Eligibility of every ethernet port, for the dashboard. Read-only."""
    api = _make_api(router_info, api_factory)
    if not api.connect():
        return {"error": "connect_failed",
                "message": getattr(api, "last_connect_error", None) or "Failed to connect to router"}
    try:
        state = read_port_state(api)
        verdicts = evaluate_all_ethernet(
            state, router_ip=router_info["ip"], lb_wan_ports=router_info.get("lb_wan_ports") or [],
        )
        return {"success": True, "ports": [v.public() for v in verdicts]}
    except RouterStateError as exc:
        return {"error": "state_unreadable", "message": str(exc)}
    finally:
        api.disconnect()


def restart_port_sync(
    router_info: Dict[str, Any],
    port_name: str,
    claim: Optional[RestartClaim] = None,
    *,
    api_factory=None,
    sleep: Optional[Callable[[float], None]] = None,
    poe_off_seconds: Optional[int] = None,
    bounce_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Check the guards on the live router, then restart the port.

    Runs in a worker thread. Releases ``claim`` when done, however it ends.
    """
    sleep = sleep or _sleep
    poe_off_seconds = POE_OFF_SECONDS if poe_off_seconds is None else poe_off_seconds
    bounce_seconds = BOUNCE_SECONDS if bounce_seconds is None else bounce_seconds
    if claim is not None and not begin_claim(claim):
        return {"error": "cancelled", "message": "Restart request expired before it started"}
    api = _make_api(router_info, api_factory)

    def reconnect() -> bool:
        try:
            api.disconnect()
        except Exception:
            pass
        return bool(api.connect())

    try:
        if not api.connect():
            return {"error": "connect_failed",
                    "message": getattr(api, "last_connect_error", None) or "Failed to connect to router"}
        try:
            state = read_port_state(api)
        except RouterStateError as exc:
            return {"error": "state_unreadable", "message": str(exc)}
        verdict = evaluate_port(
            state, port_name, router_ip=router_info["ip"],
            lb_wan_ports=router_info.get("lb_wan_ports") or [],
        )
        if not verdict.eligible:
            return {"error": "refused", "reason_code": verdict.reason_code,
                    "message": verdict.reason, "port": verdict.public()}
        if verdict.method == "poe":
            result = _poe_restart(api, reconnect, verdict, sleep, poe_off_seconds)
        else:
            result = _bounce_restart(api, reconnect, verdict, sleep, bounce_seconds)
        result["port"] = verdict.public()
        return result
    except Exception as exc:
        logger.exception("[port-restart] unexpected failure on %s", port_name)
        return {"error": "unexpected", "message": str(exc)}
    finally:
        try:
            api.disconnect()
        except Exception:
            pass
        if claim is not None:
            release_claim(claim)
