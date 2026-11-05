"""Remote control of an access point behind a reseller's MikroTik.

Discover the APs hung off a router, then -- with the AP's own admin password
that the reseller saved once -- read its status, reboot it, or "make it a safe
AP" (pure AP/bridge mode, its own DHCP server off, a static LAN IP outside the
router's hotspot pool with the router as gateway and DNS). Every request to the
AP is tunnelled through the MikroTik with ``/tool fetch``
(:mod:`app.services.ap_fetch`); the model-specific protocol lives in
:mod:`app.services.ap_adapters`.

What this module guarantees:

* **never touches the MikroTik's own config** -- it only reads router tables and
  issues ``/tool fetch`` at the AP;
* **a write is pre-checked** (credentials work AND the AP answers) before any
  change, and **verified afterwards**, including that the AP is reachable at its
  new IP;
* **lockout**: after :data:`MAX_FAILED_LOGINS` consecutive bad logins the AP is
  locked until the password is replaced, so we never hammer it;
* **gateway safety**: it refuses to set the AP's IP to the router's gateway, and
  if the AP already sits ON the gateway it reports "on-site fix needed" instead
  of failing silently (that box is unreachable through the router).

Everything here is synchronous and runs in a worker thread via
``run_with_guard`` with no DB session held. The API layer reads the (decrypted)
credential in a short session beforehand and persists the outcome afterwards.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from app.services import ap_adapters
from app.services.ap_adapters import ApAdapter, ApStatus, detect_model_key, get_adapter
from app.services.ap_fetch import RouterFetchHttpClient, parse_json_body, reply_ok
from app.services.device_classifier import (
    classify_device, infer_hotspot_subnets, normalize_oui, vendor_from_mac,
)

logger = logging.getLogger(__name__)

MAX_FAILED_LOGINS = 5
LOGIN_SETTLE_SECONDS = 1
REBOOT_SETTLE_SECONDS = 3
LAN_CHANGE_SETTLE_SECONDS = 3

ACTION_STATUS = "status"
ACTION_REBOOT = "reboot"
ACTION_MAKE_SAFE = "make_safe"


# ---------------------------------------------------------------------------
# Per-router "one AP write at a time" claim (mirror of port_restart's)
# ---------------------------------------------------------------------------

@dataclass
class ApClaim:
    router_id: int
    started: bool = False


_claims: Dict[int, ApClaim] = {}
_claims_guard = threading.Lock()


def try_claim(router_id: int) -> Optional[ApClaim]:
    with _claims_guard:
        if router_id in _claims:
            return None
        claim = ApClaim(router_id=router_id)
        _claims[router_id] = claim
        return claim


def release_claim(claim: ApClaim) -> None:
    with _claims_guard:
        if _claims.get(claim.router_id) is claim:
            del _claims[claim.router_id]


def begin_claim(claim: ApClaim) -> bool:
    with _claims_guard:
        if _claims.get(claim.router_id) is not claim:
            return False
        claim.started = True
        return True


def abandon_if_not_started(claim: ApClaim) -> None:
    with _claims_guard:
        if not claim.started and _claims.get(claim.router_id) is claim:
            del _claims[claim.router_id]


def ap_write_in_progress(router_id: int) -> bool:
    with _claims_guard:
        return router_id in _claims


def reset_claims() -> None:
    """Tests only."""
    with _claims_guard:
        _claims.clear()


# ---------------------------------------------------------------------------
# Credential view passed into the worker (password already decrypted)
# ---------------------------------------------------------------------------

@dataclass
class ApCredential:
    ap_mac: str
    ap_ip: Optional[str]
    username: str
    password: str = field(repr=False)   # decrypted: must never reach a log line
    vendor: str = "Tenda"
    model: Optional[str] = None
    login_method: Optional[str] = None
    failed_login_count: int = 0


@dataclass
class LoginResult:
    ok: bool
    method: Optional[str] = None
    locked: bool = False
    unreachable: bool = False
    error: Optional[str] = None


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _make_api(router_info: Dict[str, Any], api_factory):
    if api_factory is None:
        from app.services.mikrotik_api import MikroTikAPI
        api_factory = MikroTikAPI
    return api_factory(
        router_info["ip"], router_info["username"], router_info["password"],
        router_info["port"], timeout=15, connect_timeout=5,
    )


# ---------------------------------------------------------------------------
# Reading the router's hotspot LAN (to place the AP safely)
# ---------------------------------------------------------------------------

def _rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(result.get("data") or []) if result.get("success") else []


@dataclass
class HotspotLan:
    gateway: Optional[str] = None
    prefixlen: int = 24
    pool_ranges: str = ""
    dns: Optional[str] = None
    subnet: Optional[str] = None


def read_hotspot_lan(api) -> HotspotLan:
    """The hotspot gateway address, its subnet and DHCP pool, for IP planning.

    Reads MikroTik tables only; never changes anything.
    """
    hotspot = _rows(api.send_command("/ip/hotspot/print"))
    addresses = _rows(api.send_command("/ip/address/print"))
    pools = _rows(api.send_command("/ip/pool/print"))
    servers = _rows(api.send_command("/ip/dhcp-server/print"))
    networks = _rows(api.send_command("/ip/dhcp-server/network/print"))

    hs_ifaces = {h.get("interface", "") for h in hotspot if str(h.get("disabled", "")).lower() != "true"}
    lan = HotspotLan()

    # The gateway is the router address on the hotspot interface.
    for row in addresses:
        if row.get("interface") in hs_ifaces:
            try:
                iface = ipaddress.ip_interface(str(row.get("address", "")).strip())
            except ValueError:
                continue
            lan.gateway = str(iface.ip)
            lan.prefixlen = iface.network.prefixlen
            lan.subnet = str(iface.network)
            break

    # Pool used by the hotspot DHCP server on that interface.
    pool_name = ""
    for srv in servers:
        if srv.get("interface") in hs_ifaces:
            pool_name = srv.get("address-pool", "") or ""
            break
    for pool in pools:
        if pool_name and pool.get("name") == pool_name:
            lan.pool_ranges = pool.get("ranges", "") or ""
            break

    for net in networks:
        if lan.gateway and str(net.get("gateway", "")).strip() == lan.gateway:
            lan.dns = (net.get("dns-server", "") or "").split(",")[0].strip() or None
            break
    lan.dns = lan.dns or lan.gateway
    return lan


def _outside_hotspot_lan(ap_ip: str, lan: "HotspotLan") -> Optional[Dict[str, Any]]:
    """Refuse an AP address outside the router's hotspot subnet.

    /tool fetch to such an address would leave through the router's default
    route (WAN) and could hand the AP password to an upstream device. A new
    Tenda on its factory 192.168.0.1 lands here: it needs an on-site move into
    the hotspot subnet first.
    """
    if not lan.subnet:
        return {"error": "no_gateway",
                "message": "Could not read the router's hotspot subnet; refusing to contact the AP."}
    try:
        inside = ipaddress.ip_address(ap_ip) in ipaddress.ip_network(lan.subnet, strict=False)
    except ValueError:
        inside = False
    if inside:
        return None
    return {"error": "not_on_hotspot_lan",
            "message": f"The AP answers on {ap_ip}, outside the router's hotspot network ({lan.subnet}). "
                       f"It cannot be reached safely through the router. On-site fix needed: give it an "
                       f"address in {lan.subnet} or set it to get one by DHCP."}


def _addresses_for_mac(api, mac: str) -> List[str]:
    """Every address the router's tables currently tie to this MAC, ARP first."""
    want = str(mac or "").strip().upper().replace("-", ":")
    found: List[str] = []
    if not want:
        return found
    for cmd in ("/ip/arp/print", "/ip/dhcp-server/lease/print", "/ip/hotspot/host/print"):
        for row in _rows(api.send_command(cmd)):
            row_mac = str(row.get("mac-address", "")).strip().upper().replace("-", ":")
            if row_mac != want or not row.get("address"):
                continue
            # A dead ARP entry or an unused lease does not prove where the AP is.
            if str(row.get("status", "")).lower() in ("failed", "incomplete", "waiting", "offered"):
                continue
            address = str(row.get("address")).strip()
            if address not in found:
                found.append(address)
    return found


def resolve_ap_ip(api, mac: str, prefer: Optional[str] = None) -> Optional[str]:
    """Where this MAC is right now, according to the router.

    The address saved on the credential is only a hint: DHCP may have given it
    to someone else since, and we are about to send that address the AP's
    password. It is used only when the router still ties it to this MAC.
    """
    found = _addresses_for_mac(api, mac)
    if not found and prefer:
        # A static AP that has been quiet has no ARP entry; one ping refreshes it.
        api.send_command("/ping", {"address": prefer, "count": "1"})
        found = _addresses_for_mac(api, mac)
    if prefer and prefer in found:
        return prefer
    return found[0] if found else None


def _locate_ap(api, cred: "ApCredential"):
    """Find the AP by MAC and apply the "safe to contact" rules, BEFORE any
    request (and so before the password) is sent anywhere.

    Returns ``(lan, None)`` with ``cred.ap_ip`` set, or ``(lan, refusal)``.
    """
    lan = read_hotspot_lan(api)
    hint = cred.ap_ip
    try:
        if hint and (not lan.subnet or ipaddress.ip_address(hint)
                     not in ipaddress.ip_network(lan.subnet, strict=False)):
            hint = None   # never ping out through the WAN on a stale hint
    except ValueError:
        hint = None
    ap_ip = resolve_ap_ip(api, cred.ap_mac, prefer=hint)
    if not ap_ip:
        return lan, {"error": "no_ip", "message": "The router does not know an IP address for this access point (no "
                                                  "DHCP lease or ARP entry). It may be offline, or on a fixed address "
                                                  "outside the hotspot network."}
    cred.ap_ip = ap_ip
    if lan.gateway and ap_ip == lan.gateway:
        return lan, {"error": "on_gateway", "on_gateway": True,
                     "message": f"The AP is on the router's gateway address ({lan.gateway}); it cannot be reached "
                                f"through the router. On-site fix needed."}
    # Unconditional: with no readable hotspot subnet we cannot prove the address
    # is on the LAN, so nothing is sent.
    return lan, _outside_hotspot_lan(ap_ip, lan)


def _addresses_in_use(api) -> set:
    """Addresses a new static AP must not take: anything the router knows about."""
    used = set()
    tables = (
        ("/ip/arp/print", ("address",)),
        ("/ip/dhcp-server/lease/print", ("address",)),
        ("/ip/hotspot/host/print", ("address",)),
        ("/ip/hotspot/ip-binding/print", ("address", "to-address")),
        ("/ip/address/print", ("address",)),
    )
    for cmd, keys in tables:
        for row in _rows(api.send_command(cmd)):
            for key in keys:
                text = str(row.get(key, "") or "").split("/")[0].strip()
                try:
                    used.add(ipaddress.ip_address(text))
                except ValueError:
                    continue
    return used


def _pool_addresses(pool_ranges: str):
    out = set()
    for part in str(pool_ranges or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                a = int(ipaddress.ip_address(lo.strip()))
                b = int(ipaddress.ip_address(hi.strip()))
            except ValueError:
                continue
            for n in range(a, min(b, a + 65536) + 1):
                out.add(ipaddress.ip_address(n))
        else:
            try:
                out.add(ipaddress.ip_address(part))
            except ValueError:
                continue
    return out


def pick_static_ip(lan: HotspotLan, used=None) -> Optional[str]:
    """A LAN address for the AP: in-subnet, not the gateway, outside the pool,
    and not already held by another device (``used``)."""
    if not lan.gateway:
        return None
    try:
        network = ipaddress.ip_network(f"{lan.gateway}/{lan.prefixlen}", strict=False)
        gateway = ipaddress.ip_address(lan.gateway)
    except ValueError:
        return None
    pool = _pool_addresses(lan.pool_ranges)
    used = used or set()
    # Prefer the low host addresses just above the gateway (admins expect .2/.3).
    for host in network.hosts():
        if host == gateway or host in pool or host in used:
            continue
        return str(host)
    return None


# ---------------------------------------------------------------------------
# Login (with lockout)
# ---------------------------------------------------------------------------

def _read_status_body(client: RouterFetchHttpClient, adapter: ApAdapter):
    """Try the adapter's candidate status endpoints; return (ApRequest, dict)
    for the first that answers with a JSON object, else (None, None)."""
    for req in adapter.status_requests():
        resp = client.request(req)
        parsed = parse_json_body(resp.body) if resp.ok else None
        if isinstance(parsed, dict) and parsed:
            return resp, adapter.parse_status(resp.body, parse_json_body)
    return None, None


def _login(client: RouterFetchHttpClient, adapter: ApAdapter, cred: ApCredential) -> LoginResult:
    if cred.failed_login_count >= MAX_FAILED_LOGINS:
        return LoginResult(ok=False, locked=True,
                           error=f"Locked after {cred.failed_login_count} failed logins; replace the password.")
    attempts = adapter.login_attempts(cred.username, cred.password, preferred=cred.login_method)
    last_error = None
    answered = False
    for attempt in attempts:
        resp = client.login(attempt.post_data, adapter.login_path, attempt.cookie)
        if not resp.ok:
            last_error = resp.error or "login request failed"
            continue
        answered = True
        _sleep(LOGIN_SETTLE_SECONDS)
        # Confirm the session by reading status; a wrong password answers with a
        # login page / error rather than a usable status body.
        status_resp, _status = _read_status_body(client, adapter)
        if status_resp is not None:
            return LoginResult(ok=True, method=attempt.method)
        last_error = "The AP answered, but the saved password did not open a session."
    # No answer at all says nothing about the password, so it must not count
    # towards the lockout.
    return LoginResult(ok=False, unreachable=not answered, error=last_error or "login failed")


def _login_refusal(login: LoginResult) -> Dict[str, Any]:
    if login.unreachable:
        return {"error": "ap_unreachable",
                "message": f"The access point did not answer through the router: {login.error}"}
    return {"error": "login_locked" if login.locked else "login_failed",
            "locked": login.locked, "message": login.error, "login_ok": False}


# ---------------------------------------------------------------------------
# Public sync actions (run in a worker thread; no DB session held)
# ---------------------------------------------------------------------------

def _client_for(router_info, cred: ApCredential, api) -> RouterFetchHttpClient:
    return RouterFetchHttpClient(api, cred.ap_ip)


def _with_api(router_info, api_factory, fn):
    api = _make_api(router_info, api_factory)
    if not api.connect():
        return {"error": "connect_failed",
                "message": getattr(api, "last_connect_error", None) or "Failed to connect to router"}
    try:
        return fn(api)
    finally:
        try:
            api.disconnect()
        except Exception:
            pass


def read_status_sync(router_info: Dict[str, Any], cred: ApCredential, *, api_factory=None) -> Dict[str, Any]:
    adapter = get_adapter(cred.model, cred.vendor)

    def run(api):
        _lan, refused = _locate_ap(api, cred)
        if refused:
            return refused
        client = _client_for(router_info, cred, api)
        login = _login(client, adapter, cred)
        if not login.ok:
            return _login_refusal(login)
        _resp, status = _read_status_body(client, adapter)
        if status is None:
            return {"error": "ap_unreachable", "login_ok": True, "login_method": login.method,
                    "message": "The access point did not answer."}
        if not status.ip:
            status.ip = cred.ap_ip
        public = status.public()
        # Detect the concrete model from what the AP reported, for future writes.
        detected = detect_model_key(status.model)
        if detected:
            public["detected_model"] = detected
        return {"success": True, "login_ok": True, "login_method": login.method,
                "status": public, "_status_obj": status}

    return _with_api(router_info, api_factory, run)


def reboot_ap_sync(router_info: Dict[str, Any], cred: ApCredential, *, api_factory=None) -> Dict[str, Any]:
    adapter = get_adapter(cred.model, cred.vendor)

    def run(api):
        _lan, refused = _locate_ap(api, cred)
        if refused:
            return refused
        client = _client_for(router_info, cred, api)
        login = _login(client, adapter, cred)
        if not login.ok:
            return _login_refusal(login)
        resp = client.request(adapter.reboot_request())
        if not resp.ok or not (resp.redirected or reply_ok(resp.body)):
            return {"error": "reboot_failed", "login_ok": True, "login_method": login.method,
                    "message": resp.error or "The access point did not accept the reboot."}
        return {"success": True, "login_ok": True, "login_method": login.method,
                "action": ACTION_REBOOT,
                "message": "Reboot sent. The AP drops for about a minute while it restarts."}

    return _with_api(router_info, api_factory, run)


def make_safe_ap_sync(router_info: Dict[str, Any], cred: ApCredential, *, api_factory=None) -> Dict[str, Any]:
    """Pure AP mode + DHCP off + static LAN IP outside the hotspot pool."""
    adapter = get_adapter(cred.model, cred.vendor)

    def run(api):
        lan, refused = _locate_ap(api, cred)
        if refused:
            return refused
        # With the AP's DHCP off, its Wi-Fi users depend on the router's DHCP, and
        # the pool is what tells us which addresses are free to take.
        if not lan.pool_ranges:
            return {"error": "no_hotspot_dhcp",
                    "message": "Could not read a DHCP pool on the router's hotspot network. Turning this AP's DHCP "
                               "off could leave its users without addresses, so nothing was changed."}
        used = _addresses_in_use(api)
        used.discard(ipaddress.ip_address(cred.ap_ip))   # the AP keeping its own address is fine
        target_ip = pick_static_ip(lan, used)
        if not target_ip:
            return {"error": "no_free_ip",
                    "message": "No free LAN address outside the hotspot DHCP pool to give the AP."}
        # SAFETY: never set the AP onto the router's gateway address.
        if target_ip == lan.gateway:
            return {"error": "gateway_conflict",
                    "message": "Refusing to set the AP to the router's gateway address."}

        client = _client_for(router_info, cred, api)
        login = _login(client, adapter, cred)
        if not login.ok:
            return _login_refusal(login)

        # Pre-check: the AP is reachable right now, and tells us its model.
        _pre_resp, pre_status = _read_status_body(client, adapter)
        if pre_status is None:
            return {"error": "ap_unreachable", "login_ok": True, "login_method": login.method,
                    "message": "The access point did not answer the pre-check."}

        # A client / repeater / WISP unit may depend on its radio link (it can be
        # the very link we reach it over). Forcing AP mode would drop that link
        # and strand the box until someone visits. Unknown mode: same answer,
        # because we cannot rule it out.
        if pre_status.mode in (ap_adapters.MODE_CLIENT, ap_adapters.MODE_REPEATER, ap_adapters.MODE_WISP):
            return {"error": "ap_link_mode", "login_ok": True, "login_method": login.method,
                    "message": f"This AP is in {pre_status.mode} mode and may depend on that wireless link. "
                               f"Nothing was changed. Change it on site."}
        if pre_status.mode == ap_adapters.MODE_UNKNOWN:
            return {"error": "ap_mode_unknown", "login_ok": True, "login_method": login.method,
                    "message": "Could not read this AP's working mode, so it is not safe to reconfigure it remotely. "
                               "Nothing was changed."}

        # Pick the write adapter for the model the AP actually reported, so an
        # F3 is not reconfigured with OAP1200 payloads (and vice versa).
        detected = detect_model_key(pre_status.model)
        write_adapter = get_adapter(detected or cred.model, cred.vendor)

        steps: List[Dict[str, Any]] = []

        def apply(label, requests):
            for req in requests:
                resp = client.request(req)
                good = resp.ok and (resp.redirected or reply_ok(resp.body))
                if not good:
                    applied = [s["step"] for s in steps if s["ok"]]
                    steps.append({"step": label, "ok": False})
                    reason = resp.error or f"{label} was rejected by the AP"
                    if applied:
                        reason += (f". Already applied: {', '.join(applied)}, so the AP is partly changed; "
                                   f"refresh status before retrying")
                    return False, reason
                steps.append({"step": label, "ok": True})
            return True, None

        # Mode and DHCP first (these keep the current IP, so the session holds).
        ok, err = apply("work_mode_ap", write_adapter.set_ap_mode_requests())
        if not ok:
            return {"error": "apply_failed", "login_ok": True, "login_method": login.method,
                    "message": err, "steps": steps}
        ok, err = apply("dhcp_off", write_adapter.set_dhcp_off_requests())
        if not ok:
            return {"error": "apply_failed", "login_ok": True, "login_method": login.method,
                    "message": err, "steps": steps}
        # LAN IP last: this one moves the AP, so we re-point the client at it.
        netmask = str(ipaddress.ip_network(f"{lan.gateway}/{lan.prefixlen}", strict=False).netmask)
        ok, err = apply("lan_static", write_adapter.set_lan_static_requests(
            target_ip, netmask, lan.gateway, lan.dns or lan.gateway))
        if not ok:
            return {"error": "apply_failed", "login_ok": True, "login_method": login.method,
                    "message": err, "steps": steps}

        # Verify at the NEW address.
        _sleep(LAN_CHANGE_SETTLE_SECONDS)
        verify_client = RouterFetchHttpClient(api, target_ip)
        vlogin = _login(verify_client, adapter, ApCredential(
            ap_mac=cred.ap_mac, ap_ip=target_ip, username=cred.username,
            password=cred.password, vendor=cred.vendor, model=cred.model,
            login_method=login.method, failed_login_count=0))
        if not vlogin.ok:
            return {"error": "verify_unreachable", "login_ok": True, "login_method": login.method,
                    "new_ip": target_ip, "steps": steps,
                    "message": f"Settings sent but the AP did not answer at its new address {target_ip}. "
                               f"Give it a minute and refresh; it may still be moving. If it stays gone, someone "
                               f"on site has to reset it."}
        _vresp, status = _read_status_body(verify_client, adapter)
        if status is None:
            status = ApStatus(ip=target_ip)
        safe = status.is_safe_ap(gateway_ip=lan.gateway)
        return {"success": True, "login_ok": True, "login_method": login.method,
                "action": ACTION_MAKE_SAFE, "new_ip": target_ip, "gateway": lan.gateway,
                "dns": lan.dns or lan.gateway, "steps": steps,
                "verified_safe": bool(safe), "status": status.public(), "_status_obj": status,
                "message": (f"AP set to pure AP mode, DHCP off, static IP {target_ip} "
                            f"(gateway/DNS {lan.gateway}).") if safe else (
                            f"AP answers at {target_ip}, but it does not report plain AP mode with DHCP off. "
                            f"Check it before relying on it.")}

    return _with_api(router_info, api_factory, run)


# ---------------------------------------------------------------------------
# Discovery + detector hook
# ---------------------------------------------------------------------------

def discover_aps_sync(router_info: Dict[str, Any], *, api_factory=None) -> Dict[str, Any]:
    """List infrastructure devices (Tenda APs etc.) behind the router.

    Sources: DHCP leases, ARP, hotspot hosts, neighbours. Read-only. Flags the
    router-mode / foreign-gateway suspects the "make safe" button targets.
    """

    def run(api):
        leases = _rows(api.send_command("/ip/dhcp-server/lease/print"))
        arp = _rows(api.send_command("/ip/arp/print"))
        hosts = _rows(api.send_command("/ip/hotspot/host/print"))
        neighbors = _rows(api.send_command("/ip/neighbor/print"))
        bridge_hosts = _rows(api.send_command("/interface/bridge/host/print"))
        lan = read_hotspot_lan(api)

        all_ips = [r.get("address") for r in (leases + arp + hosts)]
        hotspot_subnets = infer_hotspot_subnets([ip for ip in all_ips if ip])

        found: Dict[str, Dict[str, Any]] = {}

        def note(mac, ip, hostname, source):
            mac = (mac or "").strip().upper()
            if not mac:
                return
            cls = classify_device(
                mac_address=mac, hostnames=[hostname] if hostname else [],
                source_ip=ip, hotspot_subnets=hotspot_subnets,
            )
            is_infra = cls["device_class"] == "infrastructure"
            if not is_infra and not cls["router_mode_suspect"]:
                return
            entry = found.setdefault(mac, {
                "mac": mac, "ip": ip, "hostname": hostname, "vendor": cls["vendor"],
                "sources": set(), "router_mode_suspect": False, "on_gateway": False,
            })
            entry["sources"].add(source)
            if ip and not entry.get("ip"):
                entry["ip"] = ip
            if cls["router_mode_suspect"]:
                entry["router_mode_suspect"] = True
            if cls["vendor"] and not entry.get("vendor"):
                entry["vendor"] = cls["vendor"]
            if lan.gateway and ip == lan.gateway:
                entry["on_gateway"] = True

        for row in leases:
            note(row.get("mac-address"), row.get("address"), row.get("host-name"), "dhcp_lease")
        for row in arp:
            note(row.get("mac-address"), row.get("address"), None, "arp")
        for row in hosts:
            note(row.get("mac-address"), row.get("address"), row.get("host-name"), "hotspot_host")
        for row in neighbors:
            note(row.get("mac-address"), row.get("address"), row.get("identity"), "neighbor")
        # A box on a fixed address that is outside the LAN has no lease or ARP
        # entry; the bridge still sees its MAC, so it shows up instead of vanishing.
        for row in bridge_hosts:
            if str(row.get("local", "")).lower() != "true":
                note(row.get("mac-address"), None, None, "bridge_host")

        devices = []
        for entry in found.values():
            entry["sources"] = sorted(entry["sources"])
            entry["vendor"] = entry.get("vendor") or vendor_from_mac(entry["mac"]) or "Unknown"
            devices.append(entry)
        devices.sort(key=lambda d: (d["vendor"] != "Tenda", d.get("ip") or ""))
        return {"success": True, "gateway": lan.gateway, "subnet": lan.subnet,
                "devices": devices}

    return _with_api(router_info, api_factory, run)


def detector_flags(status: Optional[Dict[str, Any]], *, on_gateway: bool = False,
                   router_mode_suspect: bool = False) -> Dict[str, Any]:
    """Should the UI offer "Make it a safe AP"? Combines a stored status
    snapshot with discovery signals. No I/O."""
    in_router_mode = bool(status and status.get("mode") == ap_adapters.MODE_ROUTER) or router_mode_suspect
    dhcp_on = bool(status and status.get("dhcp_server_on") is True)
    needs_fix = in_router_mode or dhcp_on or on_gateway
    return {
        "needs_safe_ap": needs_fix,
        "in_router_mode": in_router_mode,
        "dhcp_server_on": dhcp_on,
        "on_gateway": bool(on_gateway),
    }
