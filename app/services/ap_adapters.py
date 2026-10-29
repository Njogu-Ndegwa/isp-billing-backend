"""Per-model adapters for talking to an access point's own web admin.

The service layer (``app/services/ap_control.py``) speaks to an access point
through one of these adapters and a tiny HTTP client that tunnels requests
through the customer's MikroTik (``app/services/ap_fetch.py``). The adapter
owns everything model-specific: the login shape, the goform endpoint paths,
how a status reply is read, and the payloads that reboot the AP, turn its DHCP
server off, set a static LAN IP and switch it to pure AP ("bridge") mode.

Keeping the protocol behind this interface means other Tenda models (and, one
day, other vendors) are a new subclass and a registry line -- the orchestration
in ``ap_control`` never changes.

EVIDENCE / CONFIDENCE
---------------------
CONFIRMED from an open-source Tenda client (marc0u/tenda-wifi, the AC15
consumer firmware, same httpd/goform family) and Tenda CVE disclosures:

* login is ``POST /login/Auth`` with form fields ``username`` + ``password``;
* the password is ``md5(hex)`` on that firmware (some models base64 instead);
* a successful login answers ``302`` and sets a session cookie, and several
  models derive the session id straight from the credentials
  (CVE-2026-22082: "login credentials are used as the session ID");
* settings live under ``/goform/<Name>`` and replies are JSON that carries
  ``{"errCode":0}`` on success; reboot is ``POST /goform/SysToolReboot``.

ASSUMED for the OAP1200 V2 outdoor AP (firmware V2.0.0.11) and marked
``assumed=True`` on every verb below -- the exact goform names and payload
keys for working mode / DHCP / LAN on the AP firmware were NOT confirmable from
public sources. They are implemented from the closest evidence and MUST be
checked against one real unit before this is pointed at a customer AP. See the
bench-test checklist in the PR body.
"""

from __future__ import annotations

import hashlib
import base64
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# Password encodings seen across the Tenda httpd family.
LOGIN_METHOD_MD5 = "md5"
LOGIN_METHOD_BASE64 = "base64"
LOGIN_METHOD_PLAIN = "plain"


def encode_password(password: str, method: str) -> str:
    if method == LOGIN_METHOD_MD5:
        return hashlib.md5(password.encode()).hexdigest()
    if method == LOGIN_METHOD_BASE64:
        return base64.b64encode(password.encode()).decode()
    return password


# Normalised working modes the orchestration reasons about.
MODE_AP = "ap"            # pure access point / bridge: what a safe AP must be
MODE_ROUTER = "router"    # routes + NATs: the dangerous one behind a hotspot
MODE_REPEATER = "repeater"
MODE_WISP = "wisp"
MODE_CLIENT = "client"
MODE_UNKNOWN = "unknown"


@dataclass
class LoginAttempt:
    """One credential encoding to try, newest-evidence first."""
    method: str
    post_data: Dict[str, str]
    cookie: Optional[str] = None  # deterministic cookie when the firmware uses one


@dataclass
class ApRequest:
    """A single web request the transport will tunnel through the MikroTik."""
    method: str                       # "get" | "post"
    path: str                         # e.g. "/goform/getStatus"
    data: Optional[Dict[str, str]] = None


@dataclass
class ApStatus:
    """Normalised, secret-free snapshot of an AP, for the UI and the detector."""
    model: Optional[str] = None
    firmware: Optional[str] = None
    ip: Optional[str] = None
    mode: str = MODE_UNKNOWN
    mode_raw: Optional[str] = None
    dhcp_server_on: Optional[bool] = None
    client_count: Optional[int] = None
    mac: Optional[str] = None
    raw_keys: List[str] = field(default_factory=list)

    def public(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "firmware": self.firmware,
            "ip": self.ip,
            "mode": self.mode,
            "mode_raw": self.mode_raw,
            "dhcp_server_on": self.dhcp_server_on,
            "client_count": self.client_count,
            "mac": self.mac,
        }

    def is_safe_ap(self, *, gateway_ip: Optional[str] = None) -> bool:
        """A safe AP is in AP/bridge mode with its own DHCP server off."""
        return self.mode == MODE_AP and self.dhcp_server_on is False


class ApAdapter:
    """Interface every AP model adapter implements."""

    vendor: str = "Tenda"
    model: str = "generic"
    # login methods to try in order; the one that works is remembered on the row.
    login_methods: List[str] = [LOGIN_METHOD_MD5, LOGIN_METHOD_BASE64]

    login_path: str = "/login/Auth"
    username_field: str = "username"
    password_field: str = "password"

    def login_attempts(self, username: str, password: str,
                        preferred: Optional[str] = None) -> List[LoginAttempt]:
        order = list(self.login_methods)
        if preferred and preferred in order:
            order.remove(preferred)
            order.insert(0, preferred)
        attempts: List[LoginAttempt] = []
        for method in order:
            encoded = encode_password(password, method)
            attempts.append(LoginAttempt(
                method=method,
                post_data={self.username_field: username, self.password_field: encoded},
                # Some Tenda firmware uses the encoded password as the session id.
                cookie=f"password={encoded}",
            ))
        return attempts

    # --- status -----------------------------------------------------------
    def status_request(self) -> ApRequest:  # pragma: no cover - overridden
        raise NotImplementedError

    def parse_status(self, body: str, parse_json: Callable[[str], Any]) -> ApStatus:  # pragma: no cover
        raise NotImplementedError

    # --- write verbs: each returns the request(s) to send -----------------
    def reboot_request(self) -> ApRequest:  # pragma: no cover - overridden
        raise NotImplementedError

    def set_ap_mode_requests(self) -> List[ApRequest]:  # pragma: no cover
        raise NotImplementedError

    def set_dhcp_off_requests(self) -> List[ApRequest]:  # pragma: no cover
        raise NotImplementedError

    def set_lan_static_requests(self, ip: str, netmask: str, gateway: str,
                                dns: str) -> List[ApRequest]:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Tenda OAP1200 V2 (and the shared Tenda AP firmware)
# ---------------------------------------------------------------------------

def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "enable", "enabled"):
        return True
    if text in ("0", "false", "no", "off", "disable", "disabled"):
        return False
    return None


def _normalise_mode(raw: Any) -> str:
    text = str(raw or "").strip().lower()
    if not text:
        return MODE_UNKNOWN
    # Tenda labels: "ap", "apclient", "wisp", "router"/"gateway", "repeater"/"wds".
    if "wisp" in text:
        return MODE_WISP
    if "repeat" in text or "wds" in text or "universal" in text:
        return MODE_REPEATER
    if "router" in text or "gateway" in text or "wan" in text:
        return MODE_ROUTER
    if "client" in text and "ap" not in text:
        return MODE_CLIENT
    if "ap" in text or "bridge" in text or text in ("0",):
        return MODE_AP
    return MODE_UNKNOWN


class TendaApAdapter(ApAdapter):
    """Shared Tenda AP firmware. Status parsing is tolerant of key spelling so
    the same code reads several firmware revisions; the write payloads are the
    assumed part (see module docstring)."""

    vendor = "Tenda"
    model = "tenda-generic"

    # CONFIRMED path (marc0u/tenda-wifi). Status endpoint name on the AP build
    # is ASSUMED; getSysStatusInfo is the common Tenda AP status goform.
    status_path = "/goform/getSysStatusInfo"
    reboot_path = "/goform/SysToolReboot"          # CONFIRMED on AC15 family
    workmode_path = "/goform/setWorkMode"          # ASSUMED
    dhcp_path = "/goform/setLanDhcp"               # ASSUMED (Intelligent DHCP)
    lan_path = "/goform/setLan"                    # ASSUMED

    # keys we look for in a status reply, in priority order
    _MODEL_KEYS = ("deviceName", "productName", "model", "device_name")
    _FW_KEYS = ("softwareVersion", "firmware", "fwVersion", "sysVersion", "version")
    _IP_KEYS = ("lanIp", "ip", "lan_ip", "ipAddr", "lanaddr")
    _MAC_KEYS = ("mac", "lanMac", "wanMac", "sysMac")
    _MODE_KEYS = ("workMode", "work_mode", "mode", "sysMode", "opMode")
    _DHCP_KEYS = ("dhcpd", "dhcpServer", "dhcp", "lanDhcp", "intelligentDhcp", "dhcpEnable")
    _CLIENTS_KEYS = ("clientCount", "clients", "onlineNum", "staCount", "wifiClients")

    def status_request(self) -> ApRequest:
        return ApRequest("get", self.status_path)

    def parse_status(self, body: str, parse_json: Callable[[str], Any]) -> ApStatus:
        data = parse_json(body)
        if not isinstance(data, dict):
            return ApStatus(raw_keys=[])
        # Some firmware nests the payload under a single key.
        if len(data) == 1 and isinstance(next(iter(data.values())), dict):
            data = next(iter(data.values()))

        def pick(keys):
            for k in keys:
                if k in data and data[k] not in (None, ""):
                    return data[k]
            return None

        clients = pick(self._CLIENTS_KEYS)
        try:
            clients = int(clients) if clients is not None else None
        except (TypeError, ValueError):
            clients = None
        mode_raw = pick(self._MODE_KEYS)
        return ApStatus(
            model=pick(self._MODEL_KEYS),
            firmware=pick(self._FW_KEYS),
            ip=pick(self._IP_KEYS),
            mode=_normalise_mode(mode_raw),
            mode_raw=None if mode_raw is None else str(mode_raw),
            dhcp_server_on=_as_bool(pick(self._DHCP_KEYS)),
            client_count=clients,
            mac=pick(self._MAC_KEYS),
            raw_keys=sorted(data.keys()),
        )

    def reboot_request(self) -> ApRequest:
        return ApRequest("post", self.reboot_path, {})

    def set_ap_mode_requests(self) -> List[ApRequest]:
        # ASSUMED payload: workMode=ap puts the box in pure AP/bridge mode.
        return [ApRequest("post", self.workmode_path, {"workMode": "ap"})]

    def set_dhcp_off_requests(self) -> List[ApRequest]:
        # ASSUMED payload: turn the AP's own ("Intelligent") DHCP server off.
        return [ApRequest("post", self.dhcp_path, {"dhcpEnable": "0"})]

    def set_lan_static_requests(self, ip: str, netmask: str, gateway: str, dns: str) -> List[ApRequest]:
        # ASSUMED payload keys for the LAN setup page.
        return [ApRequest("post", self.lan_path, {
            "ipType": "static",
            "ip": ip,
            "mask": netmask,
            "gateway": gateway,
            "dns1": dns,
        })]


class TendaOap1200V2Adapter(TendaApAdapter):
    vendor = "Tenda"
    model = "OAP1200V2"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_ADAPTERS: Dict[str, Callable[[], ApAdapter]] = {
    "OAP1200V2": TendaOap1200V2Adapter,
    "OAP1200": TendaOap1200V2Adapter,
    "TENDA": TendaApAdapter,
}

DEFAULT_ADAPTER = "OAP1200V2"


def get_adapter(model: Optional[str] = None, vendor: Optional[str] = None) -> ApAdapter:
    """Pick an adapter by model name, then vendor, else the default Tenda AP."""
    if model:
        key = str(model).strip().upper().replace(" ", "").replace("-", "")
        for name, factory in _ADAPTERS.items():
            if name.upper() == key:
                return factory()
    if vendor and str(vendor).strip().upper() == "TENDA":
        return _ADAPTERS["TENDA"]()
    return _ADAPTERS[DEFAULT_ADAPTER]()


def supported_models() -> List[str]:
    return sorted({f().model for f in _ADAPTERS.values()})
