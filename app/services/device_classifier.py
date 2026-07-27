"""Pure, computed classification of downstream devices seen on router ports.

Distinguishes infrastructure devices (access points / CPEs such as Tenda or
TP-Link boxes) from ordinary customer devices using ONLY data the caller has
already fetched from the router — MAC OUI, DHCP lease hostname / neighbor
identity, and hotspot host source addresses. This module performs no RouterOS
calls, no DB access, and no I/O of any kind, so it is trivially unit-testable
and safe to call anywhere (including inside code that holds no DB session).

Motivation for the gateway-claim signal: the 2026-07-24 Beyond #1 incident —
an AP left in router mode plugged its LAN side into the hotspot bridge and
showed up as a hotspot host claiming a foreign gateway identity
(192.168.0.1 while the hotspot subnet was 192.168.88.0/24).
"""

import re
from typing import Any, Dict, Iterable, Optional, Set

DEVICE_CLASS_INFRASTRUCTURE = "infrastructure"
DEVICE_CLASS_CUSTOMER = "customer"

# ---------------------------------------------------------------------------
# Signal 1: MAC OUI prefix map for AP/CPE vendors seen in this fleet.
#
# Keys are the first three MAC bytes, uppercase, no separators. Plain dict —
# extend freely as new vendor hardware shows up in the field.
# ---------------------------------------------------------------------------
INFRASTRUCTURE_OUI_VENDORS: Dict[str, str] = {
    # Tenda
    "B40F3B": "Tenda",
    "C83A35": "Tenda",
    "58D9D5": "Tenda",
    "D83214": "Tenda",
    "0495E6": "Tenda",
    "502B73": "Tenda",
    "FCAAB6": "Tenda",
    # TP-Link
    "8C44BB": "TP-Link",
    "50C7BF": "TP-Link",
    "D807B6": "TP-Link",
    "F4EC38": "TP-Link",
    "500FF5": "TP-Link",
    "EC086B": "TP-Link",
    "14CC20": "TP-Link",
    "60E327": "TP-Link",
    "98DAC4": "TP-Link",
    # Mercusys (TP-Link sub-brand)
    "B83A34": "Mercusys",
    # Cudy (Shenzhen Cudy Technology)
    "80AFCA": "Cudy",
    # TOTOLINK (manufactured by Zioncom Electronics)
    "784476": "TOTOLINK",
    # Ubiquiti
    "24A43C": "Ubiquiti",
    "788A20": "Ubiquiti",
    "DC9FDB": "Ubiquiti",
    "F09FC2": "Ubiquiti",
    "687251": "Ubiquiti",
    "802AA8": "Ubiquiti",
    "0418D6": "Ubiquiti",
    # MikroTik
    "488F5A": "MikroTik",
    "DC2C6E": "MikroTik",
    "64D154": "MikroTik",
    "4C5E0C": "MikroTik",
    "6C3B6B": "MikroTik",
    "E48D8C": "MikroTik",
    "B869F4": "MikroTik",
    "CC2DE0": "MikroTik",
    "D4CA6D": "MikroTik",
    "2CC81B": "MikroTik",
    "085531": "MikroTik",
    "18FD74": "MikroTik",
}

# ---------------------------------------------------------------------------
# Signal 2: hostname / identity prefixes. Matched case-insensitively against
# the START of DHCP lease hostnames or neighbor identities the caller already
# has. (Vendor default hostnames look like "Tenda_1A2B3C", "TP-Link_5G", ...)
# ---------------------------------------------------------------------------
INFRASTRUCTURE_HOSTNAME_PREFIXES: tuple = (
    ("tenda", "Tenda"),
    ("tp-link", "TP-Link"),
    ("tplink", "TP-Link"),
    ("archer", "TP-Link"),  # TP-Link Archer product line default hostnames
    ("mercusys", "Mercusys"),
    ("cudy", "Cudy"),
    ("totolink", "TOTOLINK"),
    ("ubiquiti", "Ubiquiti"),
    ("ubnt", "Ubiquiti"),
    ("unifi", "Ubiquiti"),
    ("mikrotik", "MikroTik"),
    ("routeros", "MikroTik"),
    ("ruijie", "Ruijie"),
    ("reyee", "Ruijie"),
)

# Signal 3: a device claiming a gateway identity (x.y.z.1 in the private
# 192.168/16 space). Only suspicious when the router's hotspot subnet is a
# DIFFERENT one — that is the field signature of a misconfigured
# router-mode AP plugged into the hotspot bridge.
_GATEWAY_CLAIM_RE = re.compile(r"^192\.168\.\d{1,3}\.1$")

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def normalize_oui(mac_address: Optional[str]) -> str:
    """Return the OUI (first 6 hex digits, uppercase, no separators) or ''."""
    if not mac_address:
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac_address)).upper()
    if len(cleaned) < 6:
        return ""
    return cleaned[:6]


def vendor_from_mac(mac_address: Optional[str]) -> Optional[str]:
    """Vendor short-name for a MAC via the OUI map, else None."""
    return INFRASTRUCTURE_OUI_VENDORS.get(normalize_oui(mac_address))


def vendor_from_hostname(hostname: Optional[str]) -> Optional[str]:
    """Vendor short-name when a hostname/identity starts with a vendor name."""
    if not hostname:
        return None
    text = str(hostname).strip().lower()
    if not text:
        return None
    for prefix, vendor in INFRASTRUCTURE_HOSTNAME_PREFIXES:
        if text.startswith(prefix):
            return vendor
    return None


def subnet_24(ip_address: Optional[str]) -> Optional[str]:
    """Return the /24 prefix of an IPv4 address ("192.168.88") or None."""
    if not ip_address:
        return None
    match = _IPV4_RE.match(str(ip_address).strip())
    if not match:
        return None
    octets = [int(part) for part in match.groups()]
    if any(octet > 255 for octet in octets):
        return None
    return ".".join(str(octet) for octet in octets[:3])


def infer_hotspot_subnets(
    addresses: Iterable[Optional[str]],
    min_hosts: int = 2,
) -> Set[str]:
    """Infer the hotspot /24 subnet(s) from already-fetched host addresses.

    Uses a simple majority signal: any /24 with at least ``min_hosts``
    distinct addresses counts as a real hotspot subnet. A lone misconfigured
    CPE claiming 192.168.0.1 cannot out-vote the legitimate client pool, and
    with fewer than ``min_hosts`` total addresses nothing is inferred (so the
    gateway-claim check conservatively stays off).
    """
    seen_by_subnet: Dict[str, Set[str]] = {}
    for address in addresses:
        subnet = subnet_24(address)
        if subnet is None:
            continue
        seen_by_subnet.setdefault(subnet, set()).add(str(address).strip())
    return {
        subnet
        for subnet, members in seen_by_subnet.items()
        if len(members) >= min_hosts
    }


def is_foreign_gateway_claim(
    source_ip: Optional[str],
    hotspot_subnets: Optional[Set[str]],
) -> bool:
    """True when a device claims x.y.z.1 outside every known hotspot subnet."""
    if not source_ip or not hotspot_subnets:
        return False
    ip_text = str(source_ip).strip()
    if not _GATEWAY_CLAIM_RE.match(ip_text):
        return False
    return subnet_24(ip_text) not in hotspot_subnets


def classify_device(
    mac_address: Optional[str] = None,
    hostnames: Iterable[Optional[str]] = (),
    source_ip: Optional[str] = None,
    hotspot_subnets: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Classify one downstream device from already-fetched data.

    Returns a dict with:
      - device_class: "infrastructure" or "customer" (default "customer")
      - vendor: short vendor name when recognized, else None
      - router_mode_suspect: True when the device claims a foreign gateway
        identity (x.y.z.1 outside the router's hotspot subnet)

    Purely computed — the caller supplies whatever subset of signals it
    already has; missing signals simply do not fire.
    """
    vendor = vendor_from_mac(mac_address)
    if vendor is None:
        for hostname in hostnames:
            vendor = vendor_from_hostname(hostname)
            if vendor is not None:
                break
    router_mode_suspect = is_foreign_gateway_claim(source_ip, hotspot_subnets)
    device_class = (
        DEVICE_CLASS_INFRASTRUCTURE
        if (vendor is not None or router_mode_suspect)
        else DEVICE_CLASS_CUSTOMER
    )
    return {
        "device_class": device_class,
        "vendor": vendor,
        "router_mode_suspect": router_mode_suspect,
    }
