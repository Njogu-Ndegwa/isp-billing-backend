import base64
import hashlib
import hmac
import uuid
import secrets
import string
import ipaddress
import logging
import os
from datetime import datetime, timedelta
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.models import Router, ProvisioningToken, ProvisioningTokenStatus, User
from app.db.database import AsyncSessionLocal
from app.config import settings
from app.core.runtime_mode import require_external_side_effects_enabled

logger = logging.getLogger(__name__)

WG_SOCKET_PATH = "/var/run/wg-manager/wg-manager.sock"

WG_SUBNET = ipaddress.IPv4Network("10.0.0.0/16")
WG_SERVER_IP = ipaddress.IPv4Address("10.0.0.1")
WG_IP_RANGE = (ipaddress.IPv4Address("10.0.0.2"), ipaddress.IPv4Address("10.0.99.255"))
L2TP_IP_RANGE = (ipaddress.IPv4Address("10.0.100.0"), ipaddress.IPv4Address("10.0.199.255"))
TOKEN_EXPIRY_HOURS = 24
INSURANCE_KEY_CONTEXT = b"bitwave-insurance-wireguard-v1"

LOGIN_PAGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "captive-portal-login.html"
)

API_USERNAME = "bitwave-api"

# SSTP management tunnel (RouterOS 6). Names match the manual runbook
# (skill migrate-router-to-sstp) so provisioned and migrated routers look the
# same on the router and to the ops tooling.
SSTP_ROUTER_INTERFACE = "sstp-hetzner"
SSTP_MGMT_LOOPBACK = "lo-mgmt"
ROUTER_MGMT_CA_CN = "Bitwave Router Management CA"
ROUTER_MGMT_CA_FILE = "router-mgmt-ca.crt"
ROUTER_MGMT_CA_PATH = "/api/provision/router-mgmt-ca.crt"
# hAP lite has no RTC; certificate checks need a sane clock.
SSTP_NTP_SERVER = "162.159.200.1"

# RouterOS 7 WireGuard management tunnel to Hetzner wg2 (PROVISION_MGMT_TO_HETZNER).
# Same name the manual migrations used (skill migrate-router-to-sstp).
HETZNER_WG_ROUTER_INTERFACE = "wg-hz"
HETZNER_WG_FIREWALL_COMMENT = "Allow WireGuard (Hetzner management)"
HETZNER_API_FIREWALL_COMMENT = "Allow API from Hetzner management"


def _downgrade_https_to_http(base_url: str) -> str:
    """Return an HTTP version of base_url when it explicitly uses HTTPS."""
    clean_url = (base_url or "").strip().rstrip("/")
    parsed = urlsplit(clean_url)
    if parsed.scheme.lower() != "https":
        return clean_url
    return urlunsplit(parsed._replace(scheme="http")).rstrip("/")


def provision_base_url_for_vpn(vpn_type: str) -> str:
    """Pick the public fetch base URL for the router's provisioning transport."""
    if (vpn_type or "").lower() == "l2tp":
        legacy_url = (settings.PROVISION_LEGACY_BASE_URL or "").strip().rstrip("/")
        if legacy_url:
            return legacy_url
        return _downgrade_https_to_http(settings.PROVISION_BASE_URL)
    return settings.PROVISION_BASE_URL.rstrip("/")


def fetch_certificate_flag_for_url(url: str, vpn_type: str) -> str:
    """RouterOS v6 needs certificate checks disabled only when using HTTPS."""
    scheme = urlsplit((url or "").strip()).scheme.lower()
    if (vpn_type or "").lower() == "l2tp" and scheme == "https":
        return " check-certificate=no"
    return ""


def _wg_client(timeout: int = 10) -> httpx.AsyncClient:
    """Get an httpx client for the wg-manager. Uses Unix socket if available, TCP otherwise."""
    if os.path.exists(WG_SOCKET_PATH):
        transport = httpx.AsyncHTTPTransport(uds=WG_SOCKET_PATH)
        return httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=timeout)
    return httpx.AsyncClient(base_url=settings.WG_MANAGER_URL, timeout=timeout)


def generate_api_password(length: int = 24) -> str:
    """Generate a secure random password for the MikroTik API service account."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_wireguard_keypair() -> Tuple[str, str]:
    """Generate a WireGuard keypair using X25519. Returns (private_b64, public_b64)."""
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(private_bytes).decode(), base64.b64encode(public_bytes).decode()


def derive_insurance_ip(router_ip: str, target_subnet: str | None = None) -> str:
    """Map a primary management IP in 10.0.0.0/16 into the backup management subnet."""
    source_ip = ipaddress.IPv4Address(router_ip)
    if source_ip not in WG_SUBNET:
        raise ValueError(f"Router IP {router_ip} is outside {WG_SUBNET}; cannot derive backup IP")

    target = ipaddress.IPv4Network(target_subnet or settings.INSURANCE_WG_SUBNET)
    if target.prefixlen != WG_SUBNET.prefixlen:
        raise ValueError(f"Insurance subnet {target} must use /16 to preserve router host offsets")

    offset = int(source_ip) - int(WG_SUBNET.network_address)
    mapped = ipaddress.IPv4Address(int(target.network_address) + offset)
    if mapped not in target:
        raise ValueError(f"Derived backup IP {mapped} is outside {target}")
    return str(mapped)


def derive_insurance_wireguard_keypair(
    token_value: str,
    identity: str,
    primary_ip: str,
    primary_private_key: str,
) -> Tuple[str, str]:
    """Derive stable backup WG keys so script re-fetches match manager registration.

    The token stores only the primary router private key. A deterministic child
    key avoids a schema change while still giving the backup interface its own
    WireGuard public key.
    """
    if not primary_private_key:
        raise ValueError("Cannot derive backup WireGuard key without primary private key")

    message = f"{token_value}:{identity}:{primary_ip}".encode("utf-8")
    private_bytes = hmac.new(
        primary_private_key.encode("utf-8"),
        INSURANCE_KEY_CONTEXT + b":" + message,
        hashlib.sha256,
    ).digest()
    private_key = X25519PrivateKey.from_private_bytes(private_bytes)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_bytes).decode(), base64.b64encode(public_bytes).decode()


def _token_insurance_wireguard_keypair(token: ProvisioningToken) -> Tuple[str, str]:
    return derive_insurance_wireguard_keypair(
        token_value=token.token,
        identity=token.identity,
        primary_ip=token.wireguard_ip,
        primary_private_key=token.wg_private_key,
    )


def _insurance_l2tp_psk() -> str:
    return (settings.INSURANCE_L2TP_IPSEC_PSK or settings.L2TP_IPSEC_PSK or "").strip()


def _missing_insurance_settings(vpn_type: str) -> list[str]:
    required = [
        "INSURANCE_WG_MANAGER_URL",
        "INSURANCE_WG_MANAGER_SECRET",
        "INSURANCE_SERVER_PUBLIC_IP",
        "INSURANCE_SERVER_VPN_IP",
        "INSURANCE_WG_SUBNET",
    ]
    if vpn_type == "wireguard":
        required.append("INSURANCE_SERVER_WG_PUBLIC_KEY")

    missing = [name for name in required if not (getattr(settings, name, "") or "").strip()]
    if vpn_type == "l2tp" and not _insurance_l2tp_psk():
        missing.append("INSURANCE_L2TP_IPSEC_PSK or L2TP_IPSEC_PSK")
    return missing


def _require_insurance_settings(vpn_type: str) -> None:
    missing = _missing_insurance_settings(vpn_type)
    if missing:
        raise ValueError(
            "Backup tunnel provisioning is enabled but insurance setting(s) are missing: "
            + ", ".join(missing)
        )


# ---------------------------------------------------------------------------
# VPN IP allocation
# ---------------------------------------------------------------------------

async def allocate_vpn_ip(db: AsyncSession, vpn_type: str = "wireguard") -> str:
    """Find the next available VPN IP, respecting range split by vpn_type."""
    router_result = await db.execute(select(Router.ip_address))
    router_ips = {row[0] for row in router_result.fetchall()}

    # Only reserve IPs for PENDING tokens still within their 24h validity window.
    # Tokens past the cutoff are ignored here regardless of DB status -- their
    # status gets cleaned up to EXPIRED by the nightly scheduled job.
    cutoff = datetime.utcnow() - timedelta(hours=TOKEN_EXPIRY_HOURS)
    token_result = await db.execute(
        select(ProvisioningToken.wireguard_ip).where(
            ProvisioningToken.status == ProvisioningTokenStatus.PENDING,
            ProvisioningToken.created_at > cutoff,
        )
    )
    token_ips = {row[0] for row in token_result.fetchall()}
    used_ips = router_ips | token_ips | {str(WG_SERVER_IP)}

    if vpn_type == "l2tp":
        range_start, range_end = L2TP_IP_RANGE
    else:
        range_start, range_end = WG_IP_RANGE

    ip = range_start
    while ip <= range_end:
        ip_str = str(ip)
        if ip_str not in used_ips:
            return ip_str
        ip = ipaddress.IPv4Address(int(ip) + 1)

    label = "L2TP (10.0.100.0-10.0.199.255)" if vpn_type == "l2tp" else "WireGuard (10.0.0.2-10.0.99.255)"
    raise ValueError(f"No available VPN IPs in the {label} range")


# Keep old name as alias for backward compat with any external callers
async def allocate_wireguard_ip(db: AsyncSession) -> str:
    return await allocate_vpn_ip(db, "wireguard")


# ---------------------------------------------------------------------------
# WireGuard peer management
# ---------------------------------------------------------------------------

async def register_wireguard_peer(public_key: str, ip: str):
    """Register a new WireGuard peer via the wg-manager sidecar."""
    require_external_side_effects_enabled("primary WireGuard peer registration")
    async with _wg_client() as client:
        response = await client.post(
            "/add-peer",
            json={"public_key": public_key, "allowed_ips": f"{ip}/32"},
            headers={"X-API-Key": settings.WG_MANAGER_SECRET}
        )
        response.raise_for_status()
        return response.json()


async def remove_wireguard_peer(public_key: str):
    """Remove a WireGuard peer via the wg-manager sidecar."""
    require_external_side_effects_enabled("primary WireGuard peer removal")
    async with _wg_client() as client:
        response = await client.request(
            "DELETE",
            "/remove-peer",
            json={"public_key": public_key},
            headers={"X-API-Key": settings.WG_MANAGER_SECRET}
        )
        response.raise_for_status()
        return response.json()


async def get_server_wg_public_key() -> str:
    """Fetch the server's WireGuard public key from the wg-manager sidecar."""
    async with _wg_client() as client:
        response = await client.get(
            "/server-info",
            headers={"X-API-Key": settings.WG_MANAGER_SECRET}
        )
        response.raise_for_status()
        return response.json()["public_key"]


# ---------------------------------------------------------------------------
# L2TP peer management
# ---------------------------------------------------------------------------

async def register_l2tp_peer(username: str, password: str, ip: str):
    """Register a new L2TP peer via the wg-manager sidecar (chap-secrets)."""
    require_external_side_effects_enabled("primary L2TP peer registration")
    async with _wg_client() as client:
        response = await client.post(
            "/add-l2tp-peer",
            json={"username": username, "password": password, "ip": ip},
            headers={"X-API-Key": settings.WG_MANAGER_SECRET}
        )
        response.raise_for_status()
        return response.json()


async def remove_l2tp_peer(username: str):
    """Remove an L2TP peer via the wg-manager sidecar."""
    require_external_side_effects_enabled("primary L2TP peer removal")
    async with _wg_client() as client:
        response = await client.request(
            "DELETE",
            "/remove-l2tp-peer",
            json={"username": username},
            headers={"X-API-Key": settings.WG_MANAGER_SECRET}
        )
        response.raise_for_status()
        return response.json()


def generate_l2tp_username(identity: str) -> str:
    """Deterministic L2TP username from router identity, e.g. 'l2tp-Router-0005'."""
    return f"l2tp-{identity}"


# ---------------------------------------------------------------------------
# SSTP management tunnel (RouterOS 6, Hetzner accel-ppp)
# ---------------------------------------------------------------------------

def generate_sstp_username(identity: str) -> str:
    """SSTP login used by the runbook and chap-secrets, e.g. 'sstp-Router-0005'."""
    return f"sstp-{identity}"


def derive_sstp_ip(router_ip: str) -> str:
    """Router 10.0.X.Y -> its SSTP peer address 10.251.X.Y (SSTP_SUBNET)."""
    return derive_insurance_ip(router_ip, settings.SSTP_SUBNET)


def router_mgmt_ca_pem() -> str:
    """Return the public router-management CA certificate PEM, or "" if unset.

    ROUTER_MGMT_CA_PEM may carry literal "\\n" sequences so it fits on one
    .env line. Anything that is not a plain certificate -- above all anything
    containing a private key -- is refused, so a paste mistake can never be
    served to the internet.
    """
    raw = (settings.ROUTER_MGMT_CA_PEM or "").strip()
    if not raw:
        return ""
    pem = raw.replace("\\n", "\n").replace("\r\n", "\n").strip() + "\n"
    if "PRIVATE KEY" in pem:
        logger.error("ROUTER_MGMT_CA_PEM contains a private key; refusing to use or serve it")
        return ""
    if "-----BEGIN CERTIFICATE-----" not in pem or "-----END CERTIFICATE-----" not in pem:
        logger.error("ROUTER_MGMT_CA_PEM is not a PEM certificate; ignoring it")
        return ""
    return pem


MGMT_TUNNEL_HETZNER_WIREGUARD = "wireguard"
MGMT_TUNNEL_HETZNER_SSTP = "sstp"
HETZNER_MGMT_TUNNELS = frozenset({MGMT_TUNNEL_HETZNER_WIREGUARD, MGMT_TUNNEL_HETZNER_SSTP})


def mgmt_to_hetzner_active() -> bool:
    """New tokens get a single Hetzner management tunnel only while the flag is on."""
    return bool(settings.PROVISION_MGMT_TO_HETZNER)


def hetzner_mgmt_tunnel_for(vpn_type: str) -> str:
    """RouterOS 7 (wireguard tokens) -> wg-hz; RouterOS 6 (l2tp tokens) -> SSTP."""
    if (vpn_type or "").lower() == "l2tp":
        return MGMT_TUNNEL_HETZNER_SSTP
    return MGMT_TUNNEL_HETZNER_WIREGUARD


def token_mgmt_to_hetzner(token: ProvisioningToken) -> bool:
    """Decided once at token creation: a token issued with a Hetzner tunnel
    keeps rendering it for its whole life, even if the flag is flipped."""
    return (token.management_tunnel or "") in HETZNER_MGMT_TUNNELS


def token_uses_sstp(token: ProvisioningToken) -> bool:
    return (
        token.management_tunnel == MGMT_TUNNEL_HETZNER_SSTP
        and (token.vpn_type or "").lower() == "l2tp"
        and bool(token.sstp_username)
    )


def _split_sstp_server(server: str) -> Tuple[str, str]:
    host, sep, port = (server or "").strip().rpartition(":")
    if not sep:
        return "", ""
    return host, port


def _sstp_server_is_valid(server: str) -> bool:
    host, port = _split_sstp_server(server)
    if not host or not port.isdigit():
        return False
    return all(ch.isalnum() or ch in ".-" for ch in host)


def sstp_connect_to(server: str, routeros_major: int) -> str:
    """The sstp-client connect-to argument(s) for a RouterOS major version.

    RouterOS 6 (6.48/6.49) takes the port INSIDE connect-to (``ip:port``);
    RouterOS 7 takes the address alone plus a separate ``port=``. Mixing
    them up gave `:44443` / "unable to connect" on 2026-09-24.
    """
    host, port = _split_sstp_server(server)
    if routeros_major >= 7:
        return f"connect-to={host} port={port}"
    return f"connect-to={host}:{port}"


def _require_sstp_settings() -> None:
    missing = []
    if not _sstp_server_is_valid(settings.SSTP_SERVER):
        missing.append("SSTP_SERVER (host:port)")
    if not (settings.SSTP_SUBNET or "").strip():
        missing.append("SSTP_SUBNET")
    if not router_mgmt_ca_pem():
        missing.append("ROUTER_MGMT_CA_PEM")
    if missing:
        raise ValueError(
            "SSTP provisioning is enabled but setting(s) are missing or invalid: "
            + ", ".join(missing)
        )


def _require_hetzner_mgmt_settings(vpn_type: str) -> None:
    """Everything the single Hetzner tunnel needs, checked before any manager call.

    The AWS settings (SERVER_PUBLIC_IP, WG_MANAGER_URL, L2TP PSK) are
    deliberately NOT required: nothing in this path touches AWS.
    """
    required = [
        "INSURANCE_WG_MANAGER_URL",
        "INSURANCE_WG_MANAGER_SECRET",
        "INSURANCE_SERVER_PUBLIC_IP",
        "INSURANCE_SERVER_VPN_IP",
        "INSURANCE_WG_SUBNET",
    ]
    if hetzner_mgmt_tunnel_for(vpn_type) == MGMT_TUNNEL_HETZNER_WIREGUARD:
        required.append("INSURANCE_SERVER_WG_PUBLIC_KEY")
    missing = [name for name in required if not (str(getattr(settings, name, "") or "")).strip()]
    if missing:
        raise ValueError(
            "PROVISION_MGMT_TO_HETZNER is on but setting(s) are missing: " + ", ".join(missing)
        )
    if hetzner_mgmt_tunnel_for(vpn_type) == MGMT_TUNNEL_HETZNER_SSTP:
        _require_sstp_settings()


async def register_sstp_peer(username: str, password: str, ip: str):
    """Add/replace the router's login in the SSTP chap-secrets via the insurance manager."""
    from app.services.insurance_wireguard import insurance_manager_request

    return await insurance_manager_request(
        "POST",
        "/add-sstp-peer",
        json={"username": username, "password": password, "ip": ip},
    )


async def remove_sstp_peer(username: str):
    """Remove the router's SSTP login via the insurance manager."""
    from app.services.insurance_wireguard import insurance_manager_request

    return await insurance_manager_request(
        "DELETE",
        "/remove-sstp-peer",
        json={"username": username},
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_token_expired(token: ProvisioningToken) -> bool:
    return datetime.utcnow() > token.created_at + timedelta(hours=TOKEN_EXPIRY_HOURS)


async def expire_stale_tokens() -> int:
    """
    Mark expired PENDING tokens as EXPIRED so their IPs become available.

    Runs as a nightly scheduled job (3:00 AM EAT / 0:00 UTC).
    Uses its own DB session -- safe to call from anywhere.

    Stale WireGuard/L2TP peers are left on the server -- they are harmless
    (no one has the private key) and can be pruned separately if needed.

    Safe because:
    - Only touches tokens with status=PENDING that are past TOKEN_EXPIRY_HOURS.
    - These tokens can never complete provisioning anyway (the /complete
      endpoint already rejects expired tokens with HTTP 410).
    - Active routers live in the Router table and are never touched here.
    """
    cutoff = datetime.utcnow() - timedelta(hours=TOKEN_EXPIRY_HOURS)

    async with AsyncSessionLocal() as cleanup_db:
        try:
            result = await cleanup_db.execute(
                select(ProvisioningToken).where(
                    ProvisioningToken.status == ProvisioningTokenStatus.PENDING,
                    ProvisioningToken.created_at <= cutoff,
                )
            )
            stale_tokens = result.scalars().all()

            if not stale_tokens:
                return 0

            for tok in stale_tokens:
                tok.status = ProvisioningTokenStatus.EXPIRED

            await cleanup_db.commit()
            logger.info(f"Expired {len(stale_tokens)} stale provisioning token(s), freeing their VPN IPs")
            return len(stale_tokens)
        except Exception as e:
            await cleanup_db.rollback()
            logger.warning(f"Failed to expire stale tokens: {e}")
            return 0


def get_login_page_html() -> str:
    """Read the captive portal login.html template."""
    with open(LOGIN_PAGE_PATH, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# .rsc script generation -- shared + VPN-specific sections
# ---------------------------------------------------------------------------

def _rsc_header(token: ProvisioningToken) -> str:
    vpn_label = "WireGuard" if token.vpn_type == "wireguard" else "L2TP/IPsec"
    tunnel_line = f"# Tunnel IP: {token.wireguard_ip}"
    if token_mgmt_to_hetzner(token):
        if token_uses_sstp(token):
            vpn_label = f"SSTP to Hetzner ({SSTP_ROUTER_INTERFACE}), only management tunnel"
            tunnel_address = derive_sstp_ip(token.wireguard_ip)
        else:
            vpn_label = f"WireGuard to Hetzner ({HETZNER_WG_ROUTER_INTERFACE}), only management tunnel"
            tunnel_address = derive_insurance_ip(token.wireguard_ip, settings.INSURANCE_WG_SUBNET)
        tunnel_line = (
            f"# Management IP: {token.wireguard_ip} (pinned on {SSTP_MGMT_LOOPBACK})\n"
            f"# Tunnel IP: {tunnel_address}"
        )
    return f"""# ============================================================
# Bitwave ISP Auto-Provisioning Script
# Router: {token.identity} ({token.router_name})
# VPN Type: {vpn_label}
{tunnel_line}
# Generated: {datetime.utcnow().isoformat()}Z
# ============================================================"""


def _rsc_preflight_hotspot(token: ProvisioningToken) -> str:
    # When the hotspot feature is unavailable (blocked by device-mode on
    # v7.13+ RouterBOARDs, or the package disabled on v6) its console menus
    # do not exist at all, and any DIRECT `/ip hotspot ... [find where ...]`
    # reference fails at PARSE time -- `:do on-error` cannot catch that, so
    # the import dies mid-way and leaves the router half-provisioned with no
    # hotspot, no API user, and no /complete callback (incident
    # 2026-06-10-provision-import-parse-abort). Referencing the menu only
    # inside a [:parse "..."] string defers resolution to runtime, where the
    # failure IS catchable -- same trick as the v6 use-ipsec block below.
    #
    # The previous device-mode preflight had a hole: on preset modes like
    # `home` the per-feature `hotspot` flag is not readable, the read failed,
    # and the script "proceeded anyway" straight into the parse crash. It
    # also referenced /system/device-mode directly, which is itself a parse
    # error on v7 builds older than 7.13. Probing the hotspot menu covers
    # every cause and every version, so it replaces the device-mode check.
    if token.vpn_type == "l2tp":
        remedy = (
            "on RouterOS v6 this usually means the hotspot package is missing or "
            "disabled. Check: /system package print  -- enable the hotspot "
            "package, reboot, then re-run this provisioning command"
        )
    else:
        remedy = (
            "this is usually device-mode blocking hotspot (newer RouterBOARDs "
            "ship this way). Run: /system/device-mode/update hotspot=yes  -- "
            "then press the physical reset button briefly (or power-cycle) "
            "within 5 minutes when prompted, wait for the router to come back, "
            "then re-run this provisioning command"
        )
    return f"""
# ---- PRE-FLIGHT: HOTSPOT AVAILABILITY CHECK ----
# If the hotspot feature is unavailable its console menus do not exist and
# direct /ip hotspot references are PARSE errors that abort the import
# mid-way (half-provisioned router). Probe the menu via [:parse] so the
# failure happens at runtime, where it can be caught and turned into a
# clean abort BEFORE any configuration is applied.
:do {{
    :local bwHsProbe [:parse "/ip hotspot profile find"]
    $bwHsProbe
    :log info "Provisioning: hotspot feature available"
}} on-error={{
    :log error "PROVISION ABORTED: the hotspot feature is not available on this router -- {remedy}."
    :error "hotspot feature unavailable -- aborting before any config is applied (see /log print)"
}}"""


def _rsc_wan_setup() -> str:
    return """
# ---- STEP 1: WAN / INITIAL SETUP ----

:do { /interface wireless cap set enabled=no } on-error={}

:if ([:len [/interface bridge find where name=bridge]] = 0) do={
    /interface bridge add name=bridge
    :log info "Provisioning: created bridge interface"
} else={
    :log info "Provisioning: bridge interface already exists"
}

:foreach iface in={ether2;ether3;ether4;ether5} do={
    :do {
        :if ([:len [/interface find where name=$iface]] > 0) do={
            :if ([:len [/interface bridge port find where interface=$iface]] = 0) do={
                /interface bridge port add interface=$iface bridge=bridge
            }
        }
    } on-error={}
}

:do {
    :if ([:len [/interface find where name=wlan1]] > 0) do={
        :if ([:len [/interface bridge port find where interface=wlan1]] = 0) do={
            /interface bridge port add interface=wlan1 bridge=bridge
        }
    }
} on-error={}

:do { /interface bridge port remove [find where interface=ether1] } on-error={}
:do { /ip dhcp-client add interface=ether1 disabled=no comment="WAN uplink" } on-error={}
:do { /ip firewall nat add chain=srcnat out-interface=ether1 action=masquerade comment="NAT for internet access" } on-error={}
/ip dns set servers=8.8.8.8,8.8.4.4 allow-remote-requests=yes

:log info "Provisioning: WAN setup complete, waiting for DHCP lease..."
:delay 8s"""


def _rsc_lan_setup() -> str:
    return """
# ---- STEP 2: LAN SETUP ----

:do { /ip address add address=192.168.88.1/24 interface=bridge } on-error={}
:do { /ip pool add name=dhcp-pool ranges=192.168.88.10-192.168.88.254 } on-error={}
:do { /ip dhcp-server add name=dhcp1 interface=bridge address-pool=dhcp-pool disabled=no } on-error={}
:do { /ip dhcp-server network add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=8.8.8.8,8.8.4.4 } on-error={}

:log info "Provisioning: LAN and DHCP setup complete" """


def _rsc_vpn_wireguard(token: ProvisioningToken) -> str:
    return f"""
# ---- STEP 3: WIREGUARD VPN (RouterOS v7) ----

# add-then-set (like the L2TP block) so re-running this script -- e.g.
# after enabling device-mode hotspot and re-importing -- converges instead
# of aborting the import with "already have such name".
:do {{
    /interface wireguard add name=wg-aws listen-port=51820 private-key="{token.wg_private_key}"
}} on-error={{
    /interface wireguard set [find where name=wg-aws] listen-port=51820 private-key="{token.wg_private_key}"
}}
:do {{ /ip address add address={token.wireguard_ip}/16 interface=wg-aws }} on-error={{}}
:do {{
    /interface wireguard peers add interface=wg-aws public-key="{token.server_wg_pubkey}" endpoint-address={token.server_public_ip} endpoint-port=51820 allowed-address=10.0.0.0/16 persistent-keepalive=25
}} on-error={{
    /interface wireguard peers set [find where interface=wg-aws] public-key="{token.server_wg_pubkey}" endpoint-address={token.server_public_ip} endpoint-port=51820 allowed-address=10.0.0.0/16 persistent-keepalive=25
}}
:do {{ /ip firewall filter add chain=input protocol=udp dst-port=51820 action=accept comment="Allow WireGuard" }} on-error={{}}

:log info "Provisioning: WireGuard tunnel configured"
:delay 3s"""


def _rsc_backup_wireguard(token: ProvisioningToken) -> str:
    backup_ip = derive_insurance_ip(token.wireguard_ip)
    backup_private_key, _backup_public_key = _token_insurance_wireguard_keypair(token)
    interface_name = settings.INSURANCE_ROUTER_INTERFACE
    return f"""
# ---- STEP 3B: BACKUP WIREGUARD VPN (new server insurance tunnel) ----

:do {{
    /interface wireguard add name={interface_name} listen-port={settings.INSURANCE_WG_PORT} private-key="{backup_private_key}"
}} on-error={{
    /interface wireguard set [find where name={interface_name}] listen-port={settings.INSURANCE_WG_PORT} private-key="{backup_private_key}"
}}
:do {{ /ip address add address={backup_ip}/16 interface={interface_name} }} on-error={{}}
:do {{
    /interface wireguard peers add interface={interface_name} public-key="{settings.INSURANCE_SERVER_WG_PUBLIC_KEY}" endpoint-address={settings.INSURANCE_SERVER_PUBLIC_IP} endpoint-port={settings.INSURANCE_WG_PORT} allowed-address={settings.INSURANCE_WG_SUBNET} persistent-keepalive=25
}} on-error={{
    /interface wireguard peers set [find where interface={interface_name}] public-key="{settings.INSURANCE_SERVER_WG_PUBLIC_KEY}" endpoint-address={settings.INSURANCE_SERVER_PUBLIC_IP} endpoint-port={settings.INSURANCE_WG_PORT} allowed-address={settings.INSURANCE_WG_SUBNET} persistent-keepalive=25
}}
:do {{ /ip firewall filter add chain=input protocol=udp dst-port={settings.INSURANCE_WG_PORT} action=accept comment="Allow backup WireGuard" }} on-error={{}}

:log info "Provisioning: backup WireGuard tunnel configured"
:delay 3s"""


def _rsc_vpn_l2tp(token: ProvisioningToken) -> str:
    return f"""
# ---- STEP 3: L2TP/IPsec VPN (RouterOS v6) ----

:do {{
    /interface l2tp-client add name=l2tp-aws connect-to={token.server_public_ip} user="{token.l2tp_username}" password="{token.l2tp_password}" disabled=no allow=mschap2,mschap1 comment="Management VPN to AWS"
}} on-error={{
    /interface l2tp-client set [find where name=l2tp-aws] connect-to={token.server_public_ip} user="{token.l2tp_username}" password="{token.l2tp_password}" disabled=no allow=mschap2,mschap1 comment="Management VPN to AWS"
}}

# Some RouterOS v6 builds reject `use-ipsec` while importing an add command.
# Parse it at runtime so unsupported builds warn without aborting provisioning.
:do {{
    :local bwSetIpsec [:parse "/interface l2tp-client set [find where name=l2tp-aws] use-ipsec=yes ipsec-secret={settings.L2TP_IPSEC_PSK}"]
    $bwSetIpsec
    :log info "Provisioning: L2TP IPsec settings applied"
}} on-error={{
    :log warning "Provisioning: RouterOS rejected L2TP use-ipsec/ipsec-secret settings"
}}
:do {{ /ip firewall filter add chain=input protocol=udp dst-port=500,4500,1701 action=accept comment="Allow L2TP/IPsec" }} on-error={{}}

:log info "Provisioning: L2TP/IPsec tunnel configured, waiting for connection..."
:delay 15s

# Verify L2TP connected and got the expected IP
:local l2tpRunning [:len [/interface l2tp-client find where name=l2tp-aws running=yes]]
:if ($l2tpRunning = 0) do={{
    :log warning "Provisioning: L2TP tunnel not yet connected -- will retry on reboot"
}} else={{
    :log info "Provisioning: L2TP tunnel connected"
}}"""


def _rsc_backup_l2tp(token: ProvisioningToken) -> str:
    interface_name = settings.INSURANCE_L2TP_INTERFACE
    return f"""
# ---- STEP 3B: BACKUP L2TP/IPsec VPN (new server insurance tunnel) ----

:do {{
    /interface l2tp-client add name={interface_name} connect-to={settings.INSURANCE_SERVER_PUBLIC_IP} user="{token.l2tp_username}" password="{token.l2tp_password}" disabled=yes allow=mschap2,mschap1 add-default-route=no use-peer-dns=no comment="Standby management tunnel - enable only during failover"
}} on-error={{
    /interface l2tp-client set [find where name={interface_name}] connect-to={settings.INSURANCE_SERVER_PUBLIC_IP} user="{token.l2tp_username}" password="{token.l2tp_password}" disabled=yes allow=mschap2,mschap1 add-default-route=no use-peer-dns=no comment="Standby management tunnel - enable only during failover"
}}

:do {{
    :local bwSetInsuranceIpsec [:parse "/interface l2tp-client set [find where name={interface_name}] use-ipsec=yes ipsec-secret={_insurance_l2tp_psk()}"]
    $bwSetInsuranceIpsec
    :log info "Provisioning: backup L2TP IPsec settings applied"
}} on-error={{
    :log warning "Provisioning: RouterOS rejected backup L2TP use-ipsec/ipsec-secret settings"
}}

:log info "Provisioning: backup L2TP/IPsec tunnel staged disabled for single-active failover"
:delay 15s"""


def _rsc_input_accept_first(comment: str, match: str) -> str:
    """Add an input-chain accept rule at the TOP of the filter table.

    A plain `add` appends, so on routers that still carry MikroTik's default
    firewall the rule lands below "defconf: drop all not coming from LAN" and
    never matches (Router-0767 had its "Allow WireGuard" at position 63).
    `place-before=0` is not reliable in an imported script and fails outright
    on an empty table, so place it before the first STATIC rule's internal id
    (dynamic rules such as the hotspot/fasttrack markers cannot be anchors).
    If the table has no static rule, or placement is refused, append instead
    -- with nothing static above it, the rule is still ahead of any drop.
    Removing any copy first keeps re-runs converging on exactly one rule.
    """
    add = f'/ip firewall filter add chain=input {match} action=accept comment="{comment}"'
    return f"""
:do {{
    :do {{ /ip firewall filter remove [find where comment="{comment}"] }} on-error={{}}
    :local bwPlaced false
    :if ([:len [/ip firewall filter find where dynamic=no]] > 0) do={{
        :do {{
            :local bwFirstRule [:pick [/ip firewall filter find where dynamic=no] 0]
            {add} place-before=$bwFirstRule
            :set bwPlaced true
        }} on-error={{
            :log warning "Provisioning: could not place '{comment}' at the top -- appending it"
        }}
    }}
    :if ($bwPlaced = false) do={{
        {add}
    }}
}} on-error={{
    :log warning "Provisioning: could not add firewall rule '{comment}'"
}}"""


def _rsc_mgmt_loopback_pin(token: ProvisioningToken) -> str:
    """Pin the router's DB address 10.0.X.Y on the `lo-mgmt` loopback bridge.

    The app, route-sync and dashboards all address the router by
    routers.ip_address (10.0.X.Y) while the tunnel itself carries 10.251.X.Y.
    The host's route-sync sends 10.0.X.Y over the tunnel; the router only
    accepts it if it owns the address, which the loopback guarantees.
    """
    loopback = SSTP_MGMT_LOOPBACK
    mgmt_ip = token.wireguard_ip
    return f"""
# Pin the management IP {mgmt_ip} on a loopback bridge. The server reaches this
# router at {mgmt_ip} (routers.ip_address) through the tunnel; without the pin
# the router would not own that address and would drop the traffic.
:if ([:len [/interface bridge find where name={loopback}]] = 0) do={{
    :do {{ /interface bridge add name={loopback} comment="Management IP pin" }} on-error={{}}
}}
:if ([:len [/ip address find where address="{mgmt_ip}/32" and interface={loopback}]] = 0) do={{
    :do {{ /ip address add address={mgmt_ip}/32 interface={loopback} comment="Management IP pin" }} on-error={{}}
}}"""


def _rsc_vpn_hetzner_wireguard(token: ProvisioningToken) -> str:
    iface = HETZNER_WG_ROUTER_INTERFACE
    port = settings.INSURANCE_WG_PORT
    tunnel_ip = derive_insurance_ip(token.wireguard_ip, settings.INSURANCE_WG_SUBNET)
    peer_params = (
        f'public-key="{token.server_wg_pubkey}" endpoint-address={token.server_public_ip} '
        f"endpoint-port={port} allowed-address={settings.INSURANCE_WG_SUBNET} persistent-keepalive=25"
    )
    return f"""
# ---- STEP 3: WIREGUARD MANAGEMENT TUNNEL TO HETZNER (RouterOS v7) ----
# This is the router's ONLY management tunnel: {iface} to the Hetzner wg2
# server ({token.server_public_ip}:{port}), tunnel address {tunnel_ip}. No AWS
# tunnel and no standby/insurance tunnel is configured -- a second tunnel
# would claim the same addresses.

:do {{
    /interface wireguard add name={iface} listen-port={port} private-key="{token.wg_private_key}"
}} on-error={{
    /interface wireguard set [find where name={iface}] listen-port={port} private-key="{token.wg_private_key}"
}}
:do {{ /ip address add address={tunnel_ip}/16 interface={iface} }} on-error={{}}
:do {{
    /interface wireguard peers add interface={iface} {peer_params}
}} on-error={{
    /interface wireguard peers set [find where interface={iface}] {peer_params}
}}
{_rsc_input_accept_first(HETZNER_WG_FIREWALL_COMMENT, f"protocol=udp dst-port={port}")}
{_rsc_mgmt_loopback_pin(token)}

:log info "Provisioning: WireGuard management tunnel to Hetzner configured"
:delay 3s"""


def _rsc_sstp_client_add_or_set(client_params: str, indent: str) -> str:
    iface = SSTP_ROUTER_INTERFACE
    # Every value inside the [:parse "..."] strings is quote-free (identity
    # Router-NNNN, alphanumeric password, host:port), so no escaping is needed.
    lines = [
        ":do {",
        f'    :local bwSstpAdd [:parse "/interface sstp-client add name={iface} {client_params}"]',
        "    $bwSstpAdd",
        "} on-error={",
        "    :do {",
        f'        :local bwSstpSet [:parse "/interface sstp-client set [find where name={iface}] {client_params}"]',
        "        $bwSstpSet",
        "    } on-error={",
        '        :log warning "Provisioning: RouterOS rejected the SSTP client settings"',
        "    }",
        "}",
    ]
    return "\n".join(indent + line for line in lines)


def _rsc_vpn_sstp(token: ProvisioningToken) -> str:
    base_url = provision_base_url_for_vpn(token.vpn_type)
    cert_flag = fetch_certificate_flag_for_url(base_url, token.vpn_type)
    server = settings.SSTP_SERVER.strip()
    iface = SSTP_ROUTER_INTERFACE
    tunnel_ip = derive_sstp_ip(token.wireguard_ip)
    common = (
        f"user={token.sstp_username} password={token.sstp_password} "
        "profile=default add-default-route=no verify-server-certificate=yes "
        "verify-server-address-from-certificate=yes disabled=no"
    )
    v6_params = f"{sstp_connect_to(server, 6)} {common}"
    v7_params = f"{sstp_connect_to(server, 7)} {common}"
    return f"""
# ---- STEP 3: SSTP MANAGEMENT TUNNEL TO HETZNER (RouterOS v6) ----
# This is the router's ONLY management tunnel: {iface} to the Hetzner
# accel-ppp server ({server}), login {token.sstp_username}, tunnel address
# {tunnel_ip}. SSTP is one TCP connection per router, so any number of routers
# can share a CGNAT address (L2TP/IPsec cannot). No L2TP to AWS and no standby
# L2TP is configured -- a second tunnel would claim the same addresses.
# Commands that differ between RouterOS versions go through [:parse] so an
# unsupported build logs a warning instead of aborting the import.

:if ([:len [/certificate find where common-name="{ROUTER_MGMT_CA_CN}"]] = 0) do={{
    :do {{
        /tool fetch url="{base_url}{ROUTER_MGMT_CA_PATH}" dst-path={ROUTER_MGMT_CA_FILE}{cert_flag}
        :delay 2s
        /certificate import file-name={ROUTER_MGMT_CA_FILE} passphrase=""
        :log info "Provisioning: router management CA imported"
    }} on-error={{
        :log warning "Provisioning: could not fetch/import the router management CA -- SSTP cannot verify the server"
    }}
}}
:do {{ /certificate set [find where common-name="{ROUTER_MGMT_CA_CN}"] trusted=yes }} on-error={{}}

# SSTP certificate checks need a correct clock (hAP lite has no RTC).
:do {{
    :local bwSetNtp [:parse "/system ntp client set enabled=yes primary-ntp={SSTP_NTP_SERVER}"]
    $bwSetNtp
}} on-error={{
    :log warning "Provisioning: could not enable the NTP client"
}}

# add-then-set so re-running this script converges. RouterOS 6 takes the port
# INSIDE connect-to (ip:port); RouterOS 7 takes a separate port= -- pick the
# form for the version actually running (some v6-token routers run v7).
:do {{
    :if ([:pick [/system resource get version] 0 1] = "7") do={{
{_rsc_sstp_client_add_or_set(v7_params, "        ")}
    }} else={{
{_rsc_sstp_client_add_or_set(v6_params, "        ")}
    }}
}} on-error={{
    :log warning "Provisioning: could not configure the SSTP client"
}}
{_rsc_mgmt_loopback_pin(token)}

:log info "Provisioning: SSTP tunnel configured, waiting for connection..."
:delay 10s

:do {{
    :local sstpRunning [:len [/interface sstp-client find where name={iface} running=yes]]
    :if ($sstpRunning = 0) do={{
        :log warning "Provisioning: SSTP tunnel not yet connected -- the client keeps retrying"
    }} else={{
        :log info "Provisioning: SSTP tunnel connected"
    }}
}} on-error={{}}"""


def _rsc_hotspot(token: ProvisioningToken) -> str:
    # Pick the hotspot html-directory at script-render time based on
    # (vpn_type, is_routerboard):
    #
    #   * v7 (wireguard)              -> "hotspot"     (unified persistent FS,
    #                                                   always correct)
    #   * v6 (l2tp), is_routerboard=F -> "hotspot"     (DEFAULT: matches the
    #                                                   pre-cef0221 behaviour
    #                                                   that worked for every
    #                                                   v6 router we had in
    #                                                   the field; the
    #                                                   captive-portal redirect
    #                                                   works correctly on CHR,
    #                                                   x86, and on every v6
    #                                                   build whose firmware
    #                                                   uses a unified FS.)
    #   * v6 (l2tp), is_routerboard=T -> "flash/hotspot"  (legacy hEX/RB-series
    #                                                   workaround: the root
    #                                                   `/file` tree on those
    #                                                   boards is RAM-backed
    #                                                   tmpfs and only `flash/`
    #                                                   is NAND-persistent, so
    #                                                   custom login.html
    #                                                   written to plain
    #                                                   `hotspot/` is wiped on
    #                                                   reboot. The frontend
    #                                                   exposes this as an
    #                                                   explicit "hEX /
    #                                                   RouterBOARD on v6"
    #                                                   checkbox -- it is NOT
    #                                                   inferred from
    #                                                   board-name anymore,
    #                                                   because the same
    #                                                   detection mis-fired on
    #                                                   v6 hAP-series and
    #                                                   newer-firmware hEX
    #                                                   builds where `flash/`
    #                                                   either does not exist
    #                                                   or is not what the
    #                                                   hotspot service reads
    #                                                   from.)
    is_v6 = token.vpn_type == "l2tp"
    use_flash_dir = is_v6 and bool(getattr(token, "is_routerboard", False))

    if use_flash_dir:
        html_dir_block = """
# RouterOS v6 hEX / hAP / RB-series with split filesystem (root is tmpfs,
# only `flash/` is NAND-persistent). The frontend opted in via
# is_routerboard=true, so point hsprof1.html-directory at `flash/hotspot`
# so our custom login.html survives reboot.
:global bwHtmlDir "flash/hotspot"
:log info "Provisioning: v6 RouterBOARD opt-in, html-directory=flash/hotspot" """
    else:
        # Default path: plain `hotspot`. Correct for v7 on every platform,
        # and correct for v6 on CHR / x86 / any v6 firmware with a unified
        # persistent filesystem. Matches the behaviour we shipped before
        # commit cef0221.
        html_dir_block = """
# Default html-directory. Works on:
#   - RouterOS v7 (unified persistent FS on every supported platform)
#   - RouterOS v6 CHR / x86 / unified-FS builds
# v6 RouterBOARDs with a split RAM/flash filesystem (legacy hEX, hAP, RB-
# series) need is_routerboard=true at token-creation time to switch to
# `flash/hotspot` instead.
:global bwHtmlDir "hotspot"
:log info "Provisioning: default html-directory=hotspot" """

    return """
# ---- STEP 4: HOTSPOT SETUP ----

:if ([:len [/interface bridge find where name=bridge]] = 0) do={
    :log error "PROVISION ABORTED at hotspot step: bridge interface missing"
    :error "bridge interface does not exist -- cannot create hotspot"
}
""" + html_dir_block + """

# Clean legacy hotspot directories left behind by previous provisioners
# (CentiPid, OpenWISP, earlier versions of ours). This is best-effort and
# must never touch flash/etc*, flash/user-manager*, flash/skins, etc.
:do { /file remove [find where name="flash/centipid-hotspot"] } on-error={}
:foreach legacyId in=[/file find where name~"^flash/openwisp-hotspot" and type="directory"] do={
    :do { /file remove $legacyId } on-error={}
}

:do {
    /ip hotspot profile add name=hsprof1 hotspot-address=192.168.88.1 dns-name="" login-by=http-chap,http-pap html-directory=$bwHtmlDir
    :log info ("Provisioning: hotspot profile hsprof1 created with html-directory=" . $bwHtmlDir)
} on-error={
    :do { /ip hotspot profile set hsprof1 html-directory=$bwHtmlDir } on-error={
        :log warning "Provisioning: could not update hsprof1 html-directory, continuing"
    }
    :log info ("Provisioning: hotspot profile hsprof1 already existed, html-directory=" . $bwHtmlDir)
}

# Materialise RouterOS's default hotspot HTML file set into html-directory
# so our subsequent /tool fetch of login.html has a complete supporting
# set (rlogin.html, alogin.html, logout.html, md5.js, img/, ...). Works on
# RouterOS v6 and v7. NOTE: reset-html-directory takes the profile NAME
# as a positional argument -- it rejects [find where name=...] in the CLI
# parser even though most other commands accept that form.
:do {
    /ip hotspot profile reset-html-directory hsprof1
    :log info "Provisioning: hotspot profile reset-html-directory applied"
} on-error={
    :log warning "Provisioning: reset-html-directory not available on this RouterOS, continuing"
}

:do {
    /ip hotspot add name=hotspot1 interface=bridge address-pool=dhcp-pool profile=hsprof1 disabled=no
    :log info "Provisioning: hotspot1 created"
} on-error={
    :log warning "Provisioning: hotspot1 add failed (may already exist or hotspot feature unavailable)"
}

:local hsCount 0
:do {
    :set hsCount [:len [/ip hotspot find where name=hotspot1]]
} on-error={
    :log error "PROVISION WARNING: could not query hotspot -- the hotspot feature may not be available. Ensure device-mode hotspot is enabled: /system/device-mode/update hotspot=yes then press the physical reset button."
}
:if ($hsCount = 0) do={
    :log error "PROVISION WARNING: hotspot1 was not found -- hotspot feature may not be enabled. Run: /system/device-mode/update hotspot=yes then press the physical reset button."
} else={
    :log info "Provisioning: hotspot1 confirmed running"
}

:do { /interface bridge port remove [find where interface=ether1] } on-error={}

:log info "Provisioning: Hotspot step complete" """


def _rsc_login_page(token: ProvisioningToken) -> str:
    base_url = provision_base_url_for_vpn(token.vpn_type)
    t = token.token
    cert_flag = fetch_certificate_flag_for_url(base_url, token.vpn_type)
    return f"""
# ---- STEP 5: DOWNLOAD CUSTOM LOGIN PAGE ----

:delay 2s

# Derive the destination from the hotspot profile so we always write into
# whatever html-directory step 4 picked: `flash/hotspot` for v6 RouterBOARDs
# provisioned with is_routerboard=true, `hotspot` everywhere else. Falls back
# to the $bwHtmlDir global, then to the legacy `hotspot` path if neither is
# available.
:local htmlDir ""
:do {{
    :set htmlDir [/ip hotspot profile get hsprof1 html-directory]
}} on-error={{}}
:if ([:len $htmlDir] = 0) do={{
    :global bwHtmlDir
    :if ([:typeof $bwHtmlDir] = "str" and [:len $bwHtmlDir] > 0) do={{
        :set htmlDir $bwHtmlDir
    }} else={{
        :set htmlDir "hotspot"
    }}
}}
:local loginPath ($htmlDir . "/login.html")
:log info ("Provisioning: downloading login page to " . $loginPath)

:local fetchOk false
:for i from=1 to=5 do={{
    :if (!$fetchOk) do={{
        :do {{
            /tool fetch url="{base_url}/api/provision/{t}/login-page" dst-path=$loginPath{cert_flag}
            :set fetchOk true
            :log info ("Provisioning: Login page downloaded to " . $loginPath)
        }} on-error={{
            :log warning "Provisioning: Login page download attempt $i failed, retrying..."
            :delay 5s
        }}
    }}
}}"""


def _rsc_walled_garden(token: ProvisioningToken) -> str:
    backup_ip_line = ""
    insurance_public_ip = (settings.INSURANCE_SERVER_PUBLIC_IP or "").strip()
    if insurance_public_ip and insurance_public_ip != token.server_public_ip:
        backup_ip_line = (
            f'\n:do {{ /ip hotspot walled-garden ip add dst-address={insurance_public_ip}/32 '
            'action=accept comment="Backup backend API IP" } on-error={}'
        )
    return f"""
# ---- STEP 6: WALLED GARDEN ----

/ip hotspot walled-garden add dst-host=isp-frontend-two.vercel.app action=allow comment="External Portal"
/ip hotspot walled-garden add dst-host="*.vercel.app" action=allow comment="Vercel CDN"
/ip hotspot walled-garden add dst-host=isp.bitwavetechnologies.net action=allow comment="Backend API (.net)"
/ip hotspot walled-garden add dst-host=isp.bitwavetechnologies.com action=allow comment="Backend API (.com)"
/ip hotspot walled-garden add dst-host=ispp.bitwavetechnologies.com action=allow comment="Backend API direct (not Cloudflare-proxied)"
:do {{ /ip hotspot walled-garden ip add dst-address={token.server_public_ip}/32 action=accept comment="Backend API IP" }} on-error={{}}
{backup_ip_line}

:log info "Provisioning: Walled garden configured" """


def _rsc_api_access() -> str:
    sources = [str(WG_SERVER_IP)]
    backup_source = (settings.INSURANCE_SERVER_VPN_IP or "").strip()
    if backup_source and backup_source not in sources:
        sources.append(backup_source)

    address_list = ",".join(f"{source}/32" for source in sources)
    firewall_lines = []
    for source in sources:
        comment = "Allow API from primary AWS" if source == str(WG_SERVER_IP) else "Allow API from backup AWS"
        firewall_lines.append(
            f':do {{ /ip firewall filter add chain=input protocol=tcp dst-port=8728 '
            f'src-address={source} action=accept comment="{comment}" place-before=0 }} on-error={{}}'
        )

    return f"""
# ---- STEP 7: ENABLE MIKROTIK API (restricted to VPN servers) ----

/ip service set api address={address_list} port=8728 disabled=no
{chr(10).join(firewall_lines)}"""


def _hetzner_mgmt_server_vpn_ip(token: ProvisioningToken) -> str:
    """The address the Hetzner host uses towards the router over its tunnel
    (accel-ppp gw for SSTP, wg2's address for WireGuard) -- the only source
    the router's API has to accept."""
    if token_uses_sstp(token):
        return settings.SSTP_SERVER_VPN_IP.strip()
    return settings.INSURANCE_SERVER_VPN_IP.strip()


def _rsc_api_access_hetzner(token: ProvisioningToken) -> str:
    source = _hetzner_mgmt_server_vpn_ip(token)
    return f"""
# ---- STEP 7: ENABLE MIKROTIK API (Hetzner management tunnel only) ----
# The Hetzner host reaches this router from {source} (route-sync steers
# {token.wireguard_ip} over the tunnel); nothing else may use the API.

/ip service set api address={source}/32 port=8728 disabled=no
{_rsc_input_accept_first(HETZNER_API_FIREWALL_COMMENT, f"protocol=tcp dst-port=8728 src-address={source}")}"""


def _rsc_identity_and_user(token: ProvisioningToken) -> str:
    return f"""
# ---- STEP 8: CREATE API SERVICE ACCOUNT & SET IDENTITY ----

/system identity set name={token.identity}
:do {{ /user add name={API_USERNAME} password="{token.router_admin_password}" group=full comment="Bitwave backend API account" }} on-error={{}}

:log info "Provisioning: Identity set to {token.identity}, API user created" """


def _rsc_remove_router_command_agent() -> str:
    """New routers no longer get the outbound command agent.

    Its script fails on every run on RouterOS 7.19+ (it sat dead on 55 routers
    for a week, 2026-09-23), and nothing depends on it: cleanup and
    provisioning reach routers over the API. A router being re-provisioned
    drops any copy an earlier provisioning installed.
    """

    from app.services.router_agent_script import SCRIPT_NAME, SCHEDULER_NAME

    return f"""
# ---- STEP 9: REMOVE LEGACY OUTBOUND COMMAND AGENT ----

:do {{ /system scheduler remove [find name="{SCHEDULER_NAME}"] }} on-error={{}}
:do {{ /system script remove [find name="{SCRIPT_NAME}"] }} on-error={{}}
"""


def _rsc_notify_and_reboot(token: ProvisioningToken) -> str:
    base_url = provision_base_url_for_vpn(token.vpn_type)
    t = token.token
    cert_flag = fetch_certificate_flag_for_url(base_url, token.vpn_type)
    return f"""
# ---- STEP 9: NOTIFY SERVER ----

:delay 2s
:do {{
    /tool fetch url="{base_url}/api/provision/{t}/complete"{cert_flag}
    :log info "Provisioning: Server notified -- router registered"
}} on-error={{
    :log warning "Provisioning: Could not notify server (register manually via admin panel)"
}}

# ---- STEP 10: REBOOT ----

:log info "Provisioning complete! Rebooting in 5 seconds..."
:delay 5s
/system reboot
"""


def generate_rsc_script(token: ProvisioningToken) -> str:
    """Generate the MikroTik .rsc auto-provisioning script, adapting for v6 or v7."""
    parts = [_rsc_header(token)]

    # Both v6 and v7 can be missing the hotspot feature (disabled package on
    # v6, device-mode on v7) -- always probe before touching any config.
    parts.append(_rsc_preflight_hotspot(token))

    parts.append(_rsc_wan_setup())
    parts.append(_rsc_lan_setup())

    hetzner = token_mgmt_to_hetzner(token)
    if hetzner:
        # PROVISION_MGMT_TO_HETZNER: exactly ONE management tunnel, to Hetzner.
        # No AWS primary and no insurance/standby duplicate (either would
        # claim this router's 10.251.X.Y / 10.0.X.Y as well).
        if token_uses_sstp(token):
            parts.append(_rsc_vpn_sstp(token))
        else:
            parts.append(_rsc_vpn_hetzner_wireguard(token))
    elif token.vpn_type == "l2tp":
        parts.append(_rsc_vpn_l2tp(token))
        parts.append(_rsc_backup_l2tp(token))
    else:
        parts.append(_rsc_vpn_wireguard(token))
        parts.append(_rsc_backup_wireguard(token))

    parts.append(_rsc_hotspot(token))
    parts.append(_rsc_login_page(token))
    parts.append(_rsc_walled_garden(token))
    parts.append(_rsc_api_access_hetzner(token) if hetzner else _rsc_api_access())
    parts.append(_rsc_identity_and_user(token))
    parts.append(_rsc_remove_router_command_agent())
    parts.append(_rsc_notify_and_reboot(token))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Identity / naming generation
# ---------------------------------------------------------------------------

async def _generate_identity(db: AsyncSession) -> str:
    """Generate the next unique router identity like Router-0005."""
    router_count = await db.execute(select(func.count(Router.id)))
    token_count = await db.execute(select(func.count(ProvisioningToken.id)))
    next_num = (router_count.scalar() or 0) + (token_count.scalar() or 0) + 1

    for attempt in range(next_num, next_num + 100):
        candidate = f"Router-{attempt:04d}"
        r = await db.execute(select(Router).where(Router.identity == candidate))
        t = await db.execute(
            select(ProvisioningToken).where(
                ProvisioningToken.identity == candidate,
                ProvisioningToken.status == ProvisioningTokenStatus.PENDING,
            )
        )
        if not r.scalar_one_or_none() and not t.scalar_one_or_none():
            return candidate

    raise ValueError("Could not generate a unique router identity")


async def _generate_router_name(db: AsyncSession, user_id: int) -> str:
    """Generate a router name like 'Bitwave Technologies #3'."""
    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()
    base_name = (user.business_name or user.organization_name) if user else "Router"

    router_count_result = await db.execute(
        select(func.count(Router.id)).where(Router.user_id == user_id)
    )
    token_count_result = await db.execute(
        select(func.count(ProvisioningToken.id)).where(
            ProvisioningToken.user_id == user_id,
            ProvisioningToken.status == ProvisioningTokenStatus.PENDING,
        )
    )
    total = (router_count_result.scalar() or 0) + (token_count_result.scalar() or 0)
    return f"{base_name} #{total + 1}"


# ---------------------------------------------------------------------------
# Token creation (dual WireGuard / L2TP)
# ---------------------------------------------------------------------------

async def _create_hetzner_provisioning_token(
    db: AsyncSession,
    user_id: int,
    payment_methods: Optional[list],
    vpn_type: str,
    is_routerboard: bool,
) -> ProvisioningToken:
    """PROVISION_MGMT_TO_HETZNER: one management tunnel, to Hetzner, nothing on AWS.

    * RouterOS 7 (wireguard): router key registered on the Hetzner wg2
      manager (INSURANCE_WG_MANAGER_URL /add-peer) as 10.251.X.Y/32.
    * RouterOS 6 (l2tp): SSTP login sstp-<identity> -> 10.251.X.Y written to
      the accel-ppp chap-secrets by the same manager (/add-sstp-peer).

    The router's DB address stays 10.0.X.Y from the usual ranges; the tunnel
    address is its 10.251 twin. Nothing is registered on the AWS wg-manager.
    """
    mgmt_tunnel = hetzner_mgmt_tunnel_for(vpn_type)
    _require_hetzner_mgmt_settings(vpn_type)

    router_name = await _generate_router_name(db, user_id)
    identity = await _generate_identity(db)
    vpn_ip = await allocate_vpn_ip(db, vpn_type)
    api_password = generate_api_password()
    token_value = uuid.uuid4().hex

    wg_private_key = wg_public_key = server_wg_pubkey = None
    sstp_username = sstp_password = None
    if mgmt_tunnel == MGMT_TUNNEL_HETZNER_SSTP:
        tunnel_ip = derive_sstp_ip(vpn_ip)
        sstp_username = generate_sstp_username(identity)
        sstp_password = generate_api_password(24)
    else:
        tunnel_ip = derive_insurance_ip(vpn_ip, settings.INSURANCE_WG_SUBNET)
        wg_private_key, wg_public_key = generate_wireguard_keypair()
        server_wg_pubkey = settings.INSURANCE_SERVER_WG_PUBLIC_KEY.strip()

    registered = False

    # Release the transaction opened by the allocation SELECTs before the
    # manager HTTP call. A slow manager must not pin a pooled DB connection.
    await db.commit()

    try:
        if mgmt_tunnel == MGMT_TUNNEL_HETZNER_SSTP:
            await register_sstp_peer(sstp_username, sstp_password, tunnel_ip)
        else:
            from app.services.insurance_wireguard import register_insurance_peer

            await register_insurance_peer(wg_public_key, tunnel_ip)
        registered = True

        token_obj = ProvisioningToken(
            user_id=user_id,
            token=token_value,
            router_name=router_name,
            identity=identity,
            wireguard_ip=vpn_ip,
            ssid="N/A",
            router_admin_password=api_password,
            vpn_type=vpn_type,
            wg_private_key=wg_private_key,
            wg_public_key=wg_public_key,
            server_wg_pubkey=server_wg_pubkey,
            sstp_username=sstp_username,
            sstp_password=sstp_password,
            management_tunnel=mgmt_tunnel,
            # The Hetzner server: WireGuard endpoint for v7, and the backend
            # IP the hotspot walled garden allows.
            server_public_ip=settings.INSURANCE_SERVER_PUBLIC_IP.strip(),
            payment_methods=payment_methods or ["mpesa", "voucher"],
            is_routerboard=bool(is_routerboard) and vpn_type == "l2tp",
            status=ProvisioningTokenStatus.PENDING,
        )

        db.add(token_obj)
        await db.commit()
        await db.refresh(token_obj)
    except Exception as inner_err:
        await db.rollback()
        logger.error(
            "Hetzner provisioning failed after tunnel manager work: "
            f"{type(inner_err).__name__}: {repr(inner_err)}",
            exc_info=True,
        )
        if registered:
            try:
                if mgmt_tunnel == MGMT_TUNNEL_HETZNER_SSTP:
                    await remove_sstp_peer(sstp_username)
                else:
                    from app.services.insurance_wireguard import remove_insurance_peer

                    await remove_insurance_peer(wg_public_key)
                logger.info(f"Rolled back Hetzner {mgmt_tunnel} peer for {tunnel_ip} after failure")
            except Exception as cleanup_err:
                logger.warning(f"Failed to roll back Hetzner {mgmt_tunnel} peer for {tunnel_ip}: {cleanup_err}")
        raise

    logger.info(
        f"Provisioning token created (Hetzner {mgmt_tunnel}): identity={identity} "
        f"mgmt_ip={vpn_ip} tunnel_ip={tunnel_ip} vpn_type={vpn_type} by user_id={user_id}"
    )
    return token_obj


async def create_provisioning_token(
    db: AsyncSession,
    user_id: int,
    payment_methods: Optional[list] = None,
    vpn_type: str = "wireguard",
    is_routerboard: bool = False,
) -> ProvisioningToken:
    """
    Full provisioning flow supporting both WireGuard (v7) and L2TP/IPsec (v6):
    1. Auto-generate router name and identity
    2. Generate VPN credentials (WG keypair or L2TP user/pass)
    3. Allocate next available VPN IP from the correct range
    4. Register primary and backup peers on their tunnel managers
    5. Auto-generate API service account password
    6. Save token to database
    """
    if vpn_type not in ("wireguard", "l2tp"):
        raise ValueError(f"Invalid vpn_type '{vpn_type}'. Must be 'wireguard' or 'l2tp'.")

    if mgmt_to_hetzner_active():
        return await _create_hetzner_provisioning_token(
            db, user_id, payment_methods, vpn_type, is_routerboard
        )

    if not settings.SERVER_PUBLIC_IP:
        raise ValueError(
            "SERVER_PUBLIC_IP is not configured. "
            "Set it to your AWS server's public IP in .env"
        )

    _require_insurance_settings(vpn_type)

    router_name = await _generate_router_name(db, user_id)
    identity = await _generate_identity(db)
    vpn_ip = await allocate_vpn_ip(db, vpn_type)
    backup_ip = derive_insurance_ip(vpn_ip)
    api_password = generate_api_password()
    token_value = uuid.uuid4().hex

    # --- VPN-specific setup ---
    wg_private_key = wg_public_key = server_wg_pubkey = None
    backup_wg_public_key = None
    l2tp_username = l2tp_password = None
    primary_registered = False
    backup_registered = False

    # Release the transaction opened by the allocation SELECTs before the
    # manager HTTP calls. A slow manager must not pin a pooled DB connection.
    await db.commit()

    try:
        if vpn_type == "wireguard":
            from app.services.insurance_wireguard import register_insurance_peer

            wg_private_key, wg_public_key = generate_wireguard_keypair()
            _backup_private_key, backup_wg_public_key = derive_insurance_wireguard_keypair(
                token_value=token_value,
                identity=identity,
                primary_ip=vpn_ip,
                primary_private_key=wg_private_key,
            )
            await register_wireguard_peer(wg_public_key, vpn_ip)
            primary_registered = True
            server_wg_pubkey = await get_server_wg_public_key()
            await register_insurance_peer(backup_wg_public_key, backup_ip)
            backup_registered = True
        else:
            from app.services.insurance_l2tp import register_insurance_l2tp_peer

            l2tp_username = generate_l2tp_username(identity)
            l2tp_password = generate_api_password(20)
            await register_l2tp_peer(l2tp_username, l2tp_password, vpn_ip)
            primary_registered = True
            await register_insurance_l2tp_peer(l2tp_username, l2tp_password, backup_ip)
            backup_registered = True

        token_obj = ProvisioningToken(
            user_id=user_id,
            token=token_value,
            router_name=router_name,
            identity=identity,
            wireguard_ip=vpn_ip,
            ssid="N/A",
            router_admin_password=api_password,
            vpn_type=vpn_type,
            wg_private_key=wg_private_key,
            wg_public_key=wg_public_key,
            server_wg_pubkey=server_wg_pubkey,
            l2tp_username=l2tp_username,
            l2tp_password=l2tp_password,
            server_public_ip=settings.SERVER_PUBLIC_IP,
            payment_methods=payment_methods or ["mpesa", "voucher"],
            # v7 always uses unified `hotspot` html-directory; only honour the
            # routerboard opt-in for v6 (L2TP) tokens.
            is_routerboard=bool(is_routerboard) and vpn_type == "l2tp",
            status=ProvisioningTokenStatus.PENDING,
        )

        db.add(token_obj)
        await db.commit()
        await db.refresh(token_obj)
    except Exception as inner_err:
        await db.rollback()
        logger.error(
            "Provisioning failed after tunnel manager work: "
            f"{type(inner_err).__name__}: {repr(inner_err)}",
            exc_info=True,
        )
        if vpn_type == "wireguard":
            try:
                if backup_registered and backup_wg_public_key:
                    from app.services.insurance_wireguard import remove_insurance_peer

                    await remove_insurance_peer(backup_wg_public_key)
                    logger.info(f"Rolled back backup WG peer for {backup_ip} after failure")
            except Exception as cleanup_err:
                logger.warning(f"Failed to roll back backup WG peer for {backup_ip}: {cleanup_err}")
            try:
                if primary_registered and wg_public_key:
                    await remove_wireguard_peer(wg_public_key)
                    logger.info(f"Rolled back primary WG peer for {vpn_ip} after failure")
            except Exception as cleanup_err:
                logger.warning(f"Failed to roll back primary WG peer for {vpn_ip}: {cleanup_err}")
        else:
            try:
                if backup_registered and l2tp_username:
                    from app.services.insurance_l2tp import remove_insurance_l2tp_peer

                    await remove_insurance_l2tp_peer(l2tp_username)
                    logger.info(f"Rolled back backup L2TP peer for {backup_ip} after failure")
            except Exception as cleanup_err:
                logger.warning(f"Failed to roll back backup L2TP peer for {backup_ip}: {cleanup_err}")
            try:
                if primary_registered and l2tp_username:
                    await remove_l2tp_peer(l2tp_username)
                    logger.info(f"Rolled back primary L2TP peer for {vpn_ip} after failure")
            except Exception as cleanup_err:
                logger.warning(f"Failed to roll back primary L2TP peer for {vpn_ip}: {cleanup_err}")
        raise

    logger.info(
        f"Provisioning token created: identity={identity} vpn_ip={vpn_ip} "
        f"vpn_type={vpn_type} by user_id={user_id}"
    )
    return token_obj


def build_provision_command(token: ProvisioningToken) -> str:
    """Build the one-liner command the admin pastes on a factory-reset MikroTik."""
    base_url = provision_base_url_for_vpn(token.vpn_type)
    url = f"{base_url}/api/provision/{token.token}"
    cert_flag = fetch_certificate_flag_for_url(base_url, token.vpn_type)
    return (
        f'/tool fetch url="{url}" dst-path=provision.rsc{cert_flag};'
        f":delay 2s;"
        f"/import provision.rsc;"
    )


async def complete_provisioning(
    db: AsyncSession, token: ProvisioningToken
) -> Router:
    """Called by the .rsc callback -- creates the Router record in the database."""
    router_obj = Router(
        user_id=token.user_id,
        name=token.router_name,
        identity=token.identity,
        ip_address=token.wireguard_ip,
        username=API_USERNAME,
        password=token.router_admin_password,
        port=8728,
        payment_methods=token.payment_methods,
        # The generated RouterOS script no longer installs the outbound agent.
        router_agent_enabled=False,
    )
    if token_mgmt_to_hetzner(token):
        # "wireguard" (wg-hz) / "sstp" (sstp-hetzner): the router's only
        # management tunnel, to Hetzner. Ops health would otherwise infer the
        # tunnel from the 10.0.X.Y range (e.g. L2TP for 10.0.100.x).
        router_obj.management_tunnel = token.management_tunnel
        router_obj.management_tunnel_changed_at = datetime.utcnow()
    db.add(router_obj)
    await db.flush()

    token.status = ProvisioningTokenStatus.PROVISIONED
    token.provisioned_at = datetime.utcnow()
    token.router_id = router_obj.id

    await db.commit()
    await db.refresh(router_obj)

    logger.info(
        f"Provisioning complete: router_id={router_obj.id} "
        f"identity={token.identity} ip={token.wireguard_ip} vpn_type={token.vpn_type}"
    )
    return router_obj
