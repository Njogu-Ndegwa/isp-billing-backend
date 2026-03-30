import base64
import uuid
import secrets
import string
import ipaddress
import logging
import os
from datetime import datetime, timedelta
from typing import Optional, Tuple

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.models import Router, ProvisioningToken, ProvisioningTokenStatus, User
from app.config import settings

logger = logging.getLogger(__name__)

WG_SOCKET_PATH = "/var/run/wg-manager/wg-manager.sock"

WG_SUBNET = ipaddress.IPv4Network("10.0.0.0/24")
WG_SERVER_IP = ipaddress.IPv4Address("10.0.0.1")
WG_IP_RANGE = (ipaddress.IPv4Address("10.0.0.2"), ipaddress.IPv4Address("10.0.0.99"))
L2TP_IP_RANGE = (ipaddress.IPv4Address("10.0.0.100"), ipaddress.IPv4Address("10.0.0.199"))
TOKEN_EXPIRY_HOURS = 24

LOGIN_PAGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "captive-portal-login.html"
)

API_USERNAME = "bitwave-api"


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


# ---------------------------------------------------------------------------
# VPN IP allocation
# ---------------------------------------------------------------------------

async def allocate_vpn_ip(db: AsyncSession, vpn_type: str = "wireguard") -> str:
    """Find the next available VPN IP, respecting range split by vpn_type."""
    router_result = await db.execute(select(Router.ip_address))
    router_ips = {row[0] for row in router_result.fetchall()}

    token_result = await db.execute(
        select(ProvisioningToken.wireguard_ip).where(
            ProvisioningToken.status == ProvisioningTokenStatus.PENDING
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

    label = "L2TP (10.0.0.100-199)" if vpn_type == "l2tp" else "WireGuard (10.0.0.2-99)"
    raise ValueError(f"No available VPN IPs in the {label} range")


# Keep old name as alias for backward compat with any external callers
async def allocate_wireguard_ip(db: AsyncSession) -> str:
    return await allocate_vpn_ip(db, "wireguard")


# ---------------------------------------------------------------------------
# WireGuard peer management
# ---------------------------------------------------------------------------

async def register_wireguard_peer(public_key: str, ip: str):
    """Register a new WireGuard peer via the wg-manager sidecar."""
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
# Helpers
# ---------------------------------------------------------------------------

def is_token_expired(token: ProvisioningToken) -> bool:
    return datetime.utcnow() > token.created_at + timedelta(hours=TOKEN_EXPIRY_HOURS)


def get_login_page_html() -> str:
    """Read the captive portal login.html template."""
    with open(LOGIN_PAGE_PATH, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# .rsc script generation — shared + VPN-specific sections
# ---------------------------------------------------------------------------

def _rsc_header(token: ProvisioningToken) -> str:
    vpn_label = "WireGuard" if token.vpn_type == "wireguard" else "L2TP/IPsec"
    return f"""# ============================================================
# Bitwave ISP Auto-Provisioning Script
# Router: {token.identity} ({token.router_name})
# VPN Type: {vpn_label}
# Tunnel IP: {token.wireguard_ip}
# Generated: {datetime.utcnow().isoformat()}Z
# ============================================================"""


def _rsc_preflight_v7() -> str:
    return """
# ---- PRE-FLIGHT: DEVICE-MODE CHECK (RouterOS v7 only) ----
{
    :local mode [/system/device-mode/get mode]
    :if ($mode = "enterprise") do={
        :log info "Provisioning: device-mode=enterprise, hotspot permitted"
    } else={
        :do {
            :local dm [/system/device-mode/get hotspot]
            :if ($dm != true) do={
                :log error "PROVISION ABORTED: device-mode hotspot is disabled. Run: /system/device-mode/update hotspot=yes  then press the physical reset button within 60s. After that, re-run this script."
                :error "device-mode hotspot not enabled — aborting (see log)"
            }
            :log info "Provisioning: device-mode hotspot=yes confirmed"
        } on-error={
            :log warning "Provisioning: could not read device-mode hotspot flag, proceeding anyway (mode=$mode)"
        }
    }
}"""


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

/interface wireguard add name=wg-aws listen-port=51820 private-key="{token.wg_private_key}"
/ip address add address={token.wireguard_ip}/24 interface=wg-aws
/interface wireguard peers add interface=wg-aws \\
    public-key="{token.server_wg_pubkey}" \\
    endpoint-address={token.server_public_ip} endpoint-port=51820 \\
    allowed-address=10.0.0.0/24 persistent-keepalive=25
:do {{ /ip firewall filter add chain=input protocol=udp dst-port=51820 action=accept comment="Allow WireGuard" }} on-error={{}}

:log info "Provisioning: WireGuard tunnel configured"
:delay 3s"""


def _rsc_vpn_l2tp(token: ProvisioningToken) -> str:
    return f"""
# ---- STEP 3: L2TP/IPsec VPN (RouterOS v6) ----

/interface l2tp-client add name=l2tp-aws connect-to={token.server_public_ip} \\
    user="{token.l2tp_username}" password="{token.l2tp_password}" \\
    use-ipsec=yes ipsec-secret="{settings.L2TP_IPSEC_PSK}" \\
    disabled=no allow=mschap2,mschap1 comment="Management VPN to AWS"
:do {{ /ip firewall filter add chain=input protocol=udp dst-port=500,4500,1701 action=accept comment="Allow L2TP/IPsec" }} on-error={{}}

:log info "Provisioning: L2TP/IPsec tunnel configured, waiting for connection..."
:delay 15s

# Verify L2TP connected and got the expected IP
:local l2tpRunning [:len [/interface l2tp-client find where name=l2tp-aws running=yes]]
:if ($l2tpRunning = 0) do={{
    :log warning "Provisioning: L2TP tunnel not yet connected — will retry on reboot"
}} else={{
    :log info "Provisioning: L2TP tunnel connected"
}}"""


def _rsc_hotspot() -> str:
    return """
# ---- STEP 4: HOTSPOT SETUP ----

:if ([:len [/interface bridge find where name=bridge]] = 0) do={
    :log error "PROVISION ABORTED at hotspot step: bridge interface missing"
    :error "bridge interface does not exist — cannot create hotspot"
}

:do {
    /ip/hotspot/profile/add name=hsprof1 hotspot-address=192.168.88.1 dns-name="" login-by=http-chap,http-pap html-directory=hotspot
    :log info "Provisioning: hotspot profile hsprof1 created"
} on-error={
    :log info "Provisioning: hotspot profile hsprof1 already exists or hotspot unavailable, continuing"
}

:do {
    /ip/hotspot/add name=hotspot1 interface=bridge address-pool=dhcp-pool profile=hsprof1 disabled=no
    :log info "Provisioning: hotspot1 created"
} on-error={
    :log warning "Provisioning: hotspot1 add failed (may already exist or hotspot feature unavailable)"
}

:local hsCount 0
:do {
    :set hsCount [:len [/ip/hotspot/find where name=hotspot1]]
} on-error={
    :log error "PROVISION WARNING: could not query hotspot — the hotspot feature may not be available. Ensure device-mode hotspot is enabled: /system/device-mode/update hotspot=yes then press the physical reset button."
}
:if ($hsCount = 0) do={
    :log error "PROVISION WARNING: hotspot1 was not found — hotspot feature may not be enabled. Run: /system/device-mode/update hotspot=yes then press the physical reset button."
} else={
    :log info "Provisioning: hotspot1 confirmed running"
}

:do { /interface bridge port remove [find where interface=ether1] } on-error={}

:log info "Provisioning: Hotspot step complete" """


def _rsc_login_page(token: ProvisioningToken) -> str:
    base_url = settings.PROVISION_BASE_URL.rstrip("/")
    t = token.token
    return f"""
# ---- STEP 5: DOWNLOAD CUSTOM LOGIN PAGE ----

:delay 2s
:local fetchOk false
:for i from=1 to=5 do={{
    :if (!$fetchOk) do={{
        :do {{
            /tool fetch url="{base_url}/api/provision/{t}/login-page" dst-path=hotspot/login.html
            :set fetchOk true
            :log info "Provisioning: Login page downloaded"
        }} on-error={{
            :log warning "Provisioning: Login page download attempt $i failed, retrying..."
            :delay 5s
        }}
    }}
}}"""


def _rsc_walled_garden(token: ProvisioningToken) -> str:
    return f"""
# ---- STEP 6: WALLED GARDEN ----

/ip hotspot walled-garden add dst-host=isp-frontend-two.vercel.app action=allow comment="External Portal"
/ip hotspot walled-garden add dst-host="*.vercel.app" action=allow comment="Vercel CDN"
/ip hotspot walled-garden add dst-host=isp.bitwavetechnologies.net action=allow comment="Backend API"
:do {{ /ip hotspot walled-garden ip add dst-address={token.server_public_ip}/32 action=accept comment="Backend API IP" }} on-error={{}}

:log info "Provisioning: Walled garden configured" """


def _rsc_api_access() -> str:
    return """
# ---- STEP 7: ENABLE MIKROTIK API (restricted to VPN server) ----

/ip service set api address=10.0.0.1/32 port=8728 disabled=no
:do { /ip firewall filter add chain=input protocol=tcp dst-port=8728 src-address=10.0.0.1 action=accept comment="Allow API from AWS" place-before=0 } on-error={}"""


def _rsc_identity_and_user(token: ProvisioningToken) -> str:
    return f"""
# ---- STEP 8: CREATE API SERVICE ACCOUNT & SET IDENTITY ----

/system identity set name={token.identity}
:do {{ /user add name={API_USERNAME} password="{token.router_admin_password}" group=full comment="Bitwave backend API account" }} on-error={{}}

:log info "Provisioning: Identity set to {token.identity}, API user created" """


def _rsc_notify_and_reboot(token: ProvisioningToken) -> str:
    base_url = settings.PROVISION_BASE_URL.rstrip("/")
    t = token.token
    return f"""
# ---- STEP 9: NOTIFY SERVER ----

:delay 2s
:do {{
    /tool fetch url="{base_url}/api/provision/{t}/complete" http-method=post
    :log info "Provisioning: Server notified — router registered"
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

    if token.vpn_type == "wireguard":
        parts.append(_rsc_preflight_v7())
    # v6 (l2tp) has no device-mode concept — skip preflight

    parts.append(_rsc_wan_setup())
    parts.append(_rsc_lan_setup())

    if token.vpn_type == "l2tp":
        parts.append(_rsc_vpn_l2tp(token))
    else:
        parts.append(_rsc_vpn_wireguard(token))

    parts.append(_rsc_hotspot())
    parts.append(_rsc_login_page(token))
    parts.append(_rsc_walled_garden(token))
    parts.append(_rsc_api_access())
    parts.append(_rsc_identity_and_user(token))
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

async def create_provisioning_token(
    db: AsyncSession,
    user_id: int,
    payment_methods: Optional[list] = None,
    vpn_type: str = "wireguard",
) -> ProvisioningToken:
    """
    Full provisioning flow supporting both WireGuard (v7) and L2TP/IPsec (v6):
    1. Auto-generate router name and identity
    2. Generate VPN credentials (WG keypair or L2TP user/pass)
    3. Allocate next available VPN IP from the correct range
    4. Register peer on server via wg-manager sidecar
    5. Auto-generate API service account password
    6. Save token to database
    """
    if vpn_type not in ("wireguard", "l2tp"):
        raise ValueError(f"Invalid vpn_type '{vpn_type}'. Must be 'wireguard' or 'l2tp'.")

    if not settings.SERVER_PUBLIC_IP:
        raise ValueError(
            "SERVER_PUBLIC_IP is not configured. "
            "Set it to your AWS server's public IP in .env"
        )

    router_name = await _generate_router_name(db, user_id)
    identity = await _generate_identity(db)
    vpn_ip = await allocate_vpn_ip(db, vpn_type)
    api_password = generate_api_password()

    # --- VPN-specific setup ---
    wg_private_key = wg_public_key = server_wg_pubkey = None
    l2tp_username = l2tp_password = None

    if vpn_type == "wireguard":
        wg_private_key, wg_public_key = generate_wireguard_keypair()
        await register_wireguard_peer(wg_public_key, vpn_ip)
    else:
        l2tp_username = generate_l2tp_username(identity)
        l2tp_password = generate_api_password(20)
        await register_l2tp_peer(l2tp_username, l2tp_password, vpn_ip)

    try:
        if vpn_type == "wireguard":
            server_wg_pubkey = await get_server_wg_public_key()

        token_obj = ProvisioningToken(
            user_id=user_id,
            token=uuid.uuid4().hex,
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
            status=ProvisioningTokenStatus.PENDING,
        )

        db.add(token_obj)
        await db.commit()
        await db.refresh(token_obj)
    except Exception as inner_err:
        logger.error(f"Provisioning failed after VPN peer added: {type(inner_err).__name__}: {repr(inner_err)}", exc_info=True)
        try:
            if vpn_type == "wireguard" and wg_public_key:
                await remove_wireguard_peer(wg_public_key)
                logger.info(f"Rolled back WG peer for {vpn_ip} after failure")
            elif vpn_type == "l2tp" and l2tp_username:
                await remove_l2tp_peer(l2tp_username)
                logger.info(f"Rolled back L2TP peer for {vpn_ip} after failure")
        except Exception as cleanup_err:
            logger.warning(f"Failed to roll back VPN peer for {vpn_ip}: {cleanup_err}")
        raise

    logger.info(
        f"Provisioning token created: identity={identity} vpn_ip={vpn_ip} "
        f"vpn_type={vpn_type} by user_id={user_id}"
    )
    return token_obj


def build_provision_command(token: ProvisioningToken) -> str:
    """Build the one-liner command the admin pastes on a factory-reset MikroTik."""
    base_url = settings.PROVISION_BASE_URL.rstrip("/")
    url = f"{base_url}/api/provision/{token.token}"
    return (
        f'/tool fetch url="{url}" dst-path=provision.rsc;'
        f":delay 2s;"
        f"/import provision.rsc;"
    )


async def complete_provisioning(
    db: AsyncSession, token: ProvisioningToken
) -> Router:
    """Called by the .rsc callback — creates the Router record in the database."""
    router_obj = Router(
        user_id=token.user_id,
        name=token.router_name,
        identity=token.identity,
        ip_address=token.wireguard_ip,
        username=API_USERNAME,
        password=token.router_admin_password,
        port=8728,
        payment_methods=token.payment_methods,
    )
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
