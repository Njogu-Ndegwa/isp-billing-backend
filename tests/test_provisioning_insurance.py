import pytest

from app.db.models import ProvisioningToken, User, UserRole
from app.services import provisioning


def _token(vpn_type: str) -> ProvisioningToken:
    return ProvisioningToken(
        token="abc123",
        router_name="Test Router",
        identity="Router-0001",
        vpn_type=vpn_type,
        wireguard_ip="10.0.100.1" if vpn_type == "l2tp" else "10.0.0.2",
        router_admin_password="ApiPassword123",
        server_public_ip="203.0.113.10",
        l2tp_username="l2tp-Router-0001",
        l2tp_password="L2tpPassword123",
        wg_private_key="wg-private",
        wg_public_key="wg-public",
        server_wg_pubkey="wg-server-public",
        payment_methods=["mpesa", "voucher"],
    )


def _set_insurance_settings(monkeypatch):
    monkeypatch.setattr(provisioning.settings, "SERVER_PUBLIC_IP", "203.0.113.10")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_WG_MANAGER_URL", "http://insurance-manager")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_WG_MANAGER_SECRET", "insurance-secret")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_SERVER_PUBLIC_IP", "35.170.199.141")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_SERVER_WG_PUBLIC_KEY", "insurance-server-public")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_SERVER_VPN_IP", "10.250.0.1")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_WG_SUBNET", "10.250.0.0/16")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_ROUTER_INTERFACE", "wg-aws2")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_WG_PORT", 51821)
    monkeypatch.setattr(provisioning.settings, "INSURANCE_L2TP_INTERFACE", "l2tp-aws2")
    monkeypatch.setattr(provisioning.settings, "INSURANCE_L2TP_IPSEC_PSK", "insurance-psk")


def test_api_access_allows_primary_and_backup_vpn_servers(monkeypatch):
    _set_insurance_settings(monkeypatch)

    rsc = provisioning._rsc_api_access()

    assert "/ip service set api address=10.0.0.1/32,10.250.0.1/32" in rsc
    assert "src-address=10.0.0.1" in rsc
    assert "src-address=10.250.0.1" in rsc


def test_wireguard_provisioning_script_configures_backup_tunnel(monkeypatch):
    _set_insurance_settings(monkeypatch)
    token = _token("wireguard")

    script = provisioning.generate_rsc_script(token)
    backup_ip = provisioning.derive_insurance_ip(token.wireguard_ip)

    assert "STEP 3B: BACKUP WIREGUARD VPN" in script
    assert "name=wg-aws2 listen-port=51821" in script
    assert f"address={backup_ip}/16 interface=wg-aws2" in script
    assert 'public-key="insurance-server-public"' in script
    assert "endpoint-address=35.170.199.141 endpoint-port=51821" in script
    assert "allowed-address=10.250.0.0/16" in script
    assert 'dst-address=35.170.199.141/32 action=accept comment="Backup backend API IP"' in script


def test_l2tp_provisioning_script_configures_backup_tunnel(monkeypatch):
    _set_insurance_settings(monkeypatch)
    token = _token("l2tp")

    script = provisioning.generate_rsc_script(token)

    assert "STEP 3B: BACKUP L2TP/IPsec VPN" in script
    assert "l2tp-client add name=l2tp-aws2 connect-to=35.170.199.141" in script
    assert 'user="l2tp-Router-0001" password="L2tpPassword123"' in script
    assert "add-default-route=no use-peer-dns=no" in script
    assert "ipsec-secret=insurance-psk" in script


@pytest.mark.asyncio
async def test_create_wireguard_token_registers_primary_and_backup_peers(db, monkeypatch):
    from app.services import insurance_wireguard

    _set_insurance_settings(monkeypatch)
    user = User(
        user_code=1001,
        email="wireguard@example.com",
        password_hash="hash",
        role=UserRole.RESELLER,
        organization_name="WireGuard Org",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    calls = []

    async def fake_register_wireguard_peer(public_key, ip):
        calls.append(("primary-wg", public_key, ip))
        return {"status": "ok"}

    async def fake_get_server_wg_public_key():
        return "primary-server-public"

    async def fake_register_insurance_peer(public_key, backup_ip):
        calls.append(("backup-wg", public_key, backup_ip))
        return {"status": "ok"}

    monkeypatch.setattr(provisioning, "register_wireguard_peer", fake_register_wireguard_peer)
    monkeypatch.setattr(provisioning, "get_server_wg_public_key", fake_get_server_wg_public_key)
    monkeypatch.setattr(insurance_wireguard, "register_insurance_peer", fake_register_insurance_peer)

    token = await provisioning.create_provisioning_token(db, user.id, vpn_type="wireguard")
    _backup_private_key, backup_public_key = provisioning.derive_insurance_wireguard_keypair(
        token.token,
        token.identity,
        token.wireguard_ip,
        token.wg_private_key,
    )

    assert ("primary-wg", token.wg_public_key, token.wireguard_ip) in calls
    assert (
        "backup-wg",
        backup_public_key,
        provisioning.derive_insurance_ip(token.wireguard_ip),
    ) in calls
    assert token.server_wg_pubkey == "primary-server-public"


@pytest.mark.asyncio
async def test_create_l2tp_token_registers_primary_and_backup_peers(db, monkeypatch):
    from app.services import insurance_l2tp

    _set_insurance_settings(monkeypatch)
    user = User(
        user_code=1002,
        email="l2tp@example.com",
        password_hash="hash",
        role=UserRole.RESELLER,
        organization_name="L2TP Org",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    calls = []

    async def fake_register_l2tp_peer(username, password, ip):
        calls.append(("primary-l2tp", username, password, ip))
        return {"status": "ok"}

    async def fake_register_insurance_l2tp_peer(username, password, backup_ip):
        calls.append(("backup-l2tp", username, password, backup_ip))
        return {"status": "ok"}

    monkeypatch.setattr(provisioning, "register_l2tp_peer", fake_register_l2tp_peer)
    monkeypatch.setattr(insurance_l2tp, "register_insurance_l2tp_peer", fake_register_insurance_l2tp_peer)

    token = await provisioning.create_provisioning_token(db, user.id, vpn_type="l2tp")

    assert (
        "primary-l2tp",
        token.l2tp_username,
        token.l2tp_password,
        token.wireguard_ip,
    ) in calls
    assert (
        "backup-l2tp",
        token.l2tp_username,
        token.l2tp_password,
        provisioning.derive_insurance_ip(token.wireguard_ip),
    ) in calls
