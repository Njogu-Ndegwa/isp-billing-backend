"""SSTP management tunnel for new RouterOS 6 routers (flag SSTP_PROVISIONING_ENABLED).

The flag must deploy dark: off (or on, for a token created without SSTP
credentials) the script and token creation behave exactly as before. On, a v6
token gets an SSTP login on the Hetzner accel-ppp server (10.251.X.Y for its
10.0.X.Y), an SSTP block in place of the standby Hetzner L2TP, and the router
is flagged management_tunnel='sstp' when it completes.
"""

import importlib.util
import os
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.db.models import ProvisioningToken, ProvisioningTokenStatus, User, UserRole
from app.services import provisioning

CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIUTESTTESTTESTTESTTESTTESTTESTwCgYIKoZIzj0EAwIw\n"
    "-----END CERTIFICATE-----\n"
)
PROBE = ':local bwHsProbe [:parse "/ip hotspot profile find"]'


def _l2tp_token(sstp: bool) -> ProvisioningToken:
    return ProvisioningToken(
        token="abc123",
        router_name="Test Router",
        identity="Router-0001",
        vpn_type="l2tp",
        wireguard_ip="10.0.100.77",
        router_admin_password="ApiPassword123",
        server_public_ip="203.0.113.10",
        l2tp_username="l2tp-Router-0001",
        l2tp_password="L2tpPassword123",
        sstp_username="sstp-Router-0001" if sstp else None,
        sstp_password="SstpPassword1234567890ab" if sstp else None,
        payment_methods=["mpesa", "voucher"],
    )


def _settings(monkeypatch, *, enabled: bool, ca: str = CA_PEM):
    s = provisioning.settings
    monkeypatch.setattr(s, "SERVER_PUBLIC_IP", "203.0.113.10")
    monkeypatch.setattr(s, "PROVISION_BASE_URL", "https://isp.example.net")
    monkeypatch.setattr(s, "PROVISION_LEGACY_BASE_URL", "")
    monkeypatch.setattr(s, "INSURANCE_WG_MANAGER_URL", "http://insurance-manager")
    monkeypatch.setattr(s, "INSURANCE_WG_MANAGER_SECRET", "insurance-secret")
    monkeypatch.setattr(s, "INSURANCE_SERVER_PUBLIC_IP", "91.98.238.12")
    monkeypatch.setattr(s, "INSURANCE_SERVER_WG_PUBLIC_KEY", "insurance-server-public")
    monkeypatch.setattr(s, "INSURANCE_SERVER_VPN_IP", "10.250.0.1")
    monkeypatch.setattr(s, "INSURANCE_WG_SUBNET", "10.250.0.0/16")
    monkeypatch.setattr(s, "INSURANCE_L2TP_INTERFACE", "l2tp-aws2")
    monkeypatch.setattr(s, "INSURANCE_L2TP_IPSEC_PSK", "insurance-psk")
    monkeypatch.setattr(s, "SSTP_PROVISIONING_ENABLED", enabled)
    monkeypatch.setattr(s, "SSTP_SERVER", "91.98.238.12:4443")
    monkeypatch.setattr(s, "SSTP_SERVER_VPN_IP", "10.251.0.1")
    monkeypatch.setattr(s, "SSTP_SUBNET", "10.251.0.0/16")
    monkeypatch.setattr(s, "ROUTER_MGMT_CA_PEM", ca)


# ---------------------------------------------------------------------------
# Script generation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("enabled", [False, True])
def test_token_without_sstp_creds_keeps_the_old_l2tp_script(monkeypatch, enabled):
    # Tokens created before the flag was on (or while it is off) must keep
    # rendering the standby Hetzner L2TP and nothing SSTP.
    _settings(monkeypatch, enabled=enabled)
    script = provisioning.generate_rsc_script(_l2tp_token(sstp=False))

    assert "STEP 3B: BACKUP L2TP/IPsec VPN" in script
    assert "l2tp-client add name=l2tp-aws2" in script
    assert "sstp" not in script.lower()
    assert "lo-mgmt" not in script
    assert "10.251.0.1" not in script
    assert "# VPN Type: L2TP/IPsec\n" in script


def test_sstp_token_script_has_sstp_block_and_keeps_aws_fallback(monkeypatch):
    _settings(monkeypatch, enabled=True)
    script = provisioning.generate_rsc_script(_l2tp_token(sstp=True))

    # Primary L2TP to AWS stays as the fallback path.
    assert "/interface l2tp-client add name=l2tp-aws connect-to=203.0.113.10" in script
    # The Hetzner standby L2TP would claim the same 10.251.X.Y: dropped.
    commands = [l for l in script.splitlines() if not l.strip().startswith("#")]
    assert not any("l2tp-aws2" in l for l in commands)
    assert "BACKUP L2TP" not in script

    assert "STEP 3B: SSTP MANAGEMENT TUNNEL" in script
    assert (
        "/interface sstp-client add name=sstp-hetzner connect-to=91.98.238.12:4443 "
        "user=sstp-Router-0001 password=SstpPassword1234567890ab profile=default "
        "add-default-route=no verify-server-certificate=yes "
        "verify-server-address-from-certificate=yes disabled=no"
    ) in script
    # Re-run safe: add falls back to set.
    assert "/interface sstp-client set [find where name=sstp-hetzner] connect-to=91.98.238.12:4443" in script

    # CA fetched over the v6 bootstrap base URL (HTTP), imported and trusted.
    assert (
        '/tool fetch url="http://isp.example.net/api/provision/router-mgmt-ca.crt" '
        "dst-path=router-mgmt-ca.crt\n"
    ) in script
    assert '/certificate import file-name=router-mgmt-ca.crt passphrase=""' in script
    assert '/certificate set [find where common-name="Bitwave Router Management CA"] trusted=yes' in script
    assert "/system ntp client set enabled=yes primary-ntp=162.159.200.1" in script

    # Management IP pinned on the loopback, guarded for re-runs.
    assert "/interface bridge add name=lo-mgmt" in script
    assert "/ip address add address=10.0.100.77/32 interface=lo-mgmt" in script
    assert '[/ip address find where address="10.0.100.77/32" and interface=lo-mgmt]' in script

    assert "/interface sstp-client find where name=sstp-hetzner running=yes" in script
    assert "Provisioning: SSTP tunnel connected" in script

    # The server reaches SSTP routers from 10.251.0.1: allowed on the API.
    assert "/ip service set api address=10.0.0.1/32,10.250.0.1/32,10.251.0.1/32" in script
    assert "src-address=10.251.0.1" in script
    assert "# VPN Type: SSTP (Hetzner) + L2TP/IPsec fallback" in script

    # Order: AWS L2TP, then SSTP, then the hotspot.
    assert script.index("STEP 3: L2TP/IPsec VPN") < script.index("STEP 3B: SSTP") < script.index("STEP 4")


def test_sstp_block_does_not_duplicate_api_source_when_insurance_ip_matches(monkeypatch):
    _settings(monkeypatch, enabled=True)
    monkeypatch.setattr(provisioning.settings, "INSURANCE_SERVER_VPN_IP", "10.251.0.1")
    script = provisioning.generate_rsc_script(_l2tp_token(sstp=True))
    assert "/ip service set api address=10.0.0.1/32,10.251.0.1/32 port=8728" in script
    assert script.count("src-address=10.251.0.1") == 1


def test_sstp_script_obeys_parse_safety_rules(monkeypatch):
    _settings(monkeypatch, enabled=True)
    script = provisioning.generate_rsc_script(_l2tp_token(sstp=True))

    assert not any(line.rstrip().endswith("\\") for line in script.splitlines())
    before_probe = script[: script.index(PROBE)]
    assert "/ip hotspot" not in "\n".join(
        l for l in before_probe.splitlines() if not l.strip().startswith("#")
    )
    # Version-sensitive commands only inside [:parse] strings, so an old
    # RouterOS logs instead of aborting the import at parse time.
    for line in script.splitlines():
        stripped = line.strip()
        if "sstp-client add" in stripped or "sstp-client set" in stripped or "ntp client set" in stripped:
            assert "[:parse \"" in stripped, stripped


def test_https_legacy_base_url_disables_cert_check_on_ca_fetch(monkeypatch):
    _settings(monkeypatch, enabled=True)
    monkeypatch.setattr(provisioning.settings, "PROVISION_LEGACY_BASE_URL", "https://legacy.example.net")
    script = provisioning.generate_rsc_script(_l2tp_token(sstp=True))
    assert (
        '/tool fetch url="https://legacy.example.net/api/provision/router-mgmt-ca.crt" '
        "dst-path=router-mgmt-ca.crt check-certificate=no"
    ) in script


def test_derive_sstp_ip_maps_host_offset_into_sstp_subnet(monkeypatch):
    _settings(monkeypatch, enabled=True)
    assert provisioning.derive_sstp_ip("10.0.100.77") == "10.251.100.77"
    assert provisioning.derive_sstp_ip("10.0.150.3") == "10.251.150.3"


# ---------------------------------------------------------------------------
# Token creation
# ---------------------------------------------------------------------------


async def _user(db, code: int) -> User:
    user = User(
        user_code=code,
        email=f"sstp{code}@example.com",
        password_hash="hash",
        role=UserRole.RESELLER,
        organization_name="Tunnel Org",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def _fake_managers(monkeypatch, calls, *, sstp_fails=False):
    from app.services import insurance_l2tp

    async def register_l2tp_peer(username, password, ip):
        calls.append(("primary-l2tp", username, ip))

    async def remove_l2tp_peer(username):
        calls.append(("remove-primary-l2tp", username))

    async def register_insurance_l2tp_peer(username, password, ip):
        calls.append(("backup-l2tp", username, ip))

    async def register_sstp_peer(username, password, ip):
        if sstp_fails:
            raise RuntimeError("manager down")
        calls.append(("sstp", username, password, ip))

    async def remove_sstp_peer(username):
        calls.append(("remove-sstp", username))

    monkeypatch.setattr(provisioning, "register_l2tp_peer", register_l2tp_peer)
    monkeypatch.setattr(provisioning, "remove_l2tp_peer", remove_l2tp_peer)
    monkeypatch.setattr(insurance_l2tp, "register_insurance_l2tp_peer", register_insurance_l2tp_peer)
    monkeypatch.setattr(provisioning, "register_sstp_peer", register_sstp_peer)
    monkeypatch.setattr(provisioning, "remove_sstp_peer", remove_sstp_peer)


@pytest.mark.asyncio
async def test_flag_off_l2tp_token_has_no_sstp(db, monkeypatch):
    _settings(monkeypatch, enabled=False)
    user = await _user(db, 2001)
    calls = []
    _fake_managers(monkeypatch, calls)

    token = await provisioning.create_provisioning_token(db, user.id, vpn_type="l2tp")

    assert token.sstp_username is None and token.sstp_password is None
    assert [c[0] for c in calls] == ["primary-l2tp", "backup-l2tp"]


@pytest.mark.asyncio
async def test_flag_on_l2tp_token_registers_sstp_peer_instead_of_hetzner_l2tp(db, monkeypatch):
    _settings(monkeypatch, enabled=True)
    user = await _user(db, 2002)
    calls = []
    _fake_managers(monkeypatch, calls)

    token = await provisioning.create_provisioning_token(db, user.id, vpn_type="l2tp")

    assert token.sstp_username == f"sstp-{token.identity}"
    assert len(token.sstp_password) == 24 and token.sstp_password.isalnum()
    expected_ip = "10.251." + ".".join(token.wireguard_ip.split(".")[2:])
    assert ("sstp", token.sstp_username, token.sstp_password, expected_ip) in calls
    assert not any(c[0] == "backup-l2tp" for c in calls)
    assert ("primary-l2tp", token.l2tp_username, token.wireguard_ip) in calls

    script = provisioning.generate_rsc_script(token)
    assert f"user={token.sstp_username} password={token.sstp_password}" in script


@pytest.mark.asyncio
async def test_flag_on_wireguard_token_is_untouched(db, monkeypatch):
    from app.services import insurance_wireguard

    _settings(monkeypatch, enabled=True)
    user = await _user(db, 2003)

    async def ok(*_a, **_k):
        return {"status": "ok"}

    async def server_key():
        return "server-public"

    monkeypatch.setattr(provisioning, "register_wireguard_peer", ok)
    monkeypatch.setattr(provisioning, "get_server_wg_public_key", server_key)
    monkeypatch.setattr(insurance_wireguard, "register_insurance_peer", ok)

    async def must_not_run(*_a, **_k):
        pytest.fail("SSTP peer registered for a WireGuard token")

    monkeypatch.setattr(provisioning, "register_sstp_peer", must_not_run)

    token = await provisioning.create_provisioning_token(db, user.id, vpn_type="wireguard")
    assert token.sstp_username is None
    assert "sstp" not in provisioning.generate_rsc_script(token).lower()


@pytest.mark.asyncio
async def test_sstp_peer_rolled_back_when_token_save_fails(db, monkeypatch):
    _settings(monkeypatch, enabled=True)
    user = await _user(db, 2004)
    calls = []
    _fake_managers(monkeypatch, calls)

    def failing_add(_obj):
        raise RuntimeError("db write failed")

    monkeypatch.setattr(db, "add", failing_add)

    with pytest.raises(RuntimeError, match="db write failed"):
        await provisioning.create_provisioning_token(db, user.id, vpn_type="l2tp")

    sstp_user = next(c[1] for c in calls if c[0] == "sstp")
    assert ("remove-sstp", sstp_user) in calls
    assert any(c[0] == "remove-primary-l2tp" for c in calls)


@pytest.mark.asyncio
async def test_sstp_registration_failure_rolls_back_primary_only(db, monkeypatch):
    _settings(monkeypatch, enabled=True)
    user = await _user(db, 2005)
    calls = []
    _fake_managers(monkeypatch, calls, sstp_fails=True)

    with pytest.raises(RuntimeError, match="manager down"):
        await provisioning.create_provisioning_token(db, user.id, vpn_type="l2tp")

    assert any(c[0] == "remove-primary-l2tp" for c in calls)
    assert not any(c[0] == "remove-sstp" for c in calls)


@pytest.mark.asyncio
async def test_flag_on_without_ca_refuses_before_any_manager_call(db, monkeypatch):
    _settings(monkeypatch, enabled=True, ca="")
    user = await _user(db, 2006)
    calls = []
    _fake_managers(monkeypatch, calls)

    with pytest.raises(ValueError, match="ROUTER_MGMT_CA_PEM"):
        await provisioning.create_provisioning_token(db, user.id, vpn_type="l2tp")
    assert calls == []


# ---------------------------------------------------------------------------
# complete_provisioning
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("sstp", [True, False])
async def test_complete_provisioning_flags_sstp_routers(db, monkeypatch, sstp):
    _settings(monkeypatch, enabled=True)
    user = await _user(db, 2010 + int(sstp))
    token = _l2tp_token(sstp=sstp)
    token.user_id = user.id
    token.status = ProvisioningTokenStatus.PENDING
    db.add(token)
    await db.commit()

    router = await provisioning.complete_provisioning(db, token)

    if sstp:
        assert router.management_tunnel == "sstp"
        assert router.management_tunnel_changed_at is not None
    else:
        assert router.management_tunnel is None
        assert router.management_tunnel_changed_at is None
    assert router.ip_address == "10.0.100.77"


# ---------------------------------------------------------------------------
# Public CA endpoint
# ---------------------------------------------------------------------------


def _client():
    from app.api.provisioning import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_ca_endpoint_404_when_unset(monkeypatch):
    _settings(monkeypatch, enabled=False, ca="")
    response = _client().get("/api/provision/router-mgmt-ca.crt")
    assert response.status_code == 404


def test_ca_endpoint_serves_pem_and_accepts_escaped_newlines(monkeypatch):
    _settings(monkeypatch, enabled=False, ca=CA_PEM.strip().replace("\n", "\\n"))
    response = _client().get("/api/provision/router-mgmt-ca.crt")
    assert response.status_code == 200
    assert response.text == CA_PEM
    assert response.headers["content-type"].startswith("application/x-pem-file")


def test_ca_endpoint_refuses_anything_with_a_private_key(monkeypatch):
    leaked = CA_PEM + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    _settings(monkeypatch, enabled=False, ca=leaked)
    assert provisioning.router_mgmt_ca_pem() == ""
    assert _client().get("/api/provision/router-mgmt-ca.crt").status_code == 404


# ---------------------------------------------------------------------------
# Insurance manager /add-sstp-peer, /remove-sstp-peer
# ---------------------------------------------------------------------------


def _manager(monkeypatch, secrets_path):
    path = Path("wg-manager-insurance/main.py")
    spec = importlib.util.spec_from_file_location("wg_manager_insurance_sstp_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SSTP_CHAP_SECRETS", str(secrets_path))
    return module


def test_manager_upsert_is_idempotent_and_replaces(tmp_path, monkeypatch):
    secrets_file = tmp_path / "chap-secrets"
    secrets_file.write_text("# header\nsstp-Router-0961\t*\tOtherPass123456\t10.251.100.77\n")
    m = _manager(monkeypatch, secrets_file)

    req = m.AddSstpPeerRequest(username="sstp-Router-0005", password="Abcdef1234567890", ip="10.251.100.5")
    assert m.add_sstp_peer(req)["message"] == "SSTP peer added"
    assert m.add_sstp_peer(req)["message"] == "SSTP peer unchanged"

    req2 = m.AddSstpPeerRequest(username="sstp-Router-0005", password="Newpass123456789", ip="10.251.100.5")
    assert m.add_sstp_peer(req2)["message"] == "SSTP peer updated"

    lines = secrets_file.read_text().splitlines()
    assert lines[0] == "# header"
    assert "sstp-Router-0961\t*\tOtherPass123456\t10.251.100.77" in lines
    assert [l for l in lines if l.startswith("sstp-Router-0005")] == [
        "sstp-Router-0005\t*\tNewpass123456789\t10.251.100.5"
    ]
    # A backup of the previous file was kept.
    assert any(p.name.startswith("chap-secrets.bak.") for p in tmp_path.iterdir())
    if os.name == "posix":
        assert (secrets_file.stat().st_mode & 0o777) == 0o600


def test_manager_remove_is_idempotent(tmp_path, monkeypatch):
    secrets_file = tmp_path / "chap-secrets"
    secrets_file.write_text("sstp-Router-0005\t*\tAbcdef1234567890\t10.251.100.5\nsstp-Router-0006\t*\tAbcdef1234567891\t10.251.100.6\n")
    m = _manager(monkeypatch, secrets_file)

    req = m.RemoveSstpPeerRequest(username="sstp-Router-0005")
    assert m.remove_sstp_peer(req)["removed"] is True
    assert m.remove_sstp_peer(req)["removed"] is False
    assert secrets_file.read_text() == "sstp-Router-0006\t*\tAbcdef1234567891\t10.251.100.6\n"


def test_manager_creates_missing_file(tmp_path, monkeypatch):
    secrets_file = tmp_path / "chap-secrets"
    m = _manager(monkeypatch, secrets_file)
    m.add_sstp_peer(m.AddSstpPeerRequest(username="sstp-Router-0007", password="Abcdef1234567890", ip="10.251.100.7"))
    assert secrets_file.read_text() == "sstp-Router-0007\t*\tAbcdef1234567890\t10.251.100.7\n"


@pytest.mark.parametrize(
    "username,password,ip",
    [
        ("l2tp-Router-0005", "Abcdef1234567890", "10.251.100.5"),  # not an SSTP login
        ("sstp-Router 0005", "Abcdef1234567890", "10.251.100.5"),  # whitespace
        ("sstp-Router-0005", "short", "10.251.100.5"),
        ("sstp-Router-0005", "has space 12345678", "10.251.100.5"),
        ("sstp-Router-0005", "Abcdef1234567890", "10.251.100.5\nevil"),
    ],
)
def test_manager_rejects_values_that_could_corrupt_chap_secrets(tmp_path, monkeypatch, username, password, ip):
    m = _manager(monkeypatch, tmp_path / "chap-secrets")
    with pytest.raises(HTTPException) as exc:
        m.add_sstp_peer(m.AddSstpPeerRequest(username=username, password=password, ip=ip))
    assert exc.value.status_code == 400
    assert not (tmp_path / "chap-secrets").exists()


def test_manager_sstp_endpoints_503_when_unconfigured(monkeypatch, tmp_path):
    m = _manager(monkeypatch, tmp_path / "x")
    monkeypatch.setattr(m, "SSTP_CHAP_SECRETS", "")
    with pytest.raises(HTTPException) as exc:
        m.add_sstp_peer(m.AddSstpPeerRequest(username="sstp-Router-0005", password="Abcdef1234567890", ip="10.251.100.5"))
    assert exc.value.status_code == 503
