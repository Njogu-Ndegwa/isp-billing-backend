"""Single management tunnel to Hetzner for new routers (PROVISION_MGMT_TO_HETZNER).

Owner rule: ONE management tunnel per router. With the flag on, a RouterOS 7
token gets only WireGuard `wg-hz` to Hetzner wg2 (registered on the Hetzner
manager, never on AWS) and a RouterOS 6 token only SSTP (see
test_provisioning_sstp.py). Either way the router keeps its 10.0.X.Y DB
address, pinned on `lo-mgmt`. With the flag off everything is byte-for-byte
what origin/main produced (goldens in tests/fixtures/provisioning_golden/).
"""

import importlib.util
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db.models import ProvisioningToken, ProvisioningTokenStatus, User, UserRole
from app.services import provisioning

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "provisioning_golden"
CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIUTESTTESTTESTTESTTESTTESTTESTwCgYIKoZIzj0EAwIw\n"
    "-----END CERTIFICATE-----\n"
)


def _golden_module():
    spec = importlib.util.spec_from_file_location("provisioning_golden_generate", GOLDEN_DIR / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _settings(monkeypatch, *, enabled: bool):
    golden = _golden_module()
    golden.apply(monkeypatch.setattr)
    s = provisioning.settings
    monkeypatch.setattr(s, "PROVISION_MGMT_TO_HETZNER", enabled)
    monkeypatch.setattr(s, "SSTP_SERVER", "91.98.238.12:4443")
    monkeypatch.setattr(s, "SSTP_SERVER_VPN_IP", "10.251.0.1")
    monkeypatch.setattr(s, "SSTP_SUBNET", "10.251.0.0/16")
    monkeypatch.setattr(s, "ROUTER_MGMT_CA_PEM", CA_PEM)
    return golden


def _wg_token() -> ProvisioningToken:
    return ProvisioningToken(
        token="abc123",
        router_name="Test Router",
        identity="Router-0001",
        vpn_type="wireguard",
        wireguard_ip="10.0.0.42",
        router_admin_password="ApiPassword123",
        server_public_ip="91.98.238.12",
        wg_private_key="cm91dGVyLXByaXZhdGUta2V5LWZvci10ZXN0cy0xMjM=",
        wg_public_key="router-public",
        server_wg_pubkey="insurance-server-public",
        management_tunnel="wireguard",
        payment_methods=["mpesa", "voucher"],
    )


def _commands(script: str) -> str:
    return "\n".join(l for l in script.splitlines() if l.strip() and not l.strip().startswith("#"))


# ---------------------------------------------------------------------------
# Flag off / legacy tokens: byte-for-byte unchanged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("name", ["wireguard", "l2tp", "l2tp_routerboard"])
def test_legacy_tokens_render_byte_for_byte_as_origin_main(monkeypatch, name, enabled):
    # A token issued with the flag off (management_tunnel NULL) must render
    # exactly what origin/main rendered -- also after the flag is switched on.
    golden = _settings(monkeypatch, enabled=enabled)
    token = golden.tokens()[name]
    expected = (GOLDEN_DIR / f"{name}.rsc").read_bytes()
    assert provisioning.generate_rsc_script(token).encode("utf-8") == expected


# ---------------------------------------------------------------------------
# RouterOS 7: WireGuard wg-hz to Hetzner is the only tunnel
# ---------------------------------------------------------------------------


def test_wireguard_token_script_has_only_the_hetzner_tunnel(monkeypatch):
    _settings(monkeypatch, enabled=True)
    script = provisioning.generate_rsc_script(_wg_token())
    commands = _commands(script)

    assert "STEP 3: WIREGUARD MANAGEMENT TUNNEL TO HETZNER (RouterOS v7)" in script
    assert "# VPN Type: WireGuard to Hetzner (wg-hz), only management tunnel" in script
    assert "# Management IP: 10.0.0.42 (pinned on lo-mgmt)" in script
    assert "# Tunnel IP: 10.251.0.42" in script

    # Exactly one WireGuard interface, one peer; no AWS, no insurance duplicate.
    assert commands.count("/interface wireguard add ") == 1
    assert commands.count("/interface wireguard peers add ") == 1
    for forbidden in ("wg-aws", "l2tp", "sstp", "203.0.113.10", "10.0.0.1/", "51820", "BACKUP"):
        assert forbidden not in commands, forbidden

    assert (
        '/interface wireguard add name=wg-hz listen-port=51823 '
        'private-key="cm91dGVyLXByaXZhdGUta2V5LWZvci10ZXN0cy0xMjM="'
    ) in script
    assert "/ip address add address=10.251.0.42/16 interface=wg-hz" in script
    peer = (
        'public-key="insurance-server-public" endpoint-address=91.98.238.12 endpoint-port=51823 '
        "allowed-address=10.251.0.0/16 persistent-keepalive=25"
    )
    assert f"/interface wireguard peers add interface=wg-hz {peer}" in script
    assert f"/interface wireguard peers set [find where interface=wg-hz] {peer}" in script

    # Walled garden allows the Hetzner backend once; AWS is not in the script.
    assert script.count("dst-address=91.98.238.12/32") == 1


def test_wireguard_script_pins_mgmt_ip_on_loopback(monkeypatch):
    _settings(monkeypatch, enabled=True)
    script = provisioning.generate_rsc_script(_wg_token())
    assert "/interface bridge add name=lo-mgmt" in script
    assert "/ip address add address=10.0.0.42/32 interface=lo-mgmt" in script
    assert '[/ip address find where address="10.0.0.42/32" and interface=lo-mgmt]' in script
    # The 10.0.X.Y address lives only on the loopback, never on the tunnel.
    assert "10.0.0.42/16" not in script


def test_hetzner_firewall_accepts_are_placed_at_the_top(monkeypatch):
    # Known bug on the legacy path: "Allow WireGuard" was appended below the
    # defconf drop and never matched. The new rules go before the first rule.
    _settings(monkeypatch, enabled=True)
    script = provisioning.generate_rsc_script(_wg_token())

    wg_rule = (
        "/ip firewall filter add chain=input protocol=udp dst-port=51823 action=accept "
        'comment="Allow WireGuard (Hetzner management)" place-before=$bwFirstRule'
    )
    api_rule = (
        "/ip firewall filter add chain=input protocol=tcp dst-port=8728 src-address=10.251.0.1 "
        'action=accept comment="Allow API from Hetzner management" place-before=$bwFirstRule'
    )
    assert wg_rule in script and api_rule in script
    # Anchored on the first STATIC rule (dynamic hotspot/fasttrack markers
    # cannot be anchors); re-runs replace the rule instead of stacking copies.
    assert ":local bwFirstRule [:pick [/ip firewall filter find where dynamic=no] 0]" in script
    assert '/ip firewall filter remove [find where comment="Allow WireGuard (Hetzner management)"]' in script
    # No static rule (or placement refused): append -- nothing static is above it.
    fallback = (
        ":if ($bwPlaced = false) do={\n"
        "        /ip firewall filter add chain=input protocol=udp dst-port=51823 action=accept "
        'comment="Allow WireGuard (Hetzner management)"\n'
    )
    assert fallback in script
    # Every firewall add in the Hetzner blocks is either placed at the top or
    # is that fallback.
    hetzner_part = script[script.index("STEP 3: WIREGUARD"):script.index("STEP 4")]
    hetzner_part += script[script.index("STEP 7"):script.index("STEP 8")]
    adds = [l for l in hetzner_part.splitlines() if "/ip firewall filter add chain=input" in l]
    assert len(adds) == 4
    for line in adds:
        assert "place-before=$bwFirstRule" in line or line.startswith("        /ip firewall filter add"), line

    assert "/ip service set api address=10.251.0.1/32 port=8728 disabled=no" in script
    assert script.count("{") == script.count("}")


# ---------------------------------------------------------------------------
# Token creation
# ---------------------------------------------------------------------------


async def _user(db, code: int) -> User:
    user = User(
        user_code=code,
        email=f"hz{code}@example.com",
        password_hash="hash",
        role=UserRole.RESELLER,
        organization_name="Tunnel Org",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def _fake_managers(monkeypatch, calls, *, hetzner_fails=False):
    from app.services import insurance_wireguard

    async def aws_register(public_key, ip):
        calls.append(("aws-wg", public_key, ip))

    async def aws_remove(public_key):
        calls.append(("remove-aws-wg", public_key))

    async def aws_server_key():
        calls.append(("aws-server-info",))
        return "aws-server-public"

    async def hz_register(public_key, ip):
        if hetzner_fails:
            raise RuntimeError("hetzner manager down")
        calls.append(("hetzner-wg", public_key, ip))
        return {"status": "ok"}

    async def hz_remove(public_key):
        calls.append(("remove-hetzner-wg", public_key))
        return {"status": "ok"}

    monkeypatch.setattr(provisioning, "register_wireguard_peer", aws_register)
    monkeypatch.setattr(provisioning, "remove_wireguard_peer", aws_remove)
    monkeypatch.setattr(provisioning, "get_server_wg_public_key", aws_server_key)
    monkeypatch.setattr(insurance_wireguard, "register_insurance_peer", hz_register)
    monkeypatch.setattr(insurance_wireguard, "remove_insurance_peer", hz_remove)


@pytest.mark.asyncio
async def test_flag_off_wireguard_token_still_uses_aws_primary_plus_insurance(db, monkeypatch):
    _settings(monkeypatch, enabled=False)
    user = await _user(db, 3001)
    calls = []
    _fake_managers(monkeypatch, calls)

    token = await provisioning.create_provisioning_token(db, user.id, vpn_type="wireguard")

    assert token.management_tunnel is None
    assert [c[0] for c in calls] == ["aws-wg", "aws-server-info", "hetzner-wg"]
    assert token.server_public_ip == "203.0.113.10"
    assert "wg-aws" in provisioning.generate_rsc_script(token)


@pytest.mark.asyncio
async def test_flag_on_wireguard_token_registers_only_on_hetzner(db, monkeypatch):
    _settings(monkeypatch, enabled=True)
    monkeypatch.setattr(provisioning.settings, "SERVER_PUBLIC_IP", "")  # AWS not needed
    user = await _user(db, 3002)
    calls = []
    _fake_managers(monkeypatch, calls)

    token = await provisioning.create_provisioning_token(db, user.id, vpn_type="wireguard")

    assert token.management_tunnel == "wireguard"
    # DB address stays in the 10.0.0-99.x WireGuard range.
    assert token.wireguard_ip.startswith("10.0.") and int(token.wireguard_ip.split(".")[2]) < 100
    tunnel_ip = "10.251." + ".".join(token.wireguard_ip.split(".")[2:])
    # Only the Hetzner wg2 manager, with the router's own key -- nothing on AWS.
    assert calls == [("hetzner-wg", token.wg_public_key, tunnel_ip)]
    assert token.server_public_ip == "91.98.238.12"
    assert token.server_wg_pubkey == "insurance-server-public"
    assert token.sstp_username is None and token.l2tp_username is None

    script = provisioning.generate_rsc_script(token)
    assert f'private-key="{token.wg_private_key}"' in script
    assert f"/ip address add address={tunnel_ip}/16 interface=wg-hz" in script

    # The decision is stored: flipping the flag off does not change the token.
    monkeypatch.setattr(provisioning.settings, "PROVISION_MGMT_TO_HETZNER", False)
    assert provisioning.generate_rsc_script(token) == script


@pytest.mark.asyncio
async def test_hetzner_wg_peer_rolled_back_when_token_save_fails(db, monkeypatch):
    _settings(monkeypatch, enabled=True)
    user = await _user(db, 3003)
    calls = []
    _fake_managers(monkeypatch, calls)

    def failing_add(_obj):
        raise RuntimeError("db write failed")

    monkeypatch.setattr(db, "add", failing_add)

    with pytest.raises(RuntimeError, match="db write failed"):
        await provisioning.create_provisioning_token(db, user.id, vpn_type="wireguard")

    key = next(c[1] for c in calls if c[0] == "hetzner-wg")
    assert calls[-1] == ("remove-hetzner-wg", key)
    assert not any(c[0].startswith(("aws", "remove-aws")) for c in calls)


@pytest.mark.asyncio
async def test_hetzner_registration_failure_raises_without_token(db, monkeypatch):
    from sqlalchemy import select

    _settings(monkeypatch, enabled=True)
    user = await _user(db, 3004)
    calls = []
    _fake_managers(monkeypatch, calls, hetzner_fails=True)

    with pytest.raises(RuntimeError, match="hetzner manager down"):
        await provisioning.create_provisioning_token(db, user.id, vpn_type="wireguard")
    assert calls == []
    rows = (await db.execute(select(ProvisioningToken).where(ProvisioningToken.user_id == user.id))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["INSURANCE_WG_MANAGER_URL", "INSURANCE_SERVER_WG_PUBLIC_KEY", "INSURANCE_SERVER_PUBLIC_IP"])
async def test_flag_on_refuses_before_any_manager_call_when_settings_missing(db, monkeypatch, missing):
    _settings(monkeypatch, enabled=True)
    monkeypatch.setattr(provisioning.settings, missing, "")
    user = await _user(db, 3005)
    calls = []
    _fake_managers(monkeypatch, calls)

    with pytest.raises(ValueError, match=missing):
        await provisioning.create_provisioning_token(db, user.id, vpn_type="wireguard")
    assert calls == []


@pytest.mark.asyncio
async def test_complete_provisioning_flags_hetzner_wireguard_router(db, monkeypatch):
    _settings(monkeypatch, enabled=True)
    user = await _user(db, 3006)
    token = _wg_token()
    token.user_id = user.id
    token.status = ProvisioningTokenStatus.PENDING
    db.add(token)
    await db.commit()

    router = await provisioning.complete_provisioning(db, token)

    assert router.management_tunnel == "wireguard"
    assert router.management_tunnel_changed_at is not None
    # routers.ip_address stays the 10.0.X.Y DB address.
    assert router.ip_address == "10.0.0.42"


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_endpoint_reports_management_tunnel(db, monkeypatch):
    from app.api import provisioning as provisioning_api
    from app.db.database import get_db
    from app.services.auth import verify_token

    _settings(monkeypatch, enabled=True)
    user = await _user(db, 3007)
    calls = []
    _fake_managers(monkeypatch, calls)

    async def current_user(_token, _db):
        return user

    monkeypatch.setattr(provisioning_api, "get_current_user", current_user)
    app = FastAPI()
    app.include_router(provisioning_api.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[verify_token] = lambda: "token"

    response = TestClient(app).post("/api/provision/create", json={"vpn_type": "wireguard"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["management_tunnel"] == "wireguard"
    assert body["vpn_ip"].startswith("10.0.")
    assert [c[0] for c in calls] == ["hetzner-wg"]
