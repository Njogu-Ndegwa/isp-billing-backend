"""Step 8 of the .rsc must add OR update the backend's API user.

Incident 2026-10-24 (reseller 498): a router that was in Bitwave before was
deleted and re-provisioned on the same MikroTik. The old script ran
`:do { /user add name=bitwave-api ... } on-error={}`; the user already
existed, the add failed silently, the router kept the OLD password and the
app's API login with the new token's password failed. The script must update
an existing user's password instead of skipping it.
"""

import re

import pytest

from app.db.models import ProvisioningToken
from app.services import provisioning
from app.services.provisioning import API_USERNAME, _rsc_identity_and_user, generate_rsc_script


def _token(vpn_type: str = "wireguard", password: str = "ApiPassword123", **extra) -> ProvisioningToken:
    fields = dict(
        token="abc123",
        router_name="Test Router",
        identity="Router-0001",
        vpn_type=vpn_type,
        wireguard_ip="10.0.100.1" if vpn_type == "l2tp" else "10.0.0.2",
        router_admin_password=password,
        server_public_ip="203.0.113.10",
        l2tp_username="l2tp-Router-0001",
        l2tp_password="L2tpPassword123",
        wg_private_key="wg-private",
        server_wg_pubkey="wg-server-public",
        payment_methods=["mpesa", "voucher"],
    )
    fields.update(extra)
    return ProvisioningToken(**fields)


def _commands(script: str) -> list[str]:
    return [l.strip() for l in script.splitlines() if l.strip() and not l.strip().startswith("#")]


def test_step_has_both_add_and_set_branches_guarded_by_existence_check():
    block = _rsc_identity_and_user(_token())
    cmds = _commands(block)

    check = f':if ([:len [/user find where name="{API_USERNAME}"]] = 0) do={{'
    add = (
        f'/user add name="{API_USERNAME}" password="ApiPassword123" group=full '
        'disabled=no comment="Bitwave backend API account"'
    )
    set_ = (
        f'/user set [find where name="{API_USERNAME}"] password="ApiPassword123" group=full '
        'disabled=no comment="Bitwave backend API account"'
    )
    assert check in cmds
    assert add in cmds
    assert "} else={" in cmds
    assert set_ in cmds
    # add sits in the "missing" branch, set in the else branch
    assert cmds.index(check) < cmds.index(add) < cmds.index("} else={") < cmds.index(set_)


def test_no_silent_user_add_left():
    # The bug: an add whose failure is swallowed, so an existing user keeps
    # its old password.
    for vpn_type in ("wireguard", "l2tp"):
        script = generate_rsc_script(_token(vpn_type))
        for line in _commands(script):
            if line.startswith(":do") and "/user add" in line:
                pytest.fail(f"single-line swallowed /user add remains: {line}")
        assert len(re.findall(r"^\s*/user add ", script, re.M)) == 1, vpn_type
        assert len(re.findall(r"^\s*/user set ", script, re.M)) == 1, vpn_type


def test_whole_step_is_wrapped_so_a_failure_cannot_abort_the_import():
    block = _rsc_identity_and_user(_token())
    cmds = _commands(block)
    start = cmds.index(":do {")
    assert cmds[start + 1].startswith(":if ([:len [/user find")
    assert "} on-error={" in cmds
    assert any("could not create or update API user" in c for c in cmds)


def test_identity_still_set_before_the_user_step():
    cmds = _commands(_rsc_identity_and_user(_token()))
    assert cmds[0] == "/system identity set name=Router-0001"


def test_password_is_escaped_in_both_branches():
    # Generated passwords are alphanumeric today; a password with RouterOS
    # string metacharacters must still be written verbatim in both branches.
    nasty = 'a"b$c\\d?e'
    escaped = 'a\\"b\\$c\\\\d\\?e'
    assert provisioning.routeros_escape(nasty) == escaped
    block = _rsc_identity_and_user(_token(password=nasty))
    assert block.count(f'password="{escaped}"') == 2
    assert f'password="{nasty}"' not in block


def test_generated_api_password_needs_no_escaping():
    pw = provisioning.generate_api_password()
    assert provisioning.routeros_escape(pw) == pw


def test_hetzner_tokens_get_the_same_add_or_set(monkeypatch):
    s = provisioning.settings
    monkeypatch.setattr(s, "PROVISION_MGMT_TO_HETZNER", True)
    monkeypatch.setattr(s, "SSTP_SERVER", "91.98.238.12:4443")
    monkeypatch.setattr(s, "SSTP_SERVER_VPN_IP", "10.251.0.1")
    monkeypatch.setattr(s, "SSTP_SUBNET", "10.251.0.0/16")
    monkeypatch.setattr(s, "INSURANCE_SERVER_VPN_IP", "10.251.0.1")
    monkeypatch.setattr(s, "INSURANCE_WG_SUBNET", "10.251.0.0/16")
    for token in (
        _token("wireguard", management_tunnel="wireguard", server_public_ip="91.98.238.12"),
        _token("l2tp", management_tunnel="sstp", sstp_username="Router-0001", sstp_password="SstpPw123"),
    ):
        script = generate_rsc_script(token)
        assert f'/user set [find where name="{API_USERNAME}"] password="ApiPassword123"' in script
        assert f'/user add name="{API_USERNAME}" password="ApiPassword123"' in script
