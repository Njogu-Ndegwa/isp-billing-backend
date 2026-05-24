from app.db.models import ProvisioningToken
from app.services.provisioning import build_provision_command, generate_rsc_script


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
        server_wg_pubkey="wg-server-public",
        payment_methods=["mpesa", "voucher"],
    )


def test_l2tp_provisioning_uses_http_bootstrap_when_no_legacy_url(monkeypatch):
    import app.services.provisioning as provisioning

    monkeypatch.setattr(
        provisioning.settings,
        "PROVISION_BASE_URL",
        "https://isp.bitwavetechnologies.net",
    )
    monkeypatch.setattr(provisioning.settings, "PROVISION_LEGACY_BASE_URL", "")

    token = _token("l2tp")

    command = build_provision_command(token)
    script = generate_rsc_script(token)

    assert 'url="http://isp.bitwavetechnologies.net/api/provision/abc123"' in command
    assert "check-certificate=no" not in command
    assert 'url="http://isp.bitwavetechnologies.net/api/provision/abc123/login-page"' in script
    assert 'url="http://isp.bitwavetechnologies.net/api/provision/abc123/complete"' in script
    assert "https://isp.bitwavetechnologies.net/api/provision" not in script
    assert "l2tp-client add" in script
    assert "l2tp-client add name=l2tp-aws" in script
    assert "l2tp-client add name=l2tp-aws" in script and " use-ipsec=yes " not in script.split("l2tp-client add name=l2tp-aws", 1)[1].splitlines()[0]
    assert ':parse "/interface l2tp-client set [find where name=l2tp-aws] use-ipsec=yes' in script
    assert not any(line.rstrip().endswith("\\") for line in script.splitlines())


def test_l2tp_provisioning_honors_explicit_legacy_base_url(monkeypatch):
    import app.services.provisioning as provisioning

    monkeypatch.setattr(
        provisioning.settings,
        "PROVISION_BASE_URL",
        "https://isp.bitwavetechnologies.net",
    )
    monkeypatch.setattr(
        provisioning.settings,
        "PROVISION_LEGACY_BASE_URL",
        "http://203.0.113.10:8000",
    )

    token = _token("l2tp")

    assert (
        'url="http://203.0.113.10:8000/api/provision/abc123"'
        in build_provision_command(token)
    )


def test_wireguard_provisioning_keeps_https_base_url(monkeypatch):
    import app.services.provisioning as provisioning

    monkeypatch.setattr(
        provisioning.settings,
        "PROVISION_BASE_URL",
        "https://isp.bitwavetechnologies.net",
    )
    monkeypatch.setattr(provisioning.settings, "PROVISION_LEGACY_BASE_URL", "")

    token = _token("wireguard")

    command = build_provision_command(token)
    script = generate_rsc_script(token)

    assert 'url="https://isp.bitwavetechnologies.net/api/provision/abc123"' in command
    assert 'url="https://isp.bitwavetechnologies.net/api/provision/abc123/login-page"' in script
    assert 'url="https://isp.bitwavetechnologies.net/api/provision/abc123/complete"' in script
    assert "wireguard peers add" in script
    assert not any(line.rstrip().endswith("\\") for line in script.splitlines())
