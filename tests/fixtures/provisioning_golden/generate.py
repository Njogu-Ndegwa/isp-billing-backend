"""Regenerate the golden legacy (flag-off) .rsc scripts.

Run from the repo root of the code whose output should become the baseline:

    python tests/fixtures/provisioning_golden/generate.py <out_dir>

The goldens were captured from origin/main before PROVISION_MGMT_TO_HETZNER
existed; tests/test_provisioning_hetzner.py asserts the flag-off output is
still byte-for-byte identical to them.
"""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

from app.db.models import ProvisioningToken  # noqa: E402
from app.services import provisioning  # noqa: E402

FIXED_NOW = datetime(2026, 9, 26, 12, 0, 0)

SETTINGS = {
    "SERVER_PUBLIC_IP": "203.0.113.10",
    "PROVISION_BASE_URL": "https://isp.example.net",
    "PROVISION_LEGACY_BASE_URL": "",
    "L2TP_IPSEC_PSK": "primary-psk",
    "INSURANCE_WG_MANAGER_URL": "http://insurance-manager",
    "INSURANCE_WG_MANAGER_SECRET": "insurance-secret",
    "INSURANCE_SERVER_PUBLIC_IP": "91.98.238.12",
    "INSURANCE_SERVER_WG_PUBLIC_KEY": "insurance-server-public",
    "INSURANCE_SERVER_VPN_IP": "10.251.0.1",
    "INSURANCE_WG_PORT": 51823,
    "INSURANCE_ROUTER_INTERFACE": "wg-hz",
    "INSURANCE_WG_SUBNET": "10.251.0.0/16",
    "INSURANCE_L2TP_INTERFACE": "l2tp-aws2",
    "INSURANCE_L2TP_IPSEC_PSK": "insurance-psk",
}


class _FixedDatetime(datetime):
    @classmethod
    def utcnow(cls):
        return FIXED_NOW


def apply(setter):
    """setter(obj, name, value) -- monkeypatch.setattr or plain setattr."""
    for name, value in SETTINGS.items():
        setter(provisioning.settings, name, value)
    setter(provisioning, "datetime", _FixedDatetime)


def tokens():
    common = dict(
        token="abc123",
        router_name="Test Router",
        identity="Router-0001",
        router_admin_password="ApiPassword123",
        server_public_ip="203.0.113.10",
        payment_methods=["mpesa", "voucher"],
    )
    return {
        "wireguard": ProvisioningToken(
            vpn_type="wireguard",
            wireguard_ip="10.0.0.42",
            wg_private_key="cGNvL2+ZmFrZS1wcml2YXRlLWtleS0xMjM0NTY3ODk=",
            wg_public_key="router-public",
            server_wg_pubkey="aws-server-public",
            is_routerboard=False,
            **common,
        ),
        "l2tp": ProvisioningToken(
            vpn_type="l2tp",
            wireguard_ip="10.0.100.77",
            l2tp_username="l2tp-Router-0001",
            l2tp_password="L2tpPassword123",
            is_routerboard=False,
            **common,
        ),
        "l2tp_routerboard": ProvisioningToken(
            vpn_type="l2tp",
            wireguard_ip="10.0.100.78",
            l2tp_username="l2tp-Router-0001",
            l2tp_password="L2tpPassword123",
            is_routerboard=True,
            **common,
        ),
    }


if __name__ == "__main__":
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    apply(setattr)
    for name, token in tokens().items():
        (out / f"{name}.rsc").write_bytes(provisioning.generate_rsc_script(token).encode("utf-8"))
        print("wrote", out / f"{name}.rsc")
