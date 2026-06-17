import pytest

from app.services.insurance_wireguard import (
    InsuranceWireGuardError,
    backup_ips_from_manager_peers,
    configure_router_backup_wireguard,
    parse_routeros_major_version,
)


class FakeMikroTikAPI:
    def __init__(self, version: str):
        self.version = version
        self.calls = []
        self.firewall_rules = []

    def send_command(self, command, args=None):
        self.calls.append((command, args or {}))

        if command == "/system/resource/print":
            return {"success": True, "data": [{"version": self.version}]}
        if command == "/interface/wireguard/print":
            return {
                "success": True,
                "data": [{
                    ".id": "*1",
                    "name": "wg-aws2",
                    "public-key": "router-public-key",
                }],
            }
        if command == "/interface/wireguard/set":
            return {"success": True}
        if command == "/ip/address/print":
            return {"success": True, "data": []}
        if command == "/ip/address/add":
            return {"success": True}
        if command == "/interface/wireguard/peers/print":
            return {"success": True, "data": []}
        if command == "/interface/wireguard/peers/add":
            return {"success": True}
        if command == "/ip/service/print":
            return {
                "success": True,
                "data": [{
                    ".id": "*2",
                    "name": "api",
                    "port": "8728",
                    "address": "10.0.0.1/32",
                }],
            }
        if command == "/ip/service/set":
            return {"success": True}
        if command == "/ip/firewall/filter/print":
            return {"success": True, "data": self.firewall_rules}
        if command == "/ip/firewall/filter/add":
            self.firewall_rules.append({".id": f"*f{len(self.firewall_rules) + 1}", **(args or {})})
            return {"success": True}

        raise AssertionError(f"unexpected command: {command}")

    def add_walled_garden_ip(self, *_args, **_kwargs):
        return {"success": True}


def test_parse_routeros_major_version():
    assert parse_routeros_major_version("7.19.6 (stable)") == 7
    assert parse_routeros_major_version("6.49.10") == 6
    assert parse_routeros_major_version("") is None


def test_backup_ips_from_manager_peers_extracts_router_backup_addresses():
    payload = {
        "peers": [
            {"allowed_ips": "10.250.0.28/32"},
            {"allowed_ips": "10.250.0.29/32, 192.168.1.0/24"},
            {"allowed_ips": ["10.250.0.30/32", "not-a-cidr"]},
            {"allowed_ips": ""},
            {"public_key": "missing-allowed-ips"},
        ]
    }

    assert backup_ips_from_manager_peers(payload) == {
        "10.250.0.28",
        "10.250.0.29",
        "10.250.0.30",
    }


def test_insurance_wireguard_refuses_routeros_v6_before_writes():
    api = FakeMikroTikAPI("6.49.10")

    with pytest.raises(InsuranceWireGuardError) as exc:
        configure_router_backup_wireguard(api, "10.250.0.28")

    assert "requires RouterOS v7" in str(exc.value)
    assert api.calls == [("/system/resource/print", {})]


def test_insurance_wireguard_accepts_routeros_v7():
    api = FakeMikroTikAPI("7.19.6 (stable)")

    result = configure_router_backup_wireguard(api, "10.250.0.28")

    assert result["routeros_version"] == "7.19.6 (stable)"
    assert result["router_public_key"] == "router-public-key"
    assert ("Confirmed RouterOS 7.19.6 (stable) supports WireGuard") in result["actions"]
    assert any(command == "/interface/wireguard/print" for command, _ in api.calls)
