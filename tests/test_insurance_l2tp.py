import pytest

from app.services.insurance_l2tp import configure_router_backup_l2tp
from app.services.insurance_wireguard import InsuranceWireGuardError


class FakeMikroTikAPI:
    def __init__(self, version: str):
        self.version = version
        self.calls = []
        self.l2tp_clients = []
        self.firewall_rules = []

    def send_command(self, command, args=None):
        args = args or {}
        self.calls.append((command, args))

        if command == "/system/resource/print":
            return {"success": True, "data": [{"version": self.version}]}
        if command == "/interface/l2tp-client/print":
            return {"success": True, "data": self.l2tp_clients}
        if command == "/interface/l2tp-client/add":
            self.l2tp_clients.append({".id": "*l1", **args})
            return {"success": True}
        if command == "/interface/l2tp-client/set":
            return {"success": True}
        if command == "/ip/service/print":
            return {
                "success": True,
                "data": [{
                    ".id": "*s1",
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
            self.firewall_rules.append({".id": f"*f{len(self.firewall_rules) + 1}", **args})
            return {"success": True}

        raise AssertionError(f"unexpected command: {command}")

    def add_walled_garden_ip(self, *_args, **_kwargs):
        return {"success": True}


def test_insurance_l2tp_accepts_routeros_v6_without_wireguard_commands():
    api = FakeMikroTikAPI("6.49.10")

    result = configure_router_backup_l2tp(
        api,
        backup_ip="10.250.100.9",
        username="l2tp-Router-0001",
        password="secret",
    )

    assert result["routeros_version"] == "6.49.10"
    assert result["l2tp_username"] == "l2tp-Router-0001"
    assert "Confirmed RouterOS 6.49.10 needs L2TP/IPsec insurance tunnel" in result["actions"]
    assert any(command == "/interface/l2tp-client/add" for command, _ in api.calls)
    assert not any("wireguard" in command for command, _ in api.calls)


def test_insurance_l2tp_refuses_routeros_v7_before_writes():
    api = FakeMikroTikAPI("7.19.6 (stable)")

    with pytest.raises(InsuranceWireGuardError) as exc:
        configure_router_backup_l2tp(
            api,
            backup_ip="10.250.0.28",
            username="l2tp-Router-0001",
            password="secret",
        )

    assert "supports WireGuard" in str(exc.value)
    assert api.calls == [("/system/resource/print", {})]
