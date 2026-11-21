"""PPPoE profiles must never be left with a blank dns-server.

Live 18 Nov: routers whose base PPPoE profile had no DNS copied that blank onto
every plan profile, so CPEs connected but resolved nothing ("connected, 0 MB").
"""

from app.services import pppoe_provisioning, pppoe_resync
from app.services.mikrotik_api import DEFAULT_PPPOE_DNS_SERVERS, MikroTikAPI
from app.services.router_agent_commands import render_pppoe_provision_action


def _api(profiles, servers=None, secrets=None):
    api = MikroTikAPI("10.0.0.1", "admin", "secret")
    api.connected = True
    calls = []

    def send_command(command, args=None):
        calls.append((command, dict(args or {})))
        if command == "/ppp/profile/print":
            return {"success": True, "data": profiles}
        return {"success": True}

    def send_command_optimized(command, proplist=None, query=None):
        if command == "/interface/pppoe-server/server/print":
            return {"success": True, "data": servers or []}
        if command == "/ppp/secret/print":
            return {"success": True, "data": secrets or []}
        return {"success": True, "data": []}

    api.send_command = send_command
    api.send_command_optimized = send_command_optimized
    return api, calls


def test_new_profile_without_base_dns_gets_public_dns():
    api, calls = _api([])
    api.ensure_pppoe_profile("pppoe_5M_5M", "5M/5M", local_address="192.168.89.1", pool_name="pppoe-pool")
    command, args = calls[-1]
    assert command == "/ppp/profile/add"
    assert args["dns-server"] == DEFAULT_PPPOE_DNS_SERVERS == "8.8.8.8,8.8.4.4"


def test_existing_blank_profile_is_filled_on_update():
    api, calls = _api([{".id": "*5", "name": "pppoe_5M_5M", "dns-server": ""}])
    api.ensure_pppoe_profile("pppoe_5M_5M", "5M/5M")
    command, args = calls[-1]
    assert command == "/ppp/profile/set"
    assert args["numbers"] == "*5"
    assert args["dns-server"] == "8.8.8.8,8.8.4.4"


def test_existing_custom_dns_is_not_overwritten():
    api, calls = _api([{".id": "*5", "name": "pppoe_5M_5M", "dns-server": "1.1.1.1"}])
    api.ensure_pppoe_profile("pppoe_5M_5M", "5M/5M")
    assert "dns-server" not in calls[-1][1]


def test_base_profile_dns_still_wins():
    api, calls = _api([])
    api.ensure_pppoe_profile("pppoe_5M_5M", "5M/5M", dns_server="192.168.89.1")
    assert calls[-1][1]["dns-server"] == "192.168.89.1"


def test_ensure_plan_profile_with_blank_base_profile_gets_dns(monkeypatch):
    api, calls = _api([])
    api.get_active_pppoe_profile = lambda: {
        "found": True,
        "data": {"local_address": "192.168.89.1", "remote_address": "custom-pool", "dns_server": ""},
    }
    result = pppoe_provisioning.ensure_plan_pppoe_profile(api, "5Mbps")
    assert not result.get("error")
    add = [c for c in calls if c[0] == "/ppp/profile/add"][-1]
    assert add[1]["dns-server"] == "8.8.8.8,8.8.4.4"


def test_heal_sets_dns_only_on_blank_pppoe_profiles_and_is_idempotent():
    profiles = [
        {".id": "*1", "name": "default", "dns-server": ""},
        {".id": "*2", "name": "default-encryption", "dns-server": ""},
        {".id": "*3", "name": "default-pppoe", "dns-server": ""},
        {".id": "*4", "name": "pppoe_5M_5M", "dns-server": ""},
        {".id": "*5", "name": "pppoe_10M_10M", "dns-server": "1.1.1.1"},
        {".id": "*6", "name": "reseller-plan", "dns-server": ""},  # used by a PPPoE secret
        {".id": "*7", "name": "vpn-staff", "dns-server": ""},       # not PPPoE: left alone
    ]
    api, calls = _api(
        profiles,
        servers=[{"default-profile": "default-pppoe"}],
        secrets=[{"service": "pppoe", "profile": "reseller-plan"}, {"service": "l2tp", "profile": "vpn-staff"}],
    )
    result = api.heal_empty_pppoe_profile_dns()
    assert result["healed"] == ["default-pppoe", "pppoe_5M_5M", "reseller-plan"]
    sets = [c for c in calls if c[0] == "/ppp/profile/set"]
    assert {a["numbers"] for _, a in sets} == {"*3", "*4", "*6"}
    assert all(a["dns-server"] == "8.8.8.8,8.8.4.4" for _, a in sets)
    # Never disconnects anyone.
    assert not any(c[0].startswith("/ppp/active") for c in calls)

    # Second run after the fix writes nothing.
    for p in profiles:
        if p[".id"] in {"*3", "*4", "*6"}:
            p["dns-server"] = "8.8.8.8,8.8.4.4"
    calls.clear()
    again = api.heal_empty_pppoe_profile_dns()
    assert again["healed"] == []
    assert not [c for c in calls if c[0] == "/ppp/profile/set"]


def test_heal_dry_run_writes_nothing():
    api, calls = _api([{".id": "*4", "name": "pppoe_5M_5M", "dns-server": ""}])
    result = api.heal_empty_pppoe_profile_dns(dry_run=True)
    assert result["healed"] == ["pppoe_5M_5M"]
    assert not [c for c in calls if c[0] == "/ppp/profile/set"]


def test_recovery_sweep_listing_heals_dns(monkeypatch):
    healed = []

    class FakeAPI:
        def __init__(self, *a, **k):
            pass

        def connect(self):
            return True

        def disconnect(self):
            pass

        def get_pppoe_secrets_minimal(self):
            return {"success": True, "data": [{"name": "u1"}]}

        def heal_empty_pppoe_profile_dns(self):
            healed.append(True)
            return {"success": True, "healed": ["pppoe_5M_5M"]}

    monkeypatch.setattr("app.services.mikrotik_api.MikroTikAPI", FakeAPI)
    out = pppoe_resync._list_pppoe_secrets_sync({"ip": "10.0.0.1", "username": "a", "password": "b", "port": 8728})
    assert out["success"] and out["secrets"] == [{"name": "u1"}]
    assert out["dns_healed"] == ["pppoe_5M_5M"]
    assert healed


def test_recovery_sweep_listing_survives_heal_failure(monkeypatch):
    class FakeAPI:
        def __init__(self, *a, **k):
            pass

        def connect(self):
            return True

        def disconnect(self):
            pass

        def get_pppoe_secrets_minimal(self):
            return {"success": True, "data": []}

        def heal_empty_pppoe_profile_dns(self):
            raise RuntimeError("boom")

    monkeypatch.setattr("app.services.mikrotik_api.MikroTikAPI", FakeAPI)
    out = pppoe_resync._list_pppoe_secrets_sync({"ip": "10.0.0.1", "username": "a", "password": "b", "port": 8728})
    assert out["success"] and out["dns_healed"] == []


def test_router_agent_pppoe_script_fills_blank_dns():
    script = render_pppoe_provision_action(username="cust1", password="pw", bandwidth_limit="5Mbps")
    assert "dns-server=8.8.8.8,8.8.4.4" in script
    assert "dns-server]]] = 0" in script
