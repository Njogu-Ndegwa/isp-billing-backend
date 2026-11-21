"""The router check-up finds the known faults and names each one's tested fix."""
from datetime import datetime, timezone

from app.services import router_checkup
from app.services.provisioning import PROXY_RELAY_BLOCK_COMMENT

NOW = datetime(2026, 11, 21, 18, 0, tzinfo=timezone.utc)


class FakeRouter:
    def __init__(self, **tables):
        self.tables = {
            "/ping": [{"seq": "0", "time": "18ms", "sent": "3", "received": "3"}],
            "/system/clock/print": [{"date": "nov/21/2026", "time": "21:00:00"}],
            "/ip/hotspot/print": [{"name": "hotspot1", "interface": "bridge", "profile": "hsprof1", "disabled": "false"}],
            "/ip/hotspot/profile/print": [{"name": "hsprof1", "html-directory": "flash/hotspot"}],
            "/file/print": [{"name": "flash/hotspot/login.html"}],
            "/ip/firewall/filter/print": [{".id": "*9", "comment": PROXY_RELAY_BLOCK_COMMENT}],
            "/ip/hotspot/ip-binding/print": [],
            "/ip/dhcp-server/alert/print": [],
            "/system/resource/print": [{"cpu-load": "12"}],
            "/system/identity/print": [{"name": "Router-0305"}],
            "/ip/firewall/address-list/print": [],
        }
        self.tables.update(tables)
        self.writes = []

    def send_command(self, command, arguments=None):
        if command.endswith(("/add", "/remove", "/set")):
            self.writes.append((command, arguments))
            return {"success": True, "data": []}
        return {"success": True, "data": self.tables.get(command, [])}


def codes(api):
    return [f["code"] for f in router_checkup.check(api, 7, now=NOW)["findings"]]


def test_a_healthy_router_has_nothing_to_fix_and_nothing_is_changed():
    api = FakeRouter()
    out = router_checkup.check(api, 7, now=NOW)
    assert out["ok"] is True and out["findings"] == []
    assert out["identity"] == "Router-0305"
    assert api.writes == []


def test_a_dead_internet_line_is_said_with_what_to_check():
    api = FakeRouter(**{"/ping": [{"seq": "0", "status": "timeout", "sent": "3", "received": "0"}]})
    out = router_checkup.check(api, 7, now=NOW)
    assert out["findings"][0]["code"] == "wan_down"
    assert "port 1" in out["findings"][0]["advice"]
    assert "fix" not in out["findings"][0]   # a dead line is fixed at the site, not from here


def test_a_missing_login_page_offers_the_captive_portal_repair():
    api = FakeRouter(**{"/file/print": []})
    f = next(f for f in router_checkup.check(api, 7, now=NOW)["findings"] if f["code"] == "login_page_missing")
    assert f["fix"]["path"] == "/api/routers/7/remediate-captive-portal"


def test_no_relay_block_offers_the_bypass_fix():
    api = FakeRouter(**{"/ip/firewall/filter/print": []})
    f = next(f for f in router_checkup.check(api, 7, now=NOW)["findings"] if f["code"] == "proxy_bypass_open")
    assert f["fix"] == {"method": "POST", "path": "/api/routers/7/anti-bypass",
                        "summary": "Close the hotspot proxy bypass (HTTP Injector)"}


def test_other_known_faults():
    assert "clock_wrong" in codes(FakeRouter(**{"/system/clock/print": [{"date": "jan/02/1970"}]}))
    assert "clock_wrong" not in codes(FakeRouter(**{"/system/clock/print": [{"date": "2026-11-21"}]}))
    assert "hotspot_disabled" in codes(FakeRouter(**{"/ip/hotspot/print": [{"name": "h", "profile": "hsprof1", "disabled": "true"}]}))
    assert "rogue_dhcp" in codes(FakeRouter(**{"/ip/dhcp-server/alert/print": [{"interface": "bridge", "unknown-server": "AA:BB:CC:00:11:22"}]}))
    assert "cpu_high" in codes(FakeRouter(**{"/system/resource/print": [{"cpu-load": "97"}]}))
    assert "bypassed_devices" in codes(FakeRouter(**{"/ip/hotspot/ip-binding/print": [{"type": "bypassed", "mac-address": "AA"}]}))


def test_the_worst_comes_first():
    api = FakeRouter(**{"/ping": [{"received": "0"}], "/system/resource/print": [{"cpu-load": "95"}],
                        "/ip/hotspot/ip-binding/print": [{"type": "bypassed"}]})
    assert [f["severity"] for f in router_checkup.check(api, 7, now=NOW)["findings"]] == ["bad", "warn", "info"]


def test_a_router_without_a_hotspot_skips_the_hotspot_checks():
    api = FakeRouter(**{"/ip/hotspot/print": [], "/ip/firewall/filter/print": []})
    assert "proxy_bypass_open" not in codes(api)


def test_the_bypass_fix_replaces_its_own_rule_and_allow_list():
    api = FakeRouter(**{"/ip/firewall/address-list/print": [
        {".id": "*1", "list": "isp_portal_allow", "comment": "portal/api/backend allow (anti-tunnel)"},
        {".id": "*2", "list": "isp_portal_allow", "comment": "the reseller's own"}]})
    out = router_checkup.apply_anti_bypass(api, ["91.98.238.12", "76.76.21.0/24"])
    assert out["success"]
    removed = [a[".id"] for c, a in api.writes if c.endswith("/remove")]
    assert removed == ["*1", "*9"]   # ours only, never the reseller's entries
    rule = next(a for c, a in api.writes if c == "/ip/firewall/filter/add")
    assert rule["chain"] == "output" and rule["dst-port"] == "80,3128,8080" and rule["comment"] == PROXY_RELAY_BLOCK_COMMENT
