"""Never bridge a port that carries the router's internet into the customer LAN."""
from app.api.router_operations import _refuse_live_uplinks


class _Api:
    def __init__(self, tables, broken=()):
        self.tables, self.broken = tables, set(broken)

    def send_command(self, command, args=None):
        if command in self.broken:
            return {"success": False, "error": "timeout"}
        return {"success": True, "data": list(self.tables.get(command, []))}

    def send_command_optimized(self, command, **kwargs):
        return self.send_command(command)


def _tables(**extra):
    t = {
        "/interface/print": [{"name": f"ether{i}", "type": "ether"} for i in range(1, 6)]
                            + [{"name": "bridge", "type": "bridge"}],
        "/interface/bridge/port/print": [{"interface": "ether3", "bridge": "bridge"},
                                         {"interface": "ether4", "bridge": "bridge"}],
        "/ip/route/print": [{"dst-address": "0.0.0.0/0", "gateway": "8.8.8.8",
                             "immediate-gw": "192.168.1.1%ether1"}],
        "/ip/address/print": [{"address": "192.168.1.3/24", "interface": "ether1"},
                              {"address": "192.168.1.3/24", "interface": "ether2"},
                              {"address": "10.251.0.132/16", "interface": "wg-hz"}],
        # ZEUS after LB was disabled: line 2 keeps its DHCP client
        "/ip/dhcp-client/print": [{"interface": "ether1", "disabled": "false"},
                                  {"interface": "ether2", "disabled": "false"}],
        "/interface/pppoe-client/print": [],
        "/user/active/print": [],
    }
    t.update(extra)
    return t


INFO = {"ip": "10.251.0.132"}


def test_refuses_a_second_wan_left_after_lb_was_disabled():
    res = _refuse_live_uplinks(_Api(_tables()), INFO, ["ether2"])
    assert res and res["failed_ports"] == ["ether2"]
    assert "ether2:" in res["error"]


def test_refuses_a_pppoe_client_port():
    api = _Api(_tables(**{"/ip/dhcp-client/print": [{"interface": "ether1"}],
                          "/interface/pppoe-client/print": [{"name": "pppoe-out1",
                                                             "interface": "ether5"}]}))
    assert _refuse_live_uplinks(api, INFO, ["ether5"])["failed_ports"] == ["ether5"]


def test_allows_plain_lan_ports():
    assert _refuse_live_uplinks(_Api(_tables()), INFO, ["ether3", "ether4"]) is None
    assert _refuse_live_uplinks(_Api(_tables()), INFO, []) is None


def test_fails_closed_when_the_router_cannot_be_read():
    res = _refuse_live_uplinks(_Api(_tables(), broken={"/ip/dhcp-client/print"}), INFO, ["ether3"])
    assert res and "nothing changed" in res["error"]
