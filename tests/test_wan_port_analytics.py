"""WANs have no bridge-learned clients; that is not a silent access link."""
from datetime import datetime

import pytest

from app.api import router_operations as ro
from app.services import realtime_state


@pytest.mark.parametrize("source", ["live", "push"])
@pytest.mark.parametrize(
    "enabled,configured,bridged,running,errors,status,warning",
    [
        (True, True, False, True, 0, "active", None),
        (True, True, False, True, 4, "active", "Interface errors are present"),
        (True, True, False, False, 0, "down", "Configured WAN port has no physical link"),
        (False, True, False, True, 0, "silent_link", "no downstream MACs"),
        (True, False, False, True, 0, "silent_link", "no downstream MACs"),
        (True, True, True, True, 0, "silent_link", "no downstream MACs"),
    ],
)
def test_configured_wan_health(monkeypatch, source, enabled, configured, bridged,
                               running, errors, status, warning):
    info = dict(id=606, name="Router", identity="Router", ip="10.0.0.1",
                lb_enabled=enabled,
                lb_config={"wan_ports": ["ether1", "ether2" if configured else "ether3"]})
    bridge_ports = [{"interface": "ether2", "bridge": "bridge"}] if bridged else []
    if source == "live":
        result = ro._analyze_port_rows(
            info, {}, {}, identity_rows=[], resource_rows=[],
            interface_rows=[{"name": "ether2", "type": "ether", "running": str(running).lower(),
                             "rx-packet": "100", "rx-error": str(errors)}],
            ethernet_rows=[], bridge_rows=[], bridge_port_rows=bridge_ports,
            bridge_host_rows=[], neighbor_rows=[], dhcp_rows=[], arp_rows=[],
            hotspot_host_rows=[], hotspot_active_rows=[], ppp_active_rows=[],
        )
    else:
        realtime_state.record_push(
            606, now=datetime.utcnow(), interval_seconds=60, hosts=[], queues=[],
            live_customers={}, metrics={},
            ports=[{"name": "ether2", "running": running, "rx_packets": 100, "rx_errors": errors,
                    "rx_bytes": 1000, "tx_bytes": 500}],
            bridge_hosts=[], bridge_ports=bridge_ports, leases=[], hosts_raw=[], ppp_raw=[],
        )
        monkeypatch.setattr(ro, "_push_port_state", lambda _id: realtime_state.get_router_live(606))
        try:
            result = ro._port_analytics_from_push(info, {}, {})
        finally:
            realtime_state.reset_realtime_state()
    port = result["ports"][0]
    assert port["health"]["status"] == status
    if warning:
        assert any(warning in message for message in port["health"]["warnings"])
        assert result["warnings"][0]["port"] == "ether2"
    else:
        assert port["health"]["warnings"] == []
        assert result["warnings"] == []
