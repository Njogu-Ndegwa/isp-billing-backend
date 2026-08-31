import pytest

from app.services.router_agent_auth import derive_router_agent_token
from app.services.router_agent_script import (
    COMMAND_FILE,
    SCHEDULER_NAME,
    render_router_agent_source,
    rollback_router_agent_rsc,
)


URL = "https://isp.bitwavetechnologies.net"


def test_wireguard_agent_is_authenticated_adaptive_and_non_overlapping():
    source = render_router_agent_source(
        identity="Router-0001",
        endpoint_base_url=URL,
        tunnel_type="wireguard",
    )
    assert derive_router_agent_token("Router-0001") in source
    assert "bitwaveAgentRunning" in source
    assert "previous poll still running" in source
    assert "output=file" in source
    assert f"dst-path=$fileName" in source
    assert "/import file-name=$fileName" in source
    assert "45" in source and "90" in source and "180" in source and "300" in source
    assert ":rndnum" in source
    assert "/file get" not in source
    assert len(source.encode("utf-8")) < 8192


def test_tunnel_probe_is_transport_specific():
    l2tp = render_router_agent_source(
        identity="Router-0002",
        endpoint_base_url=URL,
        tunnel_type="l2tp",
    )
    wireguard = render_router_agent_source(
        identity="Router-0002",
        endpoint_base_url=URL,
        tunnel_type="wireguard",
    )
    assert 'name="l2tp-aws" running=yes' in l2tp
    assert "/ping 10.0.0.1" not in l2tp
    assert "/ping 10.0.0.1" in wireguard


@pytest.mark.parametrize(
    "identity,url,tunnel",
    [
        ('Router-1"; /system reset-configuration', URL, "wireguard"),
        ("Router-1", "ftp://example.com", "wireguard"),
        ("Router-1", URL, "auto"),
    ],
)
def test_unsafe_agent_inputs_are_rejected(identity, url, tunnel):
    with pytest.raises(ValueError):
        render_router_agent_source(
            identity=identity,
            endpoint_base_url=url,
            tunnel_type=tunnel,
        )


def test_rollback_disables_scheduler_before_removing_script():
    rollback = rollback_router_agent_rsc()
    assert rollback.index("scheduler remove") < rollback.index("script remove")
    assert SCHEDULER_NAME in rollback
    assert COMMAND_FILE in rollback
