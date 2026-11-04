from types import SimpleNamespace

import pytest

from app.api import router_agent_routes
from app.services.router_agent_auth import derive_router_agent_token
from app.services.router_agent_script import (
    AGENT_VERSION,
    COMMAND_FILE,
    SCHEDULER_NAME,
    SCHEDULER_TICK_SECONDS,
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
    assert "bitwavePollSkips" in source
    assert "bitwaveFailureSkips" in source
    assert ":rndnum" not in source
    assert "/system scheduler set" not in source
    assert SCHEDULER_TICK_SECONDS == 30
    assert AGENT_VERSION == "2"
    assert "bitwaveAgentRuntimeVersion" in source
    assert "recovered stale poll lock" in source
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


@pytest.mark.parametrize(
    "seconds,skips",
    [(30, 0), (60, 1), (90, 2), (91, 3), (120, 3), (150, 4)],
)
def test_server_delay_uses_fixed_scheduler_ticks_without_polling_early(seconds, skips):
    assert router_agent_routes._poll_skip_count(seconds) == skips


def test_idle_and_command_responses_never_retune_scheduler_interval():
    idle = router_agent_routes._poll_skip_directive(120)
    command = router_agent_routes._command_envelope(
        SimpleNamespace(id=7, action_script=":put ok"),
        "Router-0001",
        URL,
        60,
    )

    assert ":set bitwavePollSkips 3" in idle
    assert ":set bitwavePollSkips 1" in command
    assert "/system scheduler set" not in idle
    assert "/system scheduler set" not in command


@pytest.mark.parametrize("tunnel", ["wireguard", "l2tp"])
def test_agent_has_no_bare_return(tunnel):
    # RouterOS 7.19+ rejects a bare ":return" ("missing value(s) of argument(s)
    # value"): router 446 (7.24.3) logged a script error on every skipped tick.
    source = render_router_agent_source(
        identity="Router-0001", endpoint_base_url=URL, tunnel_type=tunnel,
    )
    assert ":return" not in source
    # Every early exit clears the run flag instead, and the poll only runs
    # while it is still set.
    assert source.count(":set bwRun false") == 3
    assert ":local bwRun true" in source
    poll = source.index("/tool fetch")
    assert source.rindex(":if ($bwRun) do={", 0, poll) > source.index(":local tunnel")
    # Blocks balance (an unclosed do={ would break the whole script).
    body = source[source.index(":global bitwaveAgentRuntimeVersion"):]
    assert body.count("{") == body.count("}")
