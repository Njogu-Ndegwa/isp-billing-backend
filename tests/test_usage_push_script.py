"""The rendered RouterOS script is executed on customer hardware.

`pull_provisioning` learned this the hard way, so the same discipline applies:
anything that fails validation raises rather than being embedded, and the
generated text is checked for the properties that keep a fleet safe.
"""

import pytest

from app.services.usage_push_auth import derive_router_token
from app.services.usage_push_script import (
    LOGOUT_SCRIPT_NAME,
    SCHEDULER_NAME,
    render_logout_hook_attach,
    render_usage_push_script,
)

URL = "https://isp.bitwavetechnologies.net/api/router/usage-push"


def test_script_carries_the_routers_own_token():
    script = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert derive_router_token("Router-0721") in script
    assert derive_router_token("Router-9999") not in script


def test_script_is_idempotent_on_reinstall():
    """Re-running the installer must replace, not accumulate — otherwise a
    retried install leaves a router pushing several times per interval."""
    script = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert script.count("/system script remove") == 2
    assert "/system scheduler remove" in script


def test_scheduler_start_is_jittered():
    """A fleet that reboots together (power cut) must not come back as one wave."""
    script = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert ":rndnum" in script


def test_failed_push_is_swallowed_not_retried_in_a_loop():
    """Counters are cumulative, so a missed push needs no retry — and a retry
    loop on 1,000 routers against a struggling server is the last thing we want."""
    script = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert "on-error=" in script


def test_script_skips_queues_that_are_not_ours():
    script = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert "plan_" in script
    assert "<pppoe-" in script


def test_logout_hook_marks_reports_final():
    script = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert '\\"final\\":true' in script
    assert LOGOUT_SCRIPT_NAME in script


@pytest.mark.parametrize(
    "identity",
    ['Router-0721"; /system reset-configuration', "Router 0721", "", "R" * 100],
)
def test_unsafe_identity_is_refused(identity):
    with pytest.raises(ValueError):
        render_usage_push_script(identity=identity, endpoint_url=URL)


@pytest.mark.parametrize(
    "url",
    ["ftp://evil.example.com", 'https://x"; :log error "', "not-a-url", ""],
)
def test_unsafe_endpoint_url_is_refused(url):
    with pytest.raises(ValueError):
        render_usage_push_script(identity="Router-0721", endpoint_url=url)


@pytest.mark.parametrize("interval", [0, 10, 5000, -1])
def test_implausible_interval_is_refused(interval):
    with pytest.raises(ValueError):
        render_usage_push_script(
            identity="Router-0721", endpoint_url=URL, interval_seconds=interval
        )


def test_scheduler_uses_a_stable_name_so_it_can_be_found_and_removed():
    """Rollback is 'remove the scheduler', so its name must be predictable."""
    script = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert SCHEDULER_NAME in script


def test_logout_hook_attach_rejects_an_unsafe_profile_name():
    assert "on-logout" in render_logout_hook_attach("pppoe_5M_5M")
    with pytest.raises(ValueError):
        render_logout_hook_attach('x"; /system reset-configuration')


def test_metrics_block_counts_connected_authorized_hosts_not_portal_logins():
    """Regression: 2026-08-06.

    ``/ip hotspot active`` lists portal LOGINS, which is permanently empty on
    the MAC-bypass model most resellers run. Reporting that zero made every
    hotspot customer surface as a phantom PPPoE user. The count must come from
    the host table, filtered to devices allowed through.
    """
    script = render_usage_push_script(
        identity="Router-0721", endpoint_url=URL, include_router_metrics=True
    )

    assert "/ip hotspot host find" in script
    assert "[:len [/ip hotspot active find]]" not in script
    # Unpaid devices sit in the host table unauthorized; they must not count.
    assert "authorized" in script and "bypassed" in script
    # Each host counted once, not two summed find lengths.
    assert "($ha || $hb) do={ :set hs ($hs + 1) }" in script


def test_metrics_block_declares_its_version():
    script = render_usage_push_script(
        identity="Router-0721", endpoint_url=URL, include_router_metrics=True
    )
    assert '\\"metrics_version\\":2' in script


def test_metrics_block_is_still_opt_in():
    script = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert "hotspot host find" not in script
    assert "metrics_version" not in script
