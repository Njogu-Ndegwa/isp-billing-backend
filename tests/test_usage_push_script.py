"""The rendered RouterOS script is executed on customer hardware.

`pull_provisioning` learned this the hard way, so the same discipline applies:
anything that fails validation raises rather than being embedded, and the
generated text is checked for the properties that keep a fleet safe.
"""

import re

import pytest

from app.services.router_script_gate import has_current_gate
from app.services.usage_push_auth import derive_router_token
from app.services.usage_push_script import (
    LOGOUT_SCRIPT_NAME,
    PUBLIC_FALLBACK_LIST,
    PUBLIC_FALLBACK_MINUTES,
    REALTIME_SCRIPT_VERSION,
    SCHEDULER_NAME,
    SCRIPT_NAME,
    push_script_version,
    render_logout_hook_attach,
    render_realtime_push_script,
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


def test_hotspot_count_includes_bypassed_hosts():
    """Paid customers ride a bypassed ip-binding and never show in
    /ip hotspot active — counting that table read 0 on a router with paying
    customers online. Must match the poller: authorized + bypassed hosts."""
    script = render_usage_push_script(
        identity="Router-0721", endpoint_url=URL, include_router_metrics=True
    )
    assert "/ip hotspot host find where bypassed" in script
    assert "/ip hotspot host find where authorized" in script
    assert "/ip hotspot active find" not in script


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


# ---------------------------------------------------------------------------
# Real-time reporter v4: public HTTPS fallback for tunnel installs
# ---------------------------------------------------------------------------
# Incident 2026-10-12 (routers 448 RONGAI, 351 HOME951): a tunnel-push router
# whose management tunnel died stopped reporting entirely and the site looked
# offline. v4 falls back to public HTTPS, at most once per 15 minutes.

TUNNEL_URL = "http://10.251.0.1:8088/api/router/usage-push"
PUBLIC_URL = URL


def _tunnel_script(**kw):
    return render_realtime_push_script(identity="Router-0448", endpoint_url=TUNNEL_URL,
                                       interval_seconds=60, fallback_url=PUBLIC_URL, **kw)


def _public_script(**kw):
    return render_realtime_push_script(identity="Router-0448", endpoint_url=PUBLIC_URL,
                                       interval_seconds=60, **kw)


def _source(rendered: str) -> str:
    start = rendered.index("source={\n") + len("source={\n")
    return rendered[start:rendered.index("\n}\n\n/system scheduler add")]


def test_tunnel_install_tries_the_tunnel_first_then_public_https():
    src = _source(_tunnel_script())
    tunnel_fetch = src.index("/tool fetch url=$url ")
    public_fetch = src.index(f'/tool fetch url="{PUBLIC_URL}" ')
    assert tunnel_fetch < src.index(":if (!$ok) do={") < public_fetch
    assert src.count("/tool fetch") == 2
    assert src.count(PUBLIC_URL) == 1
    # Either channel's reply retunes the scheduler; only a double failure defers.
    assert src.index(":if ($ok) do={") > public_fetch
    assert src.rstrip().endswith('} else={ :log info "usage-push: deferred" }')
    assert all(ord(c) < 128 for c in src)


def test_public_fallback_only_when_the_tunnel_server_does_not_answer():
    # A 503 (pool pressure) or 429 over a live tunnel must not trigger HTTPS.
    src = _source(_tunnel_script())
    assert src.index("[/ping 10.251.0.1 count=1] = 0") < src.index(f'/tool fetch url="{PUBLIC_URL}"')


def test_public_fallback_is_rate_limited_to_one_report_per_15_minutes_in_ram():
    assert PUBLIC_FALLBACK_MINUTES == 15
    src = _source(_tunnel_script())
    check = src.index(f'/ip firewall address-list find where list="{PUBLIC_FALLBACK_LIST}"]] = 0')
    mark = src.index(f"/ip firewall address-list add list={PUBLIC_FALLBACK_LIST} address=0.0.0.1 timeout=15m")
    public_fetch = src.index(f'/tool fetch url="{PUBLIC_URL}"')
    # Checked, then marked BEFORE the call, so a failed HTTPS attempt also waits.
    assert check < mark < public_fetch
    # A healthy tunnel never touches the address list.
    assert src.index("/ip firewall address-list") > src.index(":if (!$ok) do={")
    # The state is a dynamic (timeout) entry, never a :global.
    fallback = src[src.index(":local hdr "):]
    assert ":global" not in fallback
    assert re.findall(r":global \w+", src) == [":global bwPushN"]   # unchanged from v3


def test_router_never_claims_the_tunnel_channel_itself():
    # Caddy's tunnel-only site sets X-Bitwave-Push-Channel: tunnel. If the script
    # sent it, a public fallback report would be counted as a tunnel report.
    for rendered in (_tunnel_script(), _public_script()):
        assert "Push-Channel" not in rendered
    src = _source(_tunnel_script())
    assert ':local hdr ("Content-Type: application/json,Authorization: Bearer " . $tok)' in src
    assert src.count("http-header-field=$hdr") == 2


def test_public_only_installs_are_unchanged():
    plain = _public_script()
    assert plain == _public_script(fallback_url=PUBLIC_URL)     # same URL twice = no fallback
    src = _source(plain)
    assert src.count("/tool fetch") == 1
    assert "/ping" not in src and "address-list" not in src
    assert ('/tool fetch url=$url http-method=post http-header-field=("Content-Type: application/json,'
            'Authorization: Bearer " . $tok) http-data=$body output=user as-value]') in src
    assert src.rstrip().endswith('} on-error={ :log info "usage-push: deferred" }')
    # A tunnel URL with no fallback given is the old one-URL reporter too.
    tunnel_only = render_realtime_push_script(identity="Router-0448", endpoint_url=TUNNEL_URL, interval_seconds=60)
    assert "/ping" not in tunnel_only and PUBLIC_URL not in tunnel_only


def test_fallback_script_has_no_return_and_starts_with_the_gate():
    for rendered in (_tunnel_script(), _public_script()):
        assert ":return" not in rendered
        assert has_current_gate(SCRIPT_NAME, rendered[rendered.index("source={\n") + len("source={\n"):])


def test_script_version_marker_is_bumped_and_readable():
    assert REALTIME_SCRIPT_VERSION == 4
    for rendered in (_tunnel_script(), _public_script()):
        assert push_script_version(rendered) == REALTIME_SCRIPT_VERSION
    assert push_script_version(r':local body "{\"identity\":\"$ident\",\"v\":3,\"reports\":["') == 3
    assert push_script_version("old v1 push") == 0
    assert push_script_version("") == 0


@pytest.mark.parametrize("url", ['https://x.example/a" ; /system reset', "ftp://x.example/a", "not a url"])
def test_unsafe_fallback_url_is_refused(url):
    with pytest.raises(ValueError):
        render_realtime_push_script(identity="Router-0448", endpoint_url=TUNNEL_URL, fallback_url=url)
