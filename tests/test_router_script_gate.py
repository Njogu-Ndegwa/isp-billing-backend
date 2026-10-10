import pytest

from app.services import checkin_applier_script, expiry_reaper_script, mgmt_watchdog_script
from app.services import router_agent_script, usage_push_script
from app.services.router_script_gate import (
    GATED_SCRIPTS,
    MAX_WAIT_SECONDS,
    gate_rsc_body,
    has_current_gate,
    render_gate,
    strip_gate,
    with_gate,
)

IDENT = "Router-0585"
BODY = ':local url "x"\n:log info "hello"\n'


@pytest.mark.parametrize("name", GATED_SCRIPTS)
def test_gate_names_itself_and_waits_for_every_bitwave_script(name):
    gate = render_gate(name)
    assert f'[/system script job find where script="{name}"]' in gate
    for other in GATED_SCRIPTS:
        assert f'script="{other}"' in gate
    assert f"($bwgWait < {MAX_WAIT_SECONDS})" in gate
    assert ":delay 1s" in gate
    assert "__" not in gate


@pytest.mark.parametrize("forbidden", [
    ":return", "/import", ":global", ":deserialize", ":serialize", ":parse", ":execute",
    ":onerror", ":timestamp", "/system reboot",
])
def test_gate_avoids_constructs_the_router_scripts_must_not_use(forbidden):
    assert forbidden not in render_gate("bitwave-checkin")


def test_gate_balances():
    gate = render_gate("bitwave-usage-push")
    assert gate.count("{") == gate.count("}")
    assert gate.count("[") == gate.count("]")
    assert gate.count("(") == gate.count(")")
    assert gate.count('"') % 2 == 0


def test_gate_fails_open():
    gate = render_gate("bitwave-expiry-reaper")
    # Ids that do not parse leave bwgMe at 0, which skips the wait entirely.
    assert ':if ([:typeof $n] = "num")' in gate
    assert "} on-error={ :set bwgMe 0 }" in gate
    assert ":if ($bwgMe = 0) do={ :set bwgBusy false }" in gate
    assert "} on-error={ :set bwgBusy false }" in gate
    # Only older jobs block, so the oldest one always runs: no deadlock.
    assert ":if ($n < $bwgMe) do={ :set bwgBusy true }" in gate


def test_unknown_script_is_refused():
    with pytest.raises(ValueError):
        render_gate("someone-elses-script")


def test_with_gate_is_idempotent_and_reversible():
    once = with_gate("bitwave-checkin", BODY)
    assert once.startswith(render_gate("bitwave-checkin"))
    assert with_gate("bitwave-checkin", once) == once
    assert strip_gate(once) == BODY
    assert strip_gate(BODY) == BODY
    assert has_current_gate("bitwave-checkin", once)
    assert not has_current_gate("bitwave-checkin", BODY)


def test_with_gate_replaces_an_older_gate():
    old = render_gate("bitwave-checkin").replace("# bw-gate v1:", "# bw-gate v0:").replace("< 20", "< 5")
    assert with_gate("bitwave-checkin", old + BODY) == render_gate("bitwave-checkin") + BODY


def test_gate_rsc_body_lands_inside_the_source_block():
    rsc = '/system script add name="n" source={\n    :local a 1\n}\n'
    out = gate_rsc_body("bitwave-usage-push", rsc)
    assert out.startswith('/system script add name="n" source={\n' + render_gate("bitwave-usage-push"))
    assert out.endswith("    :local a 1\n}\n")


@pytest.mark.parametrize("kind", [mgmt_watchdog_script.KIND_WG, mgmt_watchdog_script.KIND_SSTP])
def test_watchdog_is_gated(kind):
    src = mgmt_watchdog_script.render_watchdog_source(kind, "10.0.0.225")
    assert has_current_gate(mgmt_watchdog_script.script_name(kind), src)


def test_checkin_is_gated():
    src = checkin_applier_script.render_checkin_applier_source(
        identity=IDENT, endpoint_url="https://isp.example.net/api/router/checkin")
    assert has_current_gate(checkin_applier_script.SCRIPT_NAME, src)


def test_expiry_reaper_is_gated():
    rendered = expiry_reaper_script.render_expiry_reaper_script(
        identity=IDENT, tunnel_url="http://10.251.0.1:8088/api/router/expiry-check",
        public_url="https://isp.example.net/api/router/expiry-check")
    assert has_current_gate(expiry_reaper_script.SCRIPT_NAME, expiry_reaper_script.script_source(rendered))


def test_usage_push_is_gated():
    rendered = usage_push_script.render_realtime_push_script(
        identity=IDENT, endpoint_url="http://10.251.0.1:8088/api/router/usage-push", interval_seconds=60)
    body = rendered[rendered.index("source={\n") + len("source={\n"):]
    assert has_current_gate(usage_push_script.SCRIPT_NAME, body)


def test_command_agent_is_gated():
    src = router_agent_script.render_router_agent_source(
        identity=IDENT, endpoint_base_url="https://isp.example.net", tunnel_type="wireguard")
    assert has_current_gate(router_agent_script.SCRIPT_NAME, src)
