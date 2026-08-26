"""Guards for the LAN-port-to-bridge step of the provisioning .rsc.

Background (field-verified 2026-08-05, Router-0826 / router id 316): the step
attached a LAN port to our hotspot `bridge` only when the port was in NO bridge
at all::

    :if ([:len [/interface bridge port find where interface=$iface]] = 0) do={
        /interface bridge port add interface=$iface bridge=bridge
    }

On any router carrying a leftover bridge -- an ex-provider base, or an old
RouterOS default config whose bridge is named `bridgeLocal` -- every LAN port is
already a member of that bridge, so the guard is false and the add is silently
skipped. Provisioning then reports success while ether2-5 remain on the foreign
bridge: they never reach the hotspot server, the DHCP server or 192.168.88.1, so
the captive portal can never appear. On router 316 the hotspot `bridge` had
received 0 bytes since provisioning, and every other check (html files, walled
garden, NAT, hotspot profile) was clean -- which is why the standard router
diagnostic returned no findings.

The fix moves a port off a FOREIGN bridge, while leaving a port that sits on one
of OUR bridges alone -- `bridge-plain`, `bridge-pppoe` and `bridge-dual` carry
deliberate reseller layouts that a re-provision must not destroy.

These are script-text guards, not a RouterOS emulator: they pin the decision
structure of the emitted block and fail on the specific shapes that caused the
outage. `test_no_managed_bridge_is_unknown_to_provisioning` is the durable one --
it fails the build when someone adds a new managed bridge without telling
provisioning about it.
"""

import ast
import pathlib
import re

import pytest

from app.db.models import ProvisioningToken
from app.services.mikrotik_api import MANAGED_BRIDGE_NAMES
from app.services.provisioning import (
    _rsc_bridge_name_array,
    _rsc_wan_setup,
    generate_rsc_script,
)

APP_DIR = pathlib.Path(__file__).resolve().parent.parent / "app"

# The interfaces provisioning is responsible for putting on the hotspot bridge.
# wifi1 is the wifiwave2 radio name on RouterOS 7 hardware; wlan1 the legacy one.
EXPECTED_LAN_IFACES = ["ether2", "ether3", "ether4", "ether5", "wlan1", "wifi1"]

# The exact predicate that caused the field bug. It must never come back.
BUGGY_GUARD = re.compile(
    r"/interface bridge port find where interface=\$iface\s*\]\s*\]\s*=\s*0"
)


def _token(vpn_type: str = "l2tp") -> ProvisioningToken:
    return ProvisioningToken(
        token="abc123",
        router_name="Test Router",
        identity="Router-0001",
        vpn_type=vpn_type,
        wireguard_ip="10.0.100.1" if vpn_type == "l2tp" else "10.0.0.2",
        router_admin_password="ApiPassword123",
        server_public_ip="203.0.113.10",
        l2tp_username="l2tp-Router-0001",
        l2tp_password="L2tpPassword123",
        wg_private_key="wg-private",
        server_wg_pubkey="wg-server-public",
        payment_methods=["mpesa", "voucher"],
    )


@pytest.fixture
def wan_block() -> str:
    return _rsc_wan_setup()


@pytest.fixture
def lan_port_loop(wan_block: str) -> str:
    """Just the `:foreach iface in={...}` block that attaches LAN ports."""
    start = wan_block.index(":foreach iface in={")
    end = wan_block.index(":do { /interface bridge port remove [find where interface=ether1]")
    block = wan_block[start:end]
    assert block.strip(), "LAN port loop came back empty -- the extraction anchors moved"
    return block


@pytest.fixture
def stale_bridge_block(wan_block: str) -> str:
    """The cleanup loop that parks an emptied foreign bridge."""
    start = wan_block.index(":foreach bwBr in=[/interface bridge find]")
    return wan_block[start:]


# --------------------------------------------------------------------------
# The regression that took router 316 off the portal
# --------------------------------------------------------------------------


def test_lan_port_attach_is_not_guarded_on_being_in_no_bridge(wan_block: str):
    """The exact shape of the field bug: `in no bridge at all` as the add guard.

    With this predicate, a port already in `bridgeLocal` is skipped and stays
    there forever.
    """
    assert not BUGGY_GUARD.search(wan_block), (
        "The LAN-port step is guarded on the port being in NO bridge again. "
        "A port sitting in a leftover bridge (bridgeLocal) will be silently "
        "skipped and the captive portal will never appear -- see router 316."
    )


def test_lan_port_loop_removes_a_foreign_membership_before_attaching(lan_port_loop: str):
    """Moving requires a remove; an `add` alone cannot relocate a port."""
    assert "/interface bridge port remove $bwPort" in lan_port_loop
    assert "/interface bridge port add interface=$iface bridge=bridge" in lan_port_loop
    assert lan_port_loop.index("/interface bridge port remove $bwPort") < lan_port_loop.index(
        "/interface bridge port add interface=$iface bridge=bridge"
    ), "the remove must precede the add, otherwise RouterOS rejects the add"


def test_a_port_on_one_of_our_own_bridges_is_kept_not_moved(lan_port_loop: str):
    """bridge-plain / bridge-pppoe / bridge-dual layouts must survive a re-provision.

    The remove has to sit in the `else` of the allowlist check, and the keep
    flag has to suppress the add -- otherwise re-running provisioning would drag
    a reseller's plain or PPPoE ports back onto the hotspot bridge.
    """
    assert ":set bwKeep true" in lan_port_loop
    assert ':if ([:typeof [:find $bwOurBridges $bwOn]] != "nil") do={' in lan_port_loop

    keep_at = lan_port_loop.index(":set bwKeep true")
    remove_at = lan_port_loop.index("/interface bridge port remove $bwPort")
    else_at = lan_port_loop.index("} else={")
    assert keep_at < else_at < remove_at, (
        "the remove must be the else-branch of the our-bridges check, so ports "
        "on bridge-plain/bridge-pppoe/bridge-dual are never torn out"
    )

    add_at = lan_port_loop.index("/interface bridge port add interface=$iface bridge=bridge")
    guard_at = lan_port_loop.index(":if (!$bwKeep) do={")
    assert guard_at < add_at, "the add must be gated on the keep flag"


def test_every_lan_interface_is_covered(lan_port_loop: str):
    header = lan_port_loop[: lan_port_loop.index("do={")]
    listed = header[header.index("{") + 1 : header.index("}")].split(";")
    assert [i.strip() for i in listed] == EXPECTED_LAN_IFACES


def test_wan_port_is_never_a_lan_port(wan_block: str, lan_port_loop: str):
    """ether1 is the WAN. Bridging it would NAT the uplink into the hotspot."""
    assert "ether1" not in lan_port_loop
    assert ":do { /interface bridge port remove [find where interface=ether1] } on-error={}" in wan_block


# --------------------------------------------------------------------------
# Leftover-bridge cleanup
# --------------------------------------------------------------------------


def test_stale_bridge_cleanup_skips_our_own_bridges(stale_bridge_block: str):
    assert ':if ([:typeof [:find $bwOurBridges $bwName]] = "nil") do={' in stale_bridge_block


def test_stale_bridge_cleanup_only_touches_an_empty_bridge(stale_bridge_block: str):
    """A foreign bridge still holding ether6-10 is left whole, not half-dismantled."""
    assert ':if ([:len [/interface bridge port find where bridge=$bwName]] = 0) do={' in stale_bridge_block

    empty_check = stale_bridge_block.index("/interface bridge port find where bridge=$bwName")
    for destructive in (
        "/ip dhcp-client remove $bwC",
        "/ip address remove $bwA",
        "/interface bridge set $bwBr disabled=yes",
    ):
        assert destructive in stale_bridge_block
        assert empty_check < stale_bridge_block.index(destructive), (
            f"{destructive} runs before the has-no-ports check"
        )


def test_stale_bridge_cleanup_runs_only_after_the_wan_is_up(wan_block: str):
    """Tearing the old address down first can leave the router with no route.

    The leftover bridge often carries the pre-existing default route (router 316
    had a `defconf` DHCP client on bridgeLocal), so ether1 must already have its
    own client and NAT before we remove it.
    """
    wan_client = wan_block.index('/ip dhcp-client add interface=ether1')
    nat = wan_block.index("action=masquerade")
    cleanup = wan_block.index(":foreach bwBr in=[/interface bridge find]")
    assert wan_client < cleanup, "leftover bridge is stripped before ether1 has a DHCP client"
    assert nat < cleanup, "leftover bridge is stripped before NAT exists"


# --------------------------------------------------------------------------
# The durable guard: provisioning must know every bridge the app creates
# --------------------------------------------------------------------------


def test_rendered_bridge_array_matches_the_source_of_truth():
    expected = "{" + ";".join(f'"{n}"' for n in MANAGED_BRIDGE_NAMES) + "}"
    assert _rsc_bridge_name_array() == expected
    assert _rsc_bridge_name_array() in _rsc_wan_setup()


def test_no_managed_bridge_is_unknown_to_provisioning():
    """Every `bridge`-shaped name used anywhere in app/ must be in the allowlist.

    This is the guard that makes the fix durable. Add a new managed bridge (say
    `bridge-iot`) without adding it to MANAGED_BRIDGE_NAMES and provisioning
    would classify it as a foreign leftover: it would yank that bridge's ports
    onto the hotspot bridge and then park the emptied bridge. That is a silent,
    config-destroying regression, so it fails the build here instead.
    """
    name_shaped = re.compile(r"^bridge(-[a-z0-9]+)*$")
    found: dict[str, set[str]] = {}

    for path in APP_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if name_shaped.match(node.value):
                    found.setdefault(node.value, set()).add(
                        str(path.relative_to(APP_DIR.parent))
                    )

    unknown = {n: sorted(f) for n, f in found.items() if n not in MANAGED_BRIDGE_NAMES}
    assert not unknown, (
        "bridge name(s) used in app/ but missing from MANAGED_BRIDGE_NAMES in "
        f"app/services/mikrotik_api.py: {unknown}. Add them there so provisioning "
        "treats them as ours instead of dismantling them as leftovers."
    )


# --------------------------------------------------------------------------
# Whole-script sanity -- the .rsc is executed verbatim on customer hardware
# --------------------------------------------------------------------------


@pytest.mark.parametrize("vpn_type", ["wireguard", "l2tp"])
def test_generated_script_has_no_unsubstituted_placeholder(vpn_type: str):
    """A renamed placeholder would ship the literal token to real routers."""
    script = generate_rsc_script(_token(vpn_type))
    assert "__OUR_BRIDGES__" not in script
    assert not re.search(r"__[A-Z][A-Z0-9_]*__", script)


@pytest.mark.parametrize("vpn_type", ["wireguard", "l2tp"])
def test_generated_script_braces_are_balanced(vpn_type: str):
    """An unbalanced `do={` aborts the import part-way, which leaves a
    half-configured router that only a full reset can recover (AGENTS.md)."""
    script = generate_rsc_script(_token(vpn_type))
    depth = 0
    for line in script.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for ch in line:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            assert depth >= 0, f"closing brace with nothing open, near: {line!r}"
    assert depth == 0, f"{depth} unclosed brace(s) in the generated {vpn_type} script"


@pytest.mark.parametrize("vpn_type", ["wireguard", "l2tp"])
def test_bridge_work_still_happens_inside_step_1(vpn_type: str):
    """Ordering guard: ports must be bridged before STEP 2 puts 192.168.88.1 on
    `bridge` and starts the DHCP server on it."""
    script = generate_rsc_script(_token(vpn_type))
    assert script.index(":foreach iface in={") < script.index("STEP 2: LAN SETUP")
    assert script.index("STEP 2: LAN SETUP") < script.index(
        "/ip dhcp-server add name=dhcp1 interface=bridge"
    )
