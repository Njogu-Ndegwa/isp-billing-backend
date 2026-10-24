"""Guards for .rsc script generation around the hotspot-availability abort.

Background (incident 2026-06-10): on routers where the hotspot feature is
unavailable (device-mode on v7.13+ RouterBOARDs, disabled package on v6) the
/ip hotspot menus do not exist, and a direct `[find where ...]` under them is
a RouterOS PARSE error that aborts the import mid-way -- `:do on-error`
cannot catch it. The script must probe hotspot availability via [:parse]
BEFORE applying any configuration.
"""

from app.db.models import ProvisioningToken
from app.services.provisioning import generate_rsc_script


def _token(vpn_type: str) -> ProvisioningToken:
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


PROBE = ':local bwHsProbe [:parse "/ip hotspot profile find"]'


def test_hotspot_probe_runs_before_any_config_for_both_vpn_types():
    for vpn_type in ("wireguard", "l2tp"):
        script = generate_rsc_script(_token(vpn_type))
        assert PROBE in script, vpn_type
        # The probe must come before WAN setup (the first config-applying
        # step) so an abort leaves the router untouched.
        assert script.index(PROBE) < script.index("STEP 1: WAN"), vpn_type


def test_no_direct_hotspot_menu_reference_before_the_probe():
    # Any /ip hotspot reference outside a [:parse "..."] string that appears
    # before the probe would parse-crash the import on routers without the
    # hotspot feature, defeating the up-front abort.
    for vpn_type in ("wireguard", "l2tp"):
        script = generate_rsc_script(_token(vpn_type))
        before_probe = script[: script.index(PROBE)]
        for line in before_probe.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            assert "/ip hotspot" not in line, (vpn_type, line)


def test_no_direct_device_mode_reference():
    # /system/device-mode does not exist on v7 builds older than 7.13, so a
    # direct reference is itself a parse error. The hotspot probe replaced it.
    for vpn_type in ("wireguard", "l2tp"):
        script = generate_rsc_script(_token(vpn_type))
        assert "/system/device-mode" not in script.replace(
            "/system/device-mode/update hotspot=yes", ""
        ), vpn_type  # the remedy text in log messages is allowed


def test_remedy_message_matches_platform():
    wg_script = generate_rsc_script(_token("wireguard"))
    assert "/system/device-mode/update hotspot=yes" in wg_script
    l2tp_script = generate_rsc_script(_token("l2tp"))
    assert "hotspot package" in l2tp_script


def test_wireguard_step_is_rerun_safe():
    # Remediation is "fix device-mode, re-run the same command" on a router
    # that already applied steps 1-3, so the wireguard add must fall back to
    # set instead of aborting the import with "already have such name".
    script = generate_rsc_script(_token("wireguard"))
    assert "/interface wireguard set [find where name=wg-aws]" in script
    assert "/interface wireguard peers set [find where interface=wg-aws]" in script
    for line in script.splitlines():
        if "/interface wireguard add" in line or "/interface wireguard peers add" in line:
            assert line.startswith("    "), f"unwrapped: {line}"


def test_hotspot_profile_fallback_avoids_parse_fragile_find_where():
    script = generate_rsc_script(_token("wireguard"))
    assert "/ip hotspot profile set [find where name=hsprof1]" not in script
    assert "/ip hotspot profile get [find where name=hsprof1]" not in script
    assert "/ip hotspot profile set hsprof1 html-directory=$bwHtmlDir" in script
    assert "/ip hotspot profile get hsprof1 html-directory" in script


def test_no_line_continuation_backslashes():
    for vpn_type in ("wireguard", "l2tp"):
        script = generate_rsc_script(_token(vpn_type))
        assert not any(
            line.rstrip().endswith("\\") for line in script.splitlines()
        ), vpn_type


# ---- smips on RouterOS 7.20+ (hAP lite / hAP mini / cAP lite) ----
# Since 7.20 smips builds ship hotspot as a separate extra package, so the
# device-mode remedy is wrong there (reseller 449, 2026-10-24). The script
# reads architecture + version at runtime and swaps in the right message.

SMIPS_TEXT = "since RouterOS 7.20 smips builds do not include hotspot"


def _preflight_abort_block(script: str) -> str:
    start = script.index(PROBE)
    end = script.index(":error \"hotspot feature unavailable", start)
    return script[start:end]


def test_smips_720_message_in_preflight_for_both_vpn_types():
    # The router may run a different RouterOS than the reseller picked, so the
    # runtime check is in both the v6 and v7 scripts.
    for vpn_type in ("wireguard", "l2tp"):
        script = generate_rsc_script(_token(vpn_type))
        block = _preflight_abort_block(script)
        assert SMIPS_TEXT in block, vpn_type
        assert "RouterOS 6.49.x" in block, vpn_type
        assert 'hotspot-" . $bwVer . "-smips.npk from the extra-packages zip' in block, vpn_type
        assert "[/system resource get architecture-name]" in block, vpn_type
        assert "[/system resource get version]" in block, vpn_type
        assert '($bwArch = "smips")' in block, vpn_type
        assert "[:tonum $bwMinor] >= 20" in block, vpn_type
        # Still aborts before any config is applied.
        assert script.index(SMIPS_TEXT) < script.index("STEP 1: WAN"), vpn_type


def test_default_remedy_kept_for_other_architectures():
    # The platform remedy is the default; the smips text only replaces it at
    # runtime when the router reports smips >= 7.20.
    wg_block = _preflight_abort_block(generate_rsc_script(_token("wireguard")))
    assert ':local bwRemedy "this is usually device-mode blocking hotspot' in wg_block
    l2tp_block = _preflight_abort_block(generate_rsc_script(_token("l2tp")))
    assert ':local bwRemedy "on RouterOS v6 this usually means the hotspot package' in l2tp_block
    for block in (wg_block, l2tp_block):
        assert ":log error (\"PROVISION ABORTED: the hotspot feature is not available on this router -- \" . $bwRemedy . \".\")" in block
        # A failed /system resource read must not change the abort.
        assert "} on-error={}" in block


def test_preflight_block_is_balanced():
    # An unbalanced brace/bracket/quote here would be a parse error that
    # breaks the import on EVERY router, not just smips ones.
    for vpn_type in ("wireguard", "l2tp"):
        script = generate_rsc_script(_token(vpn_type))
        start = script.index("# ---- PRE-FLIGHT: HOTSPOT AVAILABILITY CHECK ----")
        end = script.index("STEP 1: WAN")
        code = "\n".join(
            line for line in script[start:end].splitlines()
            if not line.strip().startswith("#")
        )
        assert code.count("{") == code.count("}"), vpn_type
        assert code.count("[") == code.count("]"), vpn_type
        assert code.count("(") == code.count(")"), vpn_type
        assert code.count('"') % 2 == 0, vpn_type
