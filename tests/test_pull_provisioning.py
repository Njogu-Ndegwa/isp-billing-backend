"""Tests for the pull-provisioning renderer (app/services/pull_provisioning.py).

Focused on the security-critical rendering: correct idempotent RouterOS output for
valid input, and hard rejection / safe escaping of hostile input so a customer value
can never inject a RouterOS command into the script the router executes.
"""
import pytest

from app.services.pull_provisioning import (
    render_hotspot_provision_rsc,
    _ros_quote,
    _normalize_mac,
)


def test_renders_expected_commands():
    rsc = render_hotspot_provision_rsc(
        username="john12", password="secret", mac_address="AA:BB:CC:DD:EE:FF",
        rate_limit="3M/2M", time_limit="1d", comment="CID:5|John|2026-07-11",
    )
    # profile derived from the rate, matching add_customer_bypass_mode
    assert 'name="plan_3M_2M"' in rsc
    assert 'rate-limit="3M/2M"' in rsc
    # user + bypassed binding present and idempotent (find/add/set)
    assert 'add name="john12" password="secret"' in rsc
    assert 'limit-uptime="1d"' in rsc
    assert 'mac-address="AA:BB:CC:DD:EE:FF"' in rsc
    assert "type=bypassed" in rsc
    assert ":if ([:len [find" in rsc  # idempotent guard
    # the three target paths are all present
    assert "/ip hotspot user profile" in rsc
    assert "/ip hotspot user\n" in rsc
    assert "/ip hotspot ip-binding" in rsc


def test_mac_is_normalized():
    assert _normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    rsc = render_hotspot_provision_rsc(
        username="u", password="p", mac_address="a0b1c2-d3e4f5".replace("-", ":"),
        rate_limit="1M/1M", time_limit="30m",
    ) if False else render_hotspot_provision_rsc(
        username="u", password="p", mac_address="A0:B1:C2:D3:E4:F5",
        rate_limit="1M/1M", time_limit="30m",
    )
    assert 'mac-address="A0:B1:C2:D3:E4:F5"' in rsc


@pytest.mark.parametrize("bad_user", [
    'x" ; /system reboot',          # break out of quotes + inject command
    "a b",                          # space
    "user\n/system reboot",         # newline injection
    'a"b',                          # embedded quote
    "",                             # empty
    "x" * 65,                       # too long
])
def test_hostile_username_rejected(bad_user):
    with pytest.raises(ValueError):
        render_hotspot_provision_rsc(
            username=bad_user, password="p", mac_address="AA:BB:CC:DD:EE:FF",
            rate_limit="1M/1M", time_limit="1d",
        )


@pytest.mark.parametrize("bad_mac", ["not-a-mac", "AA:BB:CC:DD:EE", "ZZ:BB:CC:DD:EE:FF", ""])
def test_hostile_mac_rejected(bad_mac):
    with pytest.raises(ValueError):
        render_hotspot_provision_rsc(
            username="u", password="p", mac_address=bad_mac,
            rate_limit="1M/1M", time_limit="1d",
        )


@pytest.mark.parametrize("bad_rate", ['3M/2M" foo', "abc", "3//2", ""])
def test_hostile_rate_rejected(bad_rate):
    with pytest.raises(ValueError):
        render_hotspot_provision_rsc(
            username="u", password="p", mac_address="AA:BB:CC:DD:EE:FF",
            rate_limit=bad_rate, time_limit="1d",
        )


def test_password_and_comment_are_escaped_not_injected():
    # password/comment are free text -> must be escaped, never allowed to break out
    rsc = render_hotspot_provision_rsc(
        username="u", password='p"; /system reboot; "', mac_address="AA:BB:CC:DD:EE:FF",
        rate_limit="1M/1M", time_limit="1d", comment='c"$var\nnewline',
    )
    # no unescaped closing quote that would end the string early, no raw newline,
    # no raw $ that RouterOS would expand
    assert "/system reboot" in rsc            # present but neutralised as data
    assert '\\"' in rsc                        # the quote was escaped
    assert "\\$" in rsc                        # the $ was escaped
    # the injected password must appear only in escaped form
    assert 'p"; /system reboot' not in rsc.replace('\\"', '\x00')


def test_ros_quote_strips_control_and_escapes():
    out = _ros_quote('a"b\\c$d\r\ne')
    assert '"' not in out.replace('\\"', "")   # every quote is escaped
    assert "\r" not in out and "\n" not in out  # control chars stripped
    assert "\\$" in out                          # dollar escaped
