"""Hotspot LAN ports, WiFi access point and inline CA in the .rsc script.

Field findings 2026-09-27 on two brand-new routers (539 RB951 ROS 7.21.3,
541 hAP lite ROS 6.48.7), both fixed by hand:

1. wlan1 stayed disabled, mode=station, ssid "MikroTik": the script had no
   wireless step at all since 2026-03 (commit 51bbc79 dropped it).
2. ether2..N stayed in the factory `bridgeLocal` while the hotspot runs on
   `bridge`: the old step only added ports that were in no bridge at all.
3. (flag-on SSTP path) the CA download from the plain-HTTP legacy base
   (:8081) was blocked by the ISP; the CA is now embedded in the script.
"""

import re

import pytest

from app.db.models import ProvisioningToken
from app.services import provisioning

CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIUTESTTESTTESTTESTTESTTESTTESTwCgYIKoZIzj0EAwIw\n"
    "EjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjA5MjcwMDAwMDBaFw0zNjA5MjQwMDAw\n"
    "-----END CERTIFICATE-----\n"
)


def routeros_unescape(value: str) -> str:
    """What RouterOS reads from the inside of a "..." string literal."""
    simple = {"\\": "\\", '"': '"', "$": "$", "?": "?", "n": "\n", "r": "\r", "t": "\t", "_": " "}
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch != "\\":
            assert ch not in '"$', f"unescaped {ch!r} at {i}: RouterOS would end/expand the string"
            out.append(ch)
            i += 1
            continue
        nxt = value[i + 1]
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
        else:
            out.append(chr(int(value[i + 1:i + 3], 16)))
            i += 3
    return "".join(out)


def _quoted_after(line: str, marker: str) -> str:
    """The raw (still escaped) content of the "..." string following marker."""
    m = re.search(re.escape(marker) + r'"((?:[^"\\]|\\.)*)"', line)
    assert m, (marker, line)
    return m.group(1)


def _settings(monkeypatch, *, ca: str = CA_PEM):
    s = provisioning.settings
    monkeypatch.setattr(s, "SERVER_PUBLIC_IP", "203.0.113.10")
    monkeypatch.setattr(s, "PROVISION_BASE_URL", "https://isp.example.net")
    monkeypatch.setattr(s, "PROVISION_LEGACY_BASE_URL", "http://91.98.238.12:8081")
    monkeypatch.setattr(s, "L2TP_IPSEC_PSK", "primary-psk")
    monkeypatch.setattr(s, "INSURANCE_SERVER_PUBLIC_IP", "91.98.238.12")
    monkeypatch.setattr(s, "INSURANCE_SERVER_WG_PUBLIC_KEY", "insurance-server-public")
    monkeypatch.setattr(s, "INSURANCE_SERVER_VPN_IP", "10.251.0.1")
    monkeypatch.setattr(s, "INSURANCE_WG_PORT", 51823)
    monkeypatch.setattr(s, "INSURANCE_ROUTER_INTERFACE", "wg-hz")
    monkeypatch.setattr(s, "INSURANCE_WG_SUBNET", "10.251.0.0/16")
    monkeypatch.setattr(s, "INSURANCE_L2TP_INTERFACE", "l2tp-aws2")
    monkeypatch.setattr(s, "INSURANCE_L2TP_IPSEC_PSK", "insurance-psk")
    monkeypatch.setattr(s, "SSTP_SERVER", "91.98.238.12:4443")
    monkeypatch.setattr(s, "SSTP_SERVER_VPN_IP", "10.251.0.1")
    monkeypatch.setattr(s, "SSTP_SUBNET", "10.251.0.0/16")
    monkeypatch.setattr(s, "ROUTER_MGMT_CA_PEM", ca)


def _token(kind: str, ssid=None) -> ProvisioningToken:
    common = dict(
        token="abc123",
        router_name="Test Router",
        identity="Router-0001",
        router_admin_password="ApiPassword123",
        payment_methods=["mpesa", "voucher"],
        ssid=ssid,
    )
    if kind == "wireguard":
        return ProvisioningToken(
            vpn_type="wireguard", wireguard_ip="10.0.0.42", server_public_ip="203.0.113.10",
            wg_private_key="cGNvL2+ZmFrZS1wcml2YXRlLWtleS0xMjM0NTY3ODk=",
            wg_public_key="router-public", server_wg_pubkey="aws-server-public", **common,
        )
    if kind == "l2tp":
        return ProvisioningToken(
            vpn_type="l2tp", wireguard_ip="10.0.100.77", server_public_ip="203.0.113.10",
            l2tp_username="l2tp-Router-0001", l2tp_password="L2tpPassword123", **common,
        )
    if kind == "hetzner_wg":
        return ProvisioningToken(
            vpn_type="wireguard", wireguard_ip="10.0.0.42", server_public_ip="91.98.238.12",
            wg_private_key="cm91dGVyLXByaXZhdGUta2V5LWZvci10ZXN0cy0xMjM=",
            wg_public_key="router-public", server_wg_pubkey="insurance-server-public",
            management_tunnel="wireguard", **common,
        )
    assert kind == "sstp"
    return ProvisioningToken(
        vpn_type="l2tp", wireguard_ip="10.0.100.77", server_public_ip="91.98.238.12",
        sstp_username="sstp-Router-0001", sstp_password="SstpPassword1234567890ab",
        management_tunnel="sstp", **common,
    )


ALL_KINDS = ["wireguard", "l2tp", "hetzner_wg", "sstp"]


def _commands(script: str) -> list:
    return [l for l in script.splitlines() if l.strip() and not l.strip().startswith("#")]


def _parse_block_code(script: str, var: str) -> str:
    line = next(l for l in script.splitlines() if f":local {var} [:parse " in l)
    return routeros_unescape(_quoted_after(line, "[:parse "))


# ---------------------------------------------------------------------------
# LAN ports -> hotspot bridge (flag on AND off)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_lan_ports_are_moved_into_the_hotspot_bridge(monkeypatch, kind):
    _settings(monkeypatch)
    script = provisioning.generate_rsc_script(_token(kind))

    # Every ethernet/WiFi interface except ether1 -- no hard-coded ether2..5.
    assert ":foreach iface in={ether2;ether3;ether4;ether5}" not in script
    assert ':foreach bwIfId in=[/interface find] do={' in script
    assert '($bwName != "ether1")' in script
    assert '($bwType = "ether")' in script and '($bwType = "wlan")' in script
    # Already a port of ANOTHER bridge (factory bridgeLocal) -> moved, not skipped.
    assert "/interface bridge port set [:pick $bwPorts 0] bridge=bridge" in script
    assert "/interface bridge port add interface=$bwName bridge=bridge" in script
    # ether1 never enters a bridge.
    assert ":do { /interface bridge port remove [find where interface=ether1] } on-error={}" in script
    for line in _commands(script):
        assert not re.search(r"bridge port (add|set) .*ether1", line), line

    # Ordering: ports move in step 1, before the WAN DHCP client and the hotspot.
    move = script.index("/interface bridge port set [:pick $bwPorts 0] bridge=bridge")
    assert script.index("STEP 1: WAN") < move < script.index("/ip dhcp-client add interface=ether1")
    assert move < script.index("STEP 4: HOTSPOT")


def test_port_move_guards_uplinks_and_pppoe(monkeypatch):
    # A re-run on a router in the field must not pull an uplink (second WAN,
    # PPPoE client) or a PPPoE-server bridge into the hotspot.
    _settings(monkeypatch)
    script = provisioning.generate_rsc_script(_token("l2tp"))
    assert "[/ip dhcp-client find where interface=$bwName]" in script
    assert "[/interface pppoe-client find where interface=$bwName]" in script
    assert '[:pick [/ip address get $bwAddr address] 0 11] != "192.168.88."' in script
    assert "[/interface pppoe-server server find where interface=$bwOld]" in script
    assert "left out of the hotspot bridge" in script


def test_emptied_bridges_are_neutralised_not_deleted(monkeypatch):
    _settings(monkeypatch)
    script = provisioning.generate_rsc_script(_token("wireguard"))
    assert ':foreach bwBrId in=[/interface bridge find where name!="bridge"] do={' in script
    assert ":do { /ip dhcp-client set [find where interface=$bwBr] disabled=yes } on-error={}" in script
    assert ":do { /ip dhcp-server set [find where interface=$bwBr] disabled=yes } on-error={}" in script
    assert ":do { /ip dhcp-client set [find where interface=bridge] disabled=yes } on-error={}" in script
    commands = "\n".join(_commands(script))
    assert "/interface bridge remove" not in commands
    assert "/ip dhcp-server remove" not in commands


# ---------------------------------------------------------------------------
# WiFi access point (flag on AND off)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_wireless_menu_only_referenced_inside_parse(monkeypatch, kind):
    # /interface wireless does not exist on hEX/RB4011/RB5009 or wifi-package
    # v7 boards; a direct reference would be a parse error aborting the import.
    _settings(monkeypatch)
    script = provisioning.generate_rsc_script(_token(kind))
    for line in _commands(script):
        if "/interface wireless" in line:
            assert '[:parse "' in line, line
    assert script.count("{") == script.count("}")
    assert not any(line.rstrip().endswith("\\") for line in script.splitlines())


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_wlan1_becomes_an_open_ap_with_the_token_ssid(monkeypatch, kind):
    _settings(monkeypatch)
    script = provisioning.generate_rsc_script(_token(kind, ssid="Mama Mboga WiFi"))
    code = _parse_block_code(script, "bwWifiAp")

    assert code.startswith(":if ([:len [/interface wireless find where name=wlan1]] = 0) do={")
    assert (
        '/interface wireless set wlan1 mode=ap-bridge ssid="Mama Mboga WiFi" '
        "security-profile=bw-open disabled=no"
    ) in code
    assert "/interface wireless security-profiles add name=bw-open mode=none" in code
    assert "/interface wireless set wlan1 band=2ghz-b/g/n" in code
    assert "/interface wireless set wlan1 frequency=auto" in code
    assert "/interface wireless set wlan1 wps-mode=disabled" in code
    # Only a non-AP or factory-SSID wlan1 is (re)configured on a re-run.
    assert '($bwMode != "ap-bridge") || $bwFactory' in code
    assert '($bwSsid = "MikroTik")' in code and '[:pick $bwSsid 0 9] = "MikroTik-"' in code
    assert code.count("{") == code.count("}")

    # After the LAN step, before the tunnel/hotspot.
    ap = script.index("STEP 2b: WIFI ACCESS POINT")
    assert script.index("STEP 2: LAN") < ap < script.index("STEP 3")


@pytest.mark.parametrize("stored", [None, "", "N/A", "  n/a "])
def test_placeholder_ssid_falls_back_to_default(monkeypatch, stored):
    _settings(monkeypatch)
    token = _token("l2tp", ssid=stored)
    assert provisioning.hotspot_wifi_ssid(token) == "Bitwave WiFi"
    code = _parse_block_code(provisioning.generate_rsc_script(token), "bwWifiAp")
    assert 'ssid="Bitwave WiFi"' in code


def test_hostile_ssid_cannot_break_the_script(monkeypatch):
    _settings(monkeypatch)
    token = _token("wireguard", ssid='Evil"] ; /system reset-configuration ; :put $x? {}\\' + "A" * 40)
    ssid = provisioning.hotspot_wifi_ssid(token)
    assert len(ssid) <= 32
    assert not set(ssid) & set('"\\$?;{}[]')
    script = provisioning.generate_rsc_script(token)
    code = _parse_block_code(script, "bwWifiAp")
    assert f'ssid="{ssid}"' in code
    assert "reset-configuration" not in "\n".join(_commands(script)).replace(ssid, "")


# ---------------------------------------------------------------------------
# RouterOS string escaping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        CA_PEM,
        'a "quoted" $var and a question? back\\slash',
        "tabs\tcr\r\nnul\x00bell\x07del\x7f",
        "",
    ],
)
def test_routeros_escape_round_trips_on_one_line(value):
    escaped = provisioning.routeros_escape(value)
    assert "\n" not in escaped and "\r" not in escaped
    assert routeros_unescape(escaped) == value


# ---------------------------------------------------------------------------
# Inline CA on the SSTP path (flag on only)
# ---------------------------------------------------------------------------


def test_sstp_ca_is_embedded_and_round_trips(monkeypatch):
    # .env stores the PEM on one line with literal "\n" sequences.
    _settings(monkeypatch, ca=CA_PEM.replace("\n", "\\n"))
    script = provisioning.generate_rsc_script(_token("sstp"))

    line = next(l for l in script.splitlines() if "/file set" in l and "contents=" in l)
    assert '/file set [find where name="bwca.txt"] contents="' in line
    assert routeros_unescape(_quoted_after(line, "contents=")) == provisioning.router_mgmt_ca_pem() == CA_PEM
    assert "-----BEGIN CERTIFICATE-----\\n" in line

    create = script.index("/file print file=bwca")
    assert create < script.index("/file set [find where name=\"bwca.txt\"]")
    assert script.index("/file set [find where name=\"bwca.txt\"]") < script.index(
        '/certificate import file-name=bwca.txt passphrase=""'
    )
    # The temporary file is removed afterwards; the CA is trusted.
    assert ':do { /file remove [find where name="bwca.txt"] } on-error={}' in script
    assert '/certificate set [find where common-name="Bitwave Router Management CA"] trusted=yes' in script
    assert script.count("{") == script.count("}")


def test_sstp_script_never_fetches_the_ca_over_the_legacy_port(monkeypatch):
    _settings(monkeypatch)
    script = provisioning.generate_rsc_script(_token("sstp"))
    ca_section = script[script.index("STEP 3: SSTP"):script.index("SSTP certificate checks")]
    assert "8081" not in ca_section
    assert "http://" not in ca_section
    # Fallback only when the embedded import did not produce the CA.
    fallback = ca_section.index('/tool fetch url="https://isp.example.net/api/provision/router-mgmt-ca.crt"')
    assert ca_section.index("/file print file=bwca") < fallback
    guard = ':if ([:len [/certificate find where common-name="Bitwave Router Management CA"]] = 0) do={'
    assert ca_section.count(guard) == 2


def test_oversized_ca_falls_back_to_https_download_only(monkeypatch):
    body = "\n".join(["A" * 64] * 70)
    _settings(monkeypatch, ca=f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    script = provisioning.generate_rsc_script(_token("sstp"))
    assert "/file print file=bwca" not in script
    assert '/tool fetch url="https://isp.example.net/api/provision/router-mgmt-ca.crt"' in script


def test_legacy_tokens_have_no_ca_section(monkeypatch):
    _settings(monkeypatch)
    for kind in ("wireguard", "l2tp", "hetzner_wg"):
        script = provisioning.generate_rsc_script(_token(kind))
        assert "bwca" not in script, kind
        assert "router-mgmt-ca.crt" not in script, kind
