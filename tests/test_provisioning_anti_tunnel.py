"""Hotspot anti-tunnel (HTTP Injector) rules in the provisioning .rsc.

Unauthenticated hotspot clients get TCP 80/3128/8080 handed to the router's
transparent proxy, which relays to any host -- HTTP Injector tunnels out that
way without paying. Routers installed before this change (670, 672, ...)
shipped without the fix: _rsc_anti_tunnel() was written on 2026-09-02
(a6c8c1d) but never reached main. These tests pin it for every token variant.
The rule text and comments must match the hotspot-bypass-fix skill
(apply_fix.py / verify_fix.py look for the exact comments).
"""

import importlib.util
import re
from pathlib import Path

import pytest

from app.db.models import ProvisioningToken
from app.services import provisioning

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "provisioning_golden"
CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIUTESTTESTTESTTESTTESTTESTTESTwCgYIKoZIzj0EAwIw\n"
    "-----END CERTIFICATE-----\n"
)
RELAY_BLOCK = (
    "/ip firewall filter add chain=output protocol=tcp dst-port=80,3128,8080 "
    "dst-address-list=!isp_portal_allow dst-address=!192.168.88.0/24 "
    'action=reject reject-with=tcp-reset comment="ISP_BILLING_PROXY_RELAY_BLOCK"'
)
HS_UNAUTH_RULES = (
    "/ip firewall filter add chain=hs-unauth protocol=tcp dst-port=80,443 dst-address=!192.168.88.1 "
    "dst-address-list=!isp_portal_allow connection-state=new action=reject reject-with=tcp-reset "
    'comment="ISP_BILLING_ANTI_TUNNEL"',
    "/ip firewall filter add chain=hs-unauth protocol=tcp dst-port=!53,80,443 dst-address=!192.168.88.1 "
    'action=reject reject-with=tcp-reset comment="ISP_BILLING_ANTI_TUNNEL_OTHER"',
    "/ip firewall filter add chain=hs-unauth protocol=udp dst-port=53 dst-address=!192.168.88.1 "
    'action=reject reject-with=icmp-net-prohibited comment="ISP_BILLING_ANTI_TUNNEL_DNS"',
)
VERCEL = ("216.198.79.0/24", "64.29.17.0/24", "76.76.21.0/24")


def _golden():
    spec = importlib.util.spec_from_file_location("provisioning_golden_generate", GOLDEN_DIR / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _settings(monkeypatch, *, hetzner: bool):
    _golden().apply(monkeypatch.setattr)
    s = provisioning.settings
    monkeypatch.setattr(s, "PROVISION_MGMT_TO_HETZNER", hetzner)
    monkeypatch.setattr(s, "SSTP_SERVER", "91.98.238.12:4443")
    monkeypatch.setattr(s, "SSTP_SERVER_VPN_IP", "10.251.0.1")
    monkeypatch.setattr(s, "SSTP_SUBNET", "10.251.0.0/16")
    monkeypatch.setattr(s, "ROUTER_MGMT_CA_PEM", CA_PEM)
    monkeypatch.setattr(s, "HOTSPOT_PORTAL_ALLOW_CIDRS", ",".join(VERCEL))


def _hetzner_tokens():
    common = dict(
        token="abc123",
        router_name="Test Router",
        identity="Router-0001",
        router_admin_password="ApiPassword123",
        server_public_ip="91.98.238.12",
        payment_methods=["mpesa", "voucher"],
    )
    return {
        "hetzner_wireguard": ProvisioningToken(
            vpn_type="wireguard",
            wireguard_ip="10.0.0.42",
            wg_private_key="cm91dGVyLXByaXZhdGUta2V5LWZvci10ZXN0cy0xMjM=",
            wg_public_key="router-public",
            server_wg_pubkey="insurance-server-public",
            management_tunnel="wireguard",
            **common,
        ),
        "hetzner_sstp": ProvisioningToken(
            vpn_type="l2tp",
            wireguard_ip="10.0.100.77",
            sstp_username="sstp-Router-0001",
            sstp_password="SstpPassword1234567890ab",
            management_tunnel="sstp",
            **common,
        ),
    }


VARIANTS = ["wireguard", "l2tp", "l2tp_routerboard", "hetzner_wireguard", "hetzner_sstp"]


def _script(monkeypatch, variant: str) -> str:
    hetzner = variant.startswith("hetzner_")
    _settings(monkeypatch, hetzner=hetzner)
    token = (_hetzner_tokens() if hetzner else _golden().tokens())[variant]
    return provisioning.generate_rsc_script(token)


def _step(script: str, title: str) -> str:
    start = script.index(f"# ---- {title}")
    nxt = script.find("# ---- STEP", start + 1)
    return script[start: nxt if nxt != -1 else len(script)]


# ---------------------------------------------------------------------------
# The rules are in every generated script, with the exact skill text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("variant", VARIANTS)
def test_every_variant_ships_the_full_rule_set(monkeypatch, variant):
    script = _script(monkeypatch, variant)
    block = _step(script, "STEP 9b: ANTI-TUNNEL")
    assert RELAY_BLOCK in block, variant
    for rule in HS_UNAUTH_RULES:
        assert rule in block, (variant, rule)
    for cidr in VERCEL:
        assert f"address-list add list=isp_portal_allow address={cidr} " in block
    # Each rule appears exactly once in the whole script.
    assert script.count('comment="ISP_BILLING_PROXY_RELAY_BLOCK" }') == 1


@pytest.mark.parametrize("variant", VARIANTS)
def test_allow_list_backend_ips_come_from_the_token_and_insurance_settings(monkeypatch, variant):
    script = _script(monkeypatch, variant)
    block = _step(script, "STEP 9b: ANTI-TUNNEL")
    allowed = re.findall(r"address-list add list=isp_portal_allow address=(\S+) ", block)
    if variant.startswith("hetzner_"):
        # token server and insurance server are the same Hetzner box: listed once
        assert allowed == ["91.98.238.12", *VERCEL]
    else:
        assert allowed == ["203.0.113.10", "91.98.238.12", *VERCEL]


def test_portal_cidrs_are_read_from_settings(monkeypatch):
    _settings(monkeypatch, hetzner=False)
    monkeypatch.setattr(provisioning.settings, "HOTSPOT_PORTAL_ALLOW_CIDRS", " 198.51.100.0/24 , ,203.0.113.10/32")
    token = _golden().tokens()["wireguard"]
    # 203.0.113.10/32 normalises to a different string than the bare backend IP,
    # so both stay; blanks are skipped.
    assert provisioning.portal_allow_entries(token) == [
        "203.0.113.10", "91.98.238.12", "198.51.100.0/24", "203.0.113.10/32",
    ]
    monkeypatch.setattr(provisioning.settings, "HOTSPOT_PORTAL_ALLOW_CIDRS", "216.198.79.0/33")
    with pytest.raises(ValueError):
        provisioning.portal_allow_entries(token)


@pytest.mark.parametrize("variant", VARIANTS)
def test_exemption_is_the_lan_the_script_configures(monkeypatch, variant):
    script = _script(monkeypatch, variant)
    lan = re.search(r"/ip address add address=(\S+) interface=bridge", script).group(1)
    gateway, prefix = lan.split("/")
    hs_addr = re.search(r"hotspot profile add name=hsprof1 hotspot-address=(\S+) ", script).group(1)
    net = re.search(r"dhcp-server network add address=(\S+) gateway=(\S+) ", script)
    block = _step(script, "STEP 9b: ANTI-TUNNEL")

    assert hs_addr == gateway == net.group(2)
    assert f"dst-address=!{net.group(1)} " in block  # output relay block exempts the hotspot LAN
    assert net.group(1).endswith("/" + prefix)
    assert block.count(f"dst-address=!{gateway} ") == 3  # the three hs-unauth rules


# ---------------------------------------------------------------------------
# Ordering: after /complete, before reboot; lift before the login-page fetch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("variant", VARIANTS)
def test_block_is_applied_after_complete_and_before_reboot(monkeypatch, variant):
    # RouterOS 6 calls /complete over plain HTTP to the Cloudflare-fronted
    # backend (PROVISION_LEGACY_BASE_URL); the relay block would reject it.
    script = _script(monkeypatch, variant)
    complete = script.index("/api/provision/abc123/complete")
    block = script.index("STEP 9b: ANTI-TUNNEL")
    reboot = script.index("/system reboot")
    assert complete < block < reboot


@pytest.mark.parametrize("variant", VARIANTS)
def test_existing_block_is_lifted_before_the_plain_http_fetches(monkeypatch, variant):
    # Re-provisioning a protected router: its own http:// login-page fetch
    # must not be rejected by the rule a previous run left behind.
    script = _script(monkeypatch, variant)
    lift = script.index("STEP 4b: LIFT ANY EXISTING PROXY-RELAY BLOCK")
    assert script.index("STEP 4: HOTSPOT SETUP") < lift < script.index("/login-page")
    lift_block = _step(script, "STEP 4b")
    assert '/ip firewall filter find comment="ISP_BILLING_PROXY_RELAY_BLOCK"' in lift_block
    assert "add " not in lift_block


@pytest.mark.parametrize("variant", VARIANTS)
def test_rules_are_appended_never_placed_ahead_of_the_hotspot(monkeypatch, variant):
    # Reseller walled-garden IP accepts (radios -> UISP on router 670) are
    # dynamic hotspot rules; ours must sit after them, so no place-before.
    # The relay block is chain=output, which walled-garden-IP traffic
    # (forwarded, never proxied) does not traverse.
    block = _step(_script(monkeypatch, variant), "STEP 9b: ANTI-TUNNEL")
    assert "place-before" not in block
    chains = re.findall(r"/ip firewall filter add chain=(\S+) ", block)
    assert chains == ["output", "hs-unauth", "hs-unauth", "hs-unauth"]


# ---------------------------------------------------------------------------
# Idempotency: re-running the block converges to the same state
# ---------------------------------------------------------------------------

_FILTER_REMOVE = re.compile(r'^:foreach i in=\[/ip firewall filter find comment="([^"]+)"\]')
_LIST_REMOVE = re.compile(
    r'^:foreach i in=\[/ip firewall address-list find where list=(\S+) and comment="([^"]+)"\]'
)
_FILTER_ADD = re.compile(r'^:do \{ /ip firewall filter add (.*) comment="([^"]+)" \}')
_LIST_ADD = re.compile(r'^:do \{ /ip firewall address-list add list=(\S+) address=(\S+) comment="([^"]+)" \}')


def _run(block: str, state: dict) -> dict:
    """Apply the block's remove/add lines to a model of the router."""
    filters, lists = list(state["filter"]), list(state["list"])
    for line in block.splitlines():
        line = line.strip()
        if m := _FILTER_REMOVE.match(line):
            filters = [f for f in filters if f[1] != m.group(1)]
        elif m := _LIST_REMOVE.match(line):
            lists = [e for e in lists if not (e[0] == m.group(1) and e[2] == m.group(2))]
        elif m := _FILTER_ADD.match(line):
            filters.append((m.group(1), m.group(2)))
        elif m := _LIST_ADD.match(line):
            entry = (m.group(1), m.group(2), m.group(3))
            # RouterOS refuses a duplicate list+address; the :do on-error eats it.
            if not any(e[:2] == entry[:2] for e in lists):
                lists.append(entry)
        elif "/ip firewall" in line and not line.startswith("#"):
            raise AssertionError(f"unmodelled firewall line: {line}")
    return {"filter": filters, "list": lists}


@pytest.mark.parametrize("variant", VARIANTS)
def test_block_is_idempotent_and_replaces_a_hand_applied_half_fix(monkeypatch, variant):
    block = _step(_script(monkeypatch, variant), "STEP 9b: ANTI-TUNNEL")
    router = {
        "filter": [
            # the old port-80-only half fix, as some routers still carry it
            ("chain=output protocol=tcp dst-port=80 connection-state=new", "ISP_BILLING_PROXY_RELAY_BLOCK"),
            ("chain=forward action=accept", "reseller rule"),
        ],
        "list": [
            ("isp_portal_allow", "54.91.202.229", "portal/api/backend allow (anti-tunnel)"),
            ("isp_portal_allow", "163.245.218.46", "UISP (reseller)"),
        ],
    }
    once = _run(block, router)
    twice = _run(block, once)
    assert once == twice

    ours = [f for f in once["filter"] if f[1].startswith("ISP_BILLING_")]
    assert len(ours) == 4
    assert [f for f in once["filter"] if f[1] == "ISP_BILLING_PROXY_RELAY_BLOCK"][0][0].startswith(
        "chain=output protocol=tcp dst-port=80,3128,8080 "
    )
    assert ("chain=forward action=accept", "reseller rule") in once["filter"]
    # Entries we did not add survive; our stale ones are replaced from config.
    assert ("isp_portal_allow", "163.245.218.46", "UISP (reseller)") in once["list"]
    assert all(e[1] != "54.91.202.229" for e in once["list"])


@pytest.mark.parametrize("variant", VARIANTS)
def test_block_braces_balance(monkeypatch, variant):
    for title in ("STEP 4b", "STEP 9b: ANTI-TUNNEL"):
        block = _step(_script(monkeypatch, variant), title)
        assert block.count("{") == block.count("}"), (variant, title)
        assert block.count("[") == block.count("]"), (variant, title)
