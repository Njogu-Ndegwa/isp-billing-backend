"""Anti-tethering is ON by default for new routers, and only hits hotspot traffic.

* The provisioning .rsc installs exactly the raw rules
  MikroTikAPI.enable_anti_tethering() pushes (same chain, matches, comment),
  so the dashboard toggle's disable/repair keep working on new routers.
* complete_provisioning records the router with hotspot_sharing_blocked=True;
  a router added by hand (no rules pushed) stays False; existing rows keep
  server_default false (no migration).
* Scoping: the TTL drops only match packets arriving on a hotspot server's
  interface and never a static-IP customer (address list bitwave-static).
  PPPoE (pppoe-in), management tunnels (wg/sstp/l2tp) and router-originated
  traffic never reach them.
"""

import importlib.util
import re
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.models import ProvisioningToken, ProvisioningTokenStatus, Router, User, UserRole
from app.services import provisioning
from app.services.mikrotik_api import MikroTikAPI
from app.services.static_ip import STATIC_ADDRESS_LIST
from tests.test_mikrotik_anti_tethering import FakeMikroTikAPI, _commands

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "provisioning_golden"
COMMENT = MikroTikAPI.ANTI_TETHER_COMMENT
CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIUTESTTESTTESTTESTTESTTESTTESTwCgYIKoZIzj0EAwIw\n"
    "-----END CERTIFICATE-----\n"
)


def _golden():
    spec = importlib.util.spec_from_file_location("provisioning_golden_generate", GOLDEN_DIR / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _all_scripts(monkeypatch):
    """Every token variant: legacy WG / L2TP / L2TP routerboard, Hetzner WG and SSTP."""
    golden = _golden()
    golden.apply(monkeypatch.setattr)
    s = provisioning.settings
    monkeypatch.setattr(s, "SSTP_SERVER", "91.98.238.12:4443")
    monkeypatch.setattr(s, "SSTP_SERVER_VPN_IP", "10.251.0.1")
    monkeypatch.setattr(s, "SSTP_SUBNET", "10.251.0.0/16")
    monkeypatch.setattr(s, "ROUTER_MGMT_CA_PEM", CA_PEM)
    scripts = {}
    monkeypatch.setattr(s, "PROVISION_MGMT_TO_HETZNER", False)
    for name, token in golden.tokens().items():
        scripts[name] = provisioning.generate_rsc_script(token)
    monkeypatch.setattr(s, "PROVISION_MGMT_TO_HETZNER", True)
    common = dict(
        token="abc123", router_name="Test Router", identity="Router-0001",
        router_admin_password="ApiPassword123", server_public_ip="91.98.238.12",
        payment_methods=["mpesa", "voucher"],
    )
    scripts["hetzner_wireguard"] = provisioning.generate_rsc_script(ProvisioningToken(
        vpn_type="wireguard", wireguard_ip="10.0.0.42",
        wg_private_key="cm91dGVyLXByaXZhdGUta2V5LWZvci10ZXN0cy0xMjM=",
        wg_public_key="router-public", server_wg_pubkey="insurance-server-public",
        management_tunnel="wireguard", **common,
    ))
    scripts["hetzner_sstp"] = provisioning.generate_rsc_script(ProvisioningToken(
        vpn_type="l2tp", wireguard_ip="10.0.100.77", sstp_username="sstp-Router-0001",
        sstp_password="SstpPassword1234567890ab", management_tunnel="sstp", **common,
    ))
    return scripts


def _rsc_raw_rules(script: str, iface: str = "bridge"):
    """The raw rules STEP 8b adds, as API-style dicts, for one hotspot iface."""
    step = script.split("# ---- STEP 8b: ANTI-TETHERING")[1].split("# ---- STEP 9")[0]
    ttls = re.search(r":foreach bwTtl in=\{([^}]*)\}", step).group(1)
    ttl_values = [t.strip('"') for t in ttls.split(";")]
    adds = re.findall(r"^\s*/ip firewall raw add (.+?)(?: place-before=\$bwAnchor)?$", step, re.M)
    assert len(set(adds)) == 1, adds  # placed and appended variants are the same rule
    rules = []
    for ttl in ttl_values:
        args = {}
        for key, value in re.findall(r'([\w-]+)=("[^"]*"|\S+)', adds[0]):
            args[key] = value.strip('"')
        args["in-interface"] = args["in-interface"].replace("$bwIf", iface)
        args["ttl"] = args["ttl"].replace("$bwTtl", ttl)
        rules.append(args)
    return rules


def _api_raw_rules():
    api = FakeMikroTikAPI(raw_rules=[{".id": "*r", "chain": "prerouting", "action": "accept"}])
    assert api.enable_anti_tethering()["success"] is True
    rules = _commands(api, "/ip/firewall/raw/add")
    for rule in rules:
        rule.pop("place-before")
    return rules


# ---------------------------------------------------------------------------
# Setup script
# ---------------------------------------------------------------------------


def test_every_setup_script_installs_the_same_rules_enable_anti_tethering_pushes(monkeypatch):
    expected = _api_raw_rules()
    for name, script in _all_scripts(monkeypatch).items():
        assert "# ---- STEP 8b: ANTI-TETHERING (on by default) ----" in script, name
        assert _rsc_raw_rules(script) == expected, name


def test_rules_are_added_before_the_server_is_told_the_router_is_ready(monkeypatch):
    for name, script in _all_scripts(monkeypatch).items():
        step = script.index("STEP 8b: ANTI-TETHERING")
        assert script.index("# ---- STEP 4: HOTSPOT") < step < script.index("/api/provision/abc123/complete"), name
        assert step < script.index("STEP 10: REBOOT"), name


def test_step_is_idempotent_and_installs_on_every_enabled_hotspot_server(monkeypatch):
    script = _all_scripts(monkeypatch)["wireguard"]
    step = script.split("# ---- STEP 8b: ANTI-TETHERING")[1].split("# ---- STEP 9")[0]
    for table in ("raw", "mangle", "filter"):  # strict-mode leftovers go too
        assert (
            f':foreach i in=[/ip firewall {table} find where comment="{COMMENT}"] do={{ '
            f":do {{ /ip firewall {table} remove $i }} on-error={{}} }}"
        ) in step
    assert step.index("remove $i") < step.index("/ip firewall raw add")
    assert ":foreach hs in=[/ip hotspot find where disabled=no] do={" in step
    assert ":local bwIf [/ip hotspot get $hs interface]" in step
    # Anchor = first static prerouting rule, computed once so 63/127/254 keep their order.
    assert step.count("/ip firewall raw find where chain=prerouting disabled=no dynamic=no") == 1
    assert step.count("{") == step.count("}")


def test_golden_scripts_carry_the_step(monkeypatch):
    for name in ("wireguard", "l2tp", "l2tp_routerboard"):
        golden = (GOLDEN_DIR / f"{name}.rsc").read_text(encoding="utf-8")
        assert _rsc_raw_rules(golden) == _api_raw_rules(), name


# ---------------------------------------------------------------------------
# DB flag
# ---------------------------------------------------------------------------


async def _user(db, code: int) -> User:
    user = User(
        user_code=code, email=f"at{code}@example.com", password_hash="hash",
        role=UserRole.RESELLER, organization_name="Tether Org",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def test_model_default_is_on_for_new_rows_but_existing_rows_keep_false():
    column = Router.__table__.c.hotspot_sharing_blocked
    assert column.default.arg is True
    # server_default unchanged: no migration, no existing row flips.
    assert column.server_default.arg == "false"


@pytest.mark.asyncio
async def test_new_provisioned_router_is_recorded_with_anti_tethering_on(db, monkeypatch):
    _golden().apply(monkeypatch.setattr)
    monkeypatch.setattr(provisioning.settings, "PROVISION_MGMT_TO_HETZNER", False)
    user = await _user(db, 4101)
    token = _golden().tokens()["wireguard"]
    token.user_id = user.id
    token.status = ProvisioningTokenStatus.PENDING
    db.add(token)
    await db.commit()

    router = await provisioning.complete_provisioning(db, token)

    assert router.hotspot_sharing_blocked is True


@pytest.mark.asyncio
async def test_hand_added_router_has_no_rules_so_flag_stays_off(db, monkeypatch):
    from app.api import router_management
    from app.services import expiry_reaper_enrol, realtime_push_installer

    user = await _user(db, 4102)

    async def current_user(_token, _db):
        return user

    monkeypatch.setattr(router_management, "get_current_user", current_user)
    monkeypatch.setattr(router_management, "enforce_active_subscription", lambda _u: None)
    monkeypatch.setattr(realtime_push_installer, "schedule_install_after_provisioning", lambda _id: None)
    monkeypatch.setattr(expiry_reaper_enrol, "schedule_enrol_after_provisioning", lambda _id: None)

    body = await router_management.create_router_api(
        router_management.RouterCreateRequest(
            name="Existing box", ip_address="10.0.0.77", username="admin", password="pw",
        ),
        db=db,
        token="token",
    )

    router = (await db.execute(select(Router).where(Router.id == body["id"]))).scalar_one()
    assert router.hotspot_sharing_blocked is False


# ---------------------------------------------------------------------------
# Scoping: who the TTL drops can and cannot hit
# ---------------------------------------------------------------------------


def _dropped(rules, *, in_interface: str, src: str, ttl: int, address_lists: dict) -> bool:
    """Evaluate raw prerouting drops the way RouterOS matches them."""
    for rule in rules:
        if rule.get("chain") != "prerouting" or rule.get("action") != "drop":
            continue
        if rule.get("in-interface") and rule["in-interface"] != in_interface:
            continue
        src_list = rule.get("src-address-list")
        if src_list:
            negate = src_list.startswith("!")
            in_list = src in address_lists.get(src_list.lstrip("!"), set())
            if in_list == negate:
                continue
        op, _, value = rule["ttl"].partition(":")
        assert op == "equal"
        if ttl == int(value):
            return True
    return False


INTERFACES = {
    "bridge": "hotspot",
    "pppoe-in-ole": "PPPoE customer (own router, TTL 63)",
    "wg-hz": "WireGuard management tunnel (API from 10.251.0.1)",
    "sstp-hetzner": "SSTP management tunnel",
    "l2tp-aws": "L2TP management tunnel",
    "bridge-plain": "plain (no-auth) ports",
    "ether1": "WAN",
}


@pytest.mark.parametrize("source", ["api", "rsc"])
def test_drops_only_tethered_hotspot_traffic(monkeypatch, source):
    api = FakeMikroTikAPI(hotspots=[
        {"interface": "bridge", "disabled": "false"},
        {"interface": "bridge-guest", "disabled": "true"},
    ])
    assert api.enable_anti_tethering()["success"] is True
    rules = _commands(api, "/ip/firewall/raw/add") if source == "api" else _rsc_raw_rules(
        _all_scripts(monkeypatch)["wireguard"]
    )
    assert {r["in-interface"] for r in rules} == {"bridge"}  # disabled hotspot skipped
    lists = {STATIC_ADDRESS_LIST: {"192.168.88.24"}}

    # Hotspot: tethered (63/127/254) dropped, direct (64/128/255) not.
    for ttl in (63, 127, 254):
        assert _dropped(rules, in_interface="bridge", src="192.168.88.50", ttl=ttl, address_lists=lists)
    for ttl in (64, 128, 255):
        assert not _dropped(rules, in_interface="bridge", src="192.168.88.50", ttl=ttl, address_lists=lists)

    # Static-IP customer's own router on the hotspot LAN: exempt.
    assert not _dropped(rules, in_interface="bridge", src="192.168.88.24", ttl=63, address_lists=lists)

    # Nothing outside the hotspot interface, whatever the TTL.
    for iface in INTERFACES:
        if iface == "bridge":
            continue
        for ttl in (63, 127, 254):
            assert not _dropped(rules, in_interface=iface, src="10.251.0.1", ttl=ttl, address_lists=lists), (
                INTERFACES[iface]
            )


def test_only_prerouting_is_touched_so_router_originated_traffic_is_never_dropped():
    api = FakeMikroTikAPI()
    api.enable_anti_tethering()
    added = [(cmd, args) for cmd, args in api.commands if cmd.endswith("/add")]
    assert added and all(cmd == "/ip/firewall/raw/add" for cmd, _ in added)
    assert {args["chain"] for _, args in added} == {"prerouting"}  # never output/input-only


def test_exempt_list_is_the_one_static_ip_maintains():
    assert MikroTikAPI.ANTI_TETHER_EXEMPT_SRC_LIST == STATIC_ADDRESS_LIST


def test_strict_mode_also_exempts_static_ip_customers():
    api = FakeMikroTikAPI()
    assert api.enable_anti_tethering(mode="strict")["success"] is True
    markers = _commands(api, "/ip/firewall/mangle/add", "mark-packet")
    assert markers and {m["src-address-list"] for m in markers} == {"!" + STATIC_ADDRESS_LIST}
    clamps = _commands(api, "/ip/firewall/mangle/add", "change-ttl")
    assert clamps and {c["dst-address-list"] for c in clamps} == {"!" + STATIC_ADDRESS_LIST}
