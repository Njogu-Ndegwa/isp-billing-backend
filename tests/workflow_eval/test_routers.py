"""Router and network-setup workflows: onboarding a MikroTik, ports, Wi-Fi, alerts, restarts,
load balancing, looking inside a router, and router faults.

Each scenario is an account state, a reseller's message (English or Kiswahili) and what a
good answer must contain. Checks accept any reasonable correct path.
"""
import re
from datetime import datetime, timedelta

import pytest

from tests.assistant_eval_kit import (
    KEY, any_of, ask, build, card_for, evaluate, never_says, no_card, plan, report, says, use_real_model,
)
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")


# -- local helpers -------------------------------------------------------------------

def router_menus(monkeypatch, extra: dict) -> list[str]:
    """Routers answer with the kit's healthy menus plus `extra`; returns the commands sent."""
    from app.services.mikrotik_api import MikroTikAPI
    from tests.fake_routeros import FakeRouterOS, typical_router_menus

    menus = typical_router_menus()
    menus.update({
        "/system/resource": [{"uptime": "6d4h", "cpu-load": "18", "free-memory": "41943040",
                              "total-memory": "134217728", "board-name": "hAP ac2", "version": "7.16.2"}],
        "/interface": [{"name": f"ether{i}", "type": "ether", "running": "true", "disabled": "false",
                        "rx-byte": "900000000", "tx-byte": "200000000"} for i in range(1, 6)],
        "/ip/hotspot/active": [], "/ip/hotspot/host": [], "/log": [],
    })
    menus.update(extra)
    sent: list[str] = []

    def init(self, *a, **k):
        FakeRouterOS.__init__(self, menus)

    def send(self, command, arguments=None):
        sent.append(command)
        return FakeRouterOS.send_command(self, command, arguments)

    monkeypatch.setattr(MikroTikAPI, "__init__", init)
    monkeypatch.setattr(MikroTikAPI, "send_command", send)
    return sent


# A provisioned hAP: ether2-5 and wlan1 on the hotspot bridge, the hotspot served on it.
PROVISIONED = {
    "/interface": [{".id": f"*{i}", "name": f"ether{i}", "type": "ether", "running": "true", "disabled": "false",
                    "rx-byte": "900000000", "tx-byte": "200000000"} for i in range(1, 6)]
                  + [{".id": "*w1", "name": "wlan1", "type": "wlan", "running": "true", "disabled": "false"},
                     {".id": "*b1", "name": "bridge", "type": "bridge", "running": "true", "disabled": "false"}],
    "/interface/bridge": [{".id": "*b1", "name": "bridge", "running": "true", "disabled": "false"}],
    "/ip/dhcp-server": [{".id": "*d1", "name": "hs-dhcp", "interface": "bridge", "address-pool": "hs-pool",
                         "disabled": "false"}],
    "/interface/bridge/port": [{".id": f"*p{i}", "interface": f"ether{i}", "bridge": "bridge"} for i in range(2, 6)]
                              + [{".id": "*pw", "interface": "wlan1", "bridge": "bridge"}],
    "/ip/hotspot": [{".id": "*h1", "name": "hotspot1", "interface": "bridge", "disabled": "false"}],
    "/interface/wireless": [{".id": "*w1", "name": "wlan1", "ssid": "Kahawa WiFi", "mode": "ap-bridge",
                             "disabled": "false", "running": "true"}],
    "/ip/dhcp-client": [{".id": "*c1", "interface": "ether1", "status": "bound", "gateway": "100.70.1.1"}],
    "/interface/pppoe-client": [], "/user/active": [],
}


def _values(row, path_part, key):
    out = []
    for c in row["cards"]:
        if path_part not in c["path"]:
            continue
        for source in (c.get("body") or {}, c.get("prefilled") or {}):
            v = source.get(key) if isinstance(source, dict) else None
            if v is not None:
                out.append(v)
    return out


def body_has(path_part, key, *wanted):
    """A card for path_part sends key holding every wanted value (a list or a string)."""
    def check(row):
        got = _values(row, path_part, key)
        for v in got:
            text = " ".join(map(str, v)).lower() if isinstance(v, list) else str(v).lower()
            if all(w.lower() in text for w in wanted):
                return None
        return f"{path_part} card should send {key} with {list(wanted)}, got {got}"
    return check


def body_exact(path_part, key, expected: set):
    def check(row):
        got = _values(row, path_part, key)
        if any(isinstance(v, list) and {str(x).lower() for x in v} == expected for v in got):
            return None
        return f"{path_part} card should send {key}={sorted(expected)} (the whole list), got {got}"
    return check


def used(part):
    def check(row):
        return None if any(part in t for t in row["tools"]) else f"never used {part} (tools: {row['tools']})"
    return check


def printed(menus: list[str], menu: str):
    def check(row):
        return None if any(c.startswith(menu + "/print") for c in menus) \
            else f"never read {menu} on the router (sent: {sorted(set(menus))})"
    return check


def mentions(pattern, what):
    def check(row):
        return None if re.search(pattern, row["said"], re.I) else f"should mention {what}"
    return check


def no_card_for(path_part):
    def check(row):
        bad = [c["path"] for c in row["cards"] if path_part in c["path"]]
        return None if not bad else f"should not propose {bad}"
    return check


async def set_router(db, router, **cols):
    for k, v in cols.items():
        setattr(router, k, v)
    await db.commit()


async def run(name, client, token, monkeypatch, question, checks, conversation_id=None):
    use_real_model(monkeypatch)
    row = await ask(client, token, question, monkeypatch, conversation_id=conversation_id)
    problems = evaluate(row, checks)
    report(name, row, problems)
    return row, problems


# -- 1. onboarding: no router yet ------------------------------------------------------

@pytest.mark.asyncio
async def test_new_reseller_adds_first_mikrotik(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller)
    _, problems = await run(
        "routers/onboard-first-mikrotik", client, token, monkeypatch,
        "Nimenunua MikroTik hAP ac2 mpya, sina router yoyote kwa system. Nataka kuanza kuuza WiFi. Nianze aje?",
        [
            # the first step is the setup command (the provisioning action), not a plan or a router form
            any_of(card_for("POST", "/api/provision/create"), mentions(r"winbox|terminal|setup (code|command)", "the setup command / Winbox")),
            no_card_for("/api/routers/create"),
            no_card_for("/api/plans"),
        ])
    assert not problems, problems


# -- 2. PPPoE: a port before customers ------------------------------------------------

@pytest.mark.asyncio
async def test_pppoe_customer_when_no_pppoe_port_yet(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"],
                       plans=[plan("Daily 50", 50), plan("Home 10M", 2000, days=30, kind="pppoe", speed="10M/10M")],
                       healthy_routers=monkeypatch)
    await set_router(db, made["routers"]["Main Tower"], pppoe_ports=None, plain_ports=None, dual_ports=None)
    _, problems = await run(
        "routers/pppoe-customer-needs-port-first", client, token, monkeypatch,
        "I want to start PPPoE. Register Peter Otieno 0722111222 on Home 10M, his cable goes to ether3.",
        [
            # no port on this router serves PPPoE yet: a good answer sets ether3 up (or says it must be) first
            any_of(body_has("/pppoe-ports", "ports", "ether3"), body_has("/dual-ports", "ports", "ether3"),
                   body_has("/pppoe-ports", "add", "ether3"), body_has("/dual-ports", "add", "ether3"),
                   mentions(r"ether3.{0,80}(pppoe|port)|(pppoe|port).{0,80}ether3", "making ether3 a PPPoE port first")),
        ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_add_pppoe_port_keeps_existing_ones(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"],
                       plans=[plan("Home 10M", 2000, days=30, kind="pppoe")], healthy_routers=monkeypatch)
    await set_router(db, made["routers"]["Main Tower"], pppoe_ports=["ether2"])
    _, problems = await run(
        "routers/add-pppoe-port-keeps-ether2", client, token, monkeypatch,
        "ether2 is already PPPoE. Make ether4 PPPoE too, I have new home clients on that side.",
        [
            card_for("PUT", "/pppoe-ports"),
            # "ports" replaces the whole list (dropping ether2 would cut its customers off);
            # "add" changes it and keeps ether2
            any_of(body_exact("/pppoe-ports", "ports", {"ether2", "ether4"}), body_exact("/pppoe-ports", "add", {"ether4"})),
        ])
    assert not problems, problems


# -- 3. Wi-Fi name, alerts --------------------------------------------------------------

@pytest.mark.asyncio
async def test_change_wifi_name(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Kahawa Shop"], plans=[plan("Daily 50", 50)], healthy_routers=monkeypatch)
    router_menus(monkeypatch, PROVISIONED)
    _, problems = await run(
        "routers/rename-wifi", client, token, monkeypatch,
        "Badilisha jina la WiFi yangu iwe 'Mama Mboga WiFi'",
        [card_for("PUT", "/wifi/ssid"), body_has("/wifi/ssid", "ssid", "Mama Mboga WiFi")])
    assert not problems, problems


@pytest.mark.asyncio
async def test_turn_on_status_alerts(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Kahawa Shop"], plans=[plan("Daily 50", 50)], healthy_routers=monkeypatch)
    await set_router(db, made["routers"]["Kahawa Shop"], status_alerts_enabled=False)
    _, problems = await run(
        "routers/status-alerts-on", client, token, monkeypatch,
        "I want to be told when my router goes offline and when it comes back",
        [card_for("PUT", "/status-alerts"), body_has("/status-alerts", "enabled", "true")])
    assert not problems, problems


# -- 4. restarts -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_restart_one_port_not_router(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Kahawa Shop"], plans=[plan("Daily 50", 50)], healthy_routers=monkeypatch)
    router_menus(monkeypatch, PROVISIONED)
    _, problems = await run(
        "routers/restart-port-ether3", client, token, monkeypatch,
        "The AP on ether3 has hung. Restart only that port, don't restart the whole router, people are browsing.",
        [card_for("POST", "/interfaces/ether3/restart"), no_card_for("/reboot")])
    assert not problems, problems


@pytest.mark.asyncio
async def test_restart_router_when_two_routers(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Kahawa Shop", "Ruiru Estate"], plans=[plan("Daily 50", 50)],
                healthy_routers=monkeypatch)
    _, problems = await run(
        "routers/restart-ambiguous-two-routers", client, token, monkeypatch,
        "Restart my router please",
        [
            # one card for each router is acceptable only if the person then picks; a card for one guessed router is not
            any_of(no_card, lambda r: None if len({c["path"] for c in r["cards"] if "/reboot" in c["path"]}) == 2
                   else "proposed a reboot for one guessed router"),
            any_of(says("which", "gani", "ipi", any_=True), says("Kahawa", "Ruiru")),
        ])
    assert not problems, problems


# -- 5. load balancing -------------------------------------------------------------------

@pytest.mark.asyncio
async def test_load_balance_two_lines(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Kahawa Shop"], plans=[plan("Daily 50", 50)], healthy_routers=monkeypatch)
    _, problems = await run(
        "routers/load-balance-two-lines", client, token, monkeypatch,
        "Nimeweka line ya pili ya Safaricom kwa ether2. Nataka zote mbili zifanye kazi pamoja (load balancing).",
        [
            # ether1 is the internet port on every Bitwave-provisioned router: enable (or at least run the preflight)
            any_of(card_for("POST", "/load-balancing/enable"), used("call_api POST /api/routers/1/load-balancing/preflight")),
            any_of(body_has("/load-balancing/enable", "wan_ports", "ether1", "ether2"),
                   lambda r: None if not any("/load-balancing/enable" in c["path"] for c in r["cards"]) else "enable card without ether1+ether2"),
        ])
    assert not problems, problems


# -- 6. looking inside a router ---------------------------------------------------------

@pytest.mark.asyncio
async def test_which_devices_behind_ether3(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Kahawa Shop"], plans=[plan("Daily 50", 50)], healthy_routers=monkeypatch)
    sent = router_menus(monkeypatch, {
        "/interface/bridge/host": [
            {"mac-address": "AA:BB:CC:00:00:31", "on-interface": "ether3", "bridge": "bridge"},
            {"mac-address": "AA:BB:CC:00:00:32", "on-interface": "ether3", "bridge": "bridge"},
            {"mac-address": "AA:BB:CC:00:00:21", "on-interface": "ether2", "bridge": "bridge"},
        ],
    })
    _, problems = await run(
        "routers/devices-behind-ether3", client, token, monkeypatch,
        "Which devices are behind ether3?",
        [printed(sent, "/interface/bridge/host"), no_card,
         mentions(r"\b2\b|two|AA:BB:CC:00:00:3[12]", "the two devices on ether3"),
         never_says("AA:BB:CC:00:00:21")])
    assert not problems, problems


@pytest.mark.asyncio
async def test_second_dhcp_server(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Kahawa Shop"], plans=[plan("Daily 50", 50)], healthy_routers=monkeypatch)
    sent = router_menus(monkeypatch, {
        "/ip/dhcp-server": [{"name": "hs-dhcp", "interface": "bridge", "address-pool": "hs-pool", "disabled": "false"}],
        "/ip/dhcp-server/lease": [
            {"address": "192.168.88.23", "mac-address": "11:22:33:44:55:01", "host-name": "Galaxy-A14", "status": "bound"},
            {"address": "192.168.88.41", "mac-address": "11:22:33:44:55:02", "host-name": "Tecno-Spark", "status": "bound"},
        ],
    })
    _, problems = await run(
        "routers/second-dhcp-server", client, token, monkeypatch,
        "Show my DHCP leases. Some phones get a strange IP, is there a second DHCP server on my network?",
        [
            any_of(printed(sent, "/ip/dhcp-server/lease"), printed(sent, "/ip/dhcp-server")),
            no_card,
            # the router has one server of its own; a rogue one sits on another device: good answers say so
            # and point at what tells it apart (a phone's IP/gateway, the device plugged in recently)
            mentions(r"one dhcp|only one|1 dhcp|single|another (router|device)|ip.{0,40}gateway|gateway|plugged|192\.168\.88",
                     "that the router has one DHCP server and how to spot a second one"),
        ])
    assert not problems, problems


# -- 7. faults ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_router_keeps_going_offline(client, owner, db, monkeypatch):  # noqa: F811
    from app.db.models import RouterAvailabilityCheck

    reseller, token = owner
    made = await build(db, reseller, routers=["Kahawa Shop"], plans=[plan("Daily 50", 50)], healthy_routers=monkeypatch)
    rid = made["routers"]["Kahawa Shop"].id
    now = datetime.utcnow()
    for hours_ago in range(1, 24, 3):  # eight short outages today
        for minutes in (10, 15, 20):
            db.add(RouterAvailabilityCheck(router_id=rid, checked_at=now - timedelta(hours=hours_ago, minutes=-minutes),
                                           is_online=False, source="eval"))
    await db.commit()
    _, problems = await run(
        "routers/keeps-going-offline", client, token, monkeypatch,
        "Router yangu inaenda offline kila mara, wateja wanalalamika",
        [
            used("/uptime"),
            no_card_for("/reboot"),
            mentions(r"power|ups|stima|modem|isp|line|cable|safaricom|starlink", "the line or the power as the cause"),
        ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_one_ap_next_to_working_ones_fails(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Kahawa Shop"], plans=[plan("Daily 50", 50)], healthy_routers=monkeypatch)
    router_menus(monkeypatch, PROVISIONED)
    _, problems = await run(
        "routers/one-ap-fails", client, token, monkeypatch,
        "I have 3 APs on the same switch. Two work fine, the one next to them connects but no internet and no login page.",
        [
            used("known_issues"),
            no_card,
            # either the likely cause and fix (AP in router mode -> AP/bridge mode, DHCP off) or the one question support asks
            mentions(r"router mode|nat mode|wisp|ap mode|access point \(?(bridge\)? )?mode|bridge mode|dhcp( server)? off|"
                     r"\bnew\b|reset|replaced|screenshot|wi-?fi details|which ap",
                     "the AP-in-router-mode cause/fix or the deciding question"),
        ])
    assert not problems, problems
