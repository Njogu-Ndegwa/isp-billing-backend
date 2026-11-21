"""Workflow scenarios: hotspot customers, their devices, vouchers and compensation.

Each scenario is an account in a given state, a reseller's message (English or
Kiswahili), and what a GOOD answer must contain. Checks accept any reasonable
correct path; they do not pin one exact wording.
"""
from datetime import datetime, timedelta

import pytest

from tests.assistant_eval_kit import (
    KEY, any_of, ask, build, card_for, customer, evaluate, never_says, no_card, picker_only, plan, prefilled,
    report, says, use_real_model,
)
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")


# -- small local checks ----------------------------------------------------------------

def used(*parts):
    """Some tool call contains all these parts (e.g. "GET", "/api/customers")."""
    def check(row):
        return None if any(all(p in t for p in parts) for t in row["tools"]) \
            else f"never used {' '.join(parts)}; tools were {row['tools']}"
    return check


def no_card_for(method, path_part):
    def check(row):
        bad = [c["path"] for c in row["cards"] if c["method"] == method and path_part in c["path"]]
        return None if not bad else f"should not propose {method} {bad}"
    return check


def expiry_moved_to(target: datetime, tolerance_h: float = 3):
    """A customer edit card whose expiry is about target (body or prefilled form value)."""
    def check(row):
        for c in row["cards"]:
            if c["method"] != "PUT" or "/api/customers/" not in c["path"]:
                continue
            raw = (c.get("body") or {}).get("expiry") if isinstance(c.get("body"), dict) else None
            raw = raw or c["prefilled"].get("expiry")
            if not raw:
                return "customer edit card has no expiry"
            try:
                got = datetime.fromisoformat(str(raw).replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                return f"expiry {raw!r} unreadable"
            if abs((got - target).total_seconds()) > tolerance_h * 3600:
                return f"expiry {got:%d %b %H:%M} UTC, wanted about {target:%d %b %H:%M} UTC"
            return None
        return "no customer edit card"
    return check


def fully_set_up_hotspot(monkeypatch, mac):
    """The kit's healthy router has no hotspot server, DHCP or walled garden, so the assistant
    rightly reads it as "hotspot never set up". Give it a complete hotspot, with this device bound."""
    from app.services.mikrotik_api import MikroTikAPI
    from tests.fake_routeros import FakeRouterOS, typical_router_menus

    menus = typical_router_menus()
    menus.update({
        "/system/resource": [{"uptime": "6d4h", "cpu-load": "18", "free-memory": "41943040",
                              "total-memory": "134217728", "board-name": "hAP ac2", "version": "7.16.2"}],
        "/interface": [{"name": f"ether{i}", "type": "ether", "running": "true", "disabled": "false",
                        "rx-byte": "900000000", "tx-byte": "200000000"} for i in range(1, 6)]
        + [{"name": "bridge", "type": "bridge", "running": "true", "disabled": "false"}],
        "/interface/bridge": [{".id": "*BR1", "name": "bridge", "running": "true", "disabled": "false"}],
        "/interface/bridge/port": [{".id": f"*BP{i}", "interface": f"ether{i}", "bridge": "bridge",
                                    "disabled": "false"} for i in range(2, 6)],
        "/ip/hotspot": [{".id": "*H1", "name": "hotspot1", "interface": "bridge", "profile": "hsprof1",
                         "address-pool": "hs-pool", "disabled": "false"}],
        "/ip/hotspot/profile": [{".id": "*P1", "name": "hsprof1", "hotspot-address": "192.168.88.1",
                                 "login-by": "http-chap,mac-cookie", "html-directory": "hotspot"}],
        "/ip/dhcp-server": [{".id": "*S1", "name": "dhcp1", "interface": "bridge", "address-pool": "hs-pool",
                             "disabled": "false"}],
        "/ip/dhcp-server/network": [{".id": "*N1", "address": "192.168.88.0/24", "gateway": "192.168.88.1",
                                     "dns-server": "192.168.88.1"}],
        "/ip/hotspot/walled-garden": [{".id": "*W1", "dst-host": "isp.bitwavetechnologies.net", "action": "allow"}],
        "/ip/hotspot/walled-garden/ip": [{".id": "*W2", "dst-host": "isp.bitwavetechnologies.net", "action": "accept"}],
        "/ip/hotspot/ip-binding": [{".id": "*B1", "mac-address": mac, "type": "bypassed", "comment": "paid"}],
        "/ip/hotspot/host": [{".id": "*O1", "mac-address": mac, "address": "192.168.88.45", "bypassed": "true",
                              "authorized": "false", "server": "hotspot1"}],
        "/ip/hotspot/active": [], "/log": [],
        "/ip/dhcp-server/lease": [{".id": "*L1", "mac-address": mac, "address": "192.168.88.45",
                                   "status": "bound", "server": "dhcp1"}],
    })

    def init(self, *a, **k):
        FakeRouterOS.__init__(self, menus)

    monkeypatch.setattr(MikroTikAPI, "__init__", init)


async def run(name, client, token, monkeypatch, question, checks):  # noqa: F811
    use_real_model(monkeypatch)
    row = await ask(client, token, question, monkeypatch)
    problems = evaluate(row, checks)
    report(name, row, problems)
    assert not problems, problems


HOTSPOT = [plan("Daily 50", 50), plan("Weekly 300", 300, days=7)]
PPPOE = [plan("Home 10M", 2000, days=30, kind="pppoe", speed="10M/10M"),
         plan("Home 20M", 3000, days=30, kind="pppoe", speed="20M/20M")]


# -- vouchers ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vouchers_offer_only_hotspot_plans(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT + PPPOE)
    await run("vouchers/only-hotspot-plans", client, token, monkeypatch,
              "Nitengenezee vouchers 20 nipe wateja", [
                  card_for("POST", "/api/vouchers/generate"),
                  picker_only("plan_id", ["Daily 50", "Weekly 300"], forbidden=["Home 10M", "Home 20M"]),
                  prefilled(quantity=20),
              ])


@pytest.mark.asyncio
async def test_vouchers_without_hotspot_plan_offer_plan_first(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=PPPOE)
    await run("vouchers/no-hotspot-plan", client, token, monkeypatch,
              "Generate 10 vouchers for my hotspot", [
                  says("hotspot"),
                  card_for("POST", "/api/plans/create"),
                  no_card_for("POST", "/api/vouchers/generate"),
              ])


@pytest.mark.asyncio
async def test_vouchers_without_router_mention_router(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, plans=HOTSPOT)
    await run("vouchers/no-router", client, token, monkeypatch,
              "I want to print 50 vouchers of Daily 50 to sell at my shop", [
                  says("router"),
              ])


# -- devices ----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_add_tv_when_plan_allows_one_device(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT,
                customers=[customer("Wanjiku Mwangi", "254722100200", "Weekly 300", hours_left=100)])
    await run("devices/tv-plan-allows-one", client, token, monkeypatch,
              "Wanjiku Mwangi wants to add her TV, MAC is A4:5E:60:11:22:33", [
                  # the plan allows 1 device: the device limit must be raised first (or said)
                  any_of(card_for("PUT", "/device-limit"), says("limit"), says("1 device")),
              ])


@pytest.mark.asyncio
async def test_add_device_by_mac_on_shared_plan(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT + [plan("Family 3", 800, days=7)],
                       customers=[customer("Otieno Ouma", "254733400500", "Family 3", hours_left=80)])
    made["plans"]["Family 3"].max_shared_users = 3
    await db.commit()
    await run("devices/add-by-mac", client, token, monkeypatch,
              "Add this MAC 3C:22:FB:9A:10:7E to Otieno's account, it's his TV", [
                  card_for("POST", "/devices"),
                  prefilled(mac_address="3C:22:FB:9A:10:7E"),
              ])


@pytest.mark.asyncio
async def test_tv_lost_plan(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT + [plan("Family 3", 800, days=7)],
                       customers=[customer("Kamau Njoroge", "254711222333", "Family 3", hours_left=60)],
                       healthy_routers=monkeypatch)
    made["plans"]["Family 3"].max_shared_users = 3
    await db.commit()
    await run("devices/tv-lost-plan", client, token, monkeypatch,
              "Kamau Njoroge TV yake imepoteza internet baada ya mtoto kutumia code, na bado ako na plan", [
                  used("GET", "/api/customers"),
                  used("known_issues"),
                  # the fix: put the TV on his plan by its MAC (or the connect link), not a new purchase
                  any_of(card_for("POST", "/devices"), says("mac"), says("connect link")),
              ])


# -- compensation / free time --------------------------------------------------------------

@pytest.mark.asyncio
async def test_compensate_after_power_outage(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT,
                customers=[customer("Achieng", "254700111222", "Weekly 300", hours_left=50),
                           customer("Mutua", "254700333444", "Daily 50", hours_left=10),
                           customer("Halima", "254700555666", "Weekly 300", hours_left=120)])
    await run("compensation/power-outage", client, token, monkeypatch,
              "Stima ilipotea jana kutoka saa nane mchana hadi saa kumi jioni. Compensate wateja wangu wote.", [
                  # outage compensation (preview, then apply) extends everyone hit by the downtime
                  any_of(used("/api/compensation/outage/preview"), card_for("POST", "/api/compensation/outage")),
              ])


@pytest.mark.asyncio
async def test_extend_one_customer_two_days(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT,
                       customers=[customer("Brian Kiprop", "254799888777", "Weekly 300", hours_left=30)])
    expiry = made["customers"]["Brian Kiprop"].expiry
    await run("compensation/extend-one-2-days", client, token, monkeypatch,
              "Extend Brian Kiprop by 2 days, his internet was down yesterday", [
                  any_of(expiry_moved_to(expiry + timedelta(days=2)),
                         card_for("POST", "/api/vouchers/generate")),
              ])


@pytest.mark.asyncio
async def test_give_amina_3_days_two_aminas(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT,
                customers=[customer("Amina Hassan", "254712000111", "Weekly 300", hours_left=20),
                           customer("Amina Wekesa", "254712000999", "Daily 50", hours_left=5)])
    await run("compensation/two-aminas", client, token, monkeypatch,
              "give Amina 3 days free", [
                  no_card,
                  says("Hassan", "Wekesa"),
              ])


# -- troubleshooting ------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_paid_but_no_internet(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT,
                customers=[customer("Grace Akinyi", "254768123456", "Daily 50", hours_left=20,
                                    mac_address="5C:3A:45:AB:CD:01")],
                healthy_routers=monkeypatch)
    fully_set_up_hotspot(monkeypatch, "5C:3A:45:AB:CD:01")
    await run("troubleshoot/paid-no-internet", client, token, monkeypatch,
              "Grace Akinyi amelipa lakini hana internet", [
                  used("GET", "/api/customers"),
                  used("known_issues"),
                  # it must say what the data showed: her plan is active / when it ends
                  says("active", "hai", "until", "expires", "mpaka", "inaisha", any_=True),
                  never_says("expired", "never fully set up"),
              ])


# -- login page ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_free_trial_on_login_page(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT)
    await run("portal/free-trial", client, token, monkeypatch,
              "I want new people to get 10 minutes free on the login page before they pay", [
                  card_for("POST", "/api/plans/create"),
                  prefilled(plan_type="free_trial"),
              ])


@pytest.mark.asyncio
async def test_hide_plan_from_portal(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT,
                customers=[customer("Peter", "254701010101", "Weekly 300")])
    await run("portal/hide-plan", client, token, monkeypatch,
              "Ficha Weekly 300 isionekane kwa login page, lakini usiifute", [
                  card_for("PUT", "/api/plans/"),
                  prefilled(is_hidden=True),
                  no_card_for("DELETE", "/api/plans/"),
              ])
