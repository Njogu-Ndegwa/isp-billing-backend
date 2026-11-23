"""CR-1123-B4 scenarios (real model, opt-in): offline questions are read live, never from expiries.

2026-11-23: "There is any clint go ofline to day" was answered from GET /api/customers?expires=today
("No customer has gone offline today") while 9 paid PPPoE clients were offline; "is Jawahir offline"
was answered from access enabled while her ARP entry was stale.
"""
from datetime import datetime, timedelta

import pytest

from app.services import offline_customers as oc
from app.services import static_ip
from tests.assistant_eval_kit import KEY, ask, build, customer, evaluate, plan, report, use_real_model
from tests.fake_routeros import FakeRouterOS
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")


def _menus() -> dict:
    local = datetime.utcnow() + timedelta(hours=3)
    out = (local - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "/system/clock": [{"time": local.strftime("%H:%M:%S"), "date": local.strftime("%Y-%m-%d"),
                           "gmt-offset": "+03:00", "time-zone-name": "Africa/Nairobi"}],
        "/ppp/secret": [
            {".id": "*1", "name": "suheb", "disabled": "false", "last-logged-out": out,
             "last-disconnect-reason": "peer-not-responding"},
            {".id": "*2", "name": "iqra", "disabled": "false", "last-logged-out": out,
             "last-disconnect-reason": "peer-not-responding"},
            {".id": "*3", "name": "naima", "disabled": "false"},
        ],
        "/ppp/active": [{".id": "*10", "name": "naima", "address": "192.168.89.20"}],
        "/ip/hotspot/active": [], "/ip/hotspot/host": [],
        "/ip/hotspot/ip-binding": [{".id": "*20", "address": "172.172.10.77", "type": "bypassed",
                                    "disabled": "false", "comment": "STATIC: Jawahir"}],
        "/queue/simple": [{".id": "*21", "name": "plan_static:172.172.10.77", "target": "172.172.10.77/32",
                           "max-limit": "20000000/20000000", "rate": "0/0", "disabled": "false"}],
        "/ip/address": [{".id": "*22", "address": "172.172.10.1/24", "interface": "bridge"}],
        "/ip/arp": [{".id": "*23", "address": "172.172.10.77", "mac-address": "1C:59:9B:36:42:97",
                     "status": "stale", "dynamic": "true"}],
    }


async def _account(db, reseller, monkeypatch):
    made = await build(
        db, reseller, routers=["Kainan home #2"],
        plans=[plan("Home 10M", 2000, days=30, kind="pppoe"), plan("Diamond 20M", 2000, days=30, kind="static_ip")],
        customers=[
            customer("Suheb", "254711000001", "Home 10M", hours_left=24 * 9, pppoe_username="suheb"),
            customer("Iqra", "254711000002", "Home 10M", hours_left=24 * 9, pppoe_username="iqra"),
            customer("Naima home", "254711000003", "Home 10M", hours_left=24 * 14, pppoe_username="naima"),
            customer("Eleza House", "254711000004", "Home 10M", hours_left=6, pppoe_username="eleza"),
            customer("Jawahir", "254711000005", "Diamond 20M", hours_left=24 * 7, static_ip="172.172.10.77"),
        ],
        healthy_routers=monkeypatch)
    menus = _menus()
    monkeypatch.setattr(oc, "MikroTikAPI", lambda *a, **k: FakeRouterOS(menus))
    monkeypatch.setattr(static_ip, "MikroTikAPI", lambda *a, **k: FakeRouterOS(menus))
    return made


def used(part):
    def check(row):
        return None if any(part in t for t in row["tools"]) else f"never used {part} (tools: {row['tools']})"
    return check


def never_used(part):
    def check(row):
        bad = [t for t in row["tools"] if part in t]
        return None if not bad else f"should not answer from {bad}"
    return check


def names(*wanted):
    def check(row):
        missing = [w for w in wanted if w.lower() not in row["said"].lower()]
        return None if not missing else f"should name {missing}"
    return check


@pytest.mark.asyncio
async def test_went_offline_today_reads_the_router_not_expiries(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller, monkeypatch)
    use_real_model(monkeypatch)
    row = await ask(client, token, "There is any clint go ofline to day", monkeypatch)
    problems = evaluate(row, [used("/offline-customers"), never_used("expires"), names("Suheb", "Iqra")])
    report("offline/went-offline-today", row, problems)
    assert not problems, problems


@pytest.mark.asyncio
async def test_static_customer_with_stale_arp_is_offline(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller, monkeypatch)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Is jawahir offline", monkeypatch)

    def says_offline(r):
        text = r["said"].lower()
        if "not offline" in text or "is online" in text:
            return "said Jawahir is online although her device does not answer"
        return None if any(w in text for w in ("offline", "not connect", "not answering", "isn't connect")) \
            else "should say Jawahir is offline"

    problems = evaluate(row, [any_read_of_live_state, says_offline])
    report("offline/static-stale-arp", row, problems)
    assert not problems, problems


def any_read_of_live_state(row):
    live = ("/static/status", "/offline-customers")
    return None if any(p in t for t in row["tools"] for p in live) else \
        f"never read the live device state (tools: {row['tools']})"
