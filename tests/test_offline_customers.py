"""GET /api/routers/{id}/offline-customers: paid customers not connected now, since when, why."""
from datetime import datetime, timedelta

import pytest

from app.db.models import ConnectionType, CustomerEvent, CustomerStatus, CustomerUsageBucket
from app.services import offline_customers as oc
from tests.factories import make_customer, make_plan, make_router
from tests.fake_routeros import FakeRouterOS
from tests.test_assistant import auth, client, owner  # noqa: F401  (fixtures)


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", ""))


def _menus(now_utc: datetime) -> dict:
    local = now_utc + timedelta(hours=3)  # the router runs on EAT
    otis_out = local - timedelta(hours=2)
    return {
        "/system/clock": [{"time": local.strftime("%H:%M:%S"), "date": local.strftime("%Y-%m-%d"),
                           "gmt-offset": "+03:00", "time-zone-name": "Africa/Nairobi"}],
        "/ppp/secret": [
            {".id": "*1", "name": "jane", "disabled": "false"},
            {".id": "*2", "name": "otis", "disabled": "false",
             "last-logged-out": otis_out.strftime("%Y-%m-%d %H:%M:%S"), "last-disconnect-reason": "port-error"},
            {".id": "*3", "name": "kim", "disabled": "false"},  # RouterOS 6: no logout record
            {".id": "*4", "name": "old", "disabled": "false"},
        ],
        "/ppp/active": [{".id": "*10", "name": "jane", "address": "192.168.89.20"}],
        "/ip/hotspot/active": [{".id": "*20", "user": "h1", "mac-address": "AA:00:00:00:00:01",
                                "address": "192.168.88.11"}],
        "/ip/hotspot/host": [
            {".id": "*30", "mac-address": "AA:00:00:00:00:02", "address": "192.168.88.12", "bypassed": "true"},
            {".id": "*31", "mac-address": "AA:00:00:00:00:03", "address": "192.168.88.13",
             "bypassed": "false", "authorized": "false"},
        ],
        "/ip/arp": [
            {".id": "*40", "address": "172.16.0.10", "mac-address": "BB:00:00:00:00:10", "status": "reachable",
             "dynamic": "true"},
            {".id": "*41", "address": "172.16.0.11", "mac-address": "BB:00:00:00:00:11", "status": "stale",
             "dynamic": "true"},
            {".id": "*42", "address": "172.16.0.13", "mac-address": "BB:00:00:00:00:13", "status": "stale",
             "dynamic": "true"},
        ],
        "/queue/simple": [
            {".id": "*50", "name": "plan_static:172.16.0.13", "target": "172.16.0.13/32", "rate": "12000/340000"},
            {".id": "*51", "name": "plan_static:172.16.0.11", "target": "172.16.0.11/32", "rate": "0/0"},
        ],
    }


@pytest.fixture
def fake_router(monkeypatch):
    made = []
    state = {"menus": None, "reachable": True, "reject": None}

    class Unreachable(FakeRouterOS):
        def connect(self):
            return False

    def factory(*args, **kwargs):
        cls = FakeRouterOS if state["reachable"] else Unreachable
        api = cls(state["menus"] or _menus(datetime.utcnow()), reject=state["reject"])
        made.append(api)
        return api

    monkeypatch.setattr(oc, "MikroTikAPI", factory)
    state["made"] = made
    return state


async def _seed(db, reseller):
    now = datetime.utcnow()
    paid = now + timedelta(days=10)
    r = await make_router(db, reseller, name="Kainan home")
    pppoe = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, name="Home 10M")
    hotspot = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT, name="Daily")
    static = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP, name="Static 15M")
    A = CustomerStatus.ACTIVE
    c = {}
    for name, user in (("Jane", "jane"), ("Otis", "otis"), ("Kim", "kim")):
        c[name] = await make_customer(db, reseller, pppoe, r, status=A, expiry=paid, name=name,
                                      pppoe_username=user)
    # expired yesterday, not connected: expired, not "offline"
    c["Old"] = await make_customer(db, reseller, pppoe, r, status=A, expiry=now - timedelta(days=1),
                                   name="Old", pppoe_username="old")
    c["Gone"] = await make_customer(db, reseller, pppoe, r, status=CustomerStatus.INACTIVE,
                                    expiry=now - timedelta(days=3), name="Gone", pppoe_username="gone")
    for i, name in ((1, "H1"), (2, "H2"), (3, "H3")):
        c[name] = await make_customer(db, reseller, hotspot, r, status=A, expiry=paid, name=name,
                                      mac_address=f"aa:00:00:00:00:0{i}")
    c["H4old"] = await make_customer(db, reseller, hotspot, r, status=A, expiry=now - timedelta(hours=2),
                                     name="H4old", mac_address="AA:00:00:00:00:04")
    for last, name in ((10, "S-on"), (11, "S-stale"), (12, "S-none"), (13, "S-busy")):
        c[name] = await make_customer(db, reseller, static, r, status=A, expiry=paid, name=name,
                                      static_ip=f"172.16.0.{last}")
    # Kim's drop was seen by the push reports 5 h ago; H3 last used data a day ago.
    db.add(CustomerEvent(customer_id=c["Kim"].id, router_id=r.id, occurred_at=now - timedelta(hours=9),
                         category="session", event_type="session_connected", source="router_push",
                         message="connected"))
    db.add(CustomerEvent(customer_id=c["Kim"].id, router_id=r.id, occurred_at=now - timedelta(hours=5),
                         category="session", event_type="session_disconnected", source="router_push",
                         message="ended"))
    db.add(CustomerUsageBucket(customer_id=c["H3"].id, router_id=r.id,
                               bucket_start=now - timedelta(days=1, hours=1),
                               upload_bytes=10, download_bytes=5000, updated_at=now - timedelta(days=1)))
    await db.commit()
    return r, c, now


@pytest.mark.asyncio
async def test_lists_paid_offline_customers_of_every_kind_with_since_and_why(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r, c, now = await _seed(db, reseller)

    res = await client.get(f"/api/routers/{r.id}/offline-customers", headers=auth(token))
    assert res.status_code == 200, res.text
    body = res.json()

    assert body["counts"]["paid"] == 10
    assert body["counts"]["online"] == 5
    assert body["counts"]["offline"] == 5
    assert body["counts"]["by_type"]["pppoe"] == {"paid": 3, "online": 1, "offline": 2}
    assert body["counts"]["by_type"]["hotspot"] == {"paid": 3, "online": 2, "offline": 1}
    assert body["counts"]["by_type"]["static_ip"] == {"paid": 4, "online": 2, "offline": 2}

    rows = {row["name"]: row for row in body["offline"]}
    assert set(rows) == {"Otis", "Kim", "H3", "S-stale", "S-none"}

    otis = rows["Otis"]
    assert otis["since_source"] == "router" and otis["reason_code"] == "port-error"
    assert "power, cable or radio" in otis["reason"]
    assert abs((_iso(otis["offline_since"]) - (now - timedelta(hours=2))).total_seconds()) < 60
    assert otis["offline_since"].endswith("Z") and otis["expiry"].endswith("Z")

    kim = rows["Kim"]
    assert kim["since_source"] == "session_history"
    assert abs((_iso(kim["offline_since"]) - (now - timedelta(hours=5))).total_seconds()) < 2

    h3 = rows["H3"]
    assert h3["since_source"] == "last_traffic" and h3["connection_type"] == "hotspot"

    assert rows["S-stale"]["reason_code"] == "arp_stale" and rows["S-stale"]["static_ip"] == "172.16.0.11"
    assert rows["S-none"]["reason_code"] == "no_arp_entry"
    assert rows["S-none"]["offline_since"] is None and rows["S-none"]["since_note"].startswith("unknown")

    # most recently gone first, unknown last
    names = [row["name"] for row in body["offline"]]
    assert names[:3] == ["Otis", "Kim", "H3"]

    # read-only: only prints reached the router, over one connection
    assert len(fake_router["made"]) == 1
    assert all(cmd.endswith("/print") for cmd, _ in fake_router["made"][0].calls)


@pytest.mark.asyncio
async def test_an_expired_customer_is_never_listed_as_offline(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r, c, _ = await _seed(db, reseller)
    body = (await client.get(f"/api/routers/{r.id}/offline-customers", headers=auth(token))).json()
    listed = {row["customer_id"] for row in body["offline"]}
    for name in ("Old", "Gone", "H4old"):
        assert c[name].id not in listed


@pytest.mark.asyncio
async def test_an_unreachable_router_is_an_error_not_an_empty_list(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r, _, _ = await _seed(db, reseller)
    fake_router["reachable"] = False
    res = await client.get(f"/api/routers/{r.id}/offline-customers", headers=auth(token))
    assert res.status_code == 503, res.text
    detail = res.json()["detail"]
    assert "did not answer" in detail["message"] and detail["router_reachable"] is False
    assert detail["paid_customers"] == 10
    assert "offline" not in res.json()


@pytest.mark.asyncio
async def test_a_list_the_router_refuses_is_an_error_not_everyone_offline(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r, _, _ = await _seed(db, reseller)
    fake_router["reject"] = lambda command, args: "timeout reading" if command == "/ppp/active/print" else None
    res = await client.get(f"/api/routers/{r.id}/offline-customers", headers=auth(token))
    assert res.status_code == 502, res.text
    assert "/ppp/active" in res.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_another_resellers_router_is_not_found(client, owner, db, fake_router):  # noqa: F811
    from tests.factories import make_reseller

    _, token = owner
    other = await make_reseller(db)
    theirs = await make_router(db, other, name="Not yours")
    await db.commit()
    res = await client.get(f"/api/routers/{theirs.id}/offline-customers", headers=auth(token))
    assert res.status_code == 404
    assert not fake_router["made"]
