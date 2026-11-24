"""Reading a router's RouterOS menus: own routers only, print only, secrets hidden."""
import pytest

from app.api import router_inspect_routes
from tests.factories import make_reseller, make_router
from tests.fake_routeros import FakeRouterOS, typical_router_menus
from tests.test_assistant import auth, client, owner  # noqa: F401  (fixtures)


@pytest.fixture
def fake_router(monkeypatch):
    menus = typical_router_menus()
    menus["/ip/dhcp-server/lease"] = [
        {".id": "*1", "address": "192.168.88.30", "mac-address": "AA:BB:CC:00:00:01", "server": "hs-dhcp"},
        {".id": "*2", "address": "192.168.88.31", "mac-address": "AA:BB:CC:00:00:02", "server": "hs-dhcp"},
    ]
    menus["/system/scheduler"] = [{".id": "*9", "name": "nightly", "on-event": "/user set admin password=x"}]
    made = []

    def factory(*args, **kwargs):
        api = FakeRouterOS(menus)
        made.append(api)
        return api

    monkeypatch.setattr(router_inspect_routes, "MikroTikAPI", factory)
    return made


@pytest.mark.asyncio
async def test_a_reseller_reads_a_menu_of_their_own_router(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r = await make_router(db, reseller, name="Main Tower")
    await db.commit()
    res = await client.get(f"/api/routers/{r.id}/routeros", params={"menu": "/ip/dhcp-server/lease",
                                                                    "contains": "00:02"}, headers=auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["count"] == 1 and body["rows"][0]["address"] == "192.168.88.31"
    # read-only: nothing but print reached the router
    assert [c for c, _ in fake_router[0].calls] == ["/ip/dhcp-server/lease/print"]


@pytest.mark.asyncio
async def test_passwords_and_scripts_never_leave_the_router(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r = await make_router(db, reseller, name="Main Tower")
    await db.commit()
    secrets = (await client.get(f"/api/routers/{r.id}/routeros", params={"menu": "/ppp/secret"},
                                headers=auth(token))).json()["rows"]
    assert secrets and all(row["password"] == "(hidden)" for row in secrets)
    assert secrets[0]["name"] == "jane"
    jobs = (await client.get(f"/api/routers/{r.id}/routeros", params={"menu": "/system/scheduler"},
                             headers=auth(token))).json()["rows"]
    assert "on-event" not in jobs[0] and jobs[0]["name"] == "nightly"


@pytest.mark.asyncio
async def test_log_stamps_get_true_utc_from_the_routers_own_clock(client, owner, db, monkeypatch):  # noqa: F811
    # CR-1123-B3: a router an hour slow on EAT; its log stamps are local time.
    from datetime import datetime, timedelta

    local = datetime.utcnow() + timedelta(hours=2)
    stamp = local - timedelta(minutes=40)
    menus = typical_router_menus()
    menus["/system/clock"] = [{"date": f"{local:%Y-%m-%d}", "time": f"{local:%H:%M:%S}", "gmt-offset": "+03:00"}]
    menus["/log"] = [{".id": "*1", "time": f"{stamp:%Y-%m-%d %H:%M:%S}", "topics": "pppoe", "message": "x"}]
    made = []
    monkeypatch.setattr(router_inspect_routes, "MikroTikAPI", lambda *a, **k: made.append(FakeRouterOS(menus)) or made[-1])
    reseller, token = owner
    r = await make_router(db, reseller, name="Main Tower")
    await db.commit()
    res = await client.get(f"/api/routers/{r.id}/routeros", params={"menu": "/log"}, headers=auth(token))
    assert res.status_code == 200, res.text
    row = res.json()["rows"][0]
    when = datetime.strptime(row["time_utc"], "%Y-%m-%dT%H:%M:%SZ")
    assert abs((datetime.utcnow() - timedelta(minutes=40) - when).total_seconds()) < 120
    assert all(c.endswith("/print") for c, _ in made[0].calls)


@pytest.mark.asyncio
async def test_another_resellers_router_and_other_menus_are_refused(client, owner, db, fake_router):  # noqa: F811
    _, token = owner
    other = await make_reseller(db)
    theirs = await make_router(db, other, name="Not yours")
    mine = await make_router(db, owner[0], name="Mine")
    await db.commit()
    assert (await client.get(f"/api/routers/{theirs.id}/routeros", params={"menu": "/ip/address"},
                             headers=auth(token))).status_code == 404
    # a menu off the list (a script body, users) is not even sent
    for menu in ("/system/script", "/user", "/ip/address/add"):
        res = await client.get(f"/api/routers/{mine.id}/routeros", params={"menu": menu}, headers=auth(token))
        assert res.status_code == 422, menu
    assert not fake_router
