"""Fleet scan and fix for the hotspot proxy bypass (HTTP Injector), router client mocked."""
import itertools

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api import router_management as routes
from app.db.database import get_db
from app.db.models import ProvisioningToken
from app.services import anti_bypass_fleet
from app.services.auth import verify_token
from app.services.provisioning import PROXY_RELAY_BLOCK_COMMENT
from tests.factories import make_admin, make_reseller, make_router

_TOKENS = itertools.count(1)
HOTSPOT = [{"name": "hotspot1", "profile": "hsprof1", "disabled": "false"}]
BLOCK = {".id": "*9", "comment": PROXY_RELAY_BLOCK_COMMENT}


class FakeRouterOS:
    """A stateful stand-in for one router: adds land in its tables."""

    def __init__(self, hotspot=HOTSPOT, rules=(), refuse_rule=False):
        self.tables = {"/ip/hotspot/print": list(hotspot), "/ip/firewall/filter/print": list(rules),
                       "/ip/firewall/address-list/print": []}
        self.refuse_rule = refuse_rule
        self.writes = []

    def send_command(self, command, arguments=None):
        if command.endswith(("/add", "/remove", "/set")):
            self.writes.append((command, arguments))
            if command == "/ip/firewall/filter/add":
                if self.refuse_rule:
                    return {"success": False, "error": "failure: not allowed"}
                self.tables["/ip/firewall/filter/print"].append(dict(arguments, **{".id": "*new"}))
            return {"success": True, "data": []}
        return {"success": True, "data": self.tables.get(command, [])}


@pytest.fixture
def fleet(monkeypatch):
    """ip -> FakeRouterOS, or None for a router that does not answer."""
    routers: dict[str, object] = {}
    opened: list[str] = []

    class FakeAPI:
        def __init__(self, host, username, password, port, timeout=None, connect_timeout=None):
            assert connect_timeout and connect_timeout <= 6 and timeout and timeout <= 15   # short timeouts
            self.host, self.last_connect_error = host, None

        def connect(self):
            opened.append(self.host)
            if routers.get(self.host) is None:
                self.last_connect_error = "timed out"
                return False
            return True

        def send_command(self, command, arguments=None):
            return routers[self.host].send_command(command, arguments)

        def disconnect(self):
            pass

    monkeypatch.setattr(anti_bypass_fleet, "MikroTikAPI", FakeAPI)
    routers["opened"] = opened   # handy for assertions
    return routers


async def _client(db, monkeypatch, user):
    async def current_user(token, session):
        return user

    async def database():
        yield db

    monkeypatch.setattr(routes, "get_current_user", current_user)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[verify_token] = lambda: "test-token"
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _router(db, owner, ip, *, online=True, setup=True):
    r = await make_router(db, owner, ip_address=ip, last_status=online)
    if setup:
        db.add(ProvisioningToken(user_id=owner.id, token=f"tok-{next(_TOKENS)}", router_name=r.name,
                                 identity=r.name, wireguard_ip=ip, server_public_ip="91.98.238.12",
                                 router_id=r.id))
        await db.commit()
    return r


async def test_scan_finds_open_routers_and_skips_fixed_and_offline_ones(db, monkeypatch, fleet):
    admin = await make_admin(db)
    owner = await make_reseller(db)
    open_r = await _router(db, owner, "10.0.1.1")
    fixed_r = await _router(db, owner, "10.0.1.2")
    offline_r = await _router(db, owner, "10.0.1.3", online=False)
    down_r = await _router(db, owner, "10.0.1.4")          # online in the DB, does not answer
    pppoe_r = await _router(db, owner, "10.0.1.5", setup=False)
    fleet["10.0.1.1"] = FakeRouterOS(rules=[{".id": "*1", "comment": "something else"}])
    fleet["10.0.1.2"] = FakeRouterOS(rules=[BLOCK])
    fleet["10.0.1.3"] = FakeRouterOS()
    fleet["10.0.1.5"] = FakeRouterOS(hotspot=[])

    async with await _client(db, monkeypatch, admin) as client:
        resp = await client.get("/api/admin/anti-bypass/scan", params={"concurrency": 2})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    by_id = {r["router_id"]: r for r in body["results"]}
    assert body["open"] == [open_r.id]
    assert by_id[open_r.id] == {"router_id": open_r.id, "account_id": owner.id, "status": "open",
                                "finding": "proxy_bypass_open", "fixable": True}
    assert by_id[fixed_r.id]["status"] == "protected"
    assert by_id[down_r.id]["status"] == "unreachable"     # never reported as protected
    assert by_id[pppoe_r.id]["status"] == "no_hotspot" and by_id[pppoe_r.id]["fixable"] is False
    assert offline_r.id not in by_id and "10.0.1.3" not in fleet["opened"]
    assert body["online_total"] == 4 and body["next_offset"] is None
    assert all(not r.writes for k, r in fleet.items() if isinstance(r, FakeRouterOS))   # read-only
    assert "password" not in resp.text and "ip_address" not in resp.text


async def test_scan_pages_through_the_online_routers(db, monkeypatch, fleet):
    admin = await make_admin(db)
    owner = await make_reseller(db)
    first = await _router(db, owner, "10.0.2.1")
    second = await _router(db, owner, "10.0.2.2")
    fleet["10.0.2.1"] = FakeRouterOS()
    fleet["10.0.2.2"] = FakeRouterOS()
    async with await _client(db, monkeypatch, admin) as client:
        page1 = (await client.get("/api/admin/anti-bypass/scan", params={"limit": 1})).json()
        page2 = (await client.get("/api/admin/anti-bypass/scan", params={"limit": 1, "offset": 1})).json()
    assert page1["open"] == [first.id] and page1["next_offset"] == 1
    assert page2["open"] == [second.id] and page2["next_offset"] is None


async def test_apply_runs_the_existing_fix_per_router_and_reports_failures_without_stopping(db, monkeypatch, fleet):
    admin = await make_admin(db)
    owner = await make_reseller(db)
    good = await _router(db, owner, "10.0.3.1")
    refused = await _router(db, owner, "10.0.3.2")
    down = await _router(db, owner, "10.0.3.3")
    no_setup = await _router(db, owner, "10.0.3.4", setup=False)
    fleet["10.0.3.1"] = FakeRouterOS()
    fleet["10.0.3.2"] = FakeRouterOS(refuse_rule=True)
    fleet["10.0.3.4"] = FakeRouterOS()
    calls = []
    real = anti_bypass_fleet.router_checkup.apply_anti_bypass

    def spy(api, allow):
        calls.append(allow)
        return real(api, allow)

    monkeypatch.setattr(anti_bypass_fleet.router_checkup, "apply_anti_bypass", spy)
    ids = [refused.id, good.id, down.id, no_setup.id, 999999]
    async with await _client(db, monkeypatch, admin) as client:
        resp = await client.post("/api/admin/anti-bypass/apply", json={"router_ids": ids})

    assert resp.status_code == 200, resp.text
    results = resp.json()["results"]
    assert [r["router_id"] for r in results] == ids
    status = {r["router_id"]: r["status"] for r in results}
    assert status == {refused.id: "failed", good.id: "fixed", down.id: "unreachable",
                      no_setup.id: "no_setup_record", 999999: "not_found"}
    assert next(r for r in results if r["router_id"] == good.id)["after"] == "protected"
    assert len(calls) == 2 and "91.98.238.12" in calls[0]
    rule = next(a for c, a in fleet["10.0.3.1"].writes if c == "/ip/firewall/filter/add")
    assert rule["comment"] == PROXY_RELAY_BLOCK_COMMENT and rule["dst-port"] == "80,3128,8080"
    assert not fleet["10.0.3.4"].writes           # no setup record: never touched


async def test_apply_is_bounded(db, monkeypatch, fleet):
    admin = await make_admin(db)
    async with await _client(db, monkeypatch, admin) as client:
        assert (await client.post("/api/admin/anti-bypass/apply", json={"router_ids": []})).status_code == 422
        too_many = list(range(1, 52))
        assert (await client.post("/api/admin/anti-bypass/apply", json={"router_ids": too_many})).status_code == 422


async def test_both_endpoints_refuse_non_admins(db, monkeypatch, fleet):
    reseller = await make_reseller(db)
    r = await _router(db, reseller, "10.0.4.1")
    fleet["10.0.4.1"] = FakeRouterOS()
    async with await _client(db, monkeypatch, reseller) as client:
        assert (await client.get("/api/admin/anti-bypass/scan")).status_code == 403
        assert (await client.post("/api/admin/anti-bypass/apply", json={"router_ids": [r.id]})).status_code == 403
    assert fleet["opened"] == [] and not fleet["10.0.4.1"].writes


def test_detector_lines_follow_the_contract():
    hit = anti_bypass_fleet.detector_line({"router_id": 5, "account_id": 2, "status": "open",
                                           "finding": "proxy_bypass_open"})
    assert hit["status"] == "hit" and hit["code"] == "HTTP_INJECTOR_BYPASS" and hit["reseller_message"]
    assert anti_bypass_fleet.detector_line({"router_id": 5, "account_id": 2, "status": "unreachable"})["status"] == "unreachable"
    assert anti_bypass_fleet.detector_line({"router_id": 5, "account_id": 2, "status": "protected"})["status"] == "clean"


def test_an_unreadable_filter_table_is_an_error_not_open():
    class Broken(FakeRouterOS):
        def send_command(self, command, arguments=None):
            if command == "/ip/firewall/filter/print":
                return {"success": False, "error": "timeout"}
            return super().send_command(command, arguments)

    assert anti_bypass_fleet.scan_connected(Broken(), 1)["status"] == "error"
