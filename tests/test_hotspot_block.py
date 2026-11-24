"""Block a hotspot device by MAC (feedback board post 14, zoid tech, 2026-11-24).

A reseller asked to block a hotspot user from the portal; the only tool was
force-remove, which lasts until the device logs in or pays again. The block is
a ``type=blocked`` ip-binding tagged ``BW-RESELLER-BLOCK``: the endpoints add,
list and remove it, and every cleanup / payment path leaves it alone.
"""

from datetime import datetime, timedelta

import pytest

from app.api import public_routes
from app.api import router_operations as ro
from app.services import expiry_reaper_enrol, fup, hotspot_block, hotspot_provisioning
from app.services import mikrotik_background as bg
from app.services.expiry_reaper_script import render_expiry_reaper_script
from app.services.hotspot_block import BLOCK_TAG, block_comment, is_reseller_block
from app.services.pull_provisioning import render_hotspot_provision_rsc
from app.services.router_agent_commands import render_hotspot_remove_action
from tests.factories import make_reseller, make_router
from tests.fake_routeros import FakeRouterOS
from tests.test_assistant import auth, client, owner  # noqa: F401  (fixtures)

MAC = "86:1A:C4:23:61:0F"
OTHER = "AA:00:00:00:00:01"
ROUTER_PORT_MAC = "48:A9:8A:00:00:01"


def _menus():
    return {
        "/interface": [{".id": "*1", "name": "ether2", "mac-address": ROUTER_PORT_MAC}],
        "/ip/arp": [{".id": "*2", "address": "192.168.88.20", "mac-address": MAC, "interface": "bridge"}],
        "/ip/hotspot/ip-binding": [
            {".id": "*10", "address": "192.168.88.50", "type": "bypassed", "comment": "STATIC:1"},
            {".id": "*11", "mac-address": OTHER, "type": "bypassed",
             "comment": "USER:AA0000000001|EXPIRES:DB_MANAGED|EXP:1790812800"},
        ],
        "/ip/hotspot/active": [{".id": "*20", "mac-address": MAC, "user": "861AC423610F"}],
        "/ip/hotspot/host": [{".id": "*30", "mac-address": MAC, "address": "192.168.88.20"}],
        "/ip/hotspot/user": [{".id": "*40", "name": MAC, "comment": f"MACLOGIN|MAC:{MAC}|T:1|EXP:1790812800"}],
    }


@pytest.fixture
def fake_router(monkeypatch):
    state = {"menus": _menus(), "api": None}

    def factory(*args, **kwargs):
        api = FakeRouterOS(state["menus"])
        state["api"] = api
        return api

    monkeypatch.setattr(hotspot_block, "MikroTikAPI", factory)
    return state


def _blocked_row(mac=MAC, reason="not a customer", rid="*99"):
    return {".id": rid, "mac-address": mac, "type": "blocked", "comment": block_comment(reason)}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_block_adds_a_tagged_blocked_binding_first_and_kicks_the_device(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r = await make_router(db, reseller, name="zoid tech 1")
    await db.commit()

    res = await client.post(f"/api/routers/{r.id}/blocked-devices", headers=auth(token),
                            json={"mac_address": "86-1a-c4-23-61-0f", "reason": "Richard: EXP:1 | not paying"})
    assert res.status_code == 200, res.text
    assert res.json()["action"] == "added"

    api = fake_router["api"]
    rows = api.menus["/ip/hotspot/ip-binding"]
    block = rows[0]  # place-before the first binding, ahead of address bypasses
    assert block["mac-address"] == MAC and block["type"] == "blocked"
    assert block["comment"].startswith(BLOCK_TAG + "|")
    assert "EXP:" not in block["comment"] and "USER:" not in block["comment"]
    assert api.menus["/ip/hotspot/active"] == [] and api.menus["/ip/hotspot/host"] == []
    # the MAC-login user's deadline can no longer make the v4 reaper drop bindings
    assert "EXX:" in api.menus["/ip/hotspot/user"][0]["comment"]
    assert "EXP:" not in api.menus["/ip/hotspot/user"][0]["comment"]


@pytest.mark.asyncio
async def test_block_turns_an_existing_paid_binding_into_the_block(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r = await make_router(db, reseller)
    await db.commit()

    res = await client.post(f"/api/routers/{r.id}/blocked-devices", headers=auth(token),
                            json={"mac_address": OTHER})
    assert res.status_code == 200, res.text
    assert res.json()["action"] == "converted"
    rows = fake_router["api"].menus["/ip/hotspot/ip-binding"]
    assert len(rows) == 2
    assert rows[1]["type"] == "blocked" and is_reseller_block(rows[1]) and "EXP:" not in rows[1]["comment"]


@pytest.mark.asyncio
async def test_another_resellers_router_is_refused(client, owner, db, fake_router):  # noqa: F811
    _reseller, token = owner
    stranger = await make_reseller(db, email="other@example.com")
    r = await make_router(db, stranger)
    await db.commit()

    res = await client.post(f"/api/routers/{r.id}/blocked-devices", headers=auth(token),
                            json={"mac_address": MAC})
    assert res.status_code == 404
    res = await client.delete(f"/api/routers/{r.id}/blocked-devices/{MAC}", headers=auth(token))
    assert res.status_code == 404
    res = await client.get(f"/api/routers/{r.id}/blocked-devices", headers=auth(token))
    assert res.status_code == 404
    assert fake_router["api"] is None  # never touched the router


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["richard", "86:1A:C4:23:61", "FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"])
async def test_bad_mac_is_refused(client, owner, db, fake_router, bad):  # noqa: F811
    reseller, token = owner
    r = await make_router(db, reseller)
    await db.commit()
    res = await client.post(f"/api/routers/{r.id}/blocked-devices", headers=auth(token),
                            json={"mac_address": bad})
    assert res.status_code == 400
    assert fake_router["api"] is None


@pytest.mark.asyncio
async def test_router_own_port_cannot_be_blocked(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r = await make_router(db, reseller)
    await db.commit()
    res = await client.post(f"/api/routers/{r.id}/blocked-devices", headers=auth(token),
                            json={"mac_address": ROUTER_PORT_MAC})
    assert res.status_code == 403
    assert not any(row.get("type") == "blocked" for row in fake_router["api"].menus["/ip/hotspot/ip-binding"])


@pytest.mark.asyncio
async def test_list_returns_only_reseller_blocks_with_reason(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r = await make_router(db, reseller)
    await db.commit()
    fake_router["menus"]["/ip/hotspot/ip-binding"] += [
        _blocked_row(reason="not a customer"),
        {".id": "*98", "mac-address": "BB:00:00:00:00:02", "type": "blocked", "comment": "FUP_BLOCKED|USER:x|t"},
    ]
    res = await client.get(f"/api/routers/{r.id}/blocked-devices", headers=auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["count"] == 1
    row = body["blocked"][0]
    assert row["mac_address"] == MAC and row["reason"] == "not a customer"
    assert row["blocked_at"].endswith("Z")


@pytest.mark.asyncio
async def test_unblock_removes_only_the_reseller_block(client, owner, db, fake_router):  # noqa: F811
    reseller, token = owner
    r = await make_router(db, reseller)
    await db.commit()
    fake_router["menus"]["/ip/hotspot/ip-binding"].append(_blocked_row())

    res = await client.delete(f"/api/routers/{r.id}/blocked-devices/{MAC}", headers=auth(token))
    assert res.status_code == 200, res.text
    rows = fake_router["api"].menus["/ip/hotspot/ip-binding"]
    assert [b[".id"] for b in rows] == ["*10", "*11"]

    # not blocked (a paid binding is not a block): 404, nothing removed
    fake_router["menus"] = fake_router["api"].menus
    res = await client.delete(f"/api/routers/{r.id}/blocked-devices/{OTHER}", headers=auth(token))
    assert res.status_code == 404
    assert len(fake_router["api"].menus["/ip/hotspot/ip-binding"]) == 2


def test_routes_are_in_the_openapi_with_plain_summaries():
    import main

    paths = main.app.openapi()["paths"]
    item = paths["/api/routers/{router_id}/blocked-devices"]
    assert item["post"]["summary"] and "Block a device" in item["post"]["description"]
    assert "List the devices blocked" in item["get"]["description"]
    assert "Unblock a device" in paths["/api/routers/{router_id}/blocked-devices/{mac_address}"]["delete"]["description"]

    # the assistant offers them to a reseller; block/unblock wait for Confirm
    from app.services.assistant.caller import Caller
    from app.services.assistant.catalog import Catalog

    cat = Catalog.from_openapi(main.app.openapi())
    mine = {a.key: a for a in cat.for_caller(Caller(user_id=1, role="reseller", authorization="Bearer x"))}
    assert mine["GET /api/routers/{router_id}/blocked-devices"].always_reads
    assert not mine["POST /api/routers/{router_id}/blocked-devices"].always_reads
    assert not mine["DELETE /api/routers/{router_id}/blocked-devices/{mac_address}"].always_reads


# ---------------------------------------------------------------------------
# Cleanup and payment paths leave a reseller block alone
# ---------------------------------------------------------------------------

def _router_with_block(extra=None):
    return FakeRouterOS({"/ip/hotspot/ip-binding": [_blocked_row(), *(extra or [])]})


def _patch_api(monkeypatch, module, api):
    monkeypatch.setattr(module, "MikroTikAPI", lambda *a, **k: api)


INFO = {"ip": "10.0.0.9", "username": "u", "password": "p", "port": 8728, "name": "R1", "id": 1}


def test_expiry_cleanup_keeps_the_block_and_still_counts_the_customer_removed(monkeypatch):
    api = _router_with_block()
    _patch_api(monkeypatch, bg, api)
    out = bg._cleanup_single_router_hotspot_sync(INFO, [{"id": 7, "mac_address": MAC, "name": "Richard"}])
    assert api.rows("/ip/hotspot/ip-binding", type="blocked")
    assert [r["id"] for r in out["removed"]] == [7] and not out["failed"]


def test_inactive_user_removal_keeps_the_block(monkeypatch):
    api = _router_with_block()
    _patch_api(monkeypatch, bg, api)
    bg._remove_user_from_mikrotik_sync(INFO, MAC, MAC.replace(":", ""), MAC)
    assert api.rows("/ip/hotspot/ip-binding", type="blocked")


def test_safety_net_orphan_removal_keeps_the_block(monkeypatch):
    # even if something rewrote the type, the tag alone protects it
    api = _router_with_block()
    api.menus["/ip/hotspot/ip-binding"][0]["type"] = "bypassed"
    _patch_api(monkeypatch, bg, api)
    assert bg._remove_router_bindings_sync(INFO, {MAC}) == 0
    assert len(api.menus["/ip/hotspot/ip-binding"]) == 1


@pytest.mark.asyncio
async def test_public_cleanup_blocked_bindings_keeps_reseller_blocks(monkeypatch):
    fup_row = {".id": "*98", "mac-address": OTHER, "type": "blocked", "comment": "EXPIRED|x"}
    api = _router_with_block([fup_row])
    _patch_api(monkeypatch, public_routes, api)
    out = await public_routes.cleanup_blocked_bindings_public()
    assert out["removed_count"] == 1
    assert [b[".id"] for b in api.menus["/ip/hotspot/ip-binding"]] == ["*99"]


def test_force_remove_kicks_but_keeps_the_block(monkeypatch):
    api = _router_with_block()
    api.menus["/ip/hotspot/active"] = [{".id": "*20", "mac-address": MAC}]
    _patch_api(monkeypatch, ro, api)
    ro._force_remove_mac_sync(INFO, MAC, MAC.replace(":", ""))
    assert api.rows("/ip/hotspot/ip-binding", type="blocked")
    assert api.menus["/ip/hotspot/active"] == []


def test_remove_bypassed_user_keeps_the_block():
    api = _router_with_block()
    api.remove_bypassed_user(MAC)
    assert api.rows("/ip/hotspot/ip-binding", type="blocked")


def test_fup_block_and_restore_do_not_touch_the_block(monkeypatch):
    api = _router_with_block()
    _patch_api(monkeypatch, fup, api)
    assert fup._block_hotspot_sync(INFO, MAC)["skipped"] == "blocked_by_reseller"
    assert fup._restore_hotspot_sync(INFO, MAC, "5M/5M")["skipped"] == "blocked_by_reseller"
    row = api.menus["/ip/hotspot/ip-binding"][0]
    assert row["type"] == "blocked" and is_reseller_block(row)


def test_reaper_enrolment_never_puts_an_exp_tag_on_the_block():
    api = _router_with_block()
    assert expiry_reaper_enrol._tag_bindings(api, {MAC: datetime.utcnow() + timedelta(days=1)}) == 0
    assert "EXP:" not in api.menus["/ip/hotspot/ip-binding"][0]["comment"]


def test_paying_does_not_unblock(monkeypatch):
    api = _router_with_block()
    _patch_api(monkeypatch, hotspot_provisioning, api)
    out = hotspot_provisioning._call_mikrotik_bypass_sync({
        "router_ip": "10.0.0.9", "router_username": "u", "router_password": "p", "router_port": 8728,
        "mac_address": MAC, "username": MAC.replace(":", ""), "password": "x", "time_limit": "1d",
        "bandwidth_limit": "5Mbps", "comment": "Payment", "customer_expiry": datetime.utcnow() + timedelta(days=1),
    })
    assert out["error"] == hotspot_block.BLOCKED_DELIVERY_ERROR
    assert api.writes() == []
    assert api.menus["/ip/hotspot/ip-binding"][0]["type"] == "blocked"


def test_bypass_push_will_not_rewrite_the_block_when_it_already_exists():
    api = _router_with_block()
    api.reject = lambda cmd, args: "failure: already exists" if cmd == "/ip/hotspot/ip-binding/add" else None
    out = api.add_customer_bypass_mode(MAC, MAC.replace(":", ""), "x", "1d", "5Mbps", "Payment",
                                       "10.0.0.9", "u", "p", expiry=None)
    assert out["error"] == hotspot_block.BLOCKED_DELIVERY_ERROR
    assert api.menus["/ip/hotspot/ip-binding"][0]["type"] == "blocked"


def test_router_scripts_skip_the_tag():
    reaper = render_expiry_reaper_script(identity="R1", tunnel_url="http://10.0.0.1/x", public_url="https://x/y")
    assert f'ip-binding remove [find where mac-address=$m && !(comment~"{BLOCK_TAG}")]' in reaper
    agent = render_hotspot_remove_action(mac_address=MAC, username=MAC.replace(":", ""))
    assert f'!(comment~\\"{BLOCK_TAG}\\")' in agent or f'!(comment~"{BLOCK_TAG}")' in agent
    assert "ip-binding remove [find mac-address=" not in agent
    pull = render_hotspot_provision_rsc(username="u1", password="p", mac_address=MAC,
                                        rate_limit="1M/1M", time_limit="1d", comment="x")
    guard = pull.index(f'comment~"{BLOCK_TAG}"]] > 0) do={{ :error "device blocked by reseller" }}'.replace("{{", "{").replace("}}", "}"))
    assert guard < pull.index("/ip hotspot ip-binding\n")
