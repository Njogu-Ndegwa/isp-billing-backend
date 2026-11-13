"""Remote "restart access point" = power-cycle / bounce one MikroTik LAN port.

Every router call goes to FakeRouterOS below; nothing here touches a network.
"""
import copy
from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.db.models import ResellerStaff, StaffActivityLog
from app.services import port_restart, staff_access, staff_permissions as perms
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_reseller, make_router

ROUTER_IP = "10.0.3.7"

MUTATING = {
    "/interface/disable", "/interface/enable",
    "/interface/ethernet/poe/set", "/interface/ethernet/poe/power-cycle",
}


def _iface(id_, name, type_="ether", disabled=False):
    return {".id": id_, "name": name, "type": type_, "disabled": str(disabled).lower(), "running": "true"}


BASE_TABLES = {
    "/interface/print": [
        _iface("*1", "ether1"),                       # WAN by convention + DHCP client
        _iface("*2", "ether2"),                       # hotspot, PoE auto-on -> poe
        _iface("*3", "ether3"),                       # hotspot, PoE off -> bounce
        _iface("*4", "ether4"),                       # plain bridge, no PoE -> bounce
        _iface("*5", "ether5"),                       # no bridge, no server -> not LAN
        _iface("*6", "ether6"),                       # default route via 192.168.20.1
        _iface("*7", "ether7"),                       # PPPoE client uplink
        _iface("*8", "ether8"),                       # our API session comes in here
        _iface("*9", "ether9"),                       # load-balancer WAN (from the DB)
        _iface("*A", "ether10", disabled=True),       # hotspot but turned off
        _iface("*B", "ether11"),                      # direct PPPoE server port
        _iface("*C", "ether12"),                      # in a non-customer bridge
        _iface("*D", "wlan1", "wlan"),                # wireless in the hotspot bridge
        _iface("*E", "wireguard1", "wg"),             # management tunnel
        _iface("*F", "bridge", "bridge"),
        _iface("*10", "bridge-plain", "bridge"),
        _iface("*11", "bridge-lab", "bridge"),
        _iface("*12", "pppoe-out1", "pppoe-out"),
    ],
    "/interface/bridge/port/print": [
        {"interface": "ether2", "bridge": "bridge"},
        {"interface": "ether3", "bridge": "bridge"},
        {"interface": "ether10", "bridge": "bridge"},
        {"interface": "wlan1", "bridge": "bridge"},
        {"interface": "ether4", "bridge": "bridge-plain"},
        {"interface": "ether12", "bridge": "bridge-lab"},
    ],
    "/ip/route/print": [
        {"dst-address": "0.0.0.0/0", "gateway": "192.168.20.1", "disabled": "false"},
        {"dst-address": "10.0.0.0/16", "gateway": "wireguard1", "disabled": "false"},
    ],
    "/ip/address/print": [
        {"address": "192.168.88.1/24", "interface": "bridge"},
        {"address": "192.168.20.2/24", "interface": "ether6"},
        {"address": "172.16.5.1/24", "interface": "ether8"},
        {"address": f"{ROUTER_IP}/16", "interface": "wireguard1"},
    ],
    "/ip/dhcp-client/print": [{"interface": "ether1", "disabled": "false"}],
    "/interface/pppoe-client/print": [{"name": "pppoe-out1", "interface": "ether7", "disabled": "false"}],
    "/interface/vlan/print": [],
    "/user/active/print": [
        {"name": "admin", "address": "10.0.0.1", "via": "api"},
        {"name": "admin", "address": "172.16.5.10", "via": "api"},
        {"name": "owner", "address": "192.168.88.50", "via": "winbox"},
    ],
    "/ip/hotspot/print": [{"name": "hotspot1", "interface": "bridge", "disabled": "false"}],
    "/interface/pppoe-server/server/print": [{"service-name": "pppoe", "interface": "ether11", "disabled": "false"}],
    "/interface/ethernet/poe/print": [
        {".id": "*2", "name": "ether2", "poe-out": "auto-on"},
        {".id": "*3", "name": "ether3", "poe-out": "off"},
    ],
}


class FakeRouterOS:
    """Just enough RouterOS API for the port-restart path."""

    def __init__(self, *, power_cycle=True, fail=None, poe_menu=True):
        self.tables = copy.deepcopy(BASE_TABLES)
        if not poe_menu:
            del self.tables["/interface/ethernet/poe/print"]
        self.power_cycle = power_cycle
        self.fail = dict(fail or {})   # command -> list of errors to return in turn
        self.calls = []
        self.connected = False
        self.connects = 0
        self.last_connect_error = None

    def factory(self, *_args, **_kwargs):
        return self

    def connect(self):
        self.connects += 1
        self.connected = True
        return True

    def disconnect(self):
        self.connected = False

    def mutations(self):
        return [(c, a) for c, a in self.calls if c in MUTATING]

    def iface(self, name):
        return next(r for r in self.tables["/interface/print"] if r["name"] == name)

    def poe(self, name):
        return next(r for r in self.tables["/interface/ethernet/poe/print"] if r["name"] == name)

    def send_command_optimized(self, command, proplist=None, query=None):
        return self.send_command(command)

    def send_command(self, command, arguments=None):
        self.calls.append((command, dict(arguments or {})))
        if not self.connected:
            return {"error": "Not connected"}
        queued = self.fail.get(command)
        if queued:
            error = queued.pop(0)
            if error == "drop":
                self.connected = False
                return {"error": "Not connected"}
            return {"error": error}
        if command.endswith("/print"):
            if command not in self.tables:
                return {"error": "no such command prefix"}
            return {"success": True, "data": copy.deepcopy(self.tables[command])}
        args = arguments or {}
        if command in ("/interface/disable", "/interface/enable"):
            row = next(r for r in self.tables["/interface/print"] if args["numbers"] in (r[".id"], r["name"]))
            row["disabled"] = "true" if command.endswith("disable") else "false"
            return {"success": True, "data": []}
        if command == "/interface/ethernet/poe/set":
            row = next(r for r in self.tables["/interface/ethernet/poe/print"] if args["numbers"] in (r[".id"], r["name"]))
            row["poe-out"] = args["poe-out"]
            return {"success": True, "data": []}
        if command == "/interface/ethernet/poe/power-cycle":
            if not self.power_cycle:
                return {"error": "no such command"}
            return {"success": True, "data": []}
        return {"error": f"unexpected command {command}"}


INFO = {"ip": ROUTER_IP, "username": "api", "password": "pw", "port": 8728, "lb_wan_ports": ["ether9"]}


def run(fake, port, **kwargs):
    kwargs.setdefault("sleep", lambda _s: None)
    return port_restart.restart_port_sync(INFO, port, api_factory=fake.factory, **kwargs)


@pytest.fixture(autouse=True)
def _clean_claims():
    port_restart.reset_claims()
    yield
    port_restart.reset_claims()


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("port,code", [
    ("ether1", port_restart.REASON_WAN),             # convention + DHCP client
    ("ether6", port_restart.REASON_WAN),             # default route gateway subnet
    ("ether7", port_restart.REASON_WAN),             # PPPoE client parent
    ("ether9", port_restart.REASON_WAN),             # load-balancer WAN
    ("wireguard1", port_restart.REASON_MANAGEMENT),  # holds the address we connect to
    ("ether8", port_restart.REASON_API_INGRESS),     # our API session arrives here
    ("wlan1", port_restart.REASON_NOT_ETHERNET),
    ("bridge", port_restart.REASON_NOT_ETHERNET),
    ("ether5", port_restart.REASON_NOT_LAN),
    ("ether12", port_restart.REASON_NOT_LAN),
    ("ether10", port_restart.REASON_DISABLED),
    ("ether99", port_restart.REASON_NOT_FOUND),
])
def test_guarded_ports_are_refused_without_touching_the_router(port, code):
    fake = FakeRouterOS()
    result = run(fake, port)
    assert result["error"] == "refused"
    assert result["reason_code"] == code
    assert result["message"]
    assert fake.mutations() == []


def test_options_list_matches_the_guards():
    fake = FakeRouterOS()
    result = port_restart.restart_options_sync(INFO, api_factory=fake.factory)
    by_name = {p["name"]: p for p in result["ports"]}
    assert by_name["ether2"]["eligible"] and by_name["ether2"]["method"] == "poe"
    assert by_name["ether3"]["eligible"] and by_name["ether3"]["method"] == "bounce"
    assert by_name["ether4"]["eligible"] and by_name["ether4"]["method"] == "bounce"
    assert by_name["ether11"]["eligible"]  # direct PPPoE port
    assert by_name["ether1"]["reason_code"] == port_restart.REASON_WAN
    assert by_name["ether8"]["reason_code"] == port_restart.REASON_API_INGRESS
    assert "wlan1" not in by_name and "wireguard1" not in by_name  # ethernet only
    assert fake.mutations() == []


def test_pppoe_client_default_route_guards_its_physical_port():
    fake = FakeRouterOS()
    fake.tables["/ip/dhcp-client/print"] = []
    fake.tables["/interface/pppoe-client/print"] = [{"name": "pppoe-out1", "interface": "ether3", "disabled": "true"}]
    fake.tables["/ip/route/print"] = [{"dst-address": "0.0.0.0/0", "gateway": "pppoe-out1"}]
    result = run(fake, "ether3")
    assert result["reason_code"] == port_restart.REASON_WAN


def test_ros7_immediate_gw_and_wan_bridge_members_are_guarded():
    fake = FakeRouterOS()
    fake.tables["/ip/route/print"] = [
        {"dst-address": "0.0.0.0/0", "gateway": "192.168.30.1", "immediate-gw": "192.168.30.1%bridge-lab"},
    ]
    result = run(fake, "ether12")
    assert result["reason_code"] == port_restart.REASON_WAN


def test_dhcp_client_on_the_lan_bridge_guards_every_member():
    fake = FakeRouterOS()
    fake.tables["/ip/dhcp-client/print"].append({"interface": "bridge", "disabled": "false"})
    assert run(fake, "ether2")["reason_code"] == port_restart.REASON_WAN
    assert fake.mutations() == []


def test_management_address_on_an_ethernet_port_is_guarded():
    fake = FakeRouterOS()
    fake.tables["/ip/address/print"] = [{"address": f"{ROUTER_IP}/24", "interface": "ether4"}]
    assert run(fake, "ether4")["reason_code"] == port_restart.REASON_MANAGEMENT


def test_unreadable_route_table_fails_closed():
    fake = FakeRouterOS(fail={"/ip/route/print": ["timeout"]})
    result = run(fake, "ether3")
    assert result["error"] == "state_unreadable"
    assert fake.mutations() == []


# ---------------------------------------------------------------------------
# PoE path
# ---------------------------------------------------------------------------

def test_poe_port_uses_power_cycle_when_routeros_has_it():
    fake = FakeRouterOS()
    slept = []
    result = run(fake, "ether2", sleep=slept.append)
    assert result["success"] is True
    assert result["method"] == port_restart.METHOD_POE_POWER_CYCLE
    assert fake.mutations() == [
        ("/interface/ethernet/poe/power-cycle", {"numbers": "*2", "duration": f"{port_restart.POE_OFF_SECONDS}s"}),
    ]
    assert slept and slept[0] >= port_restart.POE_OFF_SECONDS
    assert fake.poe("ether2")["poe-out"] == "auto-on"


@pytest.mark.parametrize("original", ["auto-on", "forced-on"])
def test_poe_port_falls_back_to_off_then_previous_setting(original):
    fake = FakeRouterOS(power_cycle=False)
    fake.poe("ether2")["poe-out"] = original
    result = run(fake, "ether2")
    assert result["success"] is True
    assert result["method"] == port_restart.METHOD_POE_TOGGLE
    assert [m for m in fake.mutations() if m[0] == "/interface/ethernet/poe/set"] == [
        ("/interface/ethernet/poe/set", {"numbers": "*2", "poe-out": "off"}),
        ("/interface/ethernet/poe/set", {"numbers": "*2", "poe-out": original}),
    ]
    assert fake.poe("ether2")["poe-out"] == original
    assert not any(c == "/interface/disable" for c, _ in fake.mutations())


def test_poe_restored_even_when_the_wait_blows_up():
    fake = FakeRouterOS(power_cycle=False)

    def boom(_seconds):
        raise RuntimeError("worker interrupted")

    result = run(fake, "ether2", sleep=boom)
    assert result["error"] == "unexpected"
    assert fake.poe("ether2")["poe-out"] == "auto-on"


def test_poe_off_refused_changes_nothing():
    fake = FakeRouterOS(power_cycle=False, fail={"/interface/ethernet/poe/set": ["not permitted"]})
    result = run(fake, "ether2")
    assert result["error"] == "command_failed"
    assert fake.poe("ether2")["poe-out"] == "auto-on"


# ---------------------------------------------------------------------------
# Non-PoE path
# ---------------------------------------------------------------------------

def test_non_poe_port_is_disabled_then_enabled():
    fake = FakeRouterOS()
    slept = []
    result = run(fake, "ether3", sleep=slept.append)  # PoE row exists but poe-out=off
    assert result["success"] is True
    assert result["method"] == port_restart.METHOD_INTERFACE_BOUNCE
    assert fake.mutations() == [
        ("/interface/disable", {"numbers": "*3"}),
        ("/interface/enable", {"numbers": "*3"}),
    ]
    assert slept == [port_restart.BOUNCE_SECONDS]
    assert fake.iface("ether3")["disabled"] == "false"


def test_board_without_poe_menu_bounces():
    fake = FakeRouterOS(poe_menu=False)
    result = run(fake, "ether2")
    assert result["method"] == port_restart.METHOD_INTERFACE_BOUNCE
    assert fake.iface("ether2")["disabled"] == "false"


def test_bounce_restored_even_when_the_wait_blows_up():
    fake = FakeRouterOS()

    def boom(_seconds):
        raise RuntimeError("worker interrupted")

    result = run(fake, "ether4", sleep=boom)
    assert result["error"] == "unexpected"
    assert fake.iface("ether4")["disabled"] == "false"


def test_restore_reconnects_when_the_connection_dropped():
    fake = FakeRouterOS(fail={"/interface/enable": ["drop"]})
    result = run(fake, "ether4")
    assert result["success"] is True
    assert fake.connects == 2
    assert fake.iface("ether4")["disabled"] == "false"


def test_restore_that_never_succeeds_is_reported():
    fake = FakeRouterOS(fail={"/interface/enable": ["busy"] * port_restart.RESTORE_ATTEMPTS})
    result = run(fake, "ether4")
    assert result["error"] == "restore_failed"
    assert "ether4" in result["message"]
    assert len([c for c, _ in fake.mutations() if c == "/interface/enable"]) == port_restart.RESTORE_ATTEMPTS


# ---------------------------------------------------------------------------
# One restart per router
# ---------------------------------------------------------------------------

def test_claim_is_exclusive_per_router_and_released_by_the_worker():
    first = port_restart.try_claim(1)
    assert first is not None
    assert port_restart.try_claim(1) is None
    assert port_restart.try_claim(2) is not None
    run(FakeRouterOS(), "ether3", claim=first)
    assert port_restart.try_claim(1) is not None


def test_worker_that_starts_after_the_request_gave_up_does_nothing():
    claim = port_restart.try_claim(1)
    port_restart.abandon_if_not_started(claim)
    fake = FakeRouterOS()
    result = run(fake, "ether3", claim=claim)
    assert result["error"] == "cancelled"
    assert fake.calls == []


def test_running_worker_keeps_its_claim_when_the_request_times_out():
    claim = port_restart.try_claim(1)
    assert port_restart.begin_claim(claim)
    port_restart.abandon_if_not_started(claim)  # request timed out mid-restart
    assert port_restart.restart_in_progress(1)
    port_restart.release_claim(claim)
    assert not port_restart.restart_in_progress(1)


# ---------------------------------------------------------------------------
# Endpoint: auth, staff permission, lock, audit
# ---------------------------------------------------------------------------

def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def fake_router(monkeypatch):
    fake = FakeRouterOS()
    monkeypatch.setattr(port_restart, "_make_api", lambda _info, _factory: fake)
    monkeypatch.setattr(port_restart, "_sleep", lambda _s: None)
    staff_access.reset_cache()
    yield fake
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


async def _staff(db, owner, permissions):
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Tech", email=f"tech{len(permissions)}@example.com",
        password_hash=pwd_context.hash("x"), permissions=permissions,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    return staff, create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))


def _owner_token(owner):
    return create_access_token(login_token_claims(owner), timedelta(hours=1))


def test_staff_rules():
    rule, params = perms.match_rule("POST", "/api/routers/7/interfaces/ether3/restart")
    assert rule.requirement == "routers.manage"
    assert params == {"router_id": "7", "interface_name": "ether3"}
    assert not rule.allows(["routers.view"])
    view_rule, _ = perms.match_rule("GET", "/api/routers/7/interfaces/restart-options")
    assert view_rule.requirement == "routers.view"


@pytest.mark.asyncio
async def test_owner_restarts_and_it_is_audited(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    response = await client.post(
        f"/api/routers/{router.id}/interfaces/ether2/restart",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert response.status_code == 200, response.text
    assert response.json()["method"] == port_restart.METHOD_POE_POWER_CYCLE
    rows = (await db.execute(select(StaffActivityLog).where(StaffActivityLog.owner_id == owner.id))).scalars().all()
    assert len(rows) == 1
    assert rows[0].staff_id is None
    assert rows[0].status_code == 200
    assert "ether2" in rows[0].summary and "PoE power-cycle" in rows[0].summary and ": ok" in rows[0].summary


@pytest.mark.asyncio
async def test_owner_needs_confirm(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    response = await client.post(
        f"/api/routers/{router.id}/interfaces/ether2/restart",
        headers=headers(_owner_token(owner)), json={},
    )
    assert response.status_code == 400
    assert fake_router.calls == []


@pytest.mark.asyncio
async def test_guard_refusal_is_400_with_reason(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    response = await client.post(
        f"/api/routers/{router.id}/interfaces/ether1/restart",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert response.status_code == 400
    assert "Internet port" in response.json()["detail"]
    assert fake_router.mutations() == []


@pytest.mark.asyncio
async def test_staff_with_manage_can_restart(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    staff, token = await _staff(db, owner, ["routers.view", "routers.manage"])
    response = await client.post(
        f"/api/routers/{router.id}/interfaces/ether3/restart", headers=headers(token), json={"confirm": True},
    )
    assert response.status_code == 200, response.text
    assert response.json()["method"] == port_restart.METHOD_INTERFACE_BOUNCE
    rows = (await db.execute(select(StaffActivityLog).where(StaffActivityLog.staff_id == staff.id))).scalars().all()
    assert len(rows) == 1 and rows[0].status_code == 200
    assert "port disable/enable" in rows[0].summary


@pytest.mark.asyncio
async def test_staff_with_view_only_is_denied_before_the_router(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    staff, token = await _staff(db, owner, ["routers.view"])
    response = await client.post(
        f"/api/routers/{router.id}/interfaces/ether3/restart", headers=headers(token), json={"confirm": True},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "staff_permission_denied"
    assert fake_router.calls == []
    options = await client.get(f"/api/routers/{router.id}/interfaces/restart-options", headers=headers(token))
    assert options.status_code == 200, options.text
    assert fake_router.mutations() == []


@pytest.mark.asyncio
async def test_other_reseller_gets_404(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    other = await make_reseller(db)
    response = await client.post(
        f"/api/routers/{router.id}/interfaces/ether3/restart",
        headers=headers(_owner_token(other)), json={"confirm": True},
    )
    assert response.status_code == 404
    options = await client.get(
        f"/api/routers/{router.id}/interfaces/restart-options", headers=headers(_owner_token(other)),
    )
    assert options.status_code == 404
    assert fake_router.calls == []


@pytest.mark.asyncio
async def test_second_restart_on_the_same_router_gets_409(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    held = port_restart.try_claim(router.id)
    response = await client.post(
        f"/api/routers/{router.id}/interfaces/ether3/restart",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert response.status_code == 409
    assert fake_router.calls == []
    port_restart.release_claim(held)
    again = await client.post(
        f"/api/routers/{router.id}/interfaces/ether3/restart",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert again.status_code == 200, again.text
    assert not port_restart.restart_in_progress(router.id)
