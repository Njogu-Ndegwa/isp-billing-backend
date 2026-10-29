"""Remote AP control: adapters, the /tool-fetch transport, orchestration and
the HTTP endpoints. Nothing here touches a real network -- a fake MikroTik
simulates ``/tool fetch`` responses coming from a fake Tenda AP.
"""
import copy
import json
from datetime import timedelta
from urllib.parse import parse_qs

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.config import settings
from app.db.models import ResellerStaff, RouterApCredential, StaffActivityLog, UserRole
from app.services import ap_access, ap_adapters, ap_control, ap_fetch
from app.services import staff_access, staff_permissions as perms
from app.services.ap_control import ApCredential
from app.services.auth import create_access_token, pwd_context
from app.services.payment_gateway import encrypt_credential
from tests.factories import make_reseller, make_router

ROUTER_IP = "10.0.5.9"
AP_MAC = "C8:3A:35:11:22:33"       # Tenda OUI (see device_classifier)
AP_PASSWORD = "letmein123"


# ---------------------------------------------------------------------------
# Fake Tenda AP (its web admin, reachable only at its current IP)
# ---------------------------------------------------------------------------

class FakeTenda:
    def __init__(self, *, ip="192.168.88.50", password=AP_PASSWORD, login_method="md5",
                 mode="router", dhcp_on=True, move_to=None, unreachable_after_move=False,
                 model="OAP1200 V2", firmware="V2.0.0.11"):
        self.ip = ip
        self.password = password
        self.login_method = login_method
        self.mode = mode
        self.dhcp_on = dhcp_on
        self.model = model
        self.firmware = firmware
        self.clients = 7
        self.authed = False
        self.rebooted = False
        self.move_to = move_to                       # IP setLan actually lands on
        self.unreachable_after_move = unreachable_after_move
        self.moved = False
        self.write_paths = []                         # goform setters we received

    def _status_json(self):
        return json.dumps({
            "deviceName": self.model, "softwareVersion": self.firmware,
            "lanIp": self.ip, "workMode": self.mode,
            "dhcpEnable": 1 if self.dhcp_on else 0, "clientCount": self.clients,
            "mac": AP_MAC,
        })

    def handle(self, host, method, path, data, cookie):
        """Return (http_status, body). host != self.ip => connection refused."""
        if host != self.ip:
            return None, ""     # unreachable: ROS fetch errors
        if path == "/login/Auth":
            submitted = (data or {}).get("password", "")
            expected = ap_adapters.encode_password(self.password, self.login_method)
            self.authed = submitted == expected
            return 302, ""       # Tenda answers login with a redirect
        if not self.authed:
            return 200, "<html>login</html>"   # not a JSON status
        # Status: serve both the AP-style and router-style endpoints.
        if path in ("/goform/getSysStatusInfo", "/goform/GetRouterStatus"):
            return 200, self._status_json()
        if path == "/goform/SysToolReboot":
            self.rebooted = True
            return 200, '{"errCode":0}'
        # Work-mode setters (OAP1200 and F3 spellings).
        if path in ("/goform/setWorkMode", "/goform/setWifiWorkMode"):
            self.write_paths.append(path)
            self.mode = "ap"
            return 200, '{"errCode":0}'
        # DHCP-off setters.
        if path in ("/goform/setLanDhcp", "/goform/SetLanCfg"):
            self.write_paths.append(path)
            self.dhcp_on = False
            new_ip = (data or {}).get("lanIp") or (data or {}).get("ip")
            if path == "/goform/SetLanCfg" and new_ip:
                # F3 SetLanCfg carries both DHCP and the LAN IP.
                self.ip = "169.254.0.1" if self.unreachable_after_move else new_ip
                self.moved = True
            return 200, '{"errCode":0}'
        # LAN static-IP setters.
        if path in ("/goform/setLan",):
            self.write_paths.append(path)
            new_ip = self.move_to or (data or {}).get("ip") or self.ip
            self.ip = "169.254.0.1" if self.unreachable_after_move else new_ip
            self.moved = True
            return 200, '{"errCode":0}'
        return 404, "not found"


# ---------------------------------------------------------------------------
# Fake MikroTik: router tables + /tool fetch bridging to the FakeTenda
# ---------------------------------------------------------------------------

def _router_tables(gateway="192.168.88.1"):
    return {
        "/ip/hotspot/print": [{"name": "hs1", "interface": "bridge", "disabled": "false"}],
        "/ip/address/print": [
            {"address": f"{gateway}/24", "interface": "bridge"},
            {"address": f"{ROUTER_IP}/16", "interface": "wireguard1"},
        ],
        "/ip/pool/print": [{"name": "hs-pool", "ranges": "192.168.88.10-192.168.88.254"}],
        "/ip/dhcp-server/print": [{"interface": "bridge", "address-pool": "hs-pool"}],
        "/ip/dhcp-server/network/print": [{"gateway": gateway, "dns-server": gateway}],
        "/ip/dhcp-server/lease/print": [
            {"mac-address": AP_MAC, "address": "192.168.88.50", "host-name": "Tenda"},
            {"mac-address": "AA:BB:CC:00:00:01", "address": "192.168.88.60", "host-name": "phone"},
            {"mac-address": "AA:BB:CC:00:00:02", "address": "192.168.88.61", "host-name": "laptop"},
        ],
        "/ip/arp/print": [
            {"mac-address": AP_MAC, "address": "192.168.88.50"},
            {"mac-address": "AA:BB:CC:00:00:01", "address": "192.168.88.60"},
        ],
        "/ip/hotspot/host/print": [
            {"mac-address": "AA:BB:CC:00:00:01", "address": "192.168.88.60"},
        ],
        "/ip/neighbor/print": [
            {"mac-address": AP_MAC, "address": "192.168.88.50", "identity": "Tenda"},
        ],
    }


class FakeMikroTik:
    def __init__(self, tenda, *, tables=None, connect_ok=True):
        self.tenda = tenda
        self.tables = copy.deepcopy(tables if tables is not None else _router_tables())
        self.connect_ok = connect_ok
        self.connected = False
        self.last_connect_error = None
        self.fetches = []
        self.mutating_router_calls = []

    def factory(self, *_a, **_k):
        return self

    def connect(self):
        self.connected = self.connect_ok
        return self.connect_ok

    def disconnect(self):
        self.connected = False

    def send_command_optimized(self, command, proplist=None, query=None):
        return self.send_command(command)

    def send_command(self, command, arguments=None):
        if command == "/tool/fetch":
            return self._fetch(arguments or {})
        if command.endswith("/print"):
            return {"success": True, "data": copy.deepcopy(self.tables.get(command, []))}
        # Any non-print, non-fetch command would be a router mutation -> record it
        # so the tests can assert we never change the MikroTik's own config.
        self.mutating_router_calls.append((command, dict(arguments or {})))
        return {"success": True, "data": []}

    def _fetch(self, params):
        self.fetches.append(dict(params))
        url = params.get("url", "")
        # http://host/path
        rest = url.split("://", 1)[-1]
        host, _, path = rest.partition("/")
        path = "/" + path
        method = params.get("http-method", "get")
        data = {k: v[0] for k, v in parse_qs(params.get("http-data", "")).items()}
        cookie = None
        for field in (params.get("http-header-field", "") or "").split(","):
            if field.strip().lower().startswith("cookie:"):
                cookie = field.split(":", 1)[1].strip()
        status, body = self.tenda.handle(host, method, path, data, cookie)
        if status is None:
            return {"error": "closing connection: <timeout>"}
        if status in (301, 302, 303, 307):
            return {"error": f"closing connection: <{status} found>"}
        if status >= 400:
            return {"error": f"closing connection: <{status}>"}
        return {"success": True, "data": [{"data": body, "status": "finished"}]}


ROUTER_INFO = {"ip": ROUTER_IP, "username": "admin", "password": "x", "port": 8728}


def _cred(**over):
    base = dict(ap_mac=AP_MAC, ap_ip=None, username="admin", password=AP_PASSWORD,
                vendor="Tenda", model="OAP1200V2", login_method=None, failed_login_count=0)
    base.update(over)
    return ApCredential(**base)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(ap_control, "_sleep", lambda _s: None)
    # Most tests exercise the feature as an owner; open the gate to everyone and
    # let the dedicated gate tests tighten it back to "admins".
    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "all")
    ap_control.reset_claims()
    yield
    ap_control.reset_claims()


def run(fake, fn, cred=None, **kw):
    return fn(ROUTER_INFO, *( [cred] if cred is not None else [] ),
              api_factory=fake.factory, **kw)


# ---------------------------------------------------------------------------
# Adapter + transport unit tests
# ---------------------------------------------------------------------------

def test_login_attempts_md5_then_base64():
    ad = ap_adapters.get_adapter("OAP1200V2")
    atts = ad.login_attempts("admin", "pw")
    assert [a.method for a in atts] == ["md5", "base64"]
    import hashlib, base64
    assert atts[0].post_data["password"] == hashlib.md5(b"pw").hexdigest()
    assert atts[1].post_data["password"] == base64.b64encode(b"pw").decode()
    # preferred method floats to the front
    assert ad.login_attempts("admin", "pw", preferred="base64")[0].method == "base64"


def test_f3_adapter_is_selected_and_has_its_own_write_payloads():
    ad = ap_adapters.get_adapter("F3")
    assert ad.model == "F3" and ad.vendor == "Tenda"
    # shares the confirmed login + reboot paths
    assert ad.login_path == "/login/Auth" and ad.reboot_path == "/goform/SysToolReboot"
    # F3 tries its router status endpoint plus the AP one
    paths = [r.path for r in ad.status_requests()]
    assert paths[0] == "/goform/GetRouterStatus" and "/goform/getSysStatusInfo" in paths
    # make-safe payloads differ from the OAP1200's
    oap = ap_adapters.get_adapter("OAP1200V2")
    assert ad.set_lan_static_requests("192.168.88.2", "255.255.255.0", "192.168.88.1", "192.168.88.1")[0].data \
        != oap.set_lan_static_requests("192.168.88.2", "255.255.255.0", "192.168.88.1", "192.168.88.1")[0].data


def test_model_detection_from_status_text():
    assert ap_adapters.detect_model_key("Tenda F3") == "F3"
    assert ap_adapters.detect_model_key("OAP1200 V2") == "OAP1200V2"
    assert ap_adapters.detect_model_key("AC10") is None
    assert ap_adapters.detect_model_key(None) is None


def test_parse_status_normalises_mode_and_dhcp():
    ad = ap_adapters.get_adapter("OAP1200V2")
    body = json.dumps({"deviceName": "OAP1200 V2", "softwareVersion": "V2.0.0.11",
                       "lanIp": "192.168.88.50", "workMode": "router", "dhcpEnable": 1,
                       "clientCount": "5", "mac": AP_MAC})
    s = ad.parse_status(body, ap_fetch.parse_json_body)
    assert s.mode == ap_adapters.MODE_ROUTER and s.dhcp_server_on is True
    assert s.client_count == 5 and s.firmware == "V2.0.0.11"
    assert not s.is_safe_ap()
    s2 = ad.parse_status(json.dumps({"workMode": "ap", "dhcpEnable": 0}), ap_fetch.parse_json_body)
    assert s2.is_safe_ap()


def test_reply_ok_and_json_parse():
    assert ap_fetch.reply_ok('{"errCode":0}')
    assert not ap_fetch.reply_ok('{"errCode":1}')
    assert ap_fetch.reply_ok("")           # empty 200 (reboot)
    assert ap_fetch.parse_json_body("junk{\"errCode\":0}tail") == {"errCode": 0}


def test_fetch_redirect_is_reachable_not_failure():
    tenda = FakeTenda()
    fake = FakeMikroTik(tenda)
    fake.connect()
    client = ap_fetch.RouterFetchHttpClient(fake, tenda.ip)
    resp = client.request(ap_adapters.ApRequest("post", "/login/Auth", {"username": "admin", "password": "x"}))
    assert resp.ok and resp.redirected and resp.status == 302


# ---------------------------------------------------------------------------
# Orchestration: status / reboot / make-safe / lockout / gateway / unreachable
# ---------------------------------------------------------------------------

def test_status_login_ok_reads_router_mode():
    tenda = FakeTenda(mode="router", dhcp_on=True)
    fake = FakeMikroTik(tenda)
    res = run(fake, ap_control.read_status_sync, _cred())
    assert res["success"] and res["login_ok"] and res["login_method"] == "md5"
    assert res["status"]["mode"] == "router" and res["status"]["dhcp_server_on"] is True
    assert res["status"]["ip"] == "192.168.88.50"
    assert fake.mutating_router_calls == []        # never changed the MikroTik


def test_status_tries_base64_when_md5_fails():
    tenda = FakeTenda(login_method="base64")
    fake = FakeMikroTik(tenda)
    res = run(fake, ap_control.read_status_sync, _cred())
    assert res["success"] and res["login_method"] == "base64"


def test_wrong_password_fails_login_without_touching_ap_config():
    tenda = FakeTenda(password="different")
    fake = FakeMikroTik(tenda)
    res = run(fake, ap_control.read_status_sync, _cred())
    assert res["error"] == "login_failed" and res["login_ok"] is False
    assert not tenda.rebooted


def test_lockout_stops_further_logins():
    tenda = FakeTenda()
    fake = FakeMikroTik(tenda)
    res = run(fake, ap_control.read_status_sync, _cred(failed_login_count=ap_control.MAX_FAILED_LOGINS))
    assert res["error"] == "login_locked" and res["locked"]
    assert fake.fetches == []                      # we didn't even try the AP


def test_reboot_sends_reboot_after_login():
    tenda = FakeTenda()
    fake = FakeMikroTik(tenda)
    res = run(fake, ap_control.reboot_ap_sync, _cred())
    assert res["success"] and tenda.rebooted
    assert fake.mutating_router_calls == []


def test_make_safe_sets_mode_dhcp_and_static_ip_then_verifies():
    tenda = FakeTenda(mode="router", dhcp_on=True)
    fake = FakeMikroTik(tenda)
    res = run(fake, ap_control.make_safe_ap_sync, _cred())
    assert res["success"], res
    # .2 is the first host above the gateway and outside the pool (pool starts .10)
    assert res["new_ip"] == "192.168.88.2"
    assert res["gateway"] == "192.168.88.1"
    assert res["verified_safe"] is True
    assert tenda.mode == "ap" and tenda.dhcp_on is False and tenda.ip == "192.168.88.2"
    labels = [s["step"] for s in res["steps"]]
    assert labels == ["work_mode_ap", "dhcp_off", "lan_static"]
    assert fake.mutating_router_calls == []


def test_make_safe_detects_f3_and_uses_its_payloads():
    tenda = FakeTenda(model="Tenda F3", firmware="V12.01.01.09", mode="router", dhcp_on=True)
    fake = FakeMikroTik(tenda)
    res = run(fake, ap_control.make_safe_ap_sync, _cred(model=None))  # model unknown -> detect
    assert res["success"], res
    assert res["new_ip"] == "192.168.88.2" and res["verified_safe"] is True
    # F3-specific setters were used, not the OAP1200 ones
    assert "/goform/setWifiWorkMode" in tenda.write_paths
    assert "/goform/SetLanCfg" in tenda.write_paths
    assert "/goform/setWorkMode" not in tenda.write_paths


def test_make_safe_reports_when_ap_vanishes_at_new_ip():
    tenda = FakeTenda(mode="router", dhcp_on=True, unreachable_after_move=True)
    fake = FakeMikroTik(tenda)
    res = run(fake, ap_control.make_safe_ap_sync, _cred())
    assert res["error"] == "verify_unreachable"
    assert res["new_ip"] == "192.168.88.2"


def test_ap_on_gateway_is_on_site_fix():
    tenda = FakeTenda(ip="192.168.88.1")           # AP sits ON the router gateway
    fake = FakeMikroTik(tenda)
    # ARP/lease still map the MAC to the gateway IP
    fake.tables["/ip/dhcp-server/lease/print"][0]["address"] = "192.168.88.1"
    fake.tables["/ip/arp/print"][0]["address"] = "192.168.88.1"
    res = run(fake, ap_control.make_safe_ap_sync, _cred())
    assert res["error"] == "on_gateway" and res["on_gateway"]
    assert fake.fetches == []                       # never tried to log in


def test_make_safe_unreachable_precheck():
    tenda = FakeTenda()
    fake = FakeMikroTik(tenda)
    # Make the AP answer login (redirect) but then be unreachable for status:
    # simulate by pointing discovery at an IP the AP is not serving.
    res = run(fake, ap_control.make_safe_ap_sync, _cred(ap_ip="192.168.88.99"))
    assert res["error"] in ("login_failed", "ap_unreachable")


def test_discovery_lists_tenda_and_flags_router_mode_suspect():
    tenda = FakeTenda()
    fake = FakeMikroTik(tenda)
    # a device claiming a foreign gateway identity (router-mode suspect)
    fake.tables["/ip/arp/print"].append({"mac-address": "DE:AD:BE:EF:00:01", "address": "192.168.0.1"})
    res = ap_control.discover_aps_sync(ROUTER_INFO, api_factory=fake.factory)
    assert res["success"] and res["gateway"] == "192.168.88.1"
    by_mac = {d["mac"]: d for d in res["devices"]}
    assert AP_MAC in by_mac and by_mac[AP_MAC]["vendor"] == "Tenda"
    assert "dhcp_lease" in by_mac[AP_MAC]["sources"]
    assert by_mac["DE:AD:BE:EF:00:01"]["router_mode_suspect"] is True


def test_pick_static_ip_skips_gateway_and_pool():
    lan = ap_control.HotspotLan(gateway="192.168.88.1", prefixlen=24,
                                pool_ranges="192.168.88.10-192.168.88.254")
    assert ap_control.pick_static_ip(lan) == "192.168.88.2"


def test_detector_flags():
    assert ap_control.detector_flags({"mode": "router", "dhcp_server_on": False})["needs_safe_ap"]
    assert ap_control.detector_flags({"mode": "ap", "dhcp_server_on": True})["needs_safe_ap"]
    assert ap_control.detector_flags(None, on_gateway=True)["needs_safe_ap"]
    assert not ap_control.detector_flags({"mode": "ap", "dhcp_server_on": False})["needs_safe_ap"]


def test_connect_failure_surfaces():
    tenda = FakeTenda()
    fake = FakeMikroTik(tenda, connect_ok=False)
    res = run(fake, ap_control.read_status_sync, _cred())
    assert res["error"] == "connect_failed"


# ---------------------------------------------------------------------------
# Endpoints: auth, permissions, lock, audit, 404
# ---------------------------------------------------------------------------

def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def patch_router(monkeypatch):
    holder = {}

    def factory(*_a, **_k):
        return holder["fake"]

    def install(tenda, **kw):
        fake = FakeMikroTik(tenda, **kw)
        holder["fake"] = fake
        return fake

    monkeypatch.setattr(ap_control, "_make_api", lambda info, af: holder["fake"])
    monkeypatch.setattr(ap_control, "_sleep", lambda _s: None)
    staff_access.reset_cache()
    yield install
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


def _owner_token(owner):
    return create_access_token(login_token_claims(owner), timedelta(hours=1))


async def _staff(db, owner, permissions):
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Tech", email=f"tech{len(permissions)}@example.com",
        password_hash=pwd_context.hash("x"), permissions=permissions,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    return staff, create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))


async def _saved_cred(db, router_id, **over):
    row = RouterApCredential(
        router_id=router_id, ap_mac=AP_MAC, vendor="Tenda", model="OAP1200V2",
        username="admin", password_encrypted=encrypt_credential(AP_PASSWORD),
        failed_login_count=0,
    )
    for k, v in over.items():
        setattr(row, k, v)
    db.add(row)
    await db.commit()
    return row


def test_gate_helper_admins_vs_all(monkeypatch):
    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "admins")
    assert ap_access.ap_control_allowed("admin") is True
    assert ap_access.ap_control_allowed(UserRole.ADMIN) is True
    assert ap_access.ap_control_allowed("reseller") is False
    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "all")
    assert ap_access.ap_control_allowed("reseller") is True


@pytest.mark.asyncio
async def test_reseller_blocked_when_scope_is_admins(client, db, patch_router, monkeypatch):
    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "admins")
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    patch_router(FakeTenda())
    for method, path, kw in [
        ("get", f"/api/routers/{router.id}/access-points", {}),
        ("post", f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot", {"json": {"confirm": True}}),
    ]:
        resp = await getattr(client, method)(path, headers=headers(_owner_token(owner)), **kw)
        assert resp.status_code == 403, (path, resp.text)
        assert resp.json()["detail"]["code"] == "ap_control_disabled"


@pytest.mark.asyncio
async def test_admin_allowed_when_scope_is_admins(client, db, patch_router, monkeypatch):
    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "admins")
    admin = await make_reseller(db, role=UserRole.ADMIN, organization_name="Bitwave")
    router = await make_router(db, admin, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    patch_router(FakeTenda())
    token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(token), json={"confirm": True},
    )
    assert resp.status_code == 200, resp.text


def test_staff_rules():
    rule, params = perms.match_rule("POST", f"/api/routers/7/access-points/{AP_MAC}/reboot")
    assert rule.requirement == "routers.manage"
    assert params == {"router_id": "7", "ap_mac": AP_MAC}
    view, _ = perms.match_rule("GET", "/api/routers/7/access-points")
    assert view.requirement == "routers.view"
    save, _ = perms.match_rule("PUT", f"/api/routers/7/access-points/{AP_MAC}/credential")
    assert save.requirement == "routers.manage"


@pytest.mark.asyncio
async def test_save_credential_is_write_only_and_clears_lock(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    resp = await client.put(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/credential",
        headers=headers(_owner_token(owner)),
        json={"password": "secretpw", "model": "OAP1200V2"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()["credential"]
    assert body["has_password"] is True
    assert "secretpw" not in resp.text      # the secret is never returned
    assert body["locked"] is False
    row = (await db.execute(select(RouterApCredential))).scalar_one()
    assert row.password_encrypted and row.password_encrypted != "secretpw"


@pytest.mark.asyncio
async def test_owner_reboot_is_audited(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    patch_router(FakeTenda())
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert resp.status_code == 200, resp.text
    rows = (await db.execute(select(StaffActivityLog).where(StaffActivityLog.owner_id == owner.id))).scalars().all()
    assert len(rows) == 1 and rows[0].status_code == 200
    assert AP_MAC in rows[0].summary and "ok" in rows[0].summary.lower()


@pytest.mark.asyncio
async def test_reboot_needs_confirm(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    fake = patch_router(FakeTenda())
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(_owner_token(owner)), json={},
    )
    assert resp.status_code == 400
    assert fake.fetches == []


@pytest.mark.asyncio
async def test_locked_credential_returns_423(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id, failed_login_count=ap_control.MAX_FAILED_LOGINS)
    patch_router(FakeTenda())
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert resp.status_code == 423


@pytest.mark.asyncio
async def test_failed_login_increments_lock_counter(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    patch_router(FakeTenda(password="wrong"))
    resp = await client.get(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/status",
        headers=headers(_owner_token(owner)),
    )
    assert resp.status_code == 502
    row = (await db.execute(select(RouterApCredential))).scalar_one()
    assert row.failed_login_count == 1 and row.last_login_ok is False


@pytest.mark.asyncio
async def test_make_safe_endpoint(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    patch_router(FakeTenda(mode="router", dhcp_on=True))
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/make-safe",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["new_ip"] == "192.168.88.2"
    assert resp.json()["verified_safe"] is True


@pytest.mark.asyncio
async def test_staff_with_view_cannot_reboot(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    patch_router(FakeTenda())
    staff, token = await _staff(db, owner, ["routers.view"])
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(token), json={"confirm": True},
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "staff_permission_denied"
    # but may list
    listing = await client.get(f"/api/routers/{router.id}/access-points", headers=headers(token))
    assert listing.status_code == 200, listing.text


@pytest.mark.asyncio
async def test_staff_with_manage_can_reboot(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    patch_router(FakeTenda())
    staff, token = await _staff(db, owner, ["routers.view", "routers.manage"])
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(token), json={"confirm": True},
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_other_reseller_gets_404(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    other = await make_reseller(db)
    patch_router(FakeTenda())
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(_owner_token(other)), json={"confirm": True},
    )
    assert resp.status_code == 404
    listing = await client.get(f"/api/routers/{router.id}/access-points", headers=headers(_owner_token(other)))
    assert listing.status_code == 404


@pytest.mark.asyncio
async def test_second_ap_action_gets_409(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    await _saved_cred(db, router.id)
    patch_router(FakeTenda())
    held = ap_control.try_claim(router.id)
    resp = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert resp.status_code == 409
    ap_control.release_claim(held)
    again = await client.post(
        f"/api/routers/{router.id}/access-points/{AP_MAC}/reboot",
        headers=headers(_owner_token(owner)), json={"confirm": True},
    )
    assert again.status_code == 200, again.text


def test_ap_outside_hotspot_subnet_is_refused_without_contacting_it():
    # A factory-fresh Tenda on 192.168.0.1: fetch would leave via the WAN.
    tenda = FakeTenda(ip="192.168.0.1")
    fake = FakeMikroTik(tenda)
    for fn in (ap_control.read_status_sync, ap_control.reboot_ap_sync, ap_control.make_safe_ap_sync):
        res = run(fake, fn, _cred(ap_ip="192.168.0.1"))
        assert res["error"] == "not_on_hotspot_lan", (fn.__name__, res)
    assert fake.fetches == []          # never sent anything (or the password) anywhere
