"""Remote control of a PPPoE customer's own router / CPE.

The device is a Tenda in router mode dialling the reseller's PPPoE server; we
reach it by resolving the customer's live PPPoE session on the MikroTik
(``/ppp active`` -> address) and ``/tool fetch`` to that IP on its
remote-management port. Nothing here touches a real network: a fake MikroTik
simulates ``/ppp active`` and bridges ``/tool fetch`` to a fake Tenda.
"""
import base64
import copy
import hashlib
import json
from datetime import timedelta
from urllib.parse import parse_qs

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.config import settings
from app.db.models import (
    ConnectionType, CustomerCpeCredential, StaffActivityLog, UserRole,
)
from app.services import ap_adapters, ap_control, cpe_control
from app.services import staff_access
from app.services.ap_control import ApCredential
from app.services.auth import create_access_token
from app.services.payment_gateway import encrypt_credential
from tests.factories import make_customer, make_plan, make_reseller, make_router

ROUTER_IP = "10.0.7.9"
PPPOE_USER = "pppoe_254795635368"
SESSION_IP = "10.90.0.14"          # the Tenda's WAN IP in the reseller's PPPoE pool
CPE_PASSWORD = "tendapass1"
WAN_PORT = 8888
DEVICE_MAC = "D8:32:14:03:B5:58"


# ---------------------------------------------------------------------------
# Fake Tenda CPE (its web admin, reachable only at its session IP:port)
# ---------------------------------------------------------------------------

class FakeTendaCpe:
    def __init__(self, *, ip=SESSION_IP, port=WAN_PORT, password=CPE_PASSWORD,
                 login_method="md5", mode="router", model="Tenda F3",
                 firmware="V12.01.01.09", answers=True):
        self.ip = ip
        self.port = port
        self.password = password
        self.login_method = login_method
        self.mode = mode
        self.model = model
        self.firmware = firmware
        self.answers = answers          # False => remote mgmt off / unreachable
        self.authed = False
        self.rebooted = False

    def _status_json(self):
        return json.dumps({
            "deviceName": self.model, "softwareVersion": self.firmware,
            "lanIp": "192.168.0.1", "workMode": self.mode, "dhcpEnable": 1,
            "wanIp": self.ip, "mac": DEVICE_MAC,
        })

    def handle(self, host, port, method, path, data, cookie):
        """(status, body). Wrong host/port, or not answering => unreachable."""
        if not self.answers or host != self.ip or int(port or 80) != int(self.port):
            return None, ""
        if path == "/login/Auth":
            submitted = (data or {}).get("password", "")
            self.authed = submitted == ap_adapters.encode_password(self.password, self.login_method)
            return 302, ""
        if not self.authed:
            return 200, "<html>login</html>"
        if path in ("/goform/GetRouterStatus", "/goform/getSysStatusInfo"):
            return 200, self._status_json()
        if path == "/goform/SysToolReboot":
            self.rebooted = True
            return 200, '{"errCode":0}'
        return 404, "not found"


# ---------------------------------------------------------------------------
# Fake MikroTik: /ppp active + /tool fetch bridging to the FakeTendaCpe
# ---------------------------------------------------------------------------

def _ppp_active(user=PPPOE_USER, address=SESSION_IP):
    rows = []
    if user is not None:
        rows.append({".id": "*1", "name": user, "address": address,
                     "uptime": "1h2m", "caller-id": DEVICE_MAC})
    rows.append({".id": "*2", "name": "someone_else", "address": "10.90.0.99",
                 "uptime": "3h", "caller-id": "AA:BB:CC:00:00:01"})
    return rows


class FakeMikroTik:
    def __init__(self, cpe, *, ppp_rows=None, connect_ok=True):
        self.cpe = cpe
        self.ppp_rows = copy.deepcopy(ppp_rows if ppp_rows is not None else _ppp_active())
        self.connect_ok = connect_ok
        self.connected = False
        self.last_connect_error = None
        self.commands = []
        self.fetches = []
        self.removed_sessions = []
        self.mutating_router_calls = []

    def factory(self, *_a, **_k):
        return self

    def connect(self):
        self.connected = self.connect_ok
        return self.connect_ok

    def disconnect(self):
        self.connected = False

    def send_command(self, command, arguments=None):
        self.commands.append(command)
        if command == "/tool/fetch":
            return self._fetch(arguments or {})
        if command == "/ppp/active/print":
            return {"success": True, "data": copy.deepcopy(self.ppp_rows)}
        if command == "/ppp/active/remove":
            self.removed_sessions.append((arguments or {}).get("numbers"))
            return {"success": True, "data": []}
        if command.endswith("/print"):
            return {"success": True, "data": []}
        self.mutating_router_calls.append((command, dict(arguments or {})))
        return {"success": True, "data": []}

    # Fallback "disconnect session" reuses the real API method name.
    def disconnect_pppoe_session(self, username):
        active = self.send_command("/ppp/active/print")
        disconnected = 0
        for row in active.get("data", []):
            if row.get("name") == username:
                self.send_command("/ppp/active/remove", {"numbers": row.get(".id")})
                disconnected += 1
        return {"success": True, "disconnected": disconnected}

    def _fetch(self, params):
        self.fetches.append(dict(params))
        url = params.get("url", "")
        rest = url.split("://", 1)[-1]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        path = "/" + path
        method = params.get("http-method", "get")
        data = {k: v[0] for k, v in parse_qs(params.get("http-data", "")).items()}
        status, body = self.cpe.handle(host, port or "80", method, path, data, None)
        if status is None:
            return {"error": "closing connection: <timeout>"}
        if status in (301, 302, 303, 307):
            return {"error": f"closing connection: <{status} found>"}
        if status >= 400:
            return {"error": f"closing connection: <{status}>"}
        return {"success": True, "data": [{"data": body, "status": "finished"}]}


ROUTER_INFO = {"ip": ROUTER_IP, "username": "admin", "password": "x", "port": 8728}


def _cred(**over):
    base = dict(ap_mac=DEVICE_MAC, ap_ip=None, username="admin", password=CPE_PASSWORD,
                vendor="Tenda", model="F3", login_method=None, failed_login_count=0)
    base.update(over)
    return ApCredential(**base)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(ap_control, "_sleep", lambda _s: None)
    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "all")
    ap_control.reset_claims()
    yield
    ap_control.reset_claims()


# ---------------------------------------------------------------------------
# Service-level: resolve, status, reboot, disconnect, safety
# ---------------------------------------------------------------------------

def test_resolve_pppoe_session_by_username():
    fake = FakeMikroTik(FakeTendaCpe())
    fake.connect()
    sess = cpe_control.resolve_pppoe_session(fake, PPPOE_USER)
    assert sess["address"] == SESSION_IP and sess["session_id"] == "*1"
    assert cpe_control.resolve_pppoe_session(fake, "nobody") is None


def test_status_resolves_ip_logs_in_and_reads_status_on_the_right_port():
    fake = FakeMikroTik(FakeTendaCpe(mode="router"))
    res = cpe_control.read_cpe_status_sync(ROUTER_INFO, _cred(), PPPOE_USER, WAN_PORT,
                                           api_factory=fake.factory)
    assert res["success"] and res["login_ok"] and res["login_method"] == "md5"
    assert res["status"]["mode"] == "router"
    assert res["status"]["session_address"] == SESSION_IP
    # the fetch targeted the live session IP on the configured port
    assert any(f"{SESSION_IP}:{WAN_PORT}" in f["url"] for f in fake.fetches)
    assert fake.mutating_router_calls == []


def test_offline_when_no_active_session():
    fake = FakeMikroTik(FakeTendaCpe(), ppp_rows=_ppp_active(user=None))
    res = cpe_control.read_cpe_status_sync(ROUTER_INFO, _cred(), PPPOE_USER, WAN_PORT,
                                           api_factory=fake.factory)
    assert res["error"] == "offline" and res["offline"]
    assert fake.fetches == []            # never contacted anything


def test_wrong_password_is_login_failed():
    fake = FakeMikroTik(FakeTendaCpe(password="nope"))
    res = cpe_control.read_cpe_status_sync(ROUTER_INFO, _cred(), PPPOE_USER, WAN_PORT,
                                           api_factory=fake.factory)
    assert res["error"] == "login_failed" and res["login_ok"] is False


def test_remote_mgmt_off_is_cpe_unreachable_not_wrong_password():
    fake = FakeMikroTik(FakeTendaCpe(answers=False))
    res = cpe_control.read_cpe_status_sync(ROUTER_INFO, _cred(), PPPOE_USER, WAN_PORT,
                                           api_factory=fake.factory)
    assert res["error"] == "cpe_unreachable"
    assert str(WAN_PORT) in res["message"]


def test_wrong_port_is_cpe_unreachable():
    fake = FakeMikroTik(FakeTendaCpe(port=8888))
    res = cpe_control.read_cpe_status_sync(ROUTER_INFO, _cred(), PPPOE_USER, 80,
                                           api_factory=fake.factory)
    assert res["error"] == "cpe_unreachable"


def test_unrecognised_status_page_reports_password_or_model():
    # With /tool fetch the only "logged in" signal is a readable status page, so
    # an answering device with no recognised status endpoint can't be told apart
    # from a wrong password -- the error names both causes (password / model).
    class NoStatus(FakeTendaCpe):
        def handle(self, host, port, method, path, data, cookie):
            if path in ("/goform/GetRouterStatus", "/goform/getSysStatusInfo"):
                return 404, "not found"
            return super().handle(host, port, method, path, data, cookie)

    fake = FakeMikroTik(NoStatus())
    res = cpe_control.read_cpe_status_sync(ROUTER_INFO, _cred(), PPPOE_USER, WAN_PORT,
                                           api_factory=fake.factory)
    assert res["error"] == "login_failed"
    assert "model" in res["message"] and "password" in res["message"]


def test_reboot_sends_reboot_after_login():
    cpe = FakeTendaCpe()
    fake = FakeMikroTik(cpe)
    res = cpe_control.reboot_cpe_sync(ROUTER_INFO, _cred(), PPPOE_USER, WAN_PORT,
                                      api_factory=fake.factory)
    assert res["success"] and cpe.rebooted
    assert fake.mutating_router_calls == []


def test_disconnect_fallback_drops_the_session():
    fake = FakeMikroTik(FakeTendaCpe())
    res = cpe_control.disconnect_cpe_session_sync(ROUTER_INFO, PPPOE_USER, api_factory=fake.factory)
    assert res["success"] and res["disconnected"] == 1
    assert fake.removed_sessions == ["*1"]
    assert "does not reboot" in res["message"]


def test_disconnect_when_no_session_says_nothing_to_redial():
    fake = FakeMikroTik(FakeTendaCpe(), ppp_rows=_ppp_active(user=None))
    res = cpe_control.disconnect_cpe_session_sync(ROUTER_INFO, PPPOE_USER, api_factory=fake.factory)
    assert res["success"] and res["disconnected"] == 0


def test_ip_is_resolved_live_not_from_a_stale_hint():
    # The credential carries an old address; the session now has a new one and
    # that is the only IP contacted.
    fake = FakeMikroTik(FakeTendaCpe(ip="10.90.0.21"), ppp_rows=_ppp_active(address="10.90.0.21"))
    res = cpe_control.read_cpe_status_sync(ROUTER_INFO, _cred(ap_ip="10.90.0.14"), PPPOE_USER,
                                           WAN_PORT, api_factory=fake.factory)
    assert res["success"]
    assert all("10.90.0.14" not in f["url"] for f in fake.fetches)
    assert any("10.90.0.21" in f["url"] for f in fake.fetches)


def test_connect_failure_surfaces():
    fake = FakeMikroTik(FakeTendaCpe(), connect_ok=False)
    res = cpe_control.read_cpe_status_sync(ROUTER_INFO, _cred(), PPPOE_USER, WAN_PORT,
                                           api_factory=fake.factory)
    assert res["error"] == "connect_failed"


def test_decrypted_password_not_in_repr():
    assert CPE_PASSWORD not in repr(_cred())


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def patch_router(monkeypatch):
    holder = {}

    def install(cpe, **kw):
        fake = FakeMikroTik(cpe, **kw)
        holder["fake"] = fake
        return fake

    monkeypatch.setattr(cpe_control, "_with_api",
                        lambda info, af, fn: fn(holder["fake"]) if holder["fake"].connect()
                        else {"error": "connect_failed", "message": "x"})
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


async def _pppoe_customer(db, owner, router, **over):
    plan = await make_plan(db, owner, connection_type=ConnectionType.PPPOE)
    return await make_customer(db, owner, plan, router, pppoe_username=PPPOE_USER, **over)


async def _saved_cred(db, customer_id, **over):
    row = CustomerCpeCredential(
        customer_id=customer_id, vendor="Tenda", model="F3", username="admin",
        password_encrypted=encrypt_credential(CPE_PASSWORD), port=WAN_PORT,
        device_mac=DEVICE_MAC, failed_login_count=0,
    )
    for k, v in over.items():
        setattr(row, k, v)
    db.add(row)
    await db.commit()
    return row


@pytest.mark.asyncio
async def test_reseller_blocked_when_scope_is_admins(client, db, monkeypatch):
    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "admins")
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    resp = await client.get(f"/api/customers/{customer.id}/cpe", headers=headers(_owner_token(owner)))
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "cpe_control_disabled"


@pytest.mark.asyncio
async def test_non_pppoe_customer_is_rejected(client, db):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    plan = await make_plan(db, owner, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(db, owner, plan, router)
    resp = await client.put(
        f"/api/customers/{customer.id}/cpe/credential",
        headers=headers(_owner_token(owner)), json={"password": "pw"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_save_credential_is_write_only(client, db):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    resp = await client.put(
        f"/api/customers/{customer.id}/cpe/credential",
        headers=headers(_owner_token(owner)),
        json={"password": "secretpw", "model": "F3", "port": WAN_PORT, "device_mac": DEVICE_MAC},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()["credential"]
    assert body["has_password"] is True and body["port"] == WAN_PORT
    assert "secretpw" not in resp.text
    row = (await db.execute(select(CustomerCpeCredential))).scalar_one()
    assert row.password_encrypted and row.password_encrypted != "secretpw"


@pytest.mark.asyncio
async def test_status_endpoint(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    await _saved_cred(db, customer.id)
    patch_router(FakeTendaCpe(mode="router"))
    resp = await client.get(f"/api/customers/{customer.id}/cpe/status", headers=headers(_owner_token(owner)))
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"]["mode"] == "router"


@pytest.mark.asyncio
async def test_offline_returns_409(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    await _saved_cred(db, customer.id)
    patch_router(FakeTendaCpe(), ppp_rows=_ppp_active(user=None))
    resp = await client.get(f"/api/customers/{customer.id}/cpe/status", headers=headers(_owner_token(owner)))
    assert resp.status_code == 409
    assert "offline" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reboot_needs_confirm(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    await _saved_cred(db, customer.id)
    fake = patch_router(FakeTendaCpe())
    resp = await client.post(f"/api/customers/{customer.id}/cpe/reboot",
                             headers=headers(_owner_token(owner)), json={})
    assert resp.status_code == 400
    assert fake.fetches == []


@pytest.mark.asyncio
async def test_reboot_and_disconnect(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    await _saved_cred(db, customer.id)
    cpe = FakeTendaCpe()
    fake = patch_router(cpe)
    reboot = await client.post(f"/api/customers/{customer.id}/cpe/reboot",
                               headers=headers(_owner_token(owner)), json={"confirm": True})
    assert reboot.status_code == 200, reboot.text
    assert cpe.rebooted
    disc = await client.post(f"/api/customers/{customer.id}/cpe/disconnect",
                             headers=headers(_owner_token(owner)), json={"confirm": True})
    assert disc.status_code == 200, disc.text
    assert disc.json()["disconnected"] == 1
    assert fake.removed_sessions == ["*1"]


@pytest.mark.asyncio
async def test_failed_login_increments_lock_counter(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    await _saved_cred(db, customer.id)
    patch_router(FakeTendaCpe(password="wrong"))
    resp = await client.get(f"/api/customers/{customer.id}/cpe/status", headers=headers(_owner_token(owner)))
    assert resp.status_code == 502
    row = (await db.execute(select(CustomerCpeCredential))).scalar_one()
    assert row.failed_login_count == 1 and row.last_login_ok is False


@pytest.mark.asyncio
async def test_other_reseller_gets_404(client, db, patch_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    await _saved_cred(db, customer.id)
    other = await make_reseller(db)
    fake = patch_router(FakeTendaCpe())
    token = headers(_owner_token(other))
    for method, path, kw in [
        ("get", f"/api/customers/{customer.id}/cpe", {}),
        ("get", f"/api/customers/{customer.id}/cpe/status", {}),
        ("post", f"/api/customers/{customer.id}/cpe/reboot", {"json": {"confirm": True}}),
        ("post", f"/api/customers/{customer.id}/cpe/disconnect", {"json": {"confirm": True}}),
        ("put", f"/api/customers/{customer.id}/cpe/credential", {"json": {"password": "x"}}),
    ]:
        resp = await getattr(client, method)(path, headers=token, **kw)
        assert resp.status_code == 404, (method, path, resp.text)
    assert fake.commands == []


@pytest.mark.asyncio
async def test_password_never_reaches_logs_or_responses(client, db, patch_router, caplog):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    customer = await _pppoe_customer(db, owner, router)
    patch_router(FakeTendaCpe())
    token = headers(_owner_token(owner))
    base = f"/api/customers/{customer.id}/cpe"
    secrets = [CPE_PASSWORD, hashlib.md5(CPE_PASSWORD.encode()).hexdigest(),
               base64.b64encode(CPE_PASSWORD.encode()).decode()]
    with caplog.at_level("DEBUG"):
        saved = await client.put(f"{base}/credential", headers=token,
                                 json={"password": CPE_PASSWORD, "port": WAN_PORT})
        status = await client.get(f"{base}/status", headers=token)
        reboot = await client.post(f"{base}/reboot", headers=token, json={"confirm": True})
    for resp in (saved, status, reboot):
        assert resp.status_code == 200, resp.text
        for secret in secrets:
            assert secret not in resp.text
    row = (await db.execute(select(CustomerCpeCredential))).scalar_one()
    assert CPE_PASSWORD not in row.password_encrypted
    for secret in secrets:
        assert secret not in caplog.text
    for entry in (await db.execute(select(StaffActivityLog))).scalars().all():
        assert CPE_PASSWORD not in (entry.summary or "")
