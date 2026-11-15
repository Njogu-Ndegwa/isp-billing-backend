"""Wire-level regression cases from the 2026-11-15 V12.01.01.59 bench test.

All credentials, challenges, cookies and addresses below are synthetic.
The fake requires the returned cookie, fresh challenge, exact status modules
and the firmware's real reboot payload/acknowledgement.
"""
import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services import ap_adapters, ap_control, ap_fetch, cpe_control
from tests.test_cpe_control import (
    CPE_PASSWORD, PPPOE_USER, ROUTER_INFO, SESSION_IP, WAN_PORT,
    FakeMikroTik, FakeTendaCpe, _cred,
)


class V12Router(FakeMikroTik):
    def __init__(self, *, wrong_password=False, missing_cookie=False,
                 status_body=None, reboot_body='{"errCode":100}', reboot_redirect=False):
        super().__init__(FakeTendaCpe())
        self.password = "another-test-password" if wrong_password else CPE_PASSWORD
        self.missing_cookie = missing_cookie
        self.status_body = status_body
        self.reboot_body = reboot_body
        self.reboot_redirect = reboot_redirect
        self.challenge_number = 0
        self.challenge = None
        self.token = None
        self.login_count = 0
        self.rebooted = False

    def _fetch(self, params):
        self.fetches.append(dict(params))
        url = urlsplit(params["url"])
        assert url.hostname == SESSION_IP
        assert url.port == WAN_PORT
        assert params["http-max-redirect-count"] == "0"
        path = url.path
        data = {k: v[0] for k, v in parse_qs(params.get("http-data", "")).items()}

        def body(value):
            return {"success": True, "data": [{"status": "finished", "data": value}]}

        if path == "/goform/getstok":
            self.challenge_number += 1
            self.challenge = f"test-challenge-{self.challenge_number}"
            return body(json.dumps({"random": self.challenge}))
        if path == "/login/Auth":
            self.login_count += 1
            assert params["output"] == "user-with-headers"
            expected = hashlib.md5((base64.b64encode(self.password.encode()).decode()
                                    + self.challenge).encode()).hexdigest()
            if data != {"password": expected}:
                return {"error": f'failure: Fetch failed with status 302 (Location: "http://{SESSION_IP}:{WAN_PORT}/login.html?1")'}
            self.token = f"synthetic-session-{self.challenge_number}:language=cn"
            cookie = "" if self.missing_cookie else f' Set-cookie: "ecos_pw={self.token}; path=/"'
            return {"error": f'failure: Fetch failed with status 302 (Location: "http://{SESSION_IP}:{WAN_PORT}/index.html"{cookie})'}
        assert self.token and f"Cookie: ecos_pw={self.token}" in params.get("http-header-field", "")
        if path == "/goform/getStatus":
            assert parse_qs(url.query) == {"modules": ["internetStatus,systemInfo,wifiRelay"]}
            return body(self.status_body if self.status_body is not None else json.dumps({
                "internetStatus": {"wanConnectStatus": "13103061"},
                "systemInfo": {"softVersion": "V12.01.01.59_multi", "statusWanIP": SESSION_IP,
                               "wanConnectTime": "123", "lanIP": "192.168.0.1"},
                "wifiRelay": {"wifiRelayType": "disabled"},
            }))
        if path == "/goform/sysReboot":
            assert params["http-method"] == "post"
            assert data == {"module1": "sysOperate", "action": "reboot"}
            if self.reboot_redirect:
                return {"error": f'failure: status 302 (Location: "http://{SESSION_IP}/login.html")'}
            self.rebooted = True
            return body(self.reboot_body)
        pytest.fail(f"Unexpected device endpoint: {path}")


@pytest.fixture(autouse=True)
def no_login_sleep(monkeypatch):
    monkeypatch.setattr(ap_control, "_sleep", lambda _: None)


def status(fake, cred=None):
    return cpe_control.read_cpe_status_sync(ROUTER_INFO, cred or _cred(), PPPOE_USER, WAN_PORT,
                                          api_factory=fake.factory)


def reboot(fake):
    return cpe_control.reboot_cpe_sync(ROUTER_INFO, _cred(), PPPOE_USER, WAN_PORT,
                                     api_factory=fake.factory)


@pytest.mark.parametrize("model", [None, "F3", "OAP1200V2"])
def test_firmware_detected_independently_of_model_label(model):
    fake = V12Router()
    cred = _cred()
    cred.model = model
    result = status(fake, cred)
    assert result["success"] and result["login_method"] == "tenda_v12"
    assert result["status"]["firmware"] == "V12.01.01.59_multi"
    assert result["status"]["mode"] == "router"
    assert result["status"]["protocol"] == "tenda_v12"
    assert result["status"]["session_address"] == SESSION_IP
    assert result["status"]["model"] is None  # never invent a hardware model
    assert fake.login_count == 1
    assert len(fake.fetches) == 3
    assert fake.mutating_router_calls == []
    assert CPE_PASSWORD not in json.dumps(result)
    assert fake.token not in json.dumps(result)


def test_fresh_challenge_and_cookie_for_every_action():
    fake = V12Router()
    assert status(fake)["success"]
    assert reboot(fake)["success"]
    assert fake.challenge_number == 2
    assert fake.rebooted
    assert fake.mutating_router_calls == []


def test_wrong_password_is_one_attempt_and_never_reboots():
    fake = V12Router(wrong_password=True)
    result = reboot(fake)
    assert result["error"] == "login_failed"
    assert fake.login_count == 1
    assert not fake.rebooted


@pytest.mark.parametrize("options", [
    {"missing_cookie": True},
    {"status_body": '<html>Form getStatus is not defined</html>'},
    {"status_body": '{"errCode":0}'},
    {"status_body": '{"systemInfo":{},"wifiRelay":{}}'},
])
def test_protocol_gap_is_not_bad_password_and_never_reboots(options):
    fake = V12Router(**options)
    result = reboot(fake)
    assert result["error"] == "cpe_unsupported"
    assert result.get("login_ok") is not False
    assert fake.login_count == 1
    assert not fake.rebooted


@pytest.mark.parametrize("options", [
    {"reboot_body": '{"errCode":1}'}, {"reboot_body": '{"errCode":0}'},
    {"reboot_body": ''}, {"reboot_redirect": True},
])
def test_reboot_requires_firmware_acknowledgement(options):
    assert reboot(V12Router(**options))["error"] == "cpe_reboot_failed"


@pytest.mark.parametrize("raw,expected", [
    ("disabled", "router"), ("ap", "ap"), ("wisp", "wisp"),
    ("client+ap", "repeater"), ("unrecognised", "unknown"),
])
def test_v12_modes(raw, expected):
    adapter = ap_adapters.TendaV12Adapter("test-challenge")
    parsed = adapter.parse_status(json.dumps({"systemInfo": {"softVersion": "V12"},
                                             "wifiRelay": {"wifiRelayType": raw}}), json.loads)
    assert parsed.mode == expected
    assert not adapter.supports_ap_setup


def test_real_http_headers_are_stripped_and_cookie_retained():
    class Api:
        def send_command(self, command, params):
            return {"data": [{"status": "finished", "data":
                'HTTP/1.1 200 OK\r\nSet-Cookie: session=synthetic-token; Path=/\r\nContent-Type: application/json\r\n\r\n{"ok":true}'}]}
    client = ap_fetch.RouterFetchHttpClient(Api(), "192.0.2.3")
    reply = client.request(ap_adapters.ApRequest("get", "/"), capture_headers=True)
    assert reply.body == '{"ok":true}'
    assert client.cookie == "session=synthetic-token"
    assert "synthetic-token" not in repr(reply)


def test_http_errors_never_expose_cookie_or_redirect_values():
    class Api:
        def send_command(self, command, params):
            return {"error": 'failure: status 403 (Set-Cookie: "session=synthetic-secret; path=/" Location: "http://example.invalid/?token=synthetic-secret")'}
    client = ap_fetch.RouterFetchHttpClient(Api(), "192.0.2.3")
    reply = client.request(ap_adapters.ApRequest("get", "/"))
    assert reply.status == 403
    assert "synthetic-secret" not in repr(reply)
    assert not reply.redirected


@pytest.mark.parametrize("cookie", ['session=x\r\nInjected:value', 'session=x,y', 'bad name=value'])
def test_cookies_cannot_inject_routeros_headers(cookie):
    client = ap_fetch.RouterFetchHttpClient(None, "192.0.2.3")
    client._accept_cookies([cookie])
    assert client.cookie is None


@pytest.mark.parametrize("body,expected", [
    ('{"errCode":1,"result":0}', False),
    ('{"errCode":0,"result":1}', True),
    ('{"result":"success"}', True),
    ('{"unexpected":0}', False),
])
def test_legacy_reboot_preserves_authoritative_error_field(body, expected):
    adapter = ap_adapters.TendaApAdapter()
    assert adapter.reboot_response_ok(body, json.loads) is expected


def test_v12_ap_setup_stops_before_any_unverified_setter(monkeypatch):
    fake = V12Router()
    cred = _cred(ap_ip=SESSION_IP)
    lan = ap_control.HotspotLan(gateway="10.90.0.1", subnet="10.90.0.0/24",
                                pool_ranges="10.90.0.10-10.90.0.200")
    monkeypatch.setattr(ap_control, "_locate_ap", lambda api, cred: (lan, None))
    monkeypatch.setattr(ap_control, "_addresses_in_use", lambda api: set())
    monkeypatch.setattr(ap_control, "_client_for", lambda info, cred, api:
                        ap_fetch.RouterFetchHttpClient(api, cred.ap_ip, port=WAN_PORT))
    result = ap_control.make_safe_ap_sync(ROUTER_INFO, cred, api_factory=fake.factory)
    assert result["error"] == "unsupported_firmware"
    assert result["login_ok"] is True
    assert len(fake.fetches) == 3  # challenge, login, status; no setter or reboot
    assert not fake.rebooted
    assert not fake.mutating_router_calls


def test_v12_login_method_fits_existing_credential_columns():
    from app.db.database import Base
    method = ap_adapters.TendaV12Adapter("test-challenge").login_attempts("admin", "test-password")[0].method
    for table in ("customer_cpe_credentials", "router_ap_credentials"):
        assert len(method) <= Base.metadata.tables[table].c.login_method.type.length


# Use the real route/session fixtures: a service-only success did not exercise
# the Postgres VARCHAR(16) write and missed the first live API failure.
from tests.test_cpe_control import client, _pppoe_customer, _saved_cred, _owner_token, headers


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["status", "reboot"])
async def test_v12_success_is_persisted_through_http(client, db, monkeypatch, action):
    from sqlalchemy import select
    from app.config import settings
    from app.db.models import CustomerCpeCredential
    from app.services import staff_access
    from tests.factories import make_reseller, make_router

    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "all")
    staff_access.reset_cache()
    ap_control.reset_claims()
    fake = V12Router()
    monkeypatch.setattr(cpe_control, "_with_api",
                        lambda info, factory, fn: ap_control._with_api(info, fake.factory, fn))
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_INFO["ip"])
    customer = await _pppoe_customer(db, owner, router)
    await _saved_cred(db, customer.id, failed_login_count=1, last_error="earlier failure")
    url = f"/api/customers/{customer.id}/cpe/{action}"
    try:
        response = (await client.get(url, headers=headers(_owner_token(owner))) if action == "status"
                    else await client.post(url, headers=headers(_owner_token(owner)), json={"confirm": True}))
        assert response.status_code == 200, response.text
        row = (await db.execute(select(CustomerCpeCredential))).scalar_one()
        await db.refresh(row)
        assert row.login_method == "tenda_v12"
        assert row.last_login_ok is True
        assert row.failed_login_count == 0 and row.last_error is None
        assert row.last_action == action
        if action == "status":
            assert row.last_status["firmware"] == "V12.01.01.59_multi"
        else:
            assert row.last_reboot_at is not None and fake.rebooted
    finally:
        staff_access.reset_cache()
        ap_control.reset_claims()


@pytest.mark.asyncio
@pytest.mark.parametrize("competing", ["status", "reboot", "disconnect"])
async def test_status_claim_rejects_competing_cpe_actions(client, db, monkeypatch, competing):
    import asyncio
    import threading
    from app.config import settings
    from app.services import staff_access
    from tests.factories import make_reseller, make_router

    entered, release = threading.Event(), threading.Event()
    class PausedLogin(V12Router):
        def _fetch(self, params):
            if params["url"].endswith("/goform/getstok"):
                entered.set()
                assert release.wait(10), "test did not release login"
            return super()._fetch(params)

    monkeypatch.setattr(settings, "AP_CONTROL_ENABLED_FOR", "all")
    staff_access.reset_cache()
    ap_control.reset_claims()
    fake = PausedLogin()
    monkeypatch.setattr(cpe_control, "_with_api",
                        lambda info, factory, fn: ap_control._with_api(info, fake.factory, fn))
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_INFO["ip"])
    customer = await _pppoe_customer(db, owner, router)
    await _saved_cred(db, customer.id)
    auth = headers(_owner_token(owner))
    base = f"/api/customers/{customer.id}/cpe"
    first = asyncio.create_task(client.get(base + "/status", headers=auth))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        response = (await client.get(base + "/status", headers=auth) if competing == "status"
                    else await client.post(base + "/" + competing, headers=auth, json={"confirm": True}))
        assert response.status_code == 409, response.text
        assert "Another router (CPE/AP) action" in response.json()["detail"]
        assert not fake.rebooted and not fake.removed_sessions
        release.set()
        assert (await first).status_code == 200
        assert not ap_control.ap_write_in_progress(router.id)
    finally:
        release.set()
        await first
        staff_access.reset_cache()
        ap_control.reset_claims()
