"""Hotspot Wi-Fi name: business-name SSID on new provisions, and the
dashboard read/rename endpoints.

Every router call goes to FakeRouterOS; nothing here touches a network.
"""
from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.db.models import ResellerStaff, StaffActivityLog
from app.services import provisioning, router_wifi, staff_access, staff_permissions as perms
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_reseller, make_router
from tests.fake_routeros import FakeRouterOS
from tests.test_provisioning_lan_wifi import (
    ALL_KINDS,
    _parse_block_code,
    _settings as _rsc_settings,
    _token,
)

ROUTER_IP = "10.0.3.9"


# ---------------------------------------------------------------------------
# SSID for new provisions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Mama Mboga WiFi", "Mama Mboga WiFi"),
        ("  Joe's   Café  ", "Joe's Cafe"),
        ('Kevo "The Boss" Net', "Kevo The Boss Net"),
        ("Back\\slash $money? {x}[y];`", "Backslash money xy"),
        ("Wi-Fi \U0001F680 Rocket", "Wi-Fi Rocket"),
        ("Ñandú Señor Networks Limited Company Kenya", "Nandu Senor Networks Limited Com"),
        ("中文", ""),
        (None, ""),
    ],
)
def test_sanitize_wifi_ssid(raw, expected):
    assert provisioning.sanitize_wifi_ssid(raw) == expected
    assert len(provisioning.sanitize_wifi_ssid(raw)) <= 32


class _Owner:
    def __init__(self, business_name=None, organization_name=None):
        self.business_name = business_name
        self.organization_name = organization_name


@pytest.mark.parametrize(
    "owner, expected",
    [
        (_Owner("Dreamplug Networks", "Dennis K"), "Dreamplug Networks"),
        (_Owner(None, "Kamau Hotspot"), "Kamau Hotspot"),
        (_Owner("   ", "Kamau Hotspot"), "Kamau Hotspot"),
        (_Owner("中文", "Kamau Hotspot"), "Kamau Hotspot"),
        (_Owner(None, "someone@example.com"), "Bitwave WiFi"),
        (_Owner(None, None), "Bitwave WiFi"),
        (_Owner("N/A", ""), "Bitwave WiFi"),
    ],
)
def test_wifi_ssid_for_owner_fallbacks(owner, expected):
    assert provisioning.wifi_ssid_for_owner(owner) == expected


@pytest.mark.parametrize("kind", ALL_KINDS)
@pytest.mark.parametrize("business", ["Joe's Café & Bar", 'Kevo "The Boss" $Net\\', "A" * 50])
def test_business_ssid_renders_safely_in_the_rsc(monkeypatch, kind, business):
    _rsc_settings(monkeypatch)
    ssid = provisioning.wifi_ssid_for_owner(_Owner(business, "Org"))
    token = _token(kind, ssid=ssid)
    script = provisioning.generate_rsc_script(token)
    code = _parse_block_code(script, "bwWifiAp")  # asserts the outer string is well-escaped
    assert f'/interface wireless set wlan1 mode=ap-bridge ssid="{provisioning.routeros_escape(ssid)}" ' in code
    assert len(ssid) <= 32
    assert script.count("{") == script.count("}")


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def _owner_token(owner):
    return create_access_token(login_token_claims(owner), timedelta(hours=1))


@pytest.fixture
def fake_create(monkeypatch):
    """Stub the token factory so the endpoint test needs no tunnel managers."""
    from app.api import provisioning as provisioning_api
    from app.db.models import ProvisioningToken

    seen = {}

    async def create(db, user_id, payment_methods=None, vpn_type="wireguard", is_routerboard=False, ssid=None):
        seen["ssid"] = ssid
        from datetime import datetime
        return ProvisioningToken(
            id=1, user_id=user_id, token="t" * 32, router_name="R", identity="Router-0001", vpn_type=vpn_type,
            wireguard_ip="10.0.0.5", ssid=provisioning.sanitize_wifi_ssid(ssid) or "Bitwave WiFi",
            server_public_ip="91.98.238.12", payment_methods=["mpesa"], is_routerboard=False,
            created_at=datetime.utcnow(),
        )

    monkeypatch.setattr(provisioning_api, "create_provisioning_token", create)
    monkeypatch.setattr(provisioning_api, "build_provision_command", lambda _t: "cmd")
    return seen


@pytest.mark.asyncio
async def test_new_token_defaults_to_business_name(client, db, fake_create):
    owner = await make_reseller(db, business_name="Dreamplug Networks", organization_name="Dennis")
    response = await client.post("/api/provision/create", headers=headers(_owner_token(owner)), json={})
    assert response.status_code == 200, response.text
    assert fake_create["ssid"] == "Dreamplug Networks"
    assert response.json()["ssid"] == "Dreamplug Networks"


@pytest.mark.asyncio
async def test_new_token_takes_a_typed_ssid_and_rejects_an_unusable_one(client, db, fake_create):
    owner = await make_reseller(db, business_name="Dreamplug")
    ok = await client.post("/api/provision/create", headers=headers(_owner_token(owner)),
                           json={"ssid": "  Dreamplug  Free WiFi "})
    assert ok.status_code == 200, ok.text
    assert fake_create["ssid"] == "Dreamplug Free WiFi"
    blank = await client.post("/api/provision/create", headers=headers(_owner_token(owner)), json={"ssid": "  "})
    assert blank.status_code == 200 and fake_create["ssid"] == "Dreamplug"
    bad = await client.post("/api/provision/create", headers=headers(_owner_token(owner)),
                            json={"ssid": "中文"})
    assert bad.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [True, False])
async def test_real_token_stores_the_ssid(db, monkeypatch, enabled):
    from tests.test_provisioning_hetzner import _fake_managers, _settings as _hz_settings

    _hz_settings(monkeypatch, enabled=enabled)
    _fake_managers(monkeypatch, [])
    owner = await make_reseller(db)
    token = await provisioning.create_provisioning_token(db, owner.id, vpn_type="wireguard", ssid='Kevo "Net"')
    assert token.ssid == "Kevo Net"
    assert 'ssid="Kevo Net"' in _parse_block_code(provisioning.generate_rsc_script(token), "bwWifiAp")
    default = await provisioning.create_provisioning_token(db, owner.id, vpn_type="wireguard")
    assert default.ssid == "Bitwave WiFi"


# ---------------------------------------------------------------------------
# Router side: which interfaces are renamed
# ---------------------------------------------------------------------------

def _menus(**extra):
    menus = {
        "/ip/hotspot": [{".id": "*1", "name": "hotspot1", "interface": "bridge", "disabled": "false"}],
        "/interface/bridge/port": [
            {".id": "*B1", "interface": "ether2", "bridge": "bridge"},
            {".id": "*B2", "interface": "wlan1", "bridge": "bridge"},
            {".id": "*B3", "interface": "wlan2", "bridge": "bridge"},
            {".id": "*B4", "interface": "wlan-guest", "bridge": "bridge"},
            {".id": "*B5", "interface": "wlan4", "bridge": "bridge-lab"},
            {".id": "*B6", "interface": "wlan5", "bridge": "bridge"},
        ],
        "/interface/wireless": [
            {".id": "*W1", "name": "wlan1", "mode": "ap-bridge", "ssid": "Old Name", "disabled": "false",
             "running": "true", "security-profile": "bw-open"},
            {".id": "*W2", "name": "wlan2", "mode": "ap-bridge", "ssid": "Old Name 5G", "disabled": "false",
             "running": "true", "security-profile": "wpa"},
            # Station: the router's internet uplink. Never touched.
            {".id": "*W3", "name": "wlan3", "mode": "station", "ssid": "Safaricom Home", "disabled": "false"},
            # Virtual AP on wlan1: keeps its own name.
            {".id": "*W4", "name": "wlan-guest", "mode": "ap-bridge", "ssid": "Guest", "disabled": "false",
             "master-interface": "wlan1"},
            # AP, but in a non-hotspot bridge.
            {".id": "*W5", "name": "wlan4", "mode": "ap-bridge", "ssid": "Lab", "disabled": "false"},
            # Disabled.
            {".id": "*W6", "name": "wlan5", "mode": "ap-bridge", "ssid": "Off", "disabled": "true"},
        ],
    }
    menus.update(extra)
    return menus


class WifiFake(FakeRouterOS):
    """FakeRouterOS whose call log keeps the full /set arguments (the base
    class pops ``.id`` from the logged dict while applying the set)."""

    def __init__(self, menus=None, reject=None):
        super().__init__(menus, reject=reject)
        self.set_calls = []

    def send_command(self, command, arguments=None):
        if command.endswith("/set"):
            self.set_calls.append((command, dict(arguments or {})))
        return super().send_command(command, arguments)


def _fake(menus=None, reject=None):
    fake = WifiFake(menus if menus is not None else _menus(), reject=reject)
    return fake, (lambda *_a, **_k: fake)


INFO = {"ip": ROUTER_IP, "username": "api", "password": "pw", "port": 8728}


def _sets(fake):
    return list(getattr(fake, "set_calls", None) or [(c, a) for c, a in fake.calls if c.endswith("/set")])


def test_read_marks_only_hotspot_ap_masters_renameable():
    fake, factory = _fake()
    result = router_wifi.read_wifi_sync(INFO, api_factory=factory)
    assert result["success"] and result["has_wireless"]
    by_name = {i["name"]: i for i in result["interfaces"]}
    assert by_name["wlan1"]["renameable"] and by_name["wlan2"]["renameable"]
    assert by_name["wlan3"]["reason"] == router_wifi.REASON_CLIENT_MODE
    assert by_name["wlan-guest"]["reason"] == router_wifi.REASON_VIRTUAL
    assert by_name["wlan4"]["reason"] == router_wifi.REASON_NOT_HOTSPOT
    assert by_name["wlan5"]["reason"] == router_wifi.REASON_DISABLED
    assert result["ssids"] == ["Old Name", "Old Name 5G"]
    assert _sets(fake) == []


def test_rename_sets_only_the_ssid_of_eligible_interfaces_and_verifies():
    fake, factory = _fake()
    result = router_wifi.rename_wifi_sync(INFO, "Dreamplug", api_factory=factory)
    assert result["success"] and result["verified"]
    assert _sets(fake) == [
        ("/interface/wireless/set", {".id": "*W1", "ssid": "Dreamplug"}),
        ("/interface/wireless/set", {".id": "*W2", "ssid": "Dreamplug"}),
    ]
    rows = {r["name"]: r for r in fake.menus["/interface/wireless"]}
    assert rows["wlan1"]["ssid"] == "Dreamplug" and rows["wlan1"]["security-profile"] == "bw-open"
    assert rows["wlan2"]["security-profile"] == "wpa"
    assert rows["wlan3"]["ssid"] == "Safaricom Home"
    assert rows["wlan-guest"]["ssid"] == "Guest" and rows["wlan4"]["ssid"] == "Lab"
    assert {s["name"] for s in result["skipped"]} == {"wlan3", "wlan-guest", "wlan4", "wlan5"}
    assert [(i["ssid_before"], i["ssid_after"]) for i in result["interfaces"]] == [
        ("Old Name", "Dreamplug"), ("Old Name 5G", "Dreamplug")]


def test_rename_that_does_not_stick_is_not_verified():
    fake, factory = _fake()
    # The router accepts the set but keeps the old value (e.g. a script reverts it).
    original = fake.send_command

    def no_op_set(command, arguments=None):
        if command.endswith("/set"):
            fake.calls.append((command, dict(arguments or {})))
            return {"success": True, "data": []}
        return original(command, arguments)

    fake.send_command = no_op_set
    result = router_wifi.rename_wifi_sync(INFO, "Dreamplug", api_factory=factory)
    assert result["success"] and not result["verified"]


def test_wifi_package_uses_configuration_ssid_and_reads_profiles():
    menus = {
        "/ip/hotspot": [{"name": "hs", "interface": "bridge"}],
        "/interface/bridge/port": [
            {"interface": "wifi1", "bridge": "bridge"},
            {"interface": "wifi2", "bridge": "bridge"},
            {"interface": "wifi3", "bridge": "bridge"},
        ],
        "/interface/wifi": [
            {".id": "*1", "name": "wifi1", "configuration.mode": "ap", "configuration.ssid": "MikroTik-1A2B3C",
             "disabled": "false", "security.authentication-types": "wpa2-psk"},
            {".id": "*2", "name": "wifi2", "configuration": "cfg-ap", "disabled": "false"},
            {".id": "*3", "name": "wifi3", "configuration.mode": "station", "configuration.ssid": "Uplink",
             "disabled": "false"},
        ],
        "/interface/wifi/configuration": [{".id": "*C1", "name": "cfg-ap", "mode": "ap", "ssid": "Shop 5G"}],
    }
    fake, factory = _fake(menus)
    read = router_wifi.read_wifi_sync(INFO, api_factory=factory)
    assert read["ssids"] == ["MikroTik-1A2B3C", "Shop 5G"]
    result = router_wifi.rename_wifi_sync(INFO, "Shop", api_factory=factory)
    assert result["verified"]
    assert _sets(fake) == [
        ("/interface/wifi/set", {".id": "*1", "configuration.ssid": "Shop"}),
        ("/interface/wifi/set", {".id": "*2", "configuration.ssid": "Shop"}),
    ]
    assert fake.menus["/interface/wifi"][0]["security.authentication-types"] == "wpa2-psk"


def test_router_without_hotspot_server_uses_the_default_bridge():
    menus = _menus()
    del menus["/ip/hotspot"]
    fake, factory = _fake(menus)
    read = router_wifi.read_wifi_sync(INFO, api_factory=factory)
    assert [i["name"] for i in read["interfaces"] if i["renameable"]] == ["wlan1", "wlan2"]


def test_no_mikrotik_wireless_is_a_clear_error():
    menus = {"/interface/bridge/port": [{"interface": "ether2", "bridge": "bridge"}]}
    missing = {"/interface/wireless/print", "/interface/wifi/print", "/interface/wifiwave2/print"}
    fake, factory = _fake(menus, reject=lambda cmd, _a: "no such command prefix" if cmd in missing else None)
    result = router_wifi.rename_wifi_sync(INFO, "Shop", api_factory=factory)
    assert result["error"] == "no_wireless"
    assert "separate access point" in result["message"]
    assert _sets(fake) == []


def test_only_ineligible_wifi_is_a_clear_error():
    menus = {
        "/interface/bridge/port": [],
        "/interface/wireless": [{".id": "*1", "name": "wlan1", "mode": "station", "ssid": "ISP", "disabled": "false"}],
    }
    fake, factory = _fake(menus)
    result = router_wifi.rename_wifi_sync(INFO, "Shop", api_factory=factory)
    assert result["error"] == "no_eligible_wifi"
    assert _sets(fake) == []


def test_unreadable_bridge_ports_fail_closed():
    fake, factory = _fake(reject=lambda cmd, _a: "timeout" if cmd == "/interface/bridge/port/print" else None)
    result = router_wifi.rename_wifi_sync(INFO, "Shop", api_factory=factory)
    assert result["error"] == "state_unreadable"
    assert _sets(fake) == []


@pytest.mark.parametrize("value", ["", "   ", "A" * 33, "Café", "Wi‑Fi"])
def test_validate_ssid_rejects(value):
    with pytest.raises(router_wifi.InvalidSsid):
        router_wifi.validate_ssid(value)


def test_validate_ssid_accepts_symbols():
    assert router_wifi.validate_ssid('  Joe\'s "Free" $Wi-Fi\\ ') == 'Joe\'s "Free" $Wi-Fi\\'


def test_rate_limit_window():
    router_wifi.reset_state()
    for i in range(router_wifi.RENAME_LIMIT):
        assert router_wifi.rate_limit_wait(7, now=100.0 + i) == 0
        router_wifi.record_rename(7, now=100.0 + i)
    assert router_wifi.rate_limit_wait(7, now=200.0) > 0
    assert router_wifi.rate_limit_wait(8, now=200.0) == 0
    assert router_wifi.rate_limit_wait(7, now=100.0 + router_wifi.RENAME_WINDOW_SECONDS) == 0
    router_wifi.reset_state()


# ---------------------------------------------------------------------------
# Endpoints: scoping, permissions, audit
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_router(monkeypatch):
    fake = WifiFake(_menus())
    monkeypatch.setattr(router_wifi, "_make_api", lambda _info, _factory: fake)
    router_wifi.reset_state()
    staff_access.reset_cache()
    yield fake
    router_wifi.reset_state()
    staff_access.reset_cache()


async def _staff(db, owner, permissions):
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Tech", email=f"wifi-tech{len(permissions)}@example.com",
        password_hash=pwd_context.hash("x"), permissions=permissions,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    return staff, create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))


def test_staff_rules():
    rule, params = perms.match_rule("PUT", "/api/routers/7/wifi/ssid")
    assert rule.requirement == "routers.manage" and params == {"router_id": "7"}
    assert not rule.allows(["routers.view"])
    assert rule.template in perms.OWNER_LOGGED_TEMPLATES
    view_rule, _ = perms.match_rule("GET", "/api/routers/7/wifi")
    assert view_rule.requirement == "routers.view"


@pytest.mark.asyncio
async def test_owner_reads_and_renames_and_it_is_audited(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    read = await client.get(f"/api/routers/{router.id}/wifi", headers=headers(_owner_token(owner)))
    assert read.status_code == 200, read.text
    assert read.json()["ssids"] == ["Old Name", "Old Name 5G"] and read.json()["can_rename"]

    response = await client.put(
        f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(owner)),
        json={"ssid": "Dreamplug", "confirm": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verified"] and body["ssid"] == "Dreamplug"
    assert body["previous_ssids"] == ["Old Name", "Old Name 5G"]
    rows = (await db.execute(select(StaffActivityLog).where(StaffActivityLog.owner_id == owner.id))).scalars().all()
    assert len(rows) == 1 and rows[0].staff_id is None and rows[0].status_code == 200
    assert '"Dreamplug"' in rows[0].summary and "Old Name" in rows[0].summary and "verified" in rows[0].summary


@pytest.mark.asyncio
async def test_rename_needs_confirm_and_a_valid_name(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    no_confirm = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(owner)),
                                  json={"ssid": "Dreamplug"})
    assert no_confirm.status_code == 400
    too_long = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(owner)),
                                json={"ssid": "A" * 33, "confirm": True})
    assert too_long.status_code == 400 and "32" in too_long.json()["detail"]
    assert fake_router.calls == []


@pytest.mark.asyncio
async def test_staff_with_view_only_cannot_rename(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    _staff_row, token = await _staff(db, owner, ["routers.view"])
    read = await client.get(f"/api/routers/{router.id}/wifi", headers=headers(token))
    assert read.status_code == 200, read.text
    response = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(token),
                                json={"ssid": "Dreamplug", "confirm": True})
    assert response.status_code == 403 and response.json()["code"] == "staff_permission_denied"
    assert _sets(fake_router) == []


@pytest.mark.asyncio
async def test_staff_with_manage_can_rename(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    staff, token = await _staff(db, owner, ["routers.view", "routers.manage"])
    response = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(token),
                                json={"ssid": "Dreamplug", "confirm": True})
    assert response.status_code == 200, response.text
    rows = (await db.execute(select(StaffActivityLog).where(StaffActivityLog.staff_id == staff.id))).scalars().all()
    assert len(rows) == 1 and "Dreamplug" in rows[0].summary


@pytest.mark.asyncio
async def test_other_reseller_gets_404(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    other = await make_reseller(db)
    read = await client.get(f"/api/routers/{router.id}/wifi", headers=headers(_owner_token(other)))
    assert read.status_code == 404
    response = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(other)),
                                json={"ssid": "Hijack", "confirm": True})
    assert response.status_code == 404
    assert fake_router.calls == []


@pytest.mark.asyncio
async def test_unreachable_router_is_503(client, db, monkeypatch):
    class Down(FakeRouterOS):
        def connect(self):
            self.last_connect_error = "timed out"
            return False

    monkeypatch.setattr(router_wifi, "_make_api", lambda _info, _factory: Down())
    router_wifi.reset_state()
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    read = await client.get(f"/api/routers/{router.id}/wifi", headers=headers(_owner_token(owner)))
    assert read.status_code == 503 and "Could not reach router" in read.json()["detail"]
    response = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(owner)),
                                json={"ssid": "Dreamplug", "confirm": True})
    assert response.status_code == 503
    # A failed connect does not use up the rate limit.
    assert router_wifi.rate_limit_wait(router.id) == 0


@pytest.mark.asyncio
async def test_router_without_wireless_is_409(client, db, monkeypatch):
    fake = FakeRouterOS({"/interface/bridge/port": []})
    monkeypatch.setattr(router_wifi, "_make_api", lambda _info, _factory: fake)
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    read = await client.get(f"/api/routers/{router.id}/wifi", headers=headers(_owner_token(owner)))
    assert read.status_code == 200 and read.json()["has_wireless"] is False
    assert "separate access point" in read.json()["message"]
    response = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(owner)),
                                json={"ssid": "Dreamplug", "confirm": True})
    assert response.status_code == 409 and response.json()["detail"]["code"] == "no_wireless"


@pytest.mark.asyncio
async def test_rate_limited_and_concurrent_renames(client, db, fake_router):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address=ROUTER_IP)
    held = router_wifi.try_claim(router.id)
    busy = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(owner)),
                            json={"ssid": "One", "confirm": True})
    assert busy.status_code == 409 and _sets(fake_router) == []
    router_wifi.release_claim(held)

    for i in range(router_wifi.RENAME_LIMIT):
        ok = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(owner)),
                              json={"ssid": f"Name {i}", "confirm": True})
        assert ok.status_code == 200, ok.text
    limited = await client.put(f"/api/routers/{router.id}/wifi/ssid", headers=headers(_owner_token(owner)),
                               json={"ssid": "Too many", "confirm": True})
    assert limited.status_code == 429 and "Retry-After" in limited.headers
    assert not router_wifi.rename_in_progress(router.id)
