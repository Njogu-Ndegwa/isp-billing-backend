import pytest
from fastapi import HTTPException
import httpx
from starlette.requests import Request

from app.api import router_management
from app.db.models import UserRole
from app.services import router_remote_access
from tests.factories import make_reseller, make_router


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


def _request(
    path: str,
    query: str = "",
    method: str = "GET",
    body: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": headers or [(b"host", b"testserver")],
            "query_string": query.encode(),
            "server": ("testserver", 80),
            "scheme": "http",
            "client": ("testclient", 50000),
        },
        receive,
    )


class FakeMikroTikAPI:
    instances = []
    connect_ok = True
    initial_rules = None
    initial_services = None

    def __init__(self, host, username, password, port, timeout=None, connect_timeout=None):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.connected = False
        self.last_connect_error = None
        self.next_rule = 10
        self.services = {
            "winbox": {".id": "*1", "name": "winbox", "port": "8291", "disabled": "yes", "address": ""},
            "ssh": {".id": "*2", "name": "ssh", "port": "22", "disabled": "yes", "address": ""},
            "www": {".id": "*3", "name": "www", "port": "80", "disabled": "yes", "address": ""},
        }
        if self.initial_services is not None:
            self.services = {
                name: dict(service)
                for name, service in self.initial_services.items()
            }
        self.rules = [
            {".id": "*drop", "chain": "input", "action": "drop", "comment": "defconf: drop all not coming from LAN"}
        ]
        if self.initial_rules is not None:
            self.rules = [dict(rule) for rule in self.initial_rules]
        self.__class__.instances.append(self)

    def connect(self):
        self.connected = self.connect_ok
        if not self.connect_ok:
            self.last_connect_error = "not reachable"
        return self.connected

    def disconnect(self):
        self.connected = False

    def send_command_optimized(self, command, proplist=None, query=None):
        if command != "/ip/firewall/filter/print":
            return {"error": f"unsupported optimized command {command}"}
        rows = [dict(rule) for rule in self.rules]
        if query == "?chain=input":
            rows = [row for row in rows if row.get("chain") == "input"]
        elif query and query.startswith("?comment="):
            wanted = query.split("=", 1)[1]
            rows = [row for row in rows if row.get("comment") == wanted]
        if proplist:
            rows = [{key: value for key, value in row.items() if key in proplist} for row in rows]
        return {"success": True, "data": rows}

    def send_command(self, command, arguments=None):
        arguments = arguments or {}
        if command == "/ip/service/print":
            if arguments:
                unsupported = next(iter(arguments))
                return {"error": f"unknown parameter {unsupported}"}
            return {"success": True, "data": [dict(service) for service in self.services.values()]}
        if command == "/ip/service/set":
            service = self._service_by_id(arguments["numbers"])
            for key, value in arguments.items():
                if key != "numbers":
                    service[key] = value
            return {"success": True, "data": []}
        if command == "/ip/firewall/filter/add":
            self.next_rule += 1
            rule = {".id": f"*{self.next_rule}", **arguments}
            self.rules.append(rule)
            return {"success": True, "data": []}
        if command == "/ip/firewall/filter/remove":
            rule_id = arguments["numbers"]
            self.rules = [rule for rule in self.rules if rule.get(".id") != rule_id]
            return {"success": True, "data": []}
        return {"error": f"unsupported command {command}"}

    def _service_by_id(self, service_id):
        for service in self.services.values():
            if service[".id"] == service_id:
                return service
        raise AssertionError(f"Unknown service id {service_id}")


@pytest.fixture(autouse=True)
def reset_fake_mikrotik_api():
    FakeMikroTikAPI.instances = []
    FakeMikroTikAPI.connect_ok = True
    FakeMikroTikAPI.initial_rules = None
    FakeMikroTikAPI.initial_services = None


def test_remote_access_rejects_unrestricted_sources():
    with pytest.raises(router_remote_access.RouterRemoteAccessError):
        router_remote_access.normalize_source_cidrs(["0.0.0.0/0"])


def test_remote_access_builds_targets_without_password():
    targets = router_remote_access.build_remote_access_targets(
        "10.0.0.9",
        "admin",
        ["10.0.0.1/32"],
        ["winbox", "ssh", "webfig"],
    )

    assert targets[0]["winbox_address"] == "10.0.0.9:8291"
    assert targets[1]["ssh_command"] == "ssh admin@10.0.0.9 -p 22"
    assert targets[2]["url"] == "http://10.0.0.9:80/"
    assert all("password" not in target for target in targets)
    assert "secret" not in str(targets).lower()


def test_remote_access_request_accepts_csv_fields():
    request = router_management.RouterRemoteAccessRequest(
        services="winbox, ssh",
        source_cidrs="10.0.0.1/32,10.250.0.1/32",
    )

    assert request.services == ["winbox", "ssh"]
    assert request.source_cidrs == ["10.0.0.1/32", "10.250.0.1/32"]


def test_remote_access_enable_adds_managed_rules_and_restricts_services(monkeypatch):
    monkeypatch.setattr(router_remote_access, "MikroTikAPI", FakeMikroTikAPI)

    result = router_remote_access.configure_router_remote_access_sync(
        {"ip": "10.0.0.9", "username": "admin", "password": "secret", "port": 8728},
        services=["winbox", "ssh"],
        enable=True,
        source_cidrs=["10.0.0.1/32"],
    )

    api = FakeMikroTikAPI.instances[-1]
    assert result["success"] is True
    assert api.services["winbox"]["disabled"] == "no"
    assert api.services["winbox"]["address"] == "10.0.0.1/32"
    assert api.services["ssh"]["disabled"] == "no"
    assert api.services["ssh"]["address"] == "10.0.0.1/32"
    managed = [rule for rule in api.rules if "remote-access" in (rule.get("comment") or "")]
    assert {(rule["dst-port"], rule["src-address"]) for rule in managed} == {
        ("8291", "10.0.0.1/32"),
        ("22", "10.0.0.1/32"),
    }
    assert all(rule.get("place-before") == "*drop" for rule in managed)


def test_remote_access_disable_removes_managed_rule_and_disables_service(monkeypatch):
    FakeMikroTikAPI.initial_rules = [
        {".id": "*drop", "chain": "input", "action": "drop", "comment": "defconf: drop all not coming from LAN"},
        {
            ".id": "*remote",
            "chain": "input",
            "action": "accept",
            "protocol": "tcp",
            "dst-port": "8291",
            "src-address": "10.0.0.1/32",
            "comment": "API-managed: remote-access: winbox: 10.0.0.1/32",
        },
    ]
    monkeypatch.setattr(router_remote_access, "MikroTikAPI", FakeMikroTikAPI)

    result = router_remote_access.configure_router_remote_access_sync(
        {"ip": "10.0.0.9", "username": "admin", "password": "secret", "port": 8728},
        services=["winbox"],
        enable=False,
        source_cidrs=["10.0.0.1/32"],
    )

    api = FakeMikroTikAPI.instances[-1]
    assert result["success"] is True
    assert result["winbox_service_after"] == result["services"][0]["service_after"]
    assert result["firewall_rules_after"] == result["services"][0]["firewall_rules_after"]
    assert api.services["winbox"]["disabled"] == "yes"
    assert not [rule for rule in api.rules if "remote-access" in (rule.get("comment") or "")]


def test_remote_access_webfig_uses_routeros_service_port(monkeypatch):
    FakeMikroTikAPI.initial_services = {
        "winbox": {".id": "*1", "name": "winbox", "port": "8291", "disabled": "yes", "address": ""},
        "ssh": {".id": "*2", "name": "ssh", "port": "22", "disabled": "yes", "address": ""},
        "www": {".id": "*3", "name": "www", "port": "8080", "disabled": "yes", "address": ""},
    }
    monkeypatch.setattr(router_remote_access, "MikroTikAPI", FakeMikroTikAPI)

    result = router_remote_access.configure_router_remote_access_sync(
        {"ip": "10.0.0.9", "username": "admin", "password": "secret", "port": 8728},
        services=["webfig"],
        enable=True,
        source_cidrs=["10.0.0.1/32"],
    )

    api = FakeMikroTikAPI.instances[-1]
    managed = [rule for rule in api.rules if "remote-access" in (rule.get("comment") or "")]
    assert result["services"][0]["routeros_service"] == "www"
    assert result["services"][0]["port"] == 8080
    assert result["targets"][0]["url"] == "http://10.0.0.9:8080/"
    assert managed[0]["dst-port"] == "8080"
    assert api.services["www"]["disabled"] == "no"


def test_remote_access_webfig_falls_back_to_www_ssl(monkeypatch):
    FakeMikroTikAPI.initial_services = {
        "winbox": {".id": "*1", "name": "winbox", "port": "8291", "disabled": "yes", "address": ""},
        "ssh": {".id": "*2", "name": "ssh", "port": "22", "disabled": "yes", "address": ""},
        "www-ssl": {".id": "*4", "name": "www-ssl", "port": "443", "disabled": "yes", "address": ""},
    }
    monkeypatch.setattr(router_remote_access, "MikroTikAPI", FakeMikroTikAPI)

    result = router_remote_access.configure_router_remote_access_sync(
        {"ip": "10.0.0.9", "username": "admin", "password": "secret", "port": 8728},
        services=["webfig"],
        enable=True,
        source_cidrs=["10.0.0.1/32"],
    )

    api = FakeMikroTikAPI.instances[-1]
    managed = [rule for rule in api.rules if "remote-access" in (rule.get("comment") or "")]
    assert result["services"][0]["routeros_service"] == "www-ssl"
    assert result["services"][0]["scheme"] == "https"
    assert result["targets"][0]["url"] == "https://10.0.0.9:443/"
    assert managed[0]["dst-port"] == "443"
    assert api.services["www-ssl"]["disabled"] == "no"


@pytest.mark.asyncio
async def test_configure_router_remote_access_commits_before_router_io(db, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    router = await make_router(db, admin, ip_address="10.0.9.1", port=8729)
    calls = []

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    def fake_config(router_info, services, enable, source_cidrs):
        assert db.in_transaction() is False
        calls.append((router_info, services, enable, source_cidrs))
        return {
            "success": True,
            "enabled": enable,
            "services": [],
            "source_cidrs": source_cidrs,
            "targets": [],
            "message": "ok",
        }

    async def fake_record_availability(*_args, **_kwargs):
        calls.append("availability_recorded")

    monkeypatch.setattr(router_management.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(router_management, "configure_router_remote_access_sync", fake_config)
    monkeypatch.setattr(router_management, "record_router_availability", fake_record_availability)

    response = await router_management.configure_router_remote_access(
        router.id,
        router_management.RouterRemoteAccessRequest(
            enable=True,
            services=["winbox"],
            source_cidrs=["10.0.0.1/32"],
        ),
        db,
        _token(admin),
    )

    assert response["success"] is True
    assert calls[0] == (
        {
            "ip": "10.0.9.1",
            "username": router.username,
            "password": router.password,
            "port": 8729,
        },
        ["winbox"],
        True,
        ["10.0.0.1/32"],
    )
    assert calls[1] == "availability_recorded"


@pytest.mark.asyncio
async def test_open_router_webfig_returns_short_lived_proxy_path_after_commit(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, ip_address="10.0.9.3", port=8729)
    calls = []

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    def fake_config(router_info, services, enable, source_cidrs):
        assert db.in_transaction() is False
        calls.append((router_info, services, enable, source_cidrs))
        return {
            "success": True,
            "enabled": enable,
            "services": [{"service": "webfig", "scheme": "https", "port": 8443}],
            "source_cidrs": source_cidrs,
            "targets": [],
            "message": "ok",
        }

    async def fake_record_availability(*_args, **_kwargs):
        calls.append("availability_recorded")

    monkeypatch.setattr(router_management.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(router_management, "configure_router_remote_access_sync", fake_config)
    monkeypatch.setattr(router_management, "record_router_availability", fake_record_availability)
    monkeypatch.setattr(router_management, "default_remote_access_source_cidrs", lambda: ["10.0.0.1/32"])

    response = await router_management.open_router_webfig(
        router.id,
        db,
        _token(reseller),
    )

    assert response["success"] is True
    assert response["proxy_path"].startswith(f"/api/admin/routers/{router.id}/webfig/?remote_access_token=")
    assert response["webfig_target"] == {"scheme": "https", "port": 8443}
    assert response["remote_access"]["enabled"] is True
    assert calls[0] == (
        {
            "ip": "10.0.9.3",
            "username": router.username,
            "password": router.password,
            "port": 8729,
        },
        ["webfig"],
        True,
        ["10.0.0.1/32"],
    )
    assert calls[1] == "availability_recorded"
    router_remote_access.revoke_webfig_proxy_sessions(router.id)


@pytest.mark.asyncio
async def test_webfig_proxy_uses_session_cookie_and_rewrites_router_paths(monkeypatch):
    session = router_remote_access.create_webfig_proxy_session(
        router_id=77,
        router_name="Router-77",
        router_ip="10.0.77.1",
        created_by_user_id=1,
    )
    captured = {}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            captured["client_kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def request(self, method, url, headers=None, content=None):
            captured["request"] = {
                "method": method,
                "url": url,
                "headers": headers,
                "content": content,
            }
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/html; charset=utf-8",
                    "set-cookie": "mikrotik_session=abc; Path=/; HttpOnly",
                },
                content=b'<html><a href="/webfig/">WebFig</a><script src="/webfig/app.js"></script></html>',
            )

    monkeypatch.setattr(router_management.httpx, "AsyncClient", FakeAsyncClient)

    response = await router_management.proxy_router_webfig(
        77,
        _request(
            "/api/admin/routers/77/webfig/",
            f"remote_access_token={session.token}&tab=interfaces",
            headers=[(b"host", b"testserver"), (b"cookie", b"webfig_access_77=token; mikrotik_session=abc")],
        ),
        "",
    )

    assert response.status_code == 200
    assert captured["request"]["method"] == "GET"
    assert captured["request"]["url"] == "http://10.0.77.1/?tab=interfaces"
    assert captured["request"]["headers"]["cookie"] == "mikrotik_session=abc"
    assert b'href="/api/admin/routers/77/webfig/webfig/"' in response.body
    assert b'src="/api/admin/routers/77/webfig/webfig/app.js"' in response.body
    set_cookie_headers = [
        value.decode()
        for key, value in response.raw_headers
        if key.lower() == b"set-cookie"
    ]
    assert any("mikrotik_session=abc" in header and "Path=/api/admin/routers/77/webfig" in header for header in set_cookie_headers)
    assert any("webfig_access_77=" in header and "HttpOnly" in header for header in set_cookie_headers)
    router_remote_access.revoke_webfig_proxy_sessions(77)


@pytest.mark.asyncio
async def test_webfig_proxy_uses_session_scheme_and_port(monkeypatch):
    session = router_remote_access.create_webfig_proxy_session(
        router_id=78,
        router_name="Router-78",
        router_ip="10.0.78.1",
        created_by_user_id=1,
        webfig_scheme="https",
        webfig_port=8443,
    )
    captured = {}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            captured["client_kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def request(self, method, url, headers=None, content=None):
            captured["request"] = {
                "method": method,
                "url": url,
                "headers": headers,
                "content": content,
            }
            return httpx.Response(200, headers={"content-type": "text/html"}, content=b"ok")

    monkeypatch.setattr(router_management.httpx, "AsyncClient", FakeAsyncClient)

    response = await router_management.proxy_router_webfig(
        78,
        _request(
            "/api/admin/routers/78/webfig/system",
            f"remote_access_token={session.token}",
            headers=[(b"host", b"testserver")],
        ),
        "system",
    )

    assert response.status_code == 200
    assert captured["client_kwargs"]["verify"] is False
    assert captured["request"]["url"] == "https://10.0.78.1:8443/system"
    assert captured["request"]["headers"]["host"] == "10.0.78.1:8443"
    router_remote_access.revoke_webfig_proxy_sessions(78)


@pytest.mark.asyncio
async def test_webfig_proxy_rejects_missing_or_expired_session():
    response = await router_management.proxy_router_webfig(
        77,
        _request("/api/admin/routers/77/webfig/"),
        "",
    )

    assert response.status_code == 403
    assert b"WebFig access expired" in response.body


@pytest.mark.asyncio
async def test_remote_access_options_allow_router_owner(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    response = await router_management.get_router_remote_access_options(
        router.id,
        db,
        _token(reseller),
    )

    assert response["success"] is True
    assert response["router_id"] == router.id
    assert response["targets"][0]["service"] == "winbox"


@pytest.mark.asyncio
async def test_remote_access_options_hide_other_reseller_router(db):
    owner = await make_reseller(db)
    other = await make_reseller(db)
    router = await make_router(db, owner)

    with pytest.raises(HTTPException) as exc:
        await router_management.get_router_remote_access_options(
            router.id,
            db,
            _token(other),
        )

    assert exc.value.status_code == 404
