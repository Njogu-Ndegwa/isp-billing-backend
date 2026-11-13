"""A credential stays bound until RouterOS confirms its bypass is gone."""

from app.services import mikrotik_background

MAC = "AA:BB:CC:DD:EE:02"


class Router:
    def __init__(self, *, sticky_binding=False, remove_error=False,
                 sticky_bypassed_host=False, host_reappears_unauthorized=False):
        self.sticky_binding = sticky_binding
        self.remove_error = remove_error
        self.sticky_bypassed_host = sticky_bypassed_host
        self.host_reappears_unauthorized = host_reappears_unauthorized
        self.bindings = [{".id": "*B1", "mac-address": MAC,
                          "type": "bypassed",
                          "comment": "ACCESS_CRED|cred:290|user:guest"}]
        self.hosts = [{".id": "*H1", "mac-address": MAC,
                       "idle-time": "20m", "bypassed": "true"}]
        self.commands = []

    def connect(self):
        return True

    def disconnect(self):
        pass

    def send_command(self, command, arguments=None):
        self.commands.append((command, arguments))
        if command == "/ip/hotspot/host/print":
            return {"success": True, "data": list(self.hosts)}
        if command == "/ip/hotspot/ip-binding/print":
            return {"success": True, "data": list(self.bindings)}
        if command == "/queue/simple/print":
            return {"success": True, "data": []}
        if command == "/ip/hotspot/ip-binding/remove":
            if self.remove_error:
                return {"success": False, "error": "timeout"}
            if not self.sticky_binding:
                self.bindings = []
            return {"success": True}
        if command == "/ip/hotspot/host/remove":
            if not self.sticky_bypassed_host:
                self.hosts = ([{".id": "*H2", "mac-address": MAC,
                                "bypassed": "false", "authorized": "false"}]
                              if self.host_reappears_unauthorized else [])
            return {"success": True}
        return {"success": True}


def _run(monkeypatch, router):
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI",
                        lambda *_args, **_kwargs: router)
    return mikrotik_background._scan_router_idle_credentials_sync(
        {"ip": "10.0.0.1", "username": "admin", "password": "pw",
         "port": 8728, "name": "R1"},
        [{"id": 290, "bound_mac_address": MAC, "bound_at": None}],
        15 * 60,
    )


def test_verified_binding_and_bypassed_host_removal_releases_credential(monkeypatch):
    router = Router(host_reappears_unauthorized=True)
    result = _run(monkeypatch, router)
    assert [x["id"] for x in result["to_release"]] == [290]
    assert router.bindings == []
    assert router.hosts[0]["bypassed"] == "false"


def test_router_acknowledges_but_keeps_binding(monkeypatch):
    router = Router(sticky_binding=True)
    assert _run(monkeypatch, router)["to_release"] == []


def test_binding_removal_error_keeps_credential_bound(monkeypatch):
    router = Router(remove_error=True)
    assert _run(monkeypatch, router)["to_release"] == []


def test_bypassed_host_survives_removal(monkeypatch):
    router = Router(sticky_bypassed_host=True)
    assert _run(monkeypatch, router)["to_release"] == []
