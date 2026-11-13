"""The dashboard only claims live access when RouterOS confirms a session."""

from datetime import datetime, timedelta

from app.services import expired_online_monitor as monitor


class FakeRouter:
    def __init__(self, *, authorized=True, active=True):
        self.authorized = authorized
        self.active = active

    def connect(self):
        return True

    def disconnect(self):
        pass

    def send_command_optimized(self, command, proplist=None):
        if command == "/ip/hotspot/active/print":
            return {"success": True, "data": [
                {"mac-address": "AA:BB:CC:DD:EE:01", "uptime": "2h"}
            ] if self.active else []}
        if command == "/ip/hotspot/host/print":
            return {"success": True, "data": [
                {"mac-address": "AA:BB:CC:DD:EE:01",
                 "authorized": "true" if self.authorized else "false"}
            ]}
        return {"success": True, "data": []}


def _candidate():
    return {
        "id": 1, "name": "Customer", "router_id": 2, "router_name": "Router",
        "user_id": 3, "reseller_name": "Reseller", "status": "INACTIVE",
        "expiry": datetime.utcnow() - timedelta(hours=2),
        "mac": "AA:BB:CC:DD:EE:01", "ip_address": "10.0.0.2",
        "username": "u", "password": "p", "port": 8728,
    }


def test_monitor_requires_both_active_and_authorized_host(monkeypatch):
    monkeypatch.setattr(monitor, "MikroTikAPI", lambda *_args, **_kwargs: FakeRouter())
    assert monitor._scan_router(_candidate(), [_candidate()])[0]["customer_id"] == 1

    monkeypatch.setattr(monitor, "MikroTikAPI", lambda *_args, **_kwargs: FakeRouter(authorized=False))
    assert monitor._scan_router(_candidate(), [_candidate()]) == []

    monkeypatch.setattr(monitor, "MikroTikAPI", lambda *_args, **_kwargs: FakeRouter(active=False))
    assert monitor._scan_router(_candidate(), [_candidate()]) == []
