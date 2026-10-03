"""Expired PPPoE customers must not survive removal by redialling.

2026-10-02: Mutheu (router 407) expired at 20:25:33 UTC and was online again
at 20:26:10 with no PPP secret, for ten hours; A25 on router 255 the same way.
Removal disconnected the session FIRST and deleted the secret SECOND. A PPPoE
client redials within a second, so the redial landed while the secret still
existed - and an established session is not dropped when its secret is
deleted. The fake router below redials instantly, which is what the field does.
"""

import pytest

from app.services import mikrotik_background, pppoe_provisioning


class RedialingRouter:
    """RouterOS stand-in whose PPPoE client redials the instant it is kicked,
    and succeeds whenever its secret still exists."""

    secrets: set = set()
    active: set = set()
    calls: list = []

    def __init__(self, *a, **k):
        pass

    def connect(self):
        return True

    def disconnect(self):
        pass

    def disconnect_pppoe_session(self, username):
        type(self).calls.append("disconnect")
        n = 1 if username in self.active else 0
        self.active.discard(username)
        if username in self.secrets:      # instant redial authenticates again
            self.active.add(username)
        return {"success": True, "disconnected": n}

    def remove_pppoe_secret(self, username):
        type(self).calls.append("remove_secret")
        self.secrets.discard(username)
        return {"success": True, "action": "removed"}


@pytest.fixture
def router(monkeypatch):
    RedialingRouter.secrets = {"Mutheu"}
    RedialingRouter.active = {"Mutheu"}
    RedialingRouter.calls = []
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", RedialingRouter)
    monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", RedialingRouter)
    return RedialingRouter


def test_expiry_cleanup_leaves_no_session_behind(router):
    out = mikrotik_background._cleanup_single_router_pppoe_sync(
        {"ip": "10.0.0.174", "username": "u", "password": "p", "port": 8728, "name": "wifiyetu #1"},
        [{"id": 26629, "pppoe_username": "Mutheu"}],
    )
    assert [r["id"] for r in out["removed"]] == [26629]
    assert router.calls == ["remove_secret", "disconnect"]
    assert router.active == set() and router.secrets == set()


def test_manual_removal_leaves_no_session_behind(router):
    out = pppoe_provisioning._remove_pppoe_sync({
        "router_ip": "10.0.0.174", "router_username": "u", "router_password": "p",
        "router_port": 8728, "pppoe_username": "Mutheu",
    })
    assert out.get("success")
    assert router.calls == ["remove_secret", "disconnect"]
    assert router.active == set() and router.secrets == set()


def test_failed_secret_removal_does_not_kick_and_is_retried(router, monkeypatch):
    # Kicking without removing the secret just lets them straight back in.
    monkeypatch.setattr(RedialingRouter, "remove_pppoe_secret",
                        lambda self, u: {"error": "timeout reading /ppp/secret"})
    out = mikrotik_background._cleanup_single_router_pppoe_sync(
        {"ip": "10.0.0.174", "username": "u", "password": "p", "port": 8728, "name": "wifiyetu #1"},
        [{"id": 26629, "pppoe_username": "Mutheu"}],
    )
    assert [r["id"] for r in out["failed"]] == [26629]
    assert "disconnect" not in router.calls
