"""Device-mode text and preset naming.

RouterOS 7.17 renamed the `enterprise` preset to `advanced`, so the endpoint has
to send the name the router's version understands. `home` mode blocks fetch and
scheduler as well as hotspot, so the setup text has to give the full command.
No real router is involved: the RouterOS API is faked.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import provisioning as provisioning_api
from app.api import router_operations
from app.api.provisioning import ProvisionCreateRequest, create_provision_token
from app.api.router_operations import (
    DeviceModeUpdateRequest,
    _device_mode_name_for_version,
    _update_device_mode_sync,
    update_device_mode,
)

FULL_COMMAND = "/system/device-mode/update fetch=yes scheduler=yes hotspot=yes"
ROUTER_INFO = {"ip": "10.0.0.2", "username": "u", "password": "p", "port": 8728}


def _fake_api(monkeypatch, *, version="7.18.2 (stable)", current_mode="home", update_error=None):
    sent = []

    class FakeAPI:
        last_connect_error = None

        def __init__(self, *args, **kwargs):
            pass

        def connect(self):
            return True

        def disconnect(self):
            pass

        def send_command(self, command, args=None):
            sent.append((command, args))
            if command == "/system/device-mode/print":
                return {"success": True, "data": [{"mode": current_mode}]}
            if command == "/system/resource/print":
                if version is None:
                    return {"error": "no such command"}
                return {"success": True, "data": [{"version": version}]}
            if update_error:
                return {"error": update_error}
            return {"success": True, "data": []}

    monkeypatch.setattr(router_operations, "MikroTikAPI", FakeAPI)
    return sent


def _update_args(sent):
    return next(args for command, args in sent if command == "/system/device-mode/update")


@pytest.mark.parametrize(
    "mode, version, expected",
    [
        ("advanced", "7.17", "advanced"),
        ("advanced", "7.18.2 (stable)", "advanced"),
        ("enterprise", "7.17.2", "advanced"),
        ("enterprise", "8.0", "advanced"),
        ("advanced", "7.16.2 (stable)", "enterprise"),
        ("advanced", "7.9", "enterprise"),
        ("enterprise", "7.13", "enterprise"),
        # Unreadable version: keep what the caller asked for.
        ("advanced", None, "advanced"),
        ("enterprise", "", "enterprise"),
        ("advanced", "unknown", "advanced"),
        # The other presets have one name on every version.
        ("home", "7.16", "home"),
        ("basic", "7.18", "basic"),
        (None, "7.18", None),
    ],
)
def test_preset_name_follows_routeros_version(mode, version, expected):
    assert _device_mode_name_for_version(mode, version) == expected


@pytest.mark.parametrize(
    "requested, version, expected",
    [
        ("advanced", "7.18.2 (stable)", "advanced"),
        ("enterprise", "7.18.2 (stable)", "advanced"),
        ("advanced", "7.15.3 (stable)", "enterprise"),
        ("enterprise", "7.15.3 (stable)", "enterprise"),
    ],
)
def test_router_is_sent_the_name_its_version_uses(monkeypatch, requested, version, expected):
    sent = _fake_api(monkeypatch, version=version, update_error="please press reset button to confirm")
    result = _update_device_mode_sync(ROUTER_INFO, requested)
    assert _update_args(sent) == {"mode": expected}
    assert result["sent_mode"] == expected
    assert result["status"] == "pending_physical_confirmation"


def test_unreadable_version_sends_the_requested_name(monkeypatch):
    sent = _fake_api(monkeypatch, version=None, update_error="please press reset button to confirm")
    result = _update_device_mode_sync(ROUTER_INFO, "advanced")
    assert _update_args(sent) == {"mode": "advanced"}
    assert result["sent_mode"] == "advanced"


@pytest.mark.parametrize(
    "requested, version, current",
    [
        ("enterprise", "7.18.2", "advanced"),
        ("advanced", "7.15.3", "enterprise"),
        ("advanced", "7.18.2", "advanced"),
    ],
)
def test_either_name_recognises_a_router_already_in_that_mode(monkeypatch, requested, version, current):
    sent = _fake_api(monkeypatch, version=version, current_mode=current)
    result = _update_device_mode_sync(ROUTER_INFO, requested)
    assert result["status"] == "already_in_mode"
    assert result["sent_mode"] is None
    assert not [command for command, _ in sent if command == "/system/device-mode/update"]


def test_other_presets_and_flags_do_not_read_the_version(monkeypatch):
    sent = _fake_api(monkeypatch, current_mode="home", update_error="press reset button")
    _update_device_mode_sync(ROUTER_INFO, "basic")
    assert _update_args(sent) == {"mode": "basic"}
    sent.clear()
    _update_device_mode_sync(ROUTER_INFO, None, {"hotspot": "yes"})
    assert _update_args(sent) == {"flagged": "yes", "hotspot": "yes"}
    assert not [command for command, _ in sent if command == "/system/resource/print"]


def test_rejected_mode_names_the_value_and_the_full_flag_set(monkeypatch):
    _fake_api(monkeypatch, update_error="value of mode does not match any value of mode")
    result = _update_device_mode_sync(ROUTER_INFO, "advanced")
    assert result["status"] == "mode_value_rejected"
    assert "'advanced'" in result["message"]
    for flag in ("fetch", "scheduler", "hotspot"):
        assert f'"{flag}": "yes"' in result["message"]


def _call_update(monkeypatch, mode):
    router_obj = SimpleNamespace(
        id=7, name="R", identity="R-1", ip_address="10.0.0.2",
        username="u", password="p", port=8728,
    )

    async def fake_user(token, db):
        return SimpleNamespace(id=1, role=SimpleNamespace(value="reseller"))

    async def fake_router(db, identity, user_id, role):
        return router_obj

    async def fake_availability(*args, **kwargs):
        return None

    class FakeDB:
        async def commit(self):
            return None

    monkeypatch.setattr(router_operations, "get_current_user", fake_user)
    monkeypatch.setattr(router_operations, "get_router_by_identity", fake_router)
    monkeypatch.setattr(router_operations, "record_router_availability", fake_availability)
    return asyncio.run(
        update_device_mode("R-1", DeviceModeUpdateRequest(mode=mode), db=FakeDB(), token="t")
    )


def test_endpoint_accepts_advanced_and_reports_both_names(monkeypatch):
    _fake_api(monkeypatch, version="7.15.3", update_error="press reset button")
    response = _call_update(monkeypatch, "Advanced")
    assert response["requested_mode"] == "advanced"
    assert response["sent_mode"] == "enterprise"


def test_endpoint_still_rejects_unknown_modes(monkeypatch):
    with pytest.raises(HTTPException) as exc:
        _call_update(monkeypatch, "turbo")
    assert exc.value.status_code == 400
    assert "advanced" in exc.value.detail


def _create_note(monkeypatch, vpn_type):
    async def fake_user(token, db):
        return SimpleNamespace(id=1)

    async def fake_create(**kwargs):
        return SimpleNamespace(
            token="abc", router_name="R", identity="R-1", vpn_type=vpn_type,
            management_tunnel=None, is_routerboard=False, wireguard_ip="10.0.0.2",
            created_at=datetime(2026, 11, 5),
        )

    monkeypatch.setattr(provisioning_api, "get_current_user", fake_user)
    monkeypatch.setattr(provisioning_api, "create_provisioning_token", fake_create)
    monkeypatch.setattr(provisioning_api, "build_provision_command", lambda token: "cmd")
    monkeypatch.setattr(provisioning_api, "derive_insurance_ip", lambda ip: None)
    response = asyncio.run(
        create_provision_token(ProvisionCreateRequest(vpn_type=vpn_type), db=None, token="t")
    )
    return response["note"]


def test_v7_note_gives_the_full_command_and_the_real_window(monkeypatch):
    note = _create_note(monkeypatch, "wireguard")
    assert FULL_COMMAND in note
    assert "within 5 minutes" in note
    assert "A normal reboot cancels the change" in note
    assert "connects the router to the billing system remotely" in note


def test_v6_note_does_not_mention_device_mode(monkeypatch):
    # RouterOS v6 has no device-mode.
    assert "device-mode" not in _create_note(monkeypatch, "l2tp")


def test_setup_guide_matches_the_mikrotik_docs():
    guide = (Path(__file__).parent.parent / "ROUTER_SETUP_GUIDE.md").read_text(encoding="utf-8")
    assert "60 seconds" not in guide
    assert "ships with `device-mode=home`" not in guide
    assert "device-mode/update hotspot=yes" not in guide
    assert FULL_COMMAND in guide
    assert "**5 minutes**" in guide
    assert "A normal reboot cancels the change" in guide
    assert "connects your router to the billing system remotely" in guide
