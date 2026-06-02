import pytest
from fastapi import HTTPException

from app.api import router_operations
from app.services.mikrotik_api import MikroTikAPI
from tests.factories import make_reseller, make_router


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


@pytest.mark.asyncio
async def test_reboot_router_requires_confirm(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    async def _run_with_guard(*_args, **_kwargs):
        raise AssertionError("router reboot should not run without explicit confirmation")

    monkeypatch.setattr(router_operations, "run_with_guard", _run_with_guard)

    with pytest.raises(HTTPException) as exc:
        await router_operations.reboot_router(
            router.id,
            router_operations.RebootRouterRequest(confirm=False),
            db,
            _token(reseller),
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == "Set confirm=true to reboot this router"


@pytest.mark.asyncio
async def test_reboot_router_runs_guarded_router_command(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, ip_address="10.0.20.1", port=8729)
    calls = []

    async def _run_with_guard(router_id, fn, router_info, **kwargs):
        calls.append({
            "router_id": router_id,
            "helper": fn.__name__,
            "router_info": router_info,
            "kwargs": kwargs,
        })
        return {
            "success": True,
            "status": "sent_connection_closed",
            "command_sent": True,
            "connection_closed": True,
            "message": "Reboot command sent; router closed the API connection.",
        }

    monkeypatch.setattr(router_operations, "run_with_guard", _run_with_guard)

    response = await router_operations.reboot_router(
        router.id,
        router_operations.RebootRouterRequest(confirm=True, reason="maintenance window"),
        db,
        _token(reseller),
    )

    assert response["success"] is True
    assert response["router_id"] == router.id
    assert response["router_name"] == router.name
    assert response["status"] == "sent_connection_closed"
    assert response["command_sent"] is True
    assert response["connection_closed"] is True
    assert response["reason"] == "maintenance window"
    assert calls == [{
        "router_id": router.id,
        "helper": "_reboot_router_sync",
        "router_info": {
            "ip": "10.0.20.1",
            "username": router.username,
            "password": router.password,
            "port": 8729,
        },
        "kwargs": {
            "acquire_timeout_seconds": 5,
            "timeout_seconds": 20,
        },
    }]


@pytest.mark.asyncio
async def test_reboot_router_connect_failure_returns_503(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)

    async def _run_with_guard(*_args, **_kwargs):
        return {"error": "connect_failed", "message": "API service not reachable"}

    monkeypatch.setattr(router_operations, "run_with_guard", _run_with_guard)

    with pytest.raises(HTTPException) as exc:
        await router_operations.reboot_router(
            router.id,
            router_operations.RebootRouterRequest(confirm=True),
            db,
            _token(reseller),
        )

    assert exc.value.status_code == 503
    assert exc.value.detail == "API service not reachable"


def test_mikrotik_reboot_router_accepts_done_response():
    api = MikroTikAPI("10.0.0.1", "admin", "admin")
    api.connected = True
    sent = []

    api.send_sentence = lambda words: sent.append(words)
    api.read_sentence = lambda: ["!done"]

    response = api.reboot_router()

    assert sent == [["/system/reboot"]]
    assert response["success"] is True
    assert response["status"] == "accepted"
    assert response["command_sent"] is True


def test_mikrotik_reboot_router_treats_connection_close_after_send_as_success():
    api = MikroTikAPI("10.0.0.1", "admin", "admin")
    api.connected = True
    sent = []

    def _read_sentence():
        api.connected = False
        return []

    api.send_sentence = lambda words: sent.append(words)
    api.read_sentence = _read_sentence

    response = api.reboot_router()

    assert sent == [["/system/reboot"]]
    assert response["success"] is True
    assert response["status"] == "sent_connection_closed"
    assert response["connection_closed"] is True
