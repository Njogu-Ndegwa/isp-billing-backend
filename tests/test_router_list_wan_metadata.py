"""The dashboard must receive saved WAN roles from the router list API."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api import router_management as routes
from app.db.database import get_db
from app.services.auth import verify_token
from tests.factories import make_reseller, make_router


@pytest.mark.parametrize("enabled,config", [
    (True, {"wan_ports": ["ether1", "ether2"], "applied_at": "2026-10-16T12:00:00"}),
    (False, {"wan_ports": ["ether1", "ether2"]}),
    (False, None),
])
async def test_router_list_returns_wan_settings_only_for_owned_routers(db, monkeypatch, enabled, config):
    owner = await make_reseller(db)
    own_router = await make_router(db, owner, lb_enabled=enabled, lb_config=config)
    other = await make_reseller(db)
    await make_router(db, other, lb_enabled=True, lb_config={"wan_ports": ["ether3", "ether4"]})

    async def current_user(token, session):
        return owner

    async def database():
        yield db

    monkeypatch.setattr(routes, "get_current_user", current_user)
    application = FastAPI()
    application.include_router(routes.router)
    application.dependency_overrides[get_db] = database
    application.dependency_overrides[verify_token] = lambda: "test-token"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        response = await client.get("/api/routers")

    assert response.status_code == 200
    payload = response.json()
    assert [item["id"] for item in payload] == [own_router.id]
    assert payload[0]["lb_enabled"] is enabled
    assert payload[0]["lb_config"] == config
