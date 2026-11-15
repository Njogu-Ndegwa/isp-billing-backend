import pytest
from fastapi import BackgroundTasks, HTTPException

from app.api.public_routes import access_credential_login_public
from app.db.models import AccessCredential, RouterAuthMethod
from app.services import access_credentials
from tests.factories import make_reseller, make_router


@pytest.mark.asyncio
@pytest.mark.parametrize("owner_id,limit", [(775, 2), (774, 1)])
async def test_access_login_keeps_each_bound_device_until_credential_limit(db, monkeypatch, owner_id, limit):
    owner = await make_reseller(db, id=owner_id)
    router = await make_router(db, owner, auth_method=RouterAuthMethod.DIRECT_API)
    credential = AccessCredential(user_id=owner.id, router_id=router.id, username="two-devices", password="test-password")
    db.add(credential)
    await db.commit()
    observed = []

    async def bind(credential, router, mac):
        observed.append(mac)
        return {"success": True, "client_ip": None}

    monkeypatch.setattr(access_credentials, "bind_mac_for_login", bind)
    addresses = [f"02:00:00:00:00:{n:02X}" for n in range(1, 4)]

    async def login(mac):
        return await access_credential_login_public(
            {"router_id": router.id, "username": credential.username, "password": credential.password, "mac_address": mac},
            BackgroundTasks(), db,
        )

    for mac in addresses[:limit]:
        assert (await login(mac))["success"]
    assert (await login(addresses[0]))["success"]
    with pytest.raises(HTTPException) as exc:
        await login(addresses[limit])
    assert exc.value.status_code == 409
    assert observed == addresses[:limit] + addresses[:1]
    assert access_credentials.bound_credential_macs(credential) == addresses[:limit]
