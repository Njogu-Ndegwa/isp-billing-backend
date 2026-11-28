"""A customer's MAC is stored in the one form the router accepts (Tedd, 28 Nov 2026).

Tedd registered a TV as "B8..41..D9..DE..59..39". Register and edit stored it as
typed; every provisioning attempt then failed on the router with "invalid value
of mac-address", and the TV never got online. Now any common spelling is turned
into AA:BB:CC:DD:EE:FF, and anything that is not a MAC is refused up front.
"""

from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.api.auth_routes import login_token_claims
from app.db.models import Customer
from app.services import staff_access
from app.services.auth import create_access_token
from app.services.static_ip import normalize_pin_mac
from tests.factories import make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

CANON = "B8:41:D9:DE:59:39"


def _bearer(owner):
    return {"Authorization": f"Bearer {create_access_token(login_token_claims(owner), timedelta(hours=1))}"}


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    staff_access.reset_cache()

    async def _no_alert(*_a, **_k):
        pass

    from app.services import customer_notifications

    monkeypatch.setattr(staff_access, "alert_owner", _no_alert)
    monkeypatch.setattr(customer_notifications, "spawn_welcome_message", lambda *_a, **_k: None)
    yield
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


@pytest.mark.parametrize("typed", [
    "B8..41..D9..DE..59..39", "b8:41:d9:de:59:39", "B8-41-D9-DE-59-39",
    "b841.d9de.5939", "B8 41 D9 DE 59 39", "B841D9DE5939", "  B8:41:D9:DE:59:39 ",
])
async def test_every_common_spelling_becomes_the_router_form(typed):
    assert normalize_pin_mac(typed) == CANON


@pytest.mark.parametrize("typed", ["B8:41:D9:DE:59", "B8:41:D9:DE:59:39:00", "G8:41:D9:DE:59:39", "tv sebule"])
async def test_anything_else_is_not_a_mac(typed):
    with pytest.raises(ValueError):
        normalize_pin_mac(typed)


async def _register(client, headers, plan, router, mac, phone="0722000444"):
    return await client.post("/api/customers/register", headers=headers, json={
        "name": "TV ONE", "phone": phone, "plan_id": plan.id, "router_id": router.id, "mac_address": mac})


async def test_register_stores_the_mac_the_router_accepts(client, db):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await make_plan(db, owner, price=50, duration_value=1)
    headers = _bearer(owner)

    r = await _register(client, headers, plan, router, "B8..41..D9..DE..59..39")

    assert r.status_code == 200, r.text
    db.expire_all()
    assert (await db.get(Customer, r.json()["id"])).mac_address == CANON


async def test_register_refuses_a_broken_mac_with_a_clear_reason(client, db):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await make_plan(db, owner, price=50, duration_value=1)

    r = await _register(client, _bearer(owner), plan, router, "B8..41..D9..DE..59")

    assert r.status_code == 400
    assert "not a valid MAC" in r.json()["detail"]


async def test_another_spelling_of_a_known_mac_is_a_duplicate(client, db):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await make_plan(db, owner, price=50, duration_value=1)
    headers = _bearer(owner)
    assert (await _register(client, headers, plan, router, CANON)).status_code == 200

    r = await _register(client, headers, plan, router, "b8-41-d9-de-59-39", phone="0722000555")

    assert r.status_code == 409


async def test_edit_canonicalises_and_refuses_the_same_way(client, db):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await make_plan(db, owner, price=50, duration_value=1)
    headers = _bearer(owner)
    r = await _register(client, headers, plan, router, "AA:BB:CC:DD:EE:01")
    customer_id = r.json()["id"]

    ok = await client.put(f"/api/customers/{customer_id}", headers=headers, json={"mac_address": "b8..41..d9..de..59..39"})
    bad = await client.put(f"/api/customers/{customer_id}", headers=headers, json={"mac_address": "B8..41..D9"})

    assert ok.status_code == 200, ok.text
    assert bad.status_code == 400 and "not a valid MAC" in bad.json()["detail"]
    db.expire_all()
    assert (await db.get(Customer, customer_id)).mac_address == CANON
