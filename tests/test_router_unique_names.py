"""Two routers on one account never get the same name (CR-1123-F9).

The default name "<business> #N" was counted from the routers the account has
now, so after "#2" was deleted an account with "#1" and "#3" got a second "#3".
A rename to a name another router on the account already has is refused (409),
and the assistant is told which routers share a name so it can tell them apart.
"""

import secrets

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import router_management
from app.db.models import ProvisioningToken, ProvisioningTokenStatus, Router, User, UserRole
from app.services import provisioning
from app.services.assistant import router_names


async def _user(db, code: int, business: str = "Kahawa Net") -> User:
    user = User(
        user_code=code, email=f"rn{code}@example.com", password_hash="hash",
        role=UserRole.RESELLER, organization_name=business, business_name=business,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _router(db, user, name: str, n: int) -> Router:
    router = Router(
        user_id=user.id, name=name, identity=f"Router-{9000 + n}", ip_address=f"10.0.9.{n}",
        username="admin", password="pw", port=8728,
    )
    db.add(router)
    await db.commit()
    await db.refresh(router)
    return router


def _token(user, name: str, n: int) -> ProvisioningToken:
    return ProvisioningToken(
        user_id=user.id, token=secrets.token_hex(16), router_name=name, identity=f"Router-{9100 + n}",
        vpn_type="wireguard", wireguard_ip=f"10.0.8.{n}", router_admin_password="pw",
        server_public_ip="91.98.238.12", status=ProvisioningTokenStatus.PENDING,
    )


@pytest.mark.asyncio
async def test_new_name_skips_a_number_still_in_use_after_a_delete(db):
    user = await _user(db, 5101)
    await _router(db, user, "Kahawa Net #1", 1)
    await _router(db, user, "Kahawa Net #3", 3)   # "#2" was deleted

    name = await provisioning._generate_router_name(db, user.id)

    assert name == "Kahawa Net #4"


@pytest.mark.asyncio
async def test_new_name_skips_a_pending_setup_code_name_and_spacing_or_case(db):
    user = await _user(db, 5102)
    await _router(db, user, "kahawa  net #1", 1)   # same name, different spacing and case
    db.add(_token(user, "Kahawa Net #2", 2))
    await db.commit()

    name = await provisioning._generate_router_name(db, user.id)

    assert name == "Kahawa Net #3"


@pytest.mark.asyncio
async def test_completing_a_setup_code_whose_name_was_taken_meanwhile_picks_a_free_one(db, monkeypatch):
    monkeypatch.setattr(provisioning.settings, "PROVISION_MGMT_TO_HETZNER", False)
    user = await _user(db, 5103)
    token = _token(user, "Kahawa Net #2", 2)
    db.add(token)
    await db.commit()
    await _router(db, user, "Kahawa Net #2", 5)   # an existing router renamed to it meanwhile

    router = await provisioning.complete_provisioning(db, token)

    names = (await db.execute(select(Router.name).where(Router.user_id == user.id))).scalars().all()
    assert router.name != "Kahawa Net #2"
    assert len(set(names)) == len(names)


def _patch_auth(monkeypatch, user):
    async def current_user(_token, _db):
        return user

    monkeypatch.setattr(router_management, "get_current_user", current_user)
    monkeypatch.setattr(router_management, "enforce_active_subscription", lambda _u: None)


@pytest.mark.asyncio
async def test_rename_to_a_name_another_router_has_is_refused(db, monkeypatch):
    user = await _user(db, 5104)
    await _router(db, user, "Kahawa Net #1", 1)
    second = await _router(db, user, "Kahawa Net #2", 2)
    _patch_auth(monkeypatch, user)

    with pytest.raises(HTTPException) as exc:
        await router_management.update_router(
            second.id,
            router_management.RouterUpdateRequest(name="kahawa net  #1", ip_address=second.ip_address),
            db=db, token="token",
        )

    assert exc.value.status_code == 409
    await db.refresh(second)
    assert second.name == "Kahawa Net #2"


@pytest.mark.asyncio
async def test_saving_a_router_under_its_own_name_and_a_free_name_both_work(db, monkeypatch):
    user = await _user(db, 5105)
    other = await _user(db, 5106)
    await _router(db, other, "Shop", 7)   # another account's name is not a clash
    router = await _router(db, user, "Kahawa Net #1", 1)
    _patch_auth(monkeypatch, user)

    same = await router_management.update_router(
        router.id,
        router_management.RouterUpdateRequest(name="Kahawa Net #1", ip_address=router.ip_address, port=8729),
        db=db, token="token",
    )
    renamed = await router_management.update_router(
        router.id,
        router_management.RouterUpdateRequest(name="Shop", ip_address=router.ip_address),
        db=db, token="token",
    )

    assert same["name"] == "Kahawa Net #1"
    assert renamed["name"] == "Shop"


@pytest.mark.asyncio
async def test_adding_a_router_by_hand_under_a_taken_name_is_refused(db, monkeypatch):
    user = await _user(db, 5107)
    await _router(db, user, "Kahawa Net #1", 1)
    _patch_auth(monkeypatch, user)

    with pytest.raises(HTTPException) as exc:
        await router_management.create_router_api(
            router_management.RouterCreateRequest(
                name="Kahawa Net #1", ip_address="10.0.9.200", username="admin", password="pw",
            ),
            db=db, token="token",
        )

    assert exc.value.status_code == 409


def test_assistant_router_list_marks_routers_that_share_a_name():
    rows = [
        {"id": 659, "name": "Kenjo  #3", "identity": "Router-1596", "status": "offline"},
        {"id": 734, "name": "Kenjo #3", "identity": "Router-1735", "status": "online"},
        {"id": 658, "name": "Kenjo #1", "identity": "Router-1589", "status": "offline"},
    ]

    marked = router_names.mark_shared_names(rows)

    assert marked[0]["same_name_as"] == [{"id": 734, "identity": "Router-1735", "status": "online"}]
    assert marked[1]["same_name_as"] == [{"id": 659, "identity": "Router-1596", "status": "offline"}]
    assert "same_name_as" not in marked[2]
    assert "same_name_as" not in rows[0]   # the API result itself is untouched


def test_assistant_marks_shared_names_inside_a_wrapped_result_and_leaves_others_alone():
    data = {"routers": [
        {"id": 1, "name": "A", "identity": "Router-0001", "status": "online"},
        {"id": 2, "name": "A", "identity": "Router-0002", "status": "offline"},
    ], "total": 2}
    plain = [{"id": 1, "name": "Weekly"}, {"id": 2, "name": "Weekly"}]   # not routers

    assert router_names.mark_shared_names(data)["routers"][0]["same_name_as"][0]["identity"] == "Router-0002"
    assert router_names.mark_shared_names(plain) == plain
