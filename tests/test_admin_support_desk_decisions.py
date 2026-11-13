"""Support desk decisions: Dennis's go/close on "Waiting on Dennis" items.

Driven through the real ``main.app`` with real JWTs:

* POST /api/admin/support-desk/decisions -- platform admin JWT only.
* GET  /api/admin/support-desk/decisions[?pending=1] -- laptop machine token.
* POST /api/admin/support-desk/decisions/{id}/consumed -- laptop machine token.
* GET  /api/admin/support-desk -- now also carries the recent decisions.
"""

import json
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from jose import jwt

from app.config import settings
from app.services.auth import ALGORITHM, create_access_token
from app.services.support_desk import find_open_dennis_item
from tests.factories import make_admin, make_reseller

INGEST_URL = "/api/admin/support-desk/snapshot"
READ_URL = "/api/admin/support-desk"
DECISIONS_URL = "/api/admin/support-desk/decisions"
TOKEN = "a" * 24 + "b" * 24 + "c" * 16

OPEN_ID = "wl-abcdefghijkm"
WAITING_ID = "wl-qrstuvwxyzab"
DONE_ID = "wl-nnnnnnnnnnnn"
PROMISE_ID = "wl-pppppppppppp"

SNAPSHOT = {
    "generated_at": "2026-10-24T06:40:00+00:00",
    "worklog": {"entries": [
        {"id": OPEN_ID, "date": "2026-10-24", "at": "09:10", "category": "needs_dennis",
         "title": "Approve refund for BW-046", "outcome": "open"},
        {"id": WAITING_ID, "date": "2026-10-24", "at": "09:35", "category": "needs_dennis",
         "title": "New lead: Hey", "outcome": "waiting"},
        {"id": DONE_ID, "date": "2026-10-23", "at": "10:00", "category": "needs_dennis",
         "title": "Old decision", "outcome": "done"},
        {"id": PROMISE_ID, "date": "2026-10-23", "at": "11:00", "category": "promise",
         "title": "Call back", "outcome": "open"},
    ]},
}


def _bearer_jwt(user, **extra) -> dict:
    claims = {
        "sub": str(user.id),
        "user_code": user.user_code,
        "user_id": user.id,
        "role": user.role.value,
        "organization_name": user.organization_name,
        **extra,
    }
    return {"Authorization": f"Bearer {create_access_token(claims, timedelta(minutes=30))}"}


def _machine(token=TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def ingest_token(monkeypatch):
    monkeypatch.setattr(settings, "SUPPORT_DESK_INGEST_TOKEN", TOKEN)
    return TOKEN


@pytest_asyncio.fixture
async def client(engine):
    import main

    async with AsyncClient(
        transport=ASGITransport(app=main.app), base_url="http://test"
    ) as c:
        yield c


@pytest_asyncio.fixture
async def pushed(client):
    resp = await client.post(
        INGEST_URL,
        content=json.dumps(SNAPSHOT),
        headers={**_machine(), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    return resp


@pytest_asyncio.fixture
async def admin_headers(db):
    return _bearer_jwt(await make_admin(db))


async def _decide(client, headers, item_id=OPEN_ID, action="go", note=None):
    body = {"item_id": item_id, "action": action}
    if note is not None:
        body["note"] = note
    return await client.post(DECISIONS_URL, json=body, headers=headers)


# --------------------------------------------------------------------------
# Admin-only write
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_decision_without_token_is_401(client, pushed):
    resp = await client.post(DECISIONS_URL, json={"item_id": OPEN_ID, "action": "go"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_decision_as_reseller_is_403(client, db, pushed):
    resp = await _decide(client, _bearer_jwt(await make_reseller(db)))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_decision_with_view_as_token_is_refused(client, db, pushed):
    """An admin viewing as a reseller must not be able to decide."""
    admin = await make_admin(db)
    reseller = await make_reseller(db)
    claims = {
        "sub": str(reseller.id), "user_code": reseller.user_code,
        "user_id": reseller.id, "role": reseller.role.value,
        "organization_name": reseller.organization_name,
        "imp_sid": 999, "imp_by": admin.id, "ro": True,
        "exp": datetime.utcnow() + timedelta(minutes=10),
    }
    token = jwt.encode(claims, settings.SECRET_KEY, algorithm=ALGORITHM)
    resp = await _decide(client, {"Authorization": f"Bearer {token}"})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_decision_with_admin_role_but_impersonation_claim_is_403(client, db, pushed):
    """Even an ADMIN-role token is refused while it carries a View-as session."""
    admin = await make_admin(db)
    resp = await _decide(client, _bearer_jwt(admin, imp_sid=123, imp_by=admin.id))
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_decision_with_machine_token_is_401(client, pushed):
    """The laptop token can read and consume decisions, never create them."""
    resp = await _decide(client, _machine())
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_go_creates_pending_decision(client, pushed, admin_headers):
    resp = await _decide(client, admin_headers, note="  Go ahead, use the 4K Net key  ")
    assert resp.status_code == 201
    body = resp.json()
    assert body["item_id"] == OPEN_ID
    assert body["action"] == "go"
    assert body["note"] == "Go ahead, use the 4K Net key"
    assert body["consumed_at"] is None
    assert body["created_at"].endswith("Z")
    assert isinstance(body["decided_by"], int)
    assert resp.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_admin_can_close_a_waiting_item(client, pushed, admin_headers):
    resp = await _decide(client, admin_headers, item_id=WAITING_ID, action="close")
    assert resp.status_code == 201
    assert resp.json()["note"] is None


# --------------------------------------------------------------------------
# Payload limits and item validation
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_note_limit_is_500_chars(client, pushed, admin_headers):
    assert (await _decide(client, admin_headers, note="x" * 501)).status_code == 422
    assert (await _decide(client, admin_headers, note="x" * 500)).status_code == 201


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"item_id": OPEN_ID, "action": "delete"},
    {"item_id": OPEN_ID},
    {"action": "go"},
    {"item_id": "", "action": "go"},
    {"item_id": "x" * 65, "action": "go"},
    {"item_id": "wl-<script>", "action": "go"},
    {"item_id": OPEN_ID, "action": "go", "extra": 1},
    {"item_id": OPEN_ID, "action": "go", "note": 5},
])
async def test_bad_bodies_are_422(client, pushed, admin_headers, body):
    resp = await client.post(DECISIONS_URL, json=body, headers=admin_headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("item_id", ["wl-unknownitems", DONE_ID, PROMISE_ID])
async def test_unknown_closed_or_non_dennis_item_is_404(client, pushed, admin_headers, item_id):
    resp = await _decide(client, admin_headers, item_id=item_id)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_decision_before_any_snapshot_is_404(client, admin_headers):
    assert (await _decide(client, admin_headers)).status_code == 404


@pytest.mark.asyncio
async def test_note_is_masked(client, pushed, admin_headers):
    resp = await _decide(client, admin_headers, note="call him on 0712345678 or jane@example.com")
    assert resp.status_code == 201
    note = resp.json()["note"]
    assert "0712345678" not in note and "jane@example.com" not in note


@pytest.mark.asyncio
async def test_same_action_twice_is_not_duplicated(client, pushed, admin_headers):
    first = await _decide(client, admin_headers)
    again = await _decide(client, admin_headers)
    assert first.status_code == 201
    assert again.status_code == 200
    assert again.json()["id"] == first.json()["id"]
    pending = (await client.get(DECISIONS_URL, params={"pending": 1}, headers=_machine())).json()
    assert len(pending["decisions"]) == 1


@pytest.mark.asyncio
async def test_conflicting_pending_decision_is_409(client, pushed, admin_headers):
    assert (await _decide(client, admin_headers, action="go")).status_code == 201
    assert (await _decide(client, admin_headers, action="close")).status_code == 409


# --------------------------------------------------------------------------
# Machine-token read and consume
# --------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer " + "z" * 64}, {"Authorization": TOKEN}])
async def test_pending_read_with_bad_token_is_401(client, headers):
    resp = await client.get(DECISIONS_URL, params={"pending": 1}, headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_pending_read_with_admin_jwt_is_401(client, admin_headers):
    resp = await client.get(DECISIONS_URL, params={"pending": 1}, headers=admin_headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_machine_endpoints_disabled_without_env_token(client, monkeypatch):
    monkeypatch.setattr(settings, "SUPPORT_DESK_INGEST_TOKEN", "")
    assert (await client.get(DECISIONS_URL, headers=_machine())).status_code == 503
    assert (await client.post(f"{DECISIONS_URL}/1/consumed", headers=_machine())).status_code == 503


@pytest.mark.asyncio
async def test_consume_with_bad_token_is_401(client, pushed, admin_headers):
    decision = (await _decide(client, admin_headers)).json()
    url = f"{DECISIONS_URL}/{decision['id']}/consumed"
    assert (await client.post(url)).status_code == 401
    assert (await client.post(url, headers=_machine(TOKEN[:-1] + "x"))).status_code == 401
    assert (await client.post(url, headers=admin_headers)).status_code == 401
    pending = (await client.get(DECISIONS_URL, params={"pending": 1}, headers=_machine())).json()
    assert [d["id"] for d in pending["decisions"]] == [decision["id"]]


@pytest.mark.asyncio
async def test_pull_and_consume_flow(client, pushed, admin_headers):
    go = (await _decide(client, admin_headers, action="go", note="start")).json()
    close = (await _decide(client, admin_headers, item_id=WAITING_ID, action="close")).json()

    pending = await client.get(DECISIONS_URL, params={"pending": 1}, headers=_machine())
    assert pending.status_code == 200
    assert pending.headers["cache-control"] == "no-store"
    assert [d["id"] for d in pending.json()["decisions"]] == [go["id"], close["id"]]  # oldest first

    consumed = await client.post(f"{DECISIONS_URL}/{go['id']}/consumed", headers=_machine())
    assert consumed.status_code == 200
    stamp = consumed.json()["consumed_at"]
    assert stamp.endswith("Z")
    # Idempotent: a retry keeps the first stamp.
    again = await client.post(f"{DECISIONS_URL}/{go['id']}/consumed", headers=_machine())
    assert again.json()["consumed_at"] == stamp

    pending = (await client.get(DECISIONS_URL, params={"pending": 1}, headers=_machine())).json()
    assert [d["id"] for d in pending["decisions"]] == [close["id"]]

    everything = (await client.get(DECISIONS_URL, headers=_machine())).json()
    assert {d["id"] for d in everything["decisions"]} == {go["id"], close["id"]}

    # Once picked up, Dennis may decide on the same item again.
    assert (await _decide(client, admin_headers, action="close")).status_code == 201


@pytest.mark.asyncio
async def test_consume_unknown_decision_is_404(client):
    resp = await client.post(f"{DECISIONS_URL}/987654/consumed", headers=_machine())
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# Admin read carries decision state
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_read_includes_decisions(client, pushed, admin_headers):
    empty = (await client.get(READ_URL, headers=admin_headers)).json()
    assert empty["decisions"] == []

    go = (await _decide(client, admin_headers, note="go")).json()
    await client.post(f"{DECISIONS_URL}/{go['id']}/consumed", headers=_machine())
    close = (await _decide(client, admin_headers, item_id=WAITING_ID, action="close")).json()

    body = (await client.get(READ_URL, headers=admin_headers)).json()
    assert [d["id"] for d in body["decisions"]] == [close["id"], go["id"]]  # newest first
    by_id = {d["id"]: d for d in body["decisions"]}
    assert by_id[go["id"]]["consumed_at"] is not None
    assert by_id[close["id"]]["consumed_at"] is None
    assert body["snapshot"] == SNAPSHOT


# --------------------------------------------------------------------------
# Unit: item lookup
# --------------------------------------------------------------------------

def test_find_open_dennis_item():
    assert find_open_dennis_item(SNAPSHOT, OPEN_ID)["title"] == "Approve refund for BW-046"
    assert find_open_dennis_item(SNAPSHOT, WAITING_ID) is not None
    assert find_open_dennis_item(SNAPSHOT, DONE_ID) is None
    assert find_open_dennis_item(SNAPSHOT, PROMISE_ID) is None
    assert find_open_dennis_item(SNAPSHOT, "wl-missing") is None
    assert find_open_dennis_item({"worklog": "junk"}, OPEN_ID) is None
    assert find_open_dennis_item(None, OPEN_ID) is None
