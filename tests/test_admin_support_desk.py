"""WhatsApp support desk snapshot: laptop ingest + platform-admin read.

Driven through the real ``main.app`` with real JWTs, so the route wiring in
main.py and both auth chains are what production runs:

* POST /api/admin/support-desk/snapshot -- machine bearer token from
  SUPPORT_DESK_INGEST_TOKEN (503 when unset, 401 when wrong).
* GET /api/admin/support-desk -- user JWT, role ADMIN only.
"""

import json
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from jose import jwt

from app.config import settings
from app.services.auth import ALGORITHM, create_access_token
from app.services.support_desk import mask_text, mask_value
from tests.factories import make_admin, make_reseller

INGEST_URL = "/api/admin/support-desk/snapshot"
READ_URL = "/api/admin/support-desk"
TOKEN = "a" * 24 + "b" * 24 + "c" * 16  # 64 chars, like `openssl rand -hex 32`

SNAPSHOT = {
    "generated_at": "2026-10-23T11:45:20+00:00",
    "customers": {
        "window_label": "Since 22 Oct 2026",
        "rows": [
            {
                "id": "c1",
                "name": "Prince",
                "status": "us",
                "class": "lead",
                "last_at": "2026-10-23T14:28:42+03:00",
                "open_promises": 1,
                "open_dennis": False,
                "work": [
                    {"date": "2026-10-23", "at": "13:26", "category": "promise",
                     "title": "Call back with LiteBeam prices", "outcome": "open"},
                ],
            }
        ],
    },
    "worklog": {"entries": [
        {"date": "2026-10-23", "at": "09:10", "category": "needs_dennis",
         "title": "Approve refund for BW-046", "detail": "KES 1500", "outcome": "open"},
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


@pytest.fixture
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


async def _push(client, body=SNAPSHOT, token=TOKEN):
    content = body if isinstance(body, (bytes, str)) else json.dumps(body)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return await client.post(INGEST_URL, content=content, headers=headers)


# --------------------------------------------------------------------------
# Ingest auth
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ingest_disabled_when_env_unset(client, monkeypatch):
    monkeypatch.setattr(settings, "SUPPORT_DESK_INGEST_TOKEN", "")
    resp = await _push(client, token="anything")
    assert resp.status_code == 503
    assert resp.json()["detail"] == "Support desk ingest is disabled"


@pytest.mark.asyncio
async def test_ingest_disabled_when_env_token_too_short(client, monkeypatch):
    monkeypatch.setattr(settings, "SUPPORT_DESK_INGEST_TOKEN", "short-token")
    resp = await _push(client, token="short-token")
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_ingest_missing_token_is_401(client, ingest_token):
    resp = await _push(client, token=None)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_wrong_token_is_401(client, ingest_token):
    resp = await _push(client, token=TOKEN[:-1] + "x")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_rejects_admin_user_jwt(client, db, ingest_token):
    """A logged-in admin's JWT is not the ingest token."""
    headers = _bearer_jwt(await make_admin(db))
    headers["Content-Type"] = "application/json"
    resp = await client.post(INGEST_URL, content=json.dumps(SNAPSHOT), headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_too_large_is_413(client, ingest_token, monkeypatch):
    monkeypatch.setattr(settings, "SUPPORT_DESK_SNAPSHOT_MAX_BYTES", 100)
    resp = await _push(client, body={"pad": "x" * 200})
    assert resp.status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'{"a": NaN}', b"\xff\xfe"])
async def test_ingest_rejects_non_object_json(client, ingest_token, body):
    resp = await _push(client, body=body)
    assert resp.status_code == 400


# --------------------------------------------------------------------------
# Read role gate
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_read_without_token_is_401(client):
    assert (await client.get(READ_URL)).status_code == 401


@pytest.mark.asyncio
async def test_read_as_reseller_is_403(client, db, ingest_token):
    assert (await _push(client)).status_code == 200
    resp = await client.get(READ_URL, headers=_bearer_jwt(await make_reseller(db)))
    assert resp.status_code == 403
    assert "snapshot" not in resp.text


@pytest.mark.asyncio
async def test_read_with_view_as_token_is_403(client, db, ingest_token):
    """An admin viewing as a reseller carries the reseller's role -> 403."""
    assert (await _push(client)).status_code == 200
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
    resp = await client.get(READ_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in (401, 403)
    assert "snapshot" not in resp.text


@pytest.mark.asyncio
async def test_read_before_any_push_is_404(client, db):
    resp = await client.get(READ_URL, headers=_bearer_jwt(await make_admin(db)))
    assert resp.status_code == 404
    assert resp.json()["detail"] == "No support desk snapshot yet"


@pytest.mark.asyncio
async def test_super_admin_reads_latest_snapshot(client, db, ingest_token):
    first = await _push(client, body={**SNAPSHOT, "generated_at": "old"})
    assert first.status_code == 200
    pushed = await _push(client)
    assert pushed.status_code == 200
    meta = pushed.json()
    assert meta["masked"] == 0
    assert len(meta["sha256"]) == 64
    assert meta["received_at"].endswith("Z")

    resp = await client.get(READ_URL, headers=_bearer_jwt(await make_admin(db)))
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["snapshot"] == SNAPSHOT  # latest push wins, stored verbatim
    assert body["received_at"] == meta["received_at"]
    assert body["sha256"] == meta["sha256"]


@pytest.mark.asyncio
async def test_ingest_masks_pii_before_storing(client, db, ingest_token):
    leaky = {
        "customers": {"rows": [{
            "name": "Jane 0712345678",
            "snippet": "mail me at jane.doe@example.co.ke or call +254 712 345 678",
            "jid": "254712345678@s.whatsapp.net",
            "lid": "123456789012345@lid",
            "when": "2026-10-23T14:28:42+03:00",
            "ticket": "BW-046-1021-1803-tv-test",
        }]},
        "by_number": {"254700000001": "x"},
    }
    resp = await _push(client, body=leaky)
    assert resp.status_code == 200
    assert resp.json()["masked"] >= 6

    stored = (await client.get(READ_URL, headers=_bearer_jwt(await make_admin(db)))).json()
    text = json.dumps(stored["snapshot"])
    for secret in ("0712345678", "jane.doe", "712 345 678", "254712345678",
                   "123456789012345", "@lid", "whatsapp.net", "254700000001"):
        assert secret not in text, secret
    row = stored["snapshot"]["customers"]["rows"][0]
    assert row["when"] == "2026-10-23T14:28:42+03:00"  # timestamps untouched
    assert row["ticket"] == "BW-046-1021-1803-tv-test"  # ticket ids untouched
    assert row["name"] == "Jane [number]"


# --------------------------------------------------------------------------
# Masking unit checks
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("call 0712345678 now", "call [number] now"),
    ("call 0712 345 678 now", "call [number] now"),
    ("+254-712-345-678", "[number]"),
    ("x 254712345678@s.whatsapp.net y", "x [jid] y"),
    ("x 98765432101234@lid y", "x [jid] y"),
    ("someone@example.com", "[email]"),
    ("KES 1500 on 2026-10-23 at 13:21:51", "KES 1500 on 2026-10-23 at 13:21:51"),
    ("ticket BW-046 router 383", "ticket BW-046 router 383"),
    ("BW-046-dennis-20261021-1803-tv", "BW-046-dennis-20261021-1803-tv"),
    ("id 202610211", "id [number]"),
    ("+20261021", "[number]"),
])
def test_mask_text(raw, expected):
    assert mask_text(raw)[0] == expected


def test_mask_value_walks_nested_structures():
    value, n = mask_value({"a": [{"b": "0712345678"}, 5, None, True], "c": 1.5})
    assert value == {"a": [{"b": "[number]"}, 5, None, True], "c": 1.5}
    assert n == 1
