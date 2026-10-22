"""GET /api/admin/support-desk: the laptop-pushed support dashboard snapshot.

Driven through the real ``main.app`` with real JWTs, so the route wiring in
main.py and the auth chain (oauth2 scheme -> verify_token -> get_current_user
-> ADMIN check) are what production runs. The snapshot carries customer
conversation summaries, so the role gate is the property that matters most.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.services.auth import create_access_token
from tests.factories import make_admin, make_reseller

URL = "/api/admin/support-desk"

SNAPSHOT = {
    "generated_at": "2026-10-22T22:12:00+03:00",
    "counts": {"open": 3, "review": 1},
    "tickets": [{"id": "BW-013", "status": "review", "summary": "SMS warning"}],
    "messages": [],
    "worklog": {"entries": [{"at": "2026-10-22T21:00:00Z", "text": "deployed"}],
                "counts": {"done": 1}},
    "product_backlog": [],
    "installations": {},
    "response_times": {"median_minutes": 12},
    "knowledge": {},
}


def _token_for(user) -> str:
    claims = {
        "sub": str(user.id),
        "user_code": user.user_code,
        "user_id": user.id,
        "role": user.role.value,
        "organization_name": user.organization_name,
    }
    return create_access_token(claims, timedelta(minutes=30))


def _bearer(user) -> dict:
    return {"Authorization": f"Bearer {_token_for(user)}"}


@pytest.fixture
def snapshot_path(tmp_path, monkeypatch):
    path = tmp_path / "support-desk" / "snapshot.json"
    monkeypatch.setattr(settings, "SUPPORT_DESK_SNAPSHOT_PATH", str(path))
    return path


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


@pytest_asyncio.fixture
async def client(engine):
    import main

    async with AsyncClient(
        transport=ASGITransport(app=main.app), base_url="http://test"
    ) as c:
        yield c


# --------------------------------------------------------------------------
# Role gate
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_owner_gets_snapshot_verbatim_plus_received_at(client, db, snapshot_path):
    _write(snapshot_path, json.dumps(SNAPSHOT))
    pushed_at = datetime(2026, 10, 22, 19, 15, 30, tzinfo=timezone.utc).timestamp()
    os.utime(snapshot_path, (pushed_at, pushed_at))

    resp = await client.get(URL, headers=_bearer(await make_admin(db)))

    assert resp.status_code == 200
    body = resp.json()
    received_at = body.pop("received_at")
    assert body == SNAPSHOT
    assert received_at == "2026-10-22T19:15:30Z"
    assert resp.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_reseller_is_forbidden(client, db, snapshot_path):
    _write(snapshot_path, json.dumps(SNAPSHOT))
    resp = await client.get(URL, headers=_bearer(await make_reseller(db)))
    assert resp.status_code == 403
    assert "tickets" not in resp.text


@pytest.mark.asyncio
async def test_anonymous_is_unauthorized(client, snapshot_path):
    _write(snapshot_path, json.dumps(SNAPSHOT))
    resp = await client.get(URL)
    assert resp.status_code == 401
    assert "tickets" not in resp.text


@pytest.mark.asyncio
async def test_garbage_token_is_unauthorized(client, snapshot_path):
    _write(snapshot_path, json.dumps(SNAPSHOT))
    resp = await client.get(URL, headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == 401


# --------------------------------------------------------------------------
# File states
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_missing_file_is_404_with_contract_detail(client, db, snapshot_path):
    assert not snapshot_path.exists()
    resp = await client.get(URL, headers=_bearer(await make_admin(db)))
    assert resp.status_code == 404
    assert resp.json() == {"detail": "No support desk snapshot yet"}


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [
    "{\"generated_at\": \"2026-10-22\", \"tickets\": [",   # truncated push
    "",                                                     # empty file
    b"\xff\xfe\x00garbage",                                 # not UTF-8
    "[1, 2, 3]",                                            # not an object
    "{\"counts\": NaN}",                                    # not re-serialisable
])
async def test_corrupt_file_is_503_not_500(client, db, snapshot_path, content):
    _write(snapshot_path, content)
    resp = await client.get(URL, headers=_bearer(await make_admin(db)))
    assert resp.status_code == 503
    assert "unreadable" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_oversized_file_is_rejected(client, db, snapshot_path, monkeypatch):
    monkeypatch.setattr(settings, "SUPPORT_DESK_SNAPSHOT_MAX_BYTES", 64)
    _write(snapshot_path, json.dumps({"tickets": ["x" * 100]}))
    resp = await client.get(URL, headers=_bearer(await make_admin(db)))
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_utf8_bom_is_tolerated(client, db, snapshot_path):
    _write(snapshot_path, b"\xef\xbb\xbf" + json.dumps(SNAPSHOT).encode("utf-8"))
    resp = await client.get(URL, headers=_bearer(await make_admin(db)))
    assert resp.status_code == 200
    assert resp.json()["tickets"] == SNAPSHOT["tickets"]


@pytest.mark.asyncio
async def test_new_push_is_served_without_restart(client, db, snapshot_path):
    """Read per request: an atomic replace (tmp + mv) shows up immediately."""
    admin = await make_admin(db)
    _write(snapshot_path, json.dumps({**SNAPSHOT, "generated_at": "first"}))
    first = await client.get(URL, headers=_bearer(admin))

    tmp = snapshot_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({**SNAPSHOT, "generated_at": "second"}), encoding="utf-8")
    os.replace(tmp, snapshot_path)
    second = await client.get(URL, headers=_bearer(admin))

    assert first.json()["generated_at"] == "first"
    assert second.json()["generated_at"] == "second"


# --------------------------------------------------------------------------
# Deploy wiring
# --------------------------------------------------------------------------

def test_hetzner_compose_mounts_snapshot_dir_read_only():
    from pathlib import Path

    compose = Path("docker-compose.hetzner.yml").read_text(encoding="utf-8")
    assert (
        "- ${SUPPORT_DESK_HOST_DIR:-/opt/isp-billing-shadow/support-desk}"
        ":/srv/support-desk:ro" in compose
    )
    assert "SUPPORT_DESK_SNAPSHOT_PATH: /srv/support-desk/snapshot.json" in compose
    # The container itself stays read-only.
    assert "read_only: true" in compose
