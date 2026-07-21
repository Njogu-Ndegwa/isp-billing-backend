"""Admin triage endpoints: queue priority, status patch + notification,
duplicate validation, retriage, reply, work packet, role gating."""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.admin_feedback_routes as afr
from app.api.admin_feedback_routes import router as admin_feedback_router
from app.db.database import get_db
from app.db.models import (
    FeedbackComment,
    FeedbackKind,
    FeedbackPost,
    FeedbackStatus,
    ResellerInboxMessage,
)
from app.services.auth import verify_token
from app.services.feedback_queue import compute_priority
from tests.factories import make_admin, make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(admin_feedback_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    return application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(afr, "get_current_user", _fake)


async def _make_post(db, user, **overrides):
    defaults = dict(user_id=user.id, kind=FeedbackKind.BUG,
                    title="Login broken", body="Dashboard login 500s.")
    defaults.update(overrides)
    post = FeedbackPost(**defaults)
    db.add(post)
    await db.commit()
    await db.refresh(post)
    return post


@pytest.mark.asyncio
async def test_patch_status_updates_and_notifies_author(db, client, monkeypatch):
    author = await make_reseller(db)
    admin = await make_admin(db)
    post = await _make_post(db, author)
    _auth_as(monkeypatch, admin)

    resp = await client.patch(f"/api/admin/feedback/posts/{post.id}",
                              json={"status": "planned"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "planned"
    assert resp.json()["notified"] is True

    msgs = (await db.execute(select(ResellerInboxMessage))).scalars().all()
    assert len(msgs) == 1
    assert msgs[0].recipient_user_id == author.id
    assert msgs[0].sender_user_id == admin.id
    assert post.title in msgs[0].subject or post.title in msgs[0].body


@pytest.mark.asyncio
async def test_patch_duplicate_requires_valid_target(db, client, monkeypatch):
    author = await make_reseller(db)
    admin = await make_admin(db)
    post = await _make_post(db, author)
    original = await _make_post(db, author, title="Original report")
    _auth_as(monkeypatch, admin)

    missing = await client.patch(f"/api/admin/feedback/posts/{post.id}",
                                 json={"status": "duplicate"})
    assert missing.status_code == 400

    self_ref = await client.patch(f"/api/admin/feedback/posts/{post.id}",
                                  json={"status": "duplicate",
                                        "duplicate_of_id": post.id})
    assert self_ref.status_code == 400

    ok = await client.patch(f"/api/admin/feedback/posts/{post.id}",
                            json={"status": "duplicate",
                                  "duplicate_of_id": original.id})
    assert ok.status_code == 200
    assert ok.json()["status"] == "duplicate"
    assert ok.json()["duplicate_of_id"] == original.id


@pytest.mark.asyncio
async def test_queue_sorted_by_priority(db, client, monkeypatch):
    author = await make_reseller(db)
    admin = await make_admin(db)
    now = datetime.utcnow()

    critical = await _make_post(db, author, title="Critical fresh bug",
                                ai_severity=5, ai_kind="bug",
                                ai_triaged_at=now)
    popular_old = await _make_post(db, author, title="Popular old idea",
                                   kind=FeedbackKind.IDEA, upvotes=10,
                                   ai_severity=1, ai_kind="feature",
                                   ai_triaged_at=now,
                                   created_at=now - timedelta(days=60))
    untriaged = await _make_post(db, author, title="Untriaged report")

    _auth_as(monkeypatch, admin)
    resp = await client.get("/api/admin/feedback/queue")
    assert resp.status_code == 200
    items = resp.json()["items"]
    ids = [i["id"] for i in items]
    assert set(ids) == {critical.id, popular_old.id, untriaged.id}

    expected = sorted(
        [critical, popular_old, untriaged],
        key=lambda p: compute_priority(p, 0, now), reverse=True)
    assert ids == [p.id for p in expected]
    assert ids[0] == critical.id  # fresh severity-5 bug outranks everything

    # priority monotonicity: more votes up, higher severity up, older down
    base = compute_priority(untriaged, 0, now)
    untriaged.upvotes = 5
    assert compute_priority(untriaged, 0, now) > base
    untriaged.ai_severity = 5
    assert compute_priority(untriaged, 0, now) > base


@pytest.mark.asyncio
async def test_retriage_queues_background_task(db, client, monkeypatch):
    author = await make_reseller(db)
    admin = await make_admin(db)
    post = await _make_post(db, author)
    _auth_as(monkeypatch, admin)

    calls = []

    async def _fake(post_id):
        calls.append(post_id)
    monkeypatch.setattr(afr, "run_feedback_triage", _fake)

    resp = await client.post(f"/api/admin/feedback/posts/{post.id}/retriage")
    assert resp.status_code == 200
    assert calls == [post.id]


@pytest.mark.asyncio
async def test_reply_creates_comment_and_inbox_row(db, client, monkeypatch):
    author = await make_reseller(db)
    admin = await make_admin(db)
    post = await _make_post(db, author)
    _auth_as(monkeypatch, admin)

    resp = await client.post(f"/api/admin/feedback/posts/{post.id}/reply",
                             json={"subject": "Update on your report",
                                   "body": "We shipped a fix today."})
    assert resp.status_code == 200
    assert resp.json()["comment_id"] is not None
    assert resp.json()["inbox_message_id"] is not None

    comment = (await db.execute(select(FeedbackComment))).scalars().one()
    assert comment.is_admin is True
    msg = (await db.execute(select(ResellerInboxMessage))).scalars().one()
    assert msg.recipient_user_id == author.id


@pytest.mark.asyncio
async def test_work_packet_contains_report_and_triage(db, client, monkeypatch):
    author = await make_reseller(db)
    admin = await make_admin(db)
    post = await _make_post(db, author, ai_severity=4, ai_kind="bug",
                            ai_summary="Login endpoint returns 500",
                            ai_affected_area="auth_accounts",
                            ai_triaged_at=datetime.utcnow(), upvotes=3)
    _auth_as(monkeypatch, admin)

    resp = await client.get(f"/api/admin/feedback/posts/{post.id}/work-packet")
    assert resp.status_code == 200
    md = resp.json()["markdown"]
    assert post.title in md
    assert "severity 4/5" in md
    assert "auth_accounts" in md
    assert "AGENTS.md" in md


@pytest.mark.asyncio
async def test_non_admin_is_rejected(db, client, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)
    resp = await client.get("/api/admin/feedback/queue")
    assert resp.status_code == 403
