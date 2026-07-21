"""Board endpoints: submit (+ triage queued, daily cap), list, vote, comment."""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.feedback_routes as fr
from app.api.feedback_routes import router as feedback_router
from app.db.database import get_db
from app.db.models import FeedbackKind, FeedbackPost, FeedbackStatus
from app.services.auth import verify_token
from tests.factories import make_admin, make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(feedback_router)

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
    monkeypatch.setattr(fr, "get_current_user", _fake)


def _spy_triage(monkeypatch):
    calls = []

    async def _fake(post_id):
        calls.append(post_id)
    monkeypatch.setattr(fr, "run_feedback_triage", _fake)
    return calls


async def _make_post(db, user, *, kind=FeedbackKind.BUG, title="Login broken",
                     body="The dashboard login fails with a 500 error.",
                     **overrides):
    post = FeedbackPost(user_id=user.id, kind=kind, title=title, body=body,
                        **overrides)
    db.add(post)
    await db.commit()
    await db.refresh(post)
    return post


@pytest.mark.asyncio
async def test_submit_creates_post_and_queues_triage(db, client, monkeypatch):
    r = await make_reseller(db)
    _auth_as(monkeypatch, r)
    calls = _spy_triage(monkeypatch)

    resp = await client.post("/api/feedback/posts", json={
        "kind": "bug", "title": "Payments stuck",
        "body": "STK push succeeds but customers stay offline.",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "new"
    assert data["kind"] == "bug"
    assert data["is_mine"] is True
    assert calls == [data["id"]]


@pytest.mark.asyncio
async def test_daily_cap_counts_only_today(db, client, monkeypatch):
    r = await make_reseller(db)
    _auth_as(monkeypatch, r)
    _spy_triage(monkeypatch)
    monkeypatch.setattr(fr.settings, "FEEDBACK_DAILY_POST_CAP", 1)

    # A post from yesterday must not count against today's cap.
    await _make_post(db, r, created_at=datetime.utcnow() - timedelta(days=1))

    ok = await client.post("/api/feedback/posts", json={
        "kind": "idea", "title": "Dark mode",
        "body": "Please add a dark mode to the portal."})
    assert ok.status_code == 200

    blocked = await client.post("/api/feedback/posts", json={
        "kind": "idea", "title": "Another idea",
        "body": "This one should hit the daily cap."})
    assert blocked.status_code == 429


@pytest.mark.asyncio
async def test_vote_toggle_switch_and_aggregate(db, client, monkeypatch):
    r1 = await make_reseller(db)
    r2 = await make_reseller(db)
    post = await _make_post(db, r1)

    _auth_as(monkeypatch, r1)
    up = await client.post(f"/api/feedback/posts/{post.id}/vote", json={"value": 1})
    assert up.json() == {"upvotes": 1, "downvotes": 0, "my_vote": 1}

    # Same arrow again toggles the vote off.
    off = await client.post(f"/api/feedback/posts/{post.id}/vote", json={"value": 1})
    assert off.json() == {"upvotes": 0, "downvotes": 0, "my_vote": None}

    down = await client.post(f"/api/feedback/posts/{post.id}/vote", json={"value": -1})
    assert down.json() == {"upvotes": 0, "downvotes": 1, "my_vote": -1}

    # Switching direction updates the same row (unique post+user).
    up2 = await client.post(f"/api/feedback/posts/{post.id}/vote", json={"value": 1})
    assert up2.json() == {"upvotes": 1, "downvotes": 0, "my_vote": 1}

    _auth_as(monkeypatch, r2)
    other = await client.post(f"/api/feedback/posts/{post.id}/vote", json={"value": 1})
    assert other.json() == {"upvotes": 2, "downvotes": 0, "my_vote": 1}


@pytest.mark.asyncio
async def test_comments_flag_admin_and_bump_count(db, client, monkeypatch):
    r = await make_reseller(db)
    admin = await make_admin(db)
    post = await _make_post(db, r)

    _auth_as(monkeypatch, r)
    c1 = await client.post(f"/api/feedback/posts/{post.id}/comments",
                           json={"body": "Also happening to me."})
    assert c1.status_code == 200
    assert c1.json()["is_admin"] is False
    assert c1.json()["comment_count"] == 1

    _auth_as(monkeypatch, admin)
    c2 = await client.post(f"/api/feedback/posts/{post.id}/comments",
                           json={"body": "Looking into it."})
    assert c2.json()["is_admin"] is True
    assert c2.json()["comment_count"] == 2

    _auth_as(monkeypatch, r)
    detail = await client.get(f"/api/feedback/posts/{post.id}")
    assert detail.status_code == 200
    bodies = [c["body"] for c in detail.json()["comments"]]
    assert bodies == ["Also happening to me.", "Looking into it."]


@pytest.mark.asyncio
async def test_list_sorts_filters_and_hides_spam(db, client, monkeypatch):
    r = await make_reseller(db)
    admin = await make_admin(db)
    loud = await _make_post(db, r, title="Loud bug", upvotes=5)
    quiet = await _make_post(db, r, title="Quiet idea", kind=FeedbackKind.IDEA)
    await _make_post(db, r, title="Junk", status=FeedbackStatus.SPAM)

    _auth_as(monkeypatch, r)
    top = await client.get("/api/feedback/posts", params={"sort": "top"})
    assert top.status_code == 200
    titles = [p["title"] for p in top.json()["posts"]]
    assert titles == ["Loud bug", "Quiet idea"]  # spam hidden
    assert top.json()["total"] == 2

    ideas = await client.get("/api/feedback/posts", params={"kind": "idea"})
    assert [p["id"] for p in ideas.json()["posts"]] == [quiet.id]

    # my_vote comes back on lists
    await client.post(f"/api/feedback/posts/{loud.id}/vote", json={"value": 1})
    listed = await client.get("/api/feedback/posts", params={"sort": "top"})
    votes = {p["id"]: p["my_vote"] for p in listed.json()["posts"]}
    assert votes[loud.id] == 1 and votes[quiet.id] is None

    # Resellers asking for spam get nothing; admins see it.
    spam_reseller = await client.get("/api/feedback/posts", params={"status": "spam"})
    assert spam_reseller.json()["posts"] == []
    _auth_as(monkeypatch, admin)
    spam_admin = await client.get("/api/feedback/posts", params={"status": "spam"})
    assert [p["title"] for p in spam_admin.json()["posts"]] == ["Junk"]
