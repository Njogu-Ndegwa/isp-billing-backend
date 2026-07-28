"""Agent board: the queue, the run ledger, and the approval gate.

These pin the properties that make the board trustworthy rather than decorative:
a decided approval can never be silently re-decided (it is the audit trail for
delegating money and router actions), and a run that stopped reporting is shown
as stalled instead of masquerading as live work.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.agent_board_routes as abr
from app.api.agent_board_routes import router as agent_board_router
from app.db.database import get_db
from app.db.models import AgentRun, AgentSchedule, Approval, WorkItem
from app.services.auth import verify_token
from tests.factories import make_admin, make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(agent_board_router)

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
    monkeypatch.setattr(abr, "get_current_user", _fake)


# --------------------------------------------------------------------------- #
# Access
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_board_is_admin_only(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_reseller(db))
    resp = await client.get("/api/admin/agent-board")
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# The migration actually runs
#
# test_app_boot proves main.py IMPORTS. It deliberately does not run the
# @app.on_event("startup") handler, which is where every migration lives — so
# until now nothing verified that a startup migration executes at all, only that
# one had been written. This executes it, against a database where the tables
# have been dropped, and then executes it a SECOND time, because startup runs on
# every boot and a non-idempotent migration crashes the app the next time it
# restarts.
#
# Limitation, stated plainly: this runs on SQLite. `create(checkfirst=True)` and
# `CREATE INDEX IF NOT EXISTS` are portable, so it is real evidence for THIS
# migration; it is not evidence for the Postgres-specific migrations that use
# information_schema or DO blocks, which cannot execute here.
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_agent_queue_migration_runs_and_is_idempotent(engine, monkeypatch):
    from sqlalchemy import text as sa_text

    import main

    # main.py binds async_engine at import, so rebinding the module attribute in
    # conftest is not enough — point main itself at the test engine.
    monkeypatch.setattr(main, "async_engine", engine)

    tables = ("approvals", "agent_runs", "agent_schedules", "work_items")

    # conftest's create_all already built them; drop them so we are proving the
    # MIGRATION creates the schema, not that the fixture did.
    async with engine.begin() as conn:
        for table in tables:
            await conn.execute(sa_text(f"DROP TABLE IF EXISTS {table}"))

    async with engine.connect() as conn:
        present = await conn.run_sync(
            lambda c: __import__("sqlalchemy").inspect(c).get_table_names()
        )
    assert not any(t in present for t in tables), "precondition: tables dropped"

    await main.run_agent_queue_migrations()

    async with engine.connect() as conn:
        present = await conn.run_sync(
            lambda c: __import__("sqlalchemy").inspect(c).get_table_names()
        )
    for table in tables:
        assert table in present, f"startup migration did not create {table}"

    # Second boot. A bare CREATE TABLE here would raise and crash-loop the app.
    await main.run_agent_queue_migrations()

    # And the schema is usable, not just present.
    async with engine.begin() as conn:
        await conn.execute(sa_text(
            "INSERT INTO work_items (title, source, status, priority) "
            "VALUES ('post-migration write', 'manual', 'queued', 0)"
        ))
        count = (await conn.execute(
            sa_text("SELECT COUNT(*) FROM work_items")
        )).scalar()
    assert count == 1


# --------------------------------------------------------------------------- #
# Work items
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_create_and_list_work_item(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))

    resp = await client.post("/api/admin/work-items", json={
        "code": "PKT-009", "title": "Pin production dependencies",
        "source": "backlog", "priority": 5,
    })
    assert resp.status_code == 201
    assert resp.json()["code"] == "PKT-009"
    assert resp.json()["status"] == "queued"

    listed = await client.get("/api/admin/work-items", params={"status": "queued"})
    assert listed.status_code == 200
    assert [w["code"] for w in listed.json()["work_items"]] == ["PKT-009"]


@pytest.mark.asyncio
async def test_duplicate_code_is_rejected(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))
    payload = {"code": "PKT-001", "title": "First"}
    assert (await client.post("/api/admin/work-items", json=payload)).status_code == 201

    dup = await client.post("/api/admin/work-items",
                            json={"code": "PKT-001", "title": "Second"})
    assert dup.status_code == 409


@pytest.mark.asyncio
async def test_invalid_status_is_rejected_with_the_allowed_list(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))
    resp = await client.post("/api/admin/work-items",
                             json={"title": "x", "status": "almost-done"})
    assert resp.status_code == 400
    assert "queued" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_completed_at_is_stamped_on_done_and_cleared_when_reopened(
    db, client, monkeypatch
):
    _auth_as(monkeypatch, await make_admin(db))
    item_id = (await client.post(
        "/api/admin/work-items", json={"title": "Ship the guard"}
    )).json()["id"]

    done = await client.patch(f"/api/admin/work-items/{item_id}",
                              json={"status": "done"})
    assert done.status_code == 200
    assert done.json()["completed_at"] is not None

    # Reopening must not leave a stale completion date behind.
    reopened = await client.patch(f"/api/admin/work-items/{item_id}",
                                  json={"status": "in_progress"})
    assert reopened.json()["completed_at"] is None


@pytest.mark.asyncio
async def test_only_a_cloud_session_is_marked_steerable_remotely(db, client, monkeypatch):
    """A CLI session cannot be rejoined from a phone — the board must say so."""
    _auth_as(monkeypatch, await make_admin(db))

    cloud = await client.post("/api/admin/work-items", json={
        "title": "cloud task", "session_url": "https://claude.ai/code/session_x",
        "session_surface": "cloud",
    })
    local = await client.post("/api/admin/work-items", json={
        "title": "local task", "session_url": "file:///tmp/session",
        "session_surface": "cli",
    })
    no_link = await client.post("/api/admin/work-items", json={
        "title": "no session", "session_surface": "cloud",
    })

    assert cloud.json()["steerable_remotely"] is True
    assert local.json()["steerable_remotely"] is False
    assert no_link.json()["steerable_remotely"] is False


# --------------------------------------------------------------------------- #
# Runs and liveness
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_run_lifecycle_start_heartbeat_finish(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))

    started = await client.post("/api/admin/agent-runs", json={
        "agent": "whatsapp-sweep", "session_surface": "scheduled",
    })
    assert started.status_code == 201
    run_id = started.json()["id"]
    assert started.json()["outcome"] == "running"
    assert started.json()["ended_at"] is None

    beat = await client.post(f"/api/admin/agent-runs/{run_id}/heartbeat")
    assert beat.status_code == 200
    assert beat.json()["heartbeat_at"] is not None
    assert beat.json()["stalled"] is False

    finished = await client.patch(f"/api/admin/agent-runs/{run_id}", json={
        "outcome": "green", "summary": "3 drafts prepared", "tokens": 4200,
    })
    assert finished.json()["outcome"] == "green"
    assert finished.json()["ended_at"] is not None


@pytest.mark.asyncio
async def test_a_run_that_stopped_reporting_is_marked_stalled(db, client, monkeypatch):
    """The failure this exists for: a crashed run looking identical to a live one."""
    _auth_as(monkeypatch, await make_admin(db))

    run = AgentRun(
        agent="nightly-factory",
        outcome="running",
        started_at=datetime.utcnow() - timedelta(hours=3),
        heartbeat_at=datetime.utcnow() - timedelta(hours=2),
    )
    db.add(run)
    await db.commit()

    board = await client.get("/api/admin/agent-board")
    assert board.status_code == 200
    body = board.json()

    assert body["counts"]["live_runs"] == 1
    assert body["counts"]["stalled_runs"] == 1
    assert body["stalled_runs"][0]["agent"] == "nightly-factory"


@pytest.mark.asyncio
async def test_a_fresh_run_is_not_stalled(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))
    db.add(AgentRun(agent="hourly-check", outcome="running",
                    started_at=datetime.utcnow(),
                    heartbeat_at=datetime.utcnow()))
    await db.commit()

    body = (await client.get("/api/admin/agent-board")).json()
    assert body["counts"]["live_runs"] == 1
    assert body["counts"]["stalled_runs"] == 0


# --------------------------------------------------------------------------- #
# Approvals — the steering mechanism for unattended work
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_approval_appears_in_waiting_on_you_until_decided(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))

    created = await client.post("/api/admin/approvals", json={
        "kind": "whatsapp_reply",
        "subject": "Reply to Dismas about his fourth signup",
        "payload": "Dismas, umejaribu mara nne tangu May...",
    })
    assert created.status_code == 201
    approval_id = created.json()["id"]

    board = (await client.get("/api/admin/agent-board")).json()
    assert board["counts"]["waiting_on_you"] == 1

    decided = await client.post(f"/api/admin/approvals/{approval_id}/decide",
                                json={"decision": "approved", "note": "send it"})
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    assert decided.json()["decided_by"] is not None

    board_after = (await client.get("/api/admin/agent-board")).json()
    assert board_after["counts"]["waiting_on_you"] == 0


@pytest.mark.asyncio
async def test_a_decided_approval_cannot_be_re_decided(db, client, monkeypatch):
    """The audit trail is the reason money actions can be delegated at all."""
    _auth_as(monkeypatch, await make_admin(db))

    approval_id = (await client.post("/api/admin/approvals", json={
        "kind": "payment", "subject": "Payout to reseller 294",
    })).json()["id"]

    first = await client.post(f"/api/admin/approvals/{approval_id}/decide",
                              json={"decision": "rejected"})
    assert first.status_code == 200

    second = await client.post(f"/api/admin/approvals/{approval_id}/decide",
                               json={"decision": "approved"})
    assert second.status_code == 409

    stored = (await db.execute(
        select(Approval).where(Approval.id == approval_id)
    )).scalar_one()
    assert stored.status == "rejected"


@pytest.mark.asyncio
async def test_decision_must_be_approved_or_rejected(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))
    approval_id = (await client.post("/api/admin/approvals", json={
        "kind": "other", "subject": "something",
    })).json()["id"]

    resp = await client.post(f"/api/admin/approvals/{approval_id}/decide",
                             json={"decision": "maybe"})
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Schedules — noticing that something stopped
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_schedule_upsert_is_idempotent_by_name(db, client, monkeypatch):
    """A scheduled agent announces itself on every boot; that must not pile up."""
    _auth_as(monkeypatch, await make_admin(db))
    payload = {
        "name": "hourly-whatsapp-check", "agent": "whatsapp-frontdesk",
        "cadence": "hourly at :13", "cron_expr": "13 * * * *",
        "expected_interval_minutes": 60, "surface": "session",
    }
    first = await client.put("/api/admin/agent-schedules", json=payload)
    assert first.status_code == 200

    payload["cadence"] = "hourly at :07"
    second = await client.put("/api/admin/agent-schedules", json=payload)
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["cadence"] == "hourly at :07"

    listed = await client.get("/api/admin/agent-schedules")
    assert listed.json()["count"] == 1


@pytest.mark.asyncio
async def test_a_session_schedule_is_flagged_as_not_surviving_session_close(
    db, client, monkeypatch
):
    """The hourly check dies when the terminal closes — the board should say so."""
    _auth_as(monkeypatch, await make_admin(db))

    session_bound = await client.put("/api/admin/agent-schedules", json={
        "name": "hourly-check", "agent": "whatsapp-frontdesk", "surface": "session",
    })
    on_server = await client.put("/api/admin/agent-schedules", json={
        "name": "nightly-factory", "agent": "pr-factory", "surface": "server",
    })

    assert session_bound.json()["survives_session_close"] is False
    assert on_server.json()["survives_session_close"] is True


@pytest.mark.asyncio
async def test_a_schedule_that_stopped_firing_is_reported_overdue(
    db, client, monkeypatch
):
    """The 2026-07-27 failure: the factory claimed a packet and produced nothing,
    and nothing recorded that it was supposed to run."""
    _auth_as(monkeypatch, await make_admin(db))

    db.add(AgentSchedule(
        name="nightly-factory", agent="pr-factory", enabled=True,
        expected_interval_minutes=60 * 24,
        last_run_at=datetime.utcnow() - timedelta(days=3),
    ))
    await db.commit()

    board = (await client.get("/api/admin/agent-board")).json()
    assert board["counts"]["overdue_schedules"] == 1
    assert board["overdue_schedules"][0]["name"] == "nightly-factory"


@pytest.mark.asyncio
async def test_reporting_a_run_clears_the_overdue_flag(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))
    sched = AgentSchedule(
        name="hourly-check", agent="whatsapp-frontdesk", enabled=True,
        expected_interval_minutes=60,
        last_run_at=datetime.utcnow() - timedelta(hours=6),
    )
    db.add(sched)
    await db.commit()
    await db.refresh(sched)

    before = (await client.get("/api/admin/agent-schedules")).json()["schedules"][0]
    assert before["overdue"] is True

    reported = await client.post(f"/api/admin/agent-schedules/{sched.id}/ran",
                                 json={"outcome": "green"})
    assert reported.status_code == 200
    assert reported.json()["overdue"] is False
    assert reported.json()["last_outcome"] == "green"


@pytest.mark.asyncio
async def test_a_disabled_schedule_is_never_overdue(db, client, monkeypatch):
    """Turning something off is a decision, not a failure."""
    _auth_as(monkeypatch, await make_admin(db))
    db.add(AgentSchedule(
        name="paused-sweep", agent="noc-watchdog", enabled=False,
        expected_interval_minutes=60,
        last_run_at=datetime.utcnow() - timedelta(days=30),
    ))
    await db.commit()

    board = (await client.get("/api/admin/agent-board")).json()
    assert board["counts"]["schedules"] == 1
    assert board["counts"]["overdue_schedules"] == 0


@pytest.mark.asyncio
async def test_board_separates_running_queued_blocked_and_shipped(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))

    db.add_all([
        WorkItem(title="in flight", status="in_progress"),
        WorkItem(title="next up", status="queued", priority=3),
        WorkItem(title="stuck", status="blocked", blocked_reason="needs schema approval"),
        WorkItem(title="landed", status="done", completed_at=datetime.utcnow()),
        WorkItem(title="landed last week", status="done",
                 completed_at=datetime.utcnow() - timedelta(days=5)),
    ])
    await db.commit()

    body = (await client.get("/api/admin/agent-board")).json()

    assert [w["title"] for w in body["running"]] == ["in flight"]
    assert [w["title"] for w in body["queued"]] == ["next up"]
    assert [w["title"] for w in body["blocked"]] == ["stuck"]
    # Only the last 24h counts as "shipped" — older work is history, not news.
    assert [w["title"] for w in body["shipped_24h"]] == ["landed"]
    assert body["counts"]["open"] == 3
    assert body["as_of"] is not None
