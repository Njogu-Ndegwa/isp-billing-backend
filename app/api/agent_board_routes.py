"""Agent board — the control surface for the agentic company.

Answers, without asking an agent: what is being worked on, what is waiting on
Dennis, and what shipped. Backed by work_items / agent_runs / approvals.

Two deliberate design choices:

* **Runtime-agnostic.** Plain REST over the database Dennis already runs, so any
  execution layer can write here — Claude Code today, something else later, or
  both at once. Nothing in this module knows which model is executing.
* **A row is not a conversation.** Steering an interactive agent means sending a
  message into the session that holds the context, so rows carry `session_url`
  and the board hands you back to it. For UNATTENDED runs there is no
  conversation to join, which is why approvals exist: the agent proposes and
  stops, and Dennis decides asynchronously. That is the steering mechanism for
  scheduled work.

All endpoints are admin-only. Pure database work — no network I/O inside a
session, per the Database Session Discipline in AGENTS.md.
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    AGENT_RUN_OUTCOMES,
    APPROVAL_KINDS,
    APPROVAL_STATUSES,
    WORK_ITEM_OPEN_STATUSES,
    WORK_ITEM_SOURCES,
    WORK_ITEM_STATUSES,
    AgentRun,
    AgentSchedule,
    Approval,
    User,
    UserRole,
    WorkItem,
)
from app.services.auth import verify_token, get_current_user

router = APIRouter(tags=["agent-board"])

SESSION_SURFACES = ("cloud", "cli", "scheduled")


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _one_of(value: Optional[str], allowed: tuple, field: str) -> Optional[str]:
    if value is None:
        return None
    v = value.strip().lower()
    if v not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field} '{value}'. Allowed: {', '.join(allowed)}",
        )
    return v


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #

class WorkItemCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    code: Optional[str] = Field(default=None, max_length=32)
    detail: Optional[str] = Field(default=None, max_length=4000)
    source: str = "manual"
    status: str = "queued"
    owner: Optional[str] = Field(default=None, max_length=64)
    priority: int = 0
    branch: Optional[str] = Field(default=None, max_length=200)
    pr_url: Optional[str] = Field(default=None, max_length=300)
    session_url: Optional[str] = Field(default=None, max_length=500)
    session_surface: Optional[str] = None


class WorkItemUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=300)
    detail: Optional[str] = Field(default=None, max_length=4000)
    status: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=64)
    priority: Optional[int] = None
    branch: Optional[str] = Field(default=None, max_length=200)
    pr_url: Optional[str] = Field(default=None, max_length=300)
    blocked_reason: Optional[str] = Field(default=None, max_length=500)
    session_url: Optional[str] = Field(default=None, max_length=500)
    session_surface: Optional[str] = None


class AgentRunCreate(BaseModel):
    agent: str = Field(min_length=1, max_length=64)
    work_item_id: Optional[int] = None
    outcome: str = "running"
    summary: Optional[str] = Field(default=None, max_length=4000)
    tokens: Optional[int] = None
    session_url: Optional[str] = Field(default=None, max_length=500)
    session_surface: Optional[str] = None


class AgentRunFinish(BaseModel):
    outcome: str
    summary: Optional[str] = Field(default=None, max_length=4000)
    tokens: Optional[int] = None


class ApprovalCreate(BaseModel):
    kind: str
    subject: str = Field(min_length=1, max_length=300)
    payload: Optional[str] = Field(default=None, max_length=4000)
    proposed_by: str = Field(default="agent", max_length=64)
    work_item_id: Optional[int] = None


class ScheduleUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    agent: str = Field(min_length=1, max_length=64)
    description: Optional[str] = Field(default=None, max_length=500)
    cadence: Optional[str] = Field(default=None, max_length=120)
    cron_expr: Optional[str] = Field(default=None, max_length=120)
    expected_interval_minutes: Optional[int] = None
    enabled: bool = True
    surface: Optional[str] = None


class ScheduleRunReport(BaseModel):
    outcome: str


class ApprovalDecision(BaseModel):
    decision: str  # approved | rejected
    note: Optional[str] = Field(default=None, max_length=500)


def _work_item_json(w: WorkItem) -> dict:
    return {
        "id": w.id, "code": w.code, "title": w.title, "detail": w.detail,
        "source": w.source, "status": w.status, "owner": w.owner,
        "priority": w.priority, "branch": w.branch, "pr_url": w.pr_url,
        "blocked_reason": w.blocked_reason,
        "session_url": w.session_url, "session_surface": w.session_surface,
        # Only a cloud session can be rejoined from a phone; a CLI session is
        # bound to the machine that started it. The board says so plainly
        # rather than offering a link that cannot work.
        "steerable_remotely": w.session_surface == "cloud" and bool(w.session_url),
        "created_at": w.created_at, "updated_at": w.updated_at,
        "completed_at": w.completed_at,
    }


# A run claiming to be "running" with no heartbeat this recent is not to be
# believed. Better to show "stalled — last seen 40m ago" than to imply work is
# happening when the process died.
STALE_AFTER = timedelta(minutes=20)


def _run_json(r: AgentRun) -> dict:
    last_seen = r.heartbeat_at or r.started_at
    stalled = (
        r.outcome == "running"
        and last_seen is not None
        and (datetime.utcnow() - last_seen) > STALE_AFTER
    )
    return {
        "id": r.id, "agent": r.agent, "work_item_id": r.work_item_id,
        "outcome": r.outcome, "summary": r.summary, "tokens": r.tokens,
        "session_url": r.session_url, "session_surface": r.session_surface,
        "started_at": r.started_at, "ended_at": r.ended_at,
        "heartbeat_at": r.heartbeat_at,
        "last_seen": last_seen,
        # Surfaced separately from `outcome` on purpose: the agent said
        # "running", and this is the board's own judgement about that claim.
        "stalled": stalled,
    }


def _schedule_json(s: AgentSchedule) -> dict:
    now = datetime.utcnow()
    overdue = False
    if s.enabled and s.expected_interval_minutes:
        # Two missed intervals, not one — a single skipped tick is noise, a
        # second one means it stopped.
        grace = timedelta(minutes=2 * s.expected_interval_minutes)
        overdue = s.last_run_at is None or (now - s.last_run_at) > grace
    return {
        "id": s.id, "name": s.name, "agent": s.agent,
        "description": s.description, "cadence": s.cadence,
        "cron_expr": s.cron_expr,
        "expected_interval_minutes": s.expected_interval_minutes,
        "enabled": s.enabled, "surface": s.surface,
        "last_run_at": s.last_run_at, "last_outcome": s.last_outcome,
        # A schedule that lives in a Claude Code session dies when that session
        # closes. Saying so on the board is more useful than discovering it.
        "survives_session_close": s.surface in ("server", "cloud"),
        "overdue": overdue,
    }


def _approval_json(a: Approval) -> dict:
    return {
        "id": a.id, "kind": a.kind, "subject": a.subject, "payload": a.payload,
        "proposed_by": a.proposed_by, "status": a.status,
        "work_item_id": a.work_item_id, "note": a.note,
        "created_at": a.created_at, "decided_at": a.decided_at,
        "decided_by": a.decided_by,
    }


# --------------------------------------------------------------------------- #
# The board
# --------------------------------------------------------------------------- #

@router.get("/api/admin/agent-board")
async def get_agent_board(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """One call, everything the page shows: running, waiting on you, shipped."""
    await _require_admin(token, db)

    running = (await db.execute(
        select(WorkItem).where(WorkItem.status == "in_progress")
        .order_by(desc(WorkItem.priority), desc(WorkItem.updated_at))
    )).scalars().all()

    queued = (await db.execute(
        select(WorkItem).where(WorkItem.status == "queued")
        .order_by(desc(WorkItem.priority), WorkItem.created_at).limit(25)
    )).scalars().all()

    blocked = (await db.execute(
        select(WorkItem).where(WorkItem.status.in_(("blocked", "in_review")))
        .order_by(desc(WorkItem.updated_at))
    )).scalars().all()

    pending = (await db.execute(
        select(Approval).where(Approval.status == "pending")
        .order_by(desc(Approval.created_at)).limit(50)
    )).scalars().all()

    since = datetime.utcnow() - timedelta(days=1)
    shipped = (await db.execute(
        select(WorkItem)
        .where(WorkItem.status == "done", WorkItem.completed_at >= since)
        .order_by(desc(WorkItem.completed_at))
    )).scalars().all()

    # Runs that still CLAIM to be running — the "what is happening right now"
    # question. _run_json marks the ones whose heartbeat has gone quiet.
    live_runs = (await db.execute(
        select(AgentRun).where(AgentRun.outcome == "running")
        .order_by(desc(AgentRun.started_at))
    )).scalars().all()

    recent_runs = (await db.execute(
        select(AgentRun).order_by(desc(AgentRun.started_at)).limit(15)
    )).scalars().all()

    open_count = (await db.execute(
        select(func.count()).select_from(WorkItem)
        .where(WorkItem.status.in_(WORK_ITEM_OPEN_STATUSES))
    )).scalar()

    schedules = (await db.execute(
        select(AgentSchedule).order_by(AgentSchedule.name)
    )).scalars().all()

    live = [_run_json(r) for r in live_runs]
    stalled = [r for r in live if r["stalled"]]
    sched = [_schedule_json(s) for s in schedules]
    overdue = [s for s in sched if s["overdue"]]

    return {
        # Stamped so you can tell a fresh board from a frozen tab.
        "as_of": datetime.utcnow(),
        "running": [_work_item_json(w) for w in running],
        "queued": [_work_item_json(w) for w in queued],
        "blocked": [_work_item_json(w) for w in blocked],
        "waiting_on_you": [_approval_json(a) for a in pending],
        "shipped_24h": [_work_item_json(w) for w in shipped],
        "live_runs": live,
        "stalled_runs": stalled,
        "schedules": sched,
        "overdue_schedules": overdue,
        "recent_runs": [_run_json(r) for r in recent_runs],
        "counts": {
            "open": open_count,
            "running": len(running),
            "live_runs": len(live),
            "stalled_runs": len(stalled),
            "schedules": len(sched),
            "overdue_schedules": len(overdue),
            "waiting_on_you": len(pending),
            "shipped_24h": len(shipped),
        },
    }


# --------------------------------------------------------------------------- #
# Work items
# --------------------------------------------------------------------------- #

@router.get("/api/admin/work-items")
async def list_work_items(
    status: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    stmt = select(WorkItem)
    if status:
        stmt = stmt.where(WorkItem.status == _one_of(status, WORK_ITEM_STATUSES, "status"))
    if source:
        stmt = stmt.where(WorkItem.source == _one_of(source, WORK_ITEM_SOURCES, "source"))
    stmt = stmt.order_by(desc(WorkItem.priority), desc(WorkItem.created_at)).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"work_items": [_work_item_json(w) for w in rows], "count": len(rows)}


@router.post("/api/admin/work-items", status_code=201)
async def create_work_item(
    body: WorkItemCreate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)

    code = (body.code or "").strip() or None
    if code:
        exists = (await db.execute(
            select(WorkItem.id).where(WorkItem.code == code)
        )).scalar_one_or_none()
        if exists:
            raise HTTPException(status_code=409, detail=f"Work item '{code}' already exists")

    item = WorkItem(
        code=code,
        title=body.title.strip(),
        detail=body.detail,
        source=_one_of(body.source, WORK_ITEM_SOURCES, "source") or "manual",
        status=_one_of(body.status, WORK_ITEM_STATUSES, "status") or "queued",
        owner=body.owner,
        priority=body.priority,
        branch=body.branch,
        pr_url=body.pr_url,
        session_url=body.session_url,
        session_surface=_one_of(body.session_surface, SESSION_SURFACES, "session_surface"),
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return _work_item_json(item)


@router.patch("/api/admin/work-items/{item_id}")
async def update_work_item(
    item_id: int,
    body: WorkItemUpdate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    item = (await db.execute(
        select(WorkItem).where(WorkItem.id == item_id)
    )).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Work item not found")

    data = body.model_dump(exclude_unset=True)
    if "status" in data and data["status"] is not None:
        data["status"] = _one_of(data["status"], WORK_ITEM_STATUSES, "status")
        # Stamp completion once, when it actually lands.
        if data["status"] == "done" and item.completed_at is None:
            item.completed_at = datetime.utcnow()
        elif data["status"] != "done":
            item.completed_at = None
    if "session_surface" in data and data["session_surface"] is not None:
        data["session_surface"] = _one_of(
            data["session_surface"], SESSION_SURFACES, "session_surface"
        )

    for field, value in data.items():
        setattr(item, field, value)
    item.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(item)
    return _work_item_json(item)


# --------------------------------------------------------------------------- #
# Agent runs — the ledger
# --------------------------------------------------------------------------- #

@router.post("/api/admin/agent-runs", status_code=201)
async def start_agent_run(
    body: AgentRunCreate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    run = AgentRun(
        agent=body.agent.strip(),
        work_item_id=body.work_item_id,
        outcome=_one_of(body.outcome, AGENT_RUN_OUTCOMES, "outcome") or "running",
        summary=body.summary,
        tokens=body.tokens,
        session_url=body.session_url,
        session_surface=_one_of(body.session_surface, SESSION_SURFACES, "session_surface"),
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return _run_json(run)


@router.patch("/api/admin/agent-runs/{run_id}")
async def finish_agent_run(
    run_id: int,
    body: AgentRunFinish,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    run = (await db.execute(
        select(AgentRun).where(AgentRun.id == run_id)
    )).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found")

    run.outcome = _one_of(body.outcome, AGENT_RUN_OUTCOMES, "outcome")
    if body.summary is not None:
        run.summary = body.summary
    if body.tokens is not None:
        run.tokens = body.tokens
    if run.outcome != "running" and run.ended_at is None:
        run.ended_at = datetime.utcnow()

    await db.commit()
    await db.refresh(run)
    return _run_json(run)


@router.post("/api/admin/agent-runs/{run_id}/heartbeat")
async def heartbeat_agent_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Long-running agents touch this so the board can tell alive from dead.

    Without it, a crashed run looks exactly like a working one forever.
    """
    await _require_admin(token, db)
    run = (await db.execute(
        select(AgentRun).where(AgentRun.id == run_id)
    )).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found")

    run.heartbeat_at = datetime.utcnow()
    await db.commit()
    await db.refresh(run)
    return _run_json(run)


@router.get("/api/admin/agent-runs")
async def list_agent_runs(
    agent: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    stmt = select(AgentRun)
    if agent:
        stmt = stmt.where(AgentRun.agent == agent.strip())
    stmt = stmt.order_by(desc(AgentRun.started_at)).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"agent_runs": [_run_json(r) for r in rows], "count": len(rows)}


# --------------------------------------------------------------------------- #
# Approvals — how unattended work gets steered
# --------------------------------------------------------------------------- #

@router.post("/api/admin/approvals", status_code=201)
async def create_approval(
    body: ApprovalCreate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    approval = Approval(
        kind=_one_of(body.kind, APPROVAL_KINDS, "kind"),
        subject=body.subject.strip(),
        payload=body.payload,
        proposed_by=body.proposed_by,
        work_item_id=body.work_item_id,
        status="pending",
    )
    db.add(approval)
    await db.commit()
    await db.refresh(approval)
    return _approval_json(approval)


@router.get("/api/admin/approvals")
async def list_approvals(
    status: Optional[str] = Query(default="pending"),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    stmt = select(Approval)
    if status:
        stmt = stmt.where(Approval.status == _one_of(status, APPROVAL_STATUSES, "status"))
    stmt = stmt.order_by(desc(Approval.created_at)).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"approvals": [_approval_json(a) for a in rows], "count": len(rows)}


@router.post("/api/admin/approvals/{approval_id}/decide")
async def decide_approval(
    approval_id: int,
    body: ApprovalDecision,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Approve or reject. A decision is final — re-deciding is rejected.

    An approval is the record that a human authorised an action; silently
    overwriting one would destroy the audit trail that makes money and router
    actions safe to delegate at all.
    """
    admin = await _require_admin(token, db)

    decision = (body.decision or "").strip().lower()
    if decision not in ("approved", "rejected"):
        raise HTTPException(
            status_code=400, detail="decision must be 'approved' or 'rejected'"
        )

    approval = (await db.execute(
        select(Approval).where(Approval.id == approval_id)
    )).scalar_one_or_none()
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Already {approval.status} at {approval.decided_at}",
        )

    approval.status = decision
    approval.note = body.note
    approval.decided_at = datetime.utcnow()
    approval.decided_by = admin.email

    await db.commit()
    await db.refresh(approval)
    return _approval_json(approval)


# --------------------------------------------------------------------------- #
# Schedules — what the assistant does without being asked
# --------------------------------------------------------------------------- #

@router.put("/api/admin/agent-schedules")
async def upsert_schedule(
    body: ScheduleUpsert,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Register or update a standing cadence, keyed by name.

    Idempotent so a scheduled agent can announce itself on every boot without
    accumulating duplicates.
    """
    await _require_admin(token, db)

    surface = _one_of(body.surface, ("session", "server", "cloud"), "surface")
    existing = (await db.execute(
        select(AgentSchedule).where(AgentSchedule.name == body.name.strip())
    )).scalar_one_or_none()

    if existing is None:
        existing = AgentSchedule(name=body.name.strip())
        db.add(existing)

    existing.agent = body.agent.strip()
    existing.description = body.description
    existing.cadence = body.cadence
    existing.cron_expr = body.cron_expr
    existing.expected_interval_minutes = body.expected_interval_minutes
    existing.enabled = body.enabled
    existing.surface = surface
    existing.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(existing)
    return _schedule_json(existing)


@router.get("/api/admin/agent-schedules")
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    rows = (await db.execute(
        select(AgentSchedule).order_by(AgentSchedule.name)
    )).scalars().all()
    return {"schedules": [_schedule_json(s) for s in rows], "count": len(rows)}


@router.post("/api/admin/agent-schedules/{schedule_id}/ran")
async def report_schedule_run(
    schedule_id: int,
    body: ScheduleRunReport,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """A schedule reporting that it fired. Silence is what makes it overdue."""
    await _require_admin(token, db)
    sched = (await db.execute(
        select(AgentSchedule).where(AgentSchedule.id == schedule_id)
    )).scalar_one_or_none()
    if sched is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    sched.last_outcome = _one_of(body.outcome, AGENT_RUN_OUTCOMES, "outcome")
    sched.last_run_at = datetime.utcnow()
    await db.commit()
    await db.refresh(sched)
    return _schedule_json(sched)
