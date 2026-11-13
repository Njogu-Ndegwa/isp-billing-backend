"""WhatsApp support desk snapshot, for the platform admin only.

Dennis's laptop runs the WhatsApp bridge and builds the support dashboard JSON
(customers, work log, queue...). It pushes that JSON here so the admin app can
show it on his phone.

POST /api/admin/support-desk/snapshot   (laptop -> server)
    Auth: ``Authorization: Bearer <SUPPORT_DESK_INGEST_TOKEN>``, compared in
    constant time. This is a machine token, not a user JWT, and it can only
    write this one snapshot. Unset (or too short) env var: 503, endpoint off.
    Body: the snapshot JSON object, at most SUPPORT_DESK_SNAPSHOT_MAX_BYTES.
    Every string is masked again (emails, 7+ digit numbers, WhatsApp JIDs)
    before it is stored in the single ``support_desk_snapshots`` row.
      200 {"received_at", "size_bytes", "sha256", "masked"}
      400 not JSON / not an object      401 missing or wrong token
      413 too large                      503 ingest disabled

GET /api/admin/support-desk   (admin app)
    Auth: user JWT whose user has role ADMIN (the platform owner). Resellers,
    and admin View-as sessions (which carry the reseller's role), get 403.
      200 {"received_at", "size_bytes", "sha256", "snapshot", "decisions"}
      no-store. ``decisions`` holds the latest DECISIONS_IN_READ decisions,
      newest first, so the page can show "Go sent 09:40, agent picked up 09:43".
      404 nothing pushed yet

Decisions on "Waiting on Dennis" items (Dennis's phone -> laptop):

POST /api/admin/support-desk/decisions   (admin app)
    Auth: the same platform-admin gate as the GET (View-as sessions: 403).
    Body: {"item_id": "wl-...", "action": "go" | "close", "note"?: <=500 chars}
    The item must be an open needs_dennis work-log entry in the latest
    snapshot (else 404). The note is masked like the snapshot.
      201 the new decision      200 the same action is already pending (no dup)
      409 a different action is still waiting for the laptop      422 bad body

GET /api/admin/support-desk/decisions[?pending=1]   (laptop)
    Auth: the machine token (SUPPORT_DESK_INGEST_TOKEN). pending=1 returns
    only decisions the laptop has not consumed yet, oldest first.
      200 {"decisions": [...]}      401 bad token      503 token unset

POST /api/admin/support-desk/decisions/{id}/consumed   (laptop)
    Auth: machine token. Stamps consumed_at once (idempotent).
      200 {"id", "consumed_at"}     404 unknown id
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.database import get_db
from app.db.models import SupportDeskDecision, SupportDeskSnapshot, User, UserRole
from app.services.auth import get_current_user, verify_token
from app.services.support_desk import (
    bearer_token,
    configured_ingest_token,
    find_open_dennis_item,
    ingest_token_matches,
    mask_text,
    mask_value,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-support-desk"])

SNAPSHOT_ROW_ID = 1
DISABLED_DETAIL = "Support desk ingest is disabled"
NOT_FOUND_DETAIL = "No support desk snapshot yet"
NO_STORE = {"Cache-Control": "no-store"}
DECISIONS_IN_READ = 200
PENDING_LIMIT = 200
NOTE_MAX_CHARS = 500


def _iso_utc(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat() + "Z"


async def _require_platform_admin(token: dict, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN or token.get("imp_sid") is not None:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _reject_constant(value: str):
    # NaN / Infinity parse in Python but are not valid JSON for the browser.
    raise ValueError(f"non-JSON constant {value}")


async def _read_capped_body(request: Request, max_bytes: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                raise HTTPException(status_code=413, detail="Snapshot too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise HTTPException(status_code=413, detail="Snapshot too large")
        chunks.append(chunk)
    return b"".join(chunks)


async def _discard_body(request: Request, max_bytes: int) -> None:
    """Drain (and drop) an unauthenticated upload before answering it.

    Answering 401/503 while the client is still sending makes the server close
    the socket, and the laptop then sees "connection reset" instead of the
    status code. Nothing is kept: chunks are dropped as they arrive, and the
    drain stops at the size cap.
    """
    seen = 0
    try:
        async for chunk in request.stream():
            seen += len(chunk)
            if seen > max_bytes:
                break
    except Exception:  # client went away; the error response still goes out
        pass


@router.post("/api/admin/support-desk/snapshot")
async def ingest_support_desk_snapshot(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    expected = configured_ingest_token(
        settings.SUPPORT_DESK_INGEST_TOKEN,
        settings.SUPPORT_DESK_INGEST_TOKEN_MIN_LENGTH,
    )
    max_bytes = settings.SUPPORT_DESK_SNAPSHOT_MAX_BYTES
    if expected is None:
        await _discard_body(request, max_bytes)
        raise HTTPException(status_code=503, detail=DISABLED_DETAIL)
    if not ingest_token_matches(bearer_token(authorization), expected):
        logger.warning("support desk ingest rejected: bad or missing token")
        await _discard_body(request, max_bytes)
        raise HTTPException(
            status_code=401,
            detail="Invalid ingest token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Only an authenticated request has its body parsed and stored.
    raw = await _read_capped_body(request, max_bytes)
    try:
        data = json.loads(raw.decode("utf-8-sig"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Snapshot must be a UTF-8 JSON object")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Snapshot must be a UTF-8 JSON object")

    masked, masked_count = mask_value(data)
    if masked_count:
        # Counts only; the values themselves are never logged.
        logger.warning("support desk ingest masked %d value(s) the laptop missed", masked_count)
    digest = hashlib.sha256(raw).hexdigest()
    received_at = datetime.utcnow()

    # One short session: no network I/O happens while it is open.
    from app.db.database import async_session

    async with async_session() as db:
        await _upsert(db, masked, received_at, len(raw), digest, masked_count)

    return JSONResponse(
        content={
            "received_at": _iso_utc(received_at),
            "size_bytes": len(raw),
            "sha256": digest,
            "masked": masked_count,
        },
        headers=NO_STORE,
    )


async def _upsert(db, payload, received_at, size_bytes, digest, masked_count):
    fields = dict(
        payload=payload,
        received_at=received_at,
        size_bytes=size_bytes,
        sha256=digest,
        masked_count=masked_count,
    )
    for attempt in range(2):
        row = await db.get(SupportDeskSnapshot, SNAPSHOT_ROW_ID)
        if row is None:
            db.add(SupportDeskSnapshot(id=SNAPSHOT_ROW_ID, **fields))
        else:
            for key, value in fields.items():
                setattr(row, key, value)
        try:
            await db.commit()
            return
        except IntegrityError:
            # Two first-ever pushes raced on the insert; the second updates.
            await db.rollback()
            if attempt:
                raise


@router.get("/api/admin/support-desk")
async def get_support_desk_snapshot(
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    await _require_platform_admin(token, db)
    row = await db.get(SupportDeskSnapshot, SNAPSHOT_ROW_ID)
    if row is None:
        await db.commit()
        raise HTTPException(status_code=404, detail=NOT_FOUND_DETAIL)
    decisions = (
        await db.execute(
            select(SupportDeskDecision)
            .order_by(SupportDeskDecision.created_at.desc(), SupportDeskDecision.id.desc())
            .limit(DECISIONS_IN_READ)
        )
    ).scalars().all()
    body = {
        "received_at": _iso_utc(row.received_at),
        "size_bytes": row.size_bytes,
        "sha256": row.sha256,
        "snapshot": row.payload,
        "decisions": [_decision_json(d) for d in decisions],
    }
    await db.commit()
    return JSONResponse(content=body, headers=NO_STORE)


# --------------------------------------------------------------------------
# Decisions on "Waiting on Dennis" items
# --------------------------------------------------------------------------

class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    action: Literal["go", "close"]
    note: Optional[str] = Field(default=None, max_length=NOTE_MAX_CHARS)

    @field_validator("note")
    @classmethod
    def _blank_note_is_none(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        return value or None


def _decision_json(d: SupportDeskDecision) -> dict:
    return {
        "id": d.id,
        "item_id": d.item_id,
        "action": d.action,
        "note": d.note,
        "decided_by": d.decided_by,
        "created_at": _iso_utc(d.created_at),
        "consumed_at": _iso_utc(d.consumed_at) if d.consumed_at else None,
    }


def _require_machine_token(authorization: Optional[str]) -> None:
    expected = configured_ingest_token(
        settings.SUPPORT_DESK_INGEST_TOKEN,
        settings.SUPPORT_DESK_INGEST_TOKEN_MIN_LENGTH,
    )
    if expected is None:
        raise HTTPException(status_code=503, detail=DISABLED_DETAIL)
    if not ingest_token_matches(bearer_token(authorization), expected):
        logger.warning("support desk decisions rejected: bad or missing machine token")
        raise HTTPException(
            status_code=401,
            detail="Invalid support desk token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/api/admin/support-desk/decisions")
async def create_support_desk_decision(
    body: DecisionIn,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    user = await _require_platform_admin(token, db)

    snapshot = await db.get(SupportDeskSnapshot, SNAPSHOT_ROW_ID)
    if snapshot is None or find_open_dennis_item(snapshot.payload, body.item_id) is None:
        await db.commit()
        raise HTTPException(status_code=404, detail="No open Waiting-on-Dennis item with that id")

    pending = (
        await db.execute(
            select(SupportDeskDecision)
            .where(
                SupportDeskDecision.item_id == body.item_id,
                SupportDeskDecision.consumed_at.is_(None),
            )
            .order_by(SupportDeskDecision.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if pending is not None:
        existing = _decision_json(pending)
        await db.commit()
        if pending.action == body.action:
            # Double tap or retry: the decision is already queued, not a new one.
            return JSONResponse(status_code=200, content=existing, headers=NO_STORE)
        raise HTTPException(
            status_code=409,
            detail="A different decision for this item is still waiting for the agent",
        )

    note = mask_text(body.note)[0] if body.note else None
    decision = SupportDeskDecision(
        item_id=body.item_id,
        action=body.action,
        note=note,
        decided_by=user.id,
        created_at=datetime.utcnow(),
    )
    db.add(decision)
    await db.commit()
    await db.refresh(decision)
    logger.info("support desk decision %s: %s on %s", decision.id, decision.action, decision.item_id)
    return JSONResponse(status_code=201, content=_decision_json(decision), headers=NO_STORE)


@router.get("/api/admin/support-desk/decisions")
async def list_support_desk_decisions(
    pending: bool = Query(default=False),
    authorization: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    _require_machine_token(authorization)
    stmt = select(SupportDeskDecision)
    if pending:
        stmt = (
            stmt.where(SupportDeskDecision.consumed_at.is_(None))
            .order_by(SupportDeskDecision.created_at.asc(), SupportDeskDecision.id.asc())
            .limit(PENDING_LIMIT)
        )
    else:
        stmt = stmt.order_by(
            SupportDeskDecision.created_at.desc(), SupportDeskDecision.id.desc()
        ).limit(DECISIONS_IN_READ)
    rows = (await db.execute(stmt)).scalars().all()
    body = {"decisions": [_decision_json(d) for d in rows]}
    await db.commit()
    return JSONResponse(content=body, headers=NO_STORE)


@router.post("/api/admin/support-desk/decisions/{decision_id}/consumed")
async def mark_support_desk_decision_consumed(
    decision_id: int,
    authorization: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    _require_machine_token(authorization)
    decision = await db.get(SupportDeskDecision, decision_id)
    if decision is None:
        await db.commit()
        raise HTTPException(status_code=404, detail="Unknown decision")
    if decision.consumed_at is None:
        decision.consumed_at = datetime.utcnow()
    body = {"id": decision.id, "consumed_at": _iso_utc(decision.consumed_at)}
    await db.commit()
    return JSONResponse(content=body, headers=NO_STORE)
