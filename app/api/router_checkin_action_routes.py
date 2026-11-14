"""Queue and inspect router actions delivered over the check-in channel.

``POST /api/routers/{router_id}/checkin-actions``  ``{"action": "heal_tunnel"|"reboot", "reason": "..."}``
``GET  /api/routers/{router_id}/checkin-actions``  recent actions and their state

Only ``router_checkin_actions.USER_ACTIONS`` can be queued here; the body
never carries anything that reaches the router except the action name, which
must be on the allowlist. Staff need ``routers.manage`` to queue and
``routers.view`` to list (``staff_permissions``). The router must be owned by
the caller (admins: any router), and it must be checking in with a v3 applier,
or the action could never run.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.services import router_checkin_actions as actions
from app.services.auth import get_current_user, verify_token
from app.services.router_helpers import get_router_by_id

router = APIRouter(tags=["router-checkin-actions"])


class QueueActionRequest(BaseModel):
    action: str = Field(..., max_length=32)
    reason: Optional[str] = Field(default=None, max_length=500)


async def _owned_router(db: AsyncSession, router_id: int, token: str):
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    await db.commit()  # release the connection; nothing below needs it
    return user, router_obj


def _channel(router_id: int) -> dict:
    caps = actions.router_caps(router_id)
    return {
        "checkin_actions_available": caps is not None,
        "tunnel_repair_available": bool(caps and caps.heal),
        "last_checkin_at": caps.seen_at.isoformat() if caps else None,
        "eta_minutes": actions.eta_minutes(router_id) if caps else None,
    }


@router.post("/api/routers/{router_id}/checkin-actions")
async def queue_checkin_action(
    router_id: int,
    payload: QueueActionRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    action = payload.action.strip().lower()
    if action not in actions.USER_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"action must be one of: {', '.join(actions.USER_ACTIONS)}",
        )
    user, router_obj = await _owned_router(db, router_id, token)
    caps = actions.router_caps(router_id)
    if caps is None:
        raise HTTPException(
            status_code=409,
            detail="This router is not checking in with the current Bitwave script, so it cannot take queued actions",
        )
    if action == actions.ACTION_HEAL_TUNNEL and not caps.heal:
        raise HTTPException(status_code=409, detail="This router has no tunnel repair script installed")
    try:
        row = await actions.enqueue(
            router_id, action, requested_by_user_id=user.id,
            reason=(payload.reason or "").strip() or None,
        )
    except actions.ActionRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    eta = actions.eta_minutes(router_id)
    return {
        "success": True,
        "router_id": router_id,
        "router_name": router_obj.name,
        "queued": True,
        "action": actions.serialize_action(row),
        "eta_minutes": eta,
        "message": f"queued: the router will run it on its next check-in (about {eta} min)",
    }


@router.get("/api/routers/{router_id}/checkin-actions")
async def list_checkin_actions(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _owned_router(db, router_id, token)
    rows = await actions.recent_actions(router_id)
    return {
        "router_id": router_id,
        **_channel(router_id),
        "items": [actions.serialize_action(r) for r in rows],
    }
