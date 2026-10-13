"""Admin "View as reseller" endpoints.

POST /api/admin/impersonate/{reseller_id}  -- admin starts a read-only session
POST /api/impersonation/end                -- the View-as token ends itself

The read-only and revocation rules are enforced for every request by
``app.services.impersonation.enforce_impersonation_read_only``.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from jose import jwt
from pydantic import BaseModel
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.admin_reseller_routes import _get_reseller_or_404, _require_admin
from app.api.auth_routes import login_token_claims, login_user_payload
from app.config import settings
from app.core.security import ALGORITHM
from app.db.database import get_db
from app.db.models import ImpersonationSession
from app.services import impersonation
from app.services.auth import verify_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["impersonation"])

IMPERSONATION_TTL_MINUTES = impersonation.IMPERSONATION_TTL_MINUTES


class ImpersonateRequest(BaseModel):
    # Optional so a missing reason gets the same 400 as a short one, not a 422.
    reason: Optional[str] = None


@router.post("/api/admin/impersonate/{reseller_id}")
async def start_impersonation(
    reseller_id: int,
    body: ImpersonateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Issue a 30-minute, read-only token that views the dashboard as a reseller."""
    if token.get("imp_sid") is not None:
        raise HTTPException(status_code=403, detail="Already viewing as a reseller")
    admin = await _require_admin(token, db)

    reason = (body.reason or "").strip()
    if not (impersonation.REASON_MIN_LENGTH <= len(reason) <= impersonation.REASON_MAX_LENGTH):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Reason must be {impersonation.REASON_MIN_LENGTH}-"
                f"{impersonation.REASON_MAX_LENGTH} characters"
            ),
        )

    reseller = await _get_reseller_or_404(db, reseller_id)

    now = datetime.utcnow().replace(microsecond=0)
    expires_at = now + timedelta(minutes=IMPERSONATION_TTL_MINUTES)

    # Audit tidy-up: this admin's earlier sessions that simply timed out.
    await db.execute(
        update(ImpersonationSession)
        .where(
            ImpersonationSession.admin_id == admin.id,
            ImpersonationSession.ended_at.is_(None),
            ImpersonationSession.expires_at <= now,
        )
        .values(
            ended_at=ImpersonationSession.expires_at,
            end_reason=impersonation.END_REASON_EXPIRED,
        )
    )

    user_agent = request.headers.get("user-agent")
    session = ImpersonationSession(
        admin_id=admin.id,
        reseller_id=reseller.id,
        reason=reason,
        started_at=now,
        expires_at=expires_at,
        ip_address=impersonation.client_ip(request),
        user_agent=user_agent[: impersonation.USER_AGENT_MAX_LENGTH] if user_agent else None,
        request_count=0,
    )
    db.add(session)
    await db.flush()
    session_id = session.id

    claims = {
        **login_token_claims(reseller),
        "imp_sid": session_id,
        "imp_by": admin.id,
        "ro": True,
        "exp": expires_at,
    }
    access_token = jwt.encode(claims, settings.SECRET_KEY, algorithm=ALGORITHM)

    response = {
        "access_token": access_token,
        "token_type": "bearer",
        "session_id": session_id,
        "expires_at": impersonation.iso_utc(expires_at),
        "read_only": True,
        "user": login_user_payload(reseller),
        "impersonator": {"id": admin.id, "email": admin.email},
    }
    await db.commit()

    logger.info(
        "[view-as] started sid=%s admin=%s (%s) reseller=%s (%s) reason=%r",
        session_id,
        admin.id,
        admin.email,
        reseller.id,
        reseller.organization_name,
        reason,
    )
    return response


@router.post("/api/impersonation/end")
async def end_impersonation(
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """End the View-as session this token belongs to. Idempotent."""
    sid = token.get("imp_sid")
    if sid is None:
        raise HTTPException(status_code=400, detail="Not a View-as session")
    sid = int(sid)

    await db.execute(
        update(ImpersonationSession)
        .where(
            ImpersonationSession.id == sid,
            ImpersonationSession.ended_at.is_(None),
        )
        .values(ended_at=datetime.utcnow(), end_reason=impersonation.END_REASON_EXIT)
    )
    await db.commit()
    impersonation.mark_session_ended(sid)

    logger.info(
        "[view-as] ended sid=%s admin=%s reseller=%s",
        sid,
        token.get("imp_by"),
        token.get("user_id"),
    )
    return {"ended": True}
