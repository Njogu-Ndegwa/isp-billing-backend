"""Admin view of reseller subscription reminders (who is about to expire, who was texted).

The on/off switch lives with the other messaging settings
(`subscription_reminders_enabled` on GET/PUT /api/admin/messaging/settings).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import User, UserRole
from app.services.auth import get_current_user, verify_token
from app.services.subscription_reminders import reminder_overview

router = APIRouter(tags=["admin-subscription-reminders"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@router.get("/api/admin/subscription-reminders")
async def admin_subscription_reminders(
    days: int = Query(7, ge=1, le=30),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Resellers expiring within `days` with their reminder plan, plus the send log."""
    await _require_admin(token, db)
    return await reminder_overview(db, days=days, recent_limit=limit)
