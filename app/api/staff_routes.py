"""Staff sub-users: the owner manages logins and permissions for their staff.

GET    /api/staff/me                     who am I (owner or staff) + my permissions
PUT    /api/staff/me/password            staff change their own password (staff only)
GET    /api/staff/permissions            catalog + presets            (owner only)
GET    /api/staff                        list staff                   (owner only)
POST   /api/staff                        add a staff member           (owner only)
PUT    /api/staff/{id}                   edit / permissions / active  (owner only)
POST   /api/staff/{id}/reset-password    set a new password           (owner only)
DELETE /api/staff/{id}                   remove (soft)                (owner only)
GET    /api/staff/activity               who did what                 (owner only)

"Owner only" is enforced twice: the staff middleware never lets a staff token
reach these routes (``staff.manage`` is not grantable), and every handler here
refuses a token that carries ``staff_id``.

Anything that must end a staff member's sessions -- permission change,
deactivation, removal, password reset -- bumps ``token_version`` and drops the
in-process cache, so their next request is answered 401
``staff_session_revoked``.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import ResellerStaff, StaffActivityLog, User, UserRole
from app.services import staff_access, staff_permissions as perms
from app.services.auth import get_current_user, pwd_context, verify_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["staff"])

MAX_STAFF_PER_OWNER = 50
PASSWORD_MIN_LENGTH = 6
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.replace(tzinfo=None).isoformat() + "Z" if dt else None


def staff_public(staff: ResellerStaff, business_name: Optional[str] = None) -> dict:
    """The ``staff`` object returned at login and by /api/staff/me."""
    return {
        "id": staff.id,
        "name": staff.name,
        "email": staff.email,
        "phone": staff.phone,
        "permissions": perms.clean_permissions(staff.permissions or []),
        "parent_reseller_id": staff.parent_reseller_id,
        "business_name": business_name,
    }


def _staff_row(staff: ResellerStaff) -> dict:
    return {
        "id": staff.id,
        "name": staff.name,
        "email": staff.email,
        "phone": staff.phone,
        "permissions": perms.clean_permissions(staff.permissions or []),
        "is_active": bool(staff.is_active),
        "created_at": _iso(staff.created_at),
        "last_login_at": _iso(staff.last_login_at),
        "permissions_updated_at": _iso(staff.permissions_updated_at),
    }


def business_label(owner: User) -> str:
    return owner.business_name or owner.organization_name


async def login_staff(db: AsyncSession, email: str, password: str) -> Optional[dict]:
    from app.api.auth_routes import login_user_payload
    from app.core.runtime_mode import shadow_mode_enabled
    from app.services.auth import create_access_token

    staff = (await db.execute(select(ResellerStaff).where(
        func.lower(ResellerStaff.email) == email.strip().lower(),
        ResellerStaff.deleted_at.is_(None),
        ResellerStaff.is_active.is_(True),
    ))).scalar_one_or_none()
    if staff is None or not await asyncio.to_thread(pwd_context.verify, password, staff.password_hash):
        return None
    owner = await db.get(User, staff.parent_reseller_id)
    if owner is None or owner.role != UserRole.RESELLER:
        return None
    claims = staff_access.staff_token_claims(staff, owner)
    identity = login_user_payload(owner)
    identity["email"] = staff.email
    identity["staff"] = staff_public(staff, business_label(owner))
    response = {
        "access_token": create_access_token(claims, staff_access.token_expiry()),
        "token_type": "bearer",
        "user": identity,
    }
    if not shadow_mode_enabled():
        staff.last_login_at = datetime.utcnow()
        await db.commit()
    return response


async def email_in_use(db: AsyncSession, email: str, *, exclude_staff_id: Optional[int] = None) -> bool:
    """True when ``email`` belongs to any user or any live (not removed) staff member."""
    email = email.strip().lower()
    user_hit = (await db.execute(
        select(User.id).where(func.lower(User.email) == email).limit(1)
    )).scalar_one_or_none()
    if user_hit is not None:
        return True
    stmt = select(ResellerStaff.id).where(
        func.lower(ResellerStaff.email) == email,
        ResellerStaff.deleted_at.is_(None),
    )
    if exclude_staff_id is not None:
        stmt = stmt.where(ResellerStaff.id != exclude_staff_id)
    return (await db.execute(stmt.limit(1))).scalar_one_or_none() is not None


async def _require_owner(token: dict, db: AsyncSession) -> User:
    if token.get("staff_id") is not None:
        raise staff_access.StaffPermissionDenied(perms.STAFF_MANAGE)
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Only reseller accounts can have staff")
    return user


async def _get_staff_or_404(db: AsyncSession, owner: User, staff_id: int) -> ResellerStaff:
    staff = (await db.execute(
        select(ResellerStaff).where(
            ResellerStaff.id == staff_id,
            ResellerStaff.parent_reseller_id == owner.id,
            ResellerStaff.deleted_at.is_(None),
        )
    )).scalar_one_or_none()
    if staff is None:
        raise HTTPException(status_code=404, detail="Staff member not found")
    return staff


def _check_permissions_input(values: Optional[List[str]]) -> list[str]:
    unknown = perms.unknown_permissions(values)
    if perms.STAFF_MANAGE in unknown:
        raise HTTPException(status_code=400, detail="Staff management can't be given to staff")
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown permissions: {', '.join(unknown)}")
    return perms.clean_permissions(values)


async def _log_owner_action(owner: User, method: str, path: str, summary: str) -> None:
    await staff_access.record_activity(
        owner_id=owner.id,
        staff_id=None,
        actor_label="Account owner",
        action=f"{method} staff",
        permission=perms.STAFF_MANAGE,
        method=method,
        path=path,
        status_code=200,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Who am I
# ---------------------------------------------------------------------------

@router.get("/api/staff/me")
async def staff_me(
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    staff_id = token.get("staff_id")
    if staff_id is None:
        user = await get_current_user(token, db)
        all_perms = list(perms.PERMISSIONS)
        if user.role == UserRole.RESELLER:
            all_perms.append(perms.STAFF_MANAGE)
        return {"is_staff": False, "staff": None, "permissions": all_perms}

    staff = await db.get(ResellerStaff, int(staff_id))
    owner = await db.get(User, int(token["user_id"]))
    if staff is None or owner is None:
        raise HTTPException(status_code=401, detail="Staff account not found")
    public = staff_public(staff, business_label(owner))
    return {"is_staff": True, "staff": public, "permissions": public["permissions"]}


class StaffOwnPasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.put("/api/staff/me/password")
async def change_own_staff_password(
    body: StaffOwnPasswordRequest,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """A staff member changes their own password.

    Like the owner's PUT /api/profile/password: the current password is
    required, every other session of this staff member ends (token_version
    bump), and a fresh token for this session comes back so the caller stays
    signed in. Owners use /api/profile/password instead.
    """
    staff_id = token.get("staff_id")
    if staff_id is None:
        raise HTTPException(
            status_code=400,
            detail="Only staff sign-ins use this. Change your password in Profile.",
        )
    staff = await db.get(ResellerStaff, int(staff_id))
    owner = await db.get(User, int(token["user_id"]))
    if (
        staff is None or owner is None or staff.deleted_at is not None
        or not staff.is_active or staff.parent_reseller_id != owner.id
    ):
        raise HTTPException(status_code=401, detail="Staff account not found")
    if not await asyncio.to_thread(pwd_context.verify, body.current_password, staff.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=400, detail="New password must differ from the current password",
        )
    _check_password(body.new_password)

    staff.password_hash = await asyncio.to_thread(pwd_context.hash, body.new_password)
    staff.token_version = int(staff.token_version or 0) + 1
    staff.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(staff)
    staff_access.invalidate_staff(staff.id)

    from app.services.auth import create_access_token

    return {
        "detail": "Password updated. You were signed out on your other devices.",
        "access_token": create_access_token(
            staff_access.staff_token_claims(staff, owner), staff_access.token_expiry(),
        ),
    }


# ---------------------------------------------------------------------------
# Owner: catalog, list, create, edit, reset password, remove, activity
# ---------------------------------------------------------------------------

@router.get("/api/staff/permissions")
async def staff_permission_catalog(
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    await _require_owner(token, db)
    return perms.catalog()


@router.get("/api/staff")
async def list_staff(
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    owner = await _require_owner(token, db)
    rows = (await db.execute(
        select(ResellerStaff)
        .where(
            ResellerStaff.parent_reseller_id == owner.id,
            ResellerStaff.deleted_at.is_(None),
        )
        .order_by(ResellerStaff.created_at.desc(), ResellerStaff.id.desc())
    )).scalars().all()
    return {"staff": [_staff_row(s) for s in rows]}


def _clean_name(v):
    if v is None:
        return v
    v = str(v).strip()
    if not v or len(v) > 120:
        raise ValueError("Name must be 1-120 characters")
    return v


def _clean_email(v):
    if v is None:
        return v
    v = str(v).strip().lower()
    if not _EMAIL_RE.match(v) or len(v) > 255:
        raise ValueError("Enter a valid email address")
    return v


def _clean_phone(v):
    if v is None:
        return v
    v = str(v).strip()
    if len(v) > 20:
        raise ValueError("Phone must be at most 20 characters")
    return v or None


class StaffCreateRequest(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None
    password: str
    permissions: List[str] = []

    _n = field_validator("name")(classmethod(lambda cls, v: _clean_name(v)))
    _e = field_validator("email")(classmethod(lambda cls, v: _clean_email(v)))
    _p = field_validator("phone")(classmethod(lambda cls, v: _clean_phone(v)))


class StaffUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    permissions: Optional[List[str]] = None
    is_active: Optional[bool] = None

    _n = field_validator("name")(classmethod(lambda cls, v: _clean_name(v)))
    _e = field_validator("email")(classmethod(lambda cls, v: _clean_email(v)))
    _p = field_validator("phone")(classmethod(lambda cls, v: _clean_phone(v)))


class StaffPasswordRequest(BaseModel):
    password: str


def _check_password(password: str) -> None:
    if len(password or "") < PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {PASSWORD_MIN_LENGTH} characters",
        )
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password must be at most 72 bytes")


@router.post("/api/staff")
async def create_staff(
    body: StaffCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    owner = await _require_owner(token, db)
    _check_password(body.password)
    permissions = _check_permissions_input(body.permissions)

    count = (await db.execute(
        select(func.count(ResellerStaff.id)).where(
            ResellerStaff.parent_reseller_id == owner.id,
            ResellerStaff.deleted_at.is_(None),
        )
    )).scalar_one()
    if count >= MAX_STAFF_PER_OWNER:
        raise HTTPException(status_code=400, detail=f"At most {MAX_STAFF_PER_OWNER} staff per account")

    if await email_in_use(db, body.email):
        raise HTTPException(status_code=409, detail="This email is already used by another account")

    now = datetime.utcnow()
    staff = ResellerStaff(
        parent_reseller_id=owner.id,
        name=body.name,
        email=body.email,
        phone=body.phone,
        password_hash=await asyncio.to_thread(pwd_context.hash, body.password),
        permissions=permissions,
        is_active=True,
        token_version=0,
        permissions_updated_at=now,
        created_at=now,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    row = _staff_row(staff)

    logger.info("[staff] owner=%s added staff=%s perms=%s", owner.id, staff.id, permissions)
    await _log_owner_action(
        owner, "POST", "/api/staff",
        f"Added staff {staff.name} with: {', '.join(permissions) or 'no permissions'}",
    )
    return row


@router.put("/api/staff/{staff_id}")
async def update_staff(
    staff_id: int,
    body: StaffUpdateRequest,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    owner = await _require_owner(token, db)
    staff = await _get_staff_or_404(db, owner, staff_id)

    changes: list[str] = []
    revoke = False
    now = datetime.utcnow()

    if body.name is not None and body.name != staff.name:
        staff.name = body.name
        changes.append("name")
    if "phone" in body.model_fields_set and body.phone != staff.phone:
        staff.phone = body.phone
        changes.append("phone")
    if body.email is not None and body.email != staff.email:
        if await email_in_use(db, body.email, exclude_staff_id=staff.id):
            raise HTTPException(status_code=409, detail="This email is already used by another account")
        staff.email = body.email
        changes.append("email")
        revoke = True
    if body.permissions is not None:
        new_perms = _check_permissions_input(body.permissions)
        old_perms = perms.clean_permissions(staff.permissions or [])
        if new_perms != old_perms:
            staff.permissions = new_perms
            staff.permissions_updated_at = now
            added = [p for p in new_perms if p not in old_perms]
            removed = [p for p in old_perms if p not in new_perms]
            parts = []
            if added:
                parts.append("gave " + ", ".join(added))
            if removed:
                parts.append("removed " + ", ".join(removed))
            changes.append("permissions (" + "; ".join(parts) + ")")
            revoke = True
    if body.is_active is not None and bool(body.is_active) != bool(staff.is_active):
        staff.is_active = bool(body.is_active)
        changes.append("activated" if staff.is_active else "deactivated")
        revoke = True

    if changes:
        staff.updated_at = now
        if revoke:
            staff.token_version = int(staff.token_version or 0) + 1
        await db.commit()
        await db.refresh(staff)
        staff_access.invalidate_staff(staff.id)
        await _log_owner_action(
            owner, "PUT", f"/api/staff/{staff.id}",
            f"Changed staff {staff.name}: {', '.join(changes)}",
        )
    return _staff_row(staff)


@router.post("/api/staff/{staff_id}/reset-password")
async def reset_staff_password(
    staff_id: int,
    body: StaffPasswordRequest,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    owner = await _require_owner(token, db)
    _check_password(body.password)
    staff = await _get_staff_or_404(db, owner, staff_id)
    staff.password_hash = await asyncio.to_thread(pwd_context.hash, body.password)
    staff.token_version = int(staff.token_version or 0) + 1
    staff.updated_at = datetime.utcnow()
    name = staff.name
    await db.commit()
    staff_access.invalidate_staff(staff_id)
    await _log_owner_action(
        owner, "POST", f"/api/staff/{staff_id}/reset-password", f"Reset the password of staff {name}",
    )
    return {"message": "Password updated. They have been signed out everywhere."}


@router.delete("/api/staff/{staff_id}")
async def remove_staff(
    staff_id: int,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    owner = await _require_owner(token, db)
    staff = await _get_staff_or_404(db, owner, staff_id)
    now = datetime.utcnow()
    staff.deleted_at = now
    staff.is_active = False
    staff.updated_at = now
    staff.token_version = int(staff.token_version or 0) + 1
    name = staff.name
    await db.commit()
    staff_access.invalidate_staff(staff_id)
    await _log_owner_action(owner, "DELETE", f"/api/staff/{staff_id}", f"Removed staff {name}")
    return {"message": "Staff member removed. Their access has ended."}


@router.get("/api/staff/activity")
async def staff_activity(
    staff_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    owner = await _require_owner(token, db)
    where = [StaffActivityLog.owner_id == owner.id]
    if staff_id is not None:
        where.append(StaffActivityLog.staff_id == staff_id)

    total = (await db.execute(
        select(func.count(StaffActivityLog.id)).where(*where)
    )).scalar_one()
    rows = (await db.execute(
        select(StaffActivityLog)
        .where(*where)
        .order_by(StaffActivityLog.created_at.desc(), StaffActivityLog.id.desc())
        .limit(limit)
        .offset(offset)
    )).scalars().all()
    return {
        "items": [
            {
                "id": r.id,
                "created_at": _iso(r.created_at),
                "actor_type": "staff" if r.staff_id is not None else "owner",
                "staff_id": r.staff_id,
                "actor_label": r.actor_label,
                "action": r.action,
                "permission": r.permission,
                "method": r.method,
                "path": r.path,
                "status_code": r.status_code,
                "summary": r.summary,
            }
            for r in rows
        ],
        "total": total,
    }
