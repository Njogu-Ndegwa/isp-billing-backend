from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime

from app.db.database import get_db
from app.db.models import User
from app.services.auth import verify_token, get_current_user, pwd_context
import logging
import re

logger = logging.getLogger(__name__)

router = APIRouter(tags=["profile"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ProfileResponse(BaseModel):
    id: int
    user_code: int
    email: str
    role: str
    organization_name: str
    business_name: Optional[str] = None
    support_phone: Optional[str] = None
    mpesa_shortcode: Optional[str] = None
    created_at: str
    last_login_at: Optional[str] = None


class ProfileUpdateRequest(BaseModel):
    organization_name: Optional[str] = None
    business_name: Optional[str] = None
    support_phone: Optional[str] = None
    mpesa_shortcode: Optional[str] = None
    email: Optional[str] = None

    @field_validator("support_phone")
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        cleaned = re.sub(r"[\s\-()]", "", v)
        if not re.match(r"^\+?\d{7,15}$", cleaned):
            raise ValueError("Invalid phone number format")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Invalid email format")
        return v


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user_to_profile(user: User) -> dict:
    return {
        "id": user.id,
        "user_code": user.user_code,
        "email": user.email,
        "role": user.role.value,
        "organization_name": user.organization_name,
        "business_name": user.business_name,
        "support_phone": user.support_phone,
        "mpesa_shortcode": user.mpesa_shortcode,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


# ---------------------------------------------------------------------------
# GET  /api/profile  — fetch current user's profile
# ---------------------------------------------------------------------------

@router.get("/api/profile")
async def get_profile(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Return the authenticated user's profile."""
    user = await get_current_user(token, db)
    return _user_to_profile(user)


# ---------------------------------------------------------------------------
# PATCH  /api/profile  — update profile fields
# ---------------------------------------------------------------------------

@router.patch("/api/profile")
async def update_profile(
    request: ProfileUpdateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Update one or more profile fields for the authenticated user."""
    user = await get_current_user(token, db)

    if request.email is not None and request.email != user.email:
        existing = await db.execute(
            select(User).where(User.email == request.email, User.id != user.id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this email already exists",
            )
        user.email = request.email

    if request.organization_name is not None:
        user.organization_name = request.organization_name
    if request.business_name is not None:
        user.business_name = request.business_name
    if request.support_phone is not None:
        user.support_phone = request.support_phone
    if request.mpesa_shortcode is not None:
        user.mpesa_shortcode = request.mpesa_shortcode

    await db.commit()
    await db.refresh(user)

    return _user_to_profile(user)


# ---------------------------------------------------------------------------
# PUT  /api/profile/password  — change password
# ---------------------------------------------------------------------------

@router.put("/api/profile/password")
async def change_password(
    request: PasswordChangeRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Change the authenticated user's password. Requires current password."""
    user = await get_current_user(token, db)

    if not pwd_context.verify(request.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if request.current_password == request.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must differ from the current password",
        )

    user.password_hash = pwd_context.hash(request.new_password)
    await db.commit()

    return {"detail": "Password updated successfully"}


# ---------------------------------------------------------------------------
# DELETE  /api/profile  — delete own account
# ---------------------------------------------------------------------------

@router.delete("/api/profile")
async def delete_profile(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Permanently delete the authenticated user's account.
    This is irreversible — all routers, plans, customers, and payment
    methods owned by this user will be orphaned or cascade-deleted
    depending on DB constraints.
    """
    user = await get_current_user(token, db)
    await db.delete(user)
    await db.commit()
    return {"detail": "Account deleted successfully"}
