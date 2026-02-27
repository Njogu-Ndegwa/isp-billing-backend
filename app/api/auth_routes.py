from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
from datetime import timedelta

from app.db.database import get_db
from app.db.models import User, UserRole
from app.services.auth import create_user, authenticate_user, create_access_token
from app.config import settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


class UserRegisterRequest(BaseModel):
    email: str
    password: str
    role: str
    organization_name: str
    business_name: Optional[str] = None
    mpesa_shortcode: Optional[str] = None


@router.post("/api/users/register")
async def register_user_api(
    request: UserRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user (admin or reseller)"""
    try:
        try:
            role_enum = UserRole(request.role.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'reseller'")

        existing_user_stmt = select(User).filter(User.email == request.email.lower())
        existing_result = await db.execute(existing_user_stmt)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="User with this email already exists")

        user = await create_user(
            db, request.email, request.password, role_enum, request.organization_name,
            business_name=request.business_name,
            mpesa_shortcode=request.mpesa_shortcode
        )

        return {
            "id": user.id,
            "email": user.email,
            "user_code": user.user_code,
            "role": user.role.value,
            "organization_name": user.organization_name,
            "business_name": user.business_name,
            "mpesa_shortcode": user.mpesa_shortcode,
            "created_at": user.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/api/auth/login")
async def login_api(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Login and get JWT token"""
    try:
        user = await authenticate_user(db, request.email, request.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token_data = {
            "sub": str(user.id),
            "user_code": user.user_code,
            "user_id": user.id,
            "role": user.role.value,
            "organization_name": user.organization_name
        }
        access_token = create_access_token(
            data=token_data,
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role.value,
                "organization_name": user.organization_name,
                "business_name": user.business_name,
                "mpesa_shortcode": user.mpesa_shortcode
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")
