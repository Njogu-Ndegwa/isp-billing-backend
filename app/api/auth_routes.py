from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import asyncio
import hashlib
import secrets

from app.db.database import get_db
from app.db.models import User, UserRole, PasswordResetToken
from app.services.auth import create_user, authenticate_user, create_access_token, pwd_context
from app.services.subscription import get_invoice_alert_for_user
from app.services import email_service
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
    support_phone: Optional[str] = None
    mpesa_shortcode: Optional[str] = None


@router.post("/api/users/register")
async def register_user_api(
    request: UserRegisterRequest,
    background: BackgroundTasks,
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
            support_phone=request.support_phone,
            mpesa_shortcode=request.mpesa_shortcode
        )

        response_data = {
            "id": user.id,
            "email": user.email,
            "user_code": user.user_code,
            "role": user.role.value,
            "organization_name": user.organization_name,
            "business_name": getattr(user, 'business_name', None),
            "support_phone": getattr(user, 'support_phone', None),
            "mpesa_shortcode": getattr(user, 'mpesa_shortcode', None),
            "created_at": user.created_at.isoformat()
        }

        if role_enum == UserRole.RESELLER:
            try:
                from app.services.lead_tracking import try_link_lead_on_registration
                await try_link_lead_on_registration(
                    db, user.id, request.email, request.support_phone,
                    request.organization_name,
                )
                await db.commit()
            except Exception as link_err:
                logger.warning(f"Lead auto-link failed (non-fatal): {link_err}")
                try:
                    await db.rollback()
                except Exception:
                    pass

            try:
                from app.services.reseller_welcome import queue_reseller_welcome
                from app.services import sms_dispatch
                from app.services.messaging import resolve_sender_id
                from app.db.models import MessagingSettings

                sms_ids = await queue_reseller_welcome(db, user)
                settings_row = await db.get(MessagingSettings, 1)
                sender_id = resolve_sender_id(
                    settings_row.sender_id
                    if settings_row and settings_row.sender_id else None
                )
                await db.commit()
                if sms_ids:
                    background.add_task(
                        sms_dispatch.dispatch_admin_sms_messages,
                        sms_ids, sender_id)
            except Exception as welcome_err:
                logger.warning(
                    f"Reseller welcome message failed (non-fatal): {welcome_err}")
                try:
                    await db.rollback()
                except Exception:
                    pass

        return response_data
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

        user.last_login_at = datetime.utcnow()
        db.add(user)
        await db.flush()

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

        sub_status = getattr(user, 'subscription_status', None)
        if sub_status and hasattr(sub_status, 'value'):
            sub_status = sub_status.value

        subscription_alert = None
        try:
            subscription_alert = await get_invoice_alert_for_user(db, user.id)
        except Exception as alert_err:
            logger.warning(f"Failed to get subscription alert for user {user.id}: {alert_err}")

        await db.commit()

        response = {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role.value,
                "organization_name": user.organization_name,
                "business_name": getattr(user, 'business_name', None),
                "support_phone": getattr(user, 'support_phone', None),
                "mpesa_shortcode": getattr(user, 'mpesa_shortcode', None),
                "subscription_status": sub_status,
                "subscription_expires_at": user.subscription_expires_at.isoformat() if getattr(user, 'subscription_expires_at', None) else None,
            },
        }

        if subscription_alert:
            response["subscription_alert"] = subscription_alert

        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")


# ============================================================================
# Self-service password reset (forgot password)
# ============================================================================

# Both endpoints answer with the same generic message whether or not the email
# exists, so they cannot be used to enumerate accounts.
FORGOT_PASSWORD_GENERIC_RESPONSE = {
    "message": "If an account with that email exists, a password reset link has been sent."
}

# In-memory throttle: max requests per email within the window. Single-worker
# app, so a module-level dict is sufficient; restart clears it, which is fine
# for an abuse brake (not a security boundary — tokens are).
RESET_REQUEST_WINDOW_MINUTES = 15
RESET_REQUESTS_PER_WINDOW = 3
_reset_request_log: dict[str, list[datetime]] = {}


def _reset_request_allowed(email: str, now: datetime) -> bool:
    cutoff = now - timedelta(minutes=RESET_REQUEST_WINDOW_MINUTES)
    recent = [t for t in _reset_request_log.get(email, []) if t > cutoff]
    if len(recent) >= RESET_REQUESTS_PER_WINDOW:
        _reset_request_log[email] = recent
        return False
    recent.append(now)
    _reset_request_log[email] = recent
    if len(_reset_request_log) > 10000:
        _reset_request_log.clear()
    return True


def _hash_reset_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class ForgotPasswordRequest(BaseModel):
    email: str


@router.post("/api/auth/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Start a password reset: email the user a one-time reset link."""
    email = request.email.strip().lower()
    now = datetime.utcnow()
    if not email or not _reset_request_allowed(email, now):
        return FORGOT_PASSWORD_GENERIC_RESPONSE

    try:
        result = await db.execute(select(User).filter(User.email == email))
        user = result.scalar_one_or_none()
        if not user:
            return FORGOT_PASSWORD_GENERIC_RESPONSE

        raw_token = secrets.token_urlsafe(32)
        await db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None),
            )
            .values(used_at=now)
        )
        db.add(PasswordResetToken(
            user_id=user.id,
            token_hash=_hash_reset_token(raw_token),
            created_at=now,
            expires_at=now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_TTL_MINUTES),
        ))
        # Commit before the email send: the send is external I/O and must not
        # ride on (or hold) a DB session — see Database Session Discipline.
        await db.commit()

        reset_url = (
            f"{settings.FRONTEND_BASE_URL.rstrip('/')}/reset-password?token={raw_token}"
        )
        background.add_task(email_service.send_password_reset_email, user.email, reset_url)
        return FORGOT_PASSWORD_GENERIC_RESPONSE
    except Exception as e:
        logger.error(f"Forgot-password error for {email}: {e}")
        # Still generic: an internal failure must not leak account existence.
        return FORGOT_PASSWORD_GENERIC_RESPONSE


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@router.post("/api/auth/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    """Complete a password reset with a token from the emailed link."""
    if len(request.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if not request.token:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    now = datetime.utcnow()
    result = await db.execute(
        select(PasswordResetToken).filter(
            PasswordResetToken.token_hash == _hash_reset_token(request.token)
        )
    )
    token_row = result.scalar_one_or_none()
    if not token_row or token_row.used_at is not None or token_row.expires_at < now:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset link. Please request a new one.",
        )

    user = await db.get(User, token_row.user_id)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset link. Please request a new one.",
        )

    user.password_hash = await asyncio.to_thread(pwd_context.hash, request.new_password)
    token_row.used_at = now
    await db.commit()
    logger.info(f"Password reset completed for user {user.id}")
    return {"message": "Password reset successfully. You can now sign in."}
