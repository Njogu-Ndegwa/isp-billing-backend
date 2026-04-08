from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import ALGORITHM
from app.config import settings
from app.db.database import get_db
from pydantic import BaseModel

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/graphql", auto_error=False)  # Disable auto-error

class CurrentUser(BaseModel):
    user_code: int
    user_id: int
    role: str
    organization_name: str

async def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    if not token:
        return None  # Allow unauthenticated access
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_code: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        role: str = payload.get("role")
        organization_name: str = payload.get("organization_name")
        if not all([user_code, user_id, role, organization_name]):
            raise credentials_exception
        return CurrentUser(
            user_code=int(user_code),
            user_id=int(user_id),
            role=role,
            organization_name=organization_name
        )
    except JWTError:
        raise credentials_exception


async def get_current_active_user(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require authenticated user - rejects unauthenticated requests."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


async def require_active_subscription(
    current_user: CurrentUser = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """
    Require that a reseller has an active or trial subscription.
    Admins always pass. Suspended/inactive resellers are blocked.
    """
    if current_user.role == "admin":
        return current_user

    from sqlalchemy import select
    from app.db.models import User, SubscriptionStatus

    user = (await db.execute(
        select(User).where(User.id == current_user.user_id)
    )).scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    sub_status = user.subscription_status
    if hasattr(sub_status, 'value'):
        sub_status = sub_status.value

    if sub_status not in ("active", "trial"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your subscription is inactive. Please renew your subscription to continue using the service.",
        )
    return current_user
