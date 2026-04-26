"""
Reseller API for managing access credentials (comp hotspot logins).
"""

from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    AccessCredential, AccessCredStatus, Router, UserRole,
)
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.access_credentials import (
    bind_mac_for_login,
    deprovision_credential,
    fetch_live_usage,
    generate_password,
    generate_username,
    provision_credential,
    release_mac,
    serialize_credential,
)
from app.services.router_helpers import get_router_by_id

import logging
import re

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/access-credentials", tags=["access-credentials"])


_RATE_LIMIT_RE = re.compile(r"^\d+(?:\.\d+)?[kKmMgG]?/\d+(?:\.\d+)?[kKmMgG]?$")
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


def _validate_rate_limit(value: Optional[str]) -> Optional[str]:
    if value is None or value == "":
        return None
    value = value.strip()
    if not _RATE_LIMIT_RE.match(value):
        raise HTTPException(
            status_code=400,
            detail="rate_limit must look like '5M/2M' (upload/download in K/M/G)",
        )
    return value


def _validate_username(value: str) -> str:
    value = value.strip().lower()
    if not _USERNAME_RE.match(value):
        raise HTTPException(
            status_code=400,
            detail=(
                "username must be 3-64 chars, start with a letter or digit, "
                "and contain only lowercase letters, digits, '.', '-', or '_'"
            ),
        )
    return value


async def _own_or_admin(db: AsyncSession, cred_id: int, user) -> AccessCredential:
    stmt = select(AccessCredential).where(AccessCredential.id == cred_id)
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(AccessCredential.user_id == user.id)
    result = await db.execute(stmt)
    cred = result.scalar_one_or_none()
    if not cred:
        raise HTTPException(status_code=404, detail="Access credential not found")
    return cred


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CreateRequest(BaseModel):
    router_id: int
    username: Optional[str] = Field(default=None, max_length=64)
    password: Optional[str] = Field(default=None, min_length=4, max_length=128)
    rate_limit: Optional[str] = Field(default=None, max_length=50)
    data_cap_mb: Optional[int] = Field(default=None, ge=0)
    label: Optional[str] = Field(default=None, max_length=255)


class UpdateRequest(BaseModel):
    rate_limit: Optional[str] = Field(default=None, max_length=50)
    data_cap_mb: Optional[int] = Field(default=None, ge=0)
    label: Optional[str] = Field(default=None, max_length=255)
    clear_rate_limit: bool = False
    clear_data_cap: bool = False
    clear_label: bool = False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("")
async def create_credential(
    payload: CreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    enforce_active_subscription(user)

    router_obj = await get_router_by_id(
        db, payload.router_id, user_id=user.id,
        role=user.role.value if user.role else None,
    )
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    rate_limit = _validate_rate_limit(payload.rate_limit)

    if payload.username:
        username = _validate_username(payload.username)
    else:
        for _ in range(10):
            username = generate_username()
            existing = await db.execute(select(AccessCredential.id).where(
                AccessCredential.router_id == router_obj.id,
                AccessCredential.username == username,
            ))
            if not existing.scalar_one_or_none():
                break
        else:
            raise HTTPException(status_code=500, detail="Failed to allocate unique username")

    existing = await db.execute(select(AccessCredential.id).where(
        AccessCredential.router_id == router_obj.id,
        AccessCredential.username == username,
    ))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"A credential with username '{username}' already exists on this router",
        )

    password = (payload.password or generate_password()).strip()
    if not password:
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    cred = AccessCredential(
        user_id=user.id,
        router_id=router_obj.id,
        username=username,
        password=password,
        rate_limit=rate_limit,
        data_cap_mb=payload.data_cap_mb,
        label=payload.label,
        status=AccessCredStatus.ACTIVE,
    )
    db.add(cred)
    await db.commit()
    await db.refresh(cred)

    provision_result = await provision_credential(db, cred, router_obj)
    if provision_result.get("error"):
        # Soft-fail: keep DB row but flag the error so the reseller can retry.
        logger.warning(
            f"Provision failed for new credential {cred.id} on router {router_obj.id}: "
            f"{provision_result.get('message')}"
        )
        return {
            **serialize_credential(cred, include_password=True),
            "warning": provision_result.get("message", "Router provisioning failed"),
            "provisioned": False,
        }

    return {
        **serialize_credential(cred, include_password=True),
        "provisioned": True,
    }


@router.get("")
async def list_credentials(
    router_id: Optional[int] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)

    stmt = select(AccessCredential)
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(AccessCredential.user_id == user.id)

    if router_id is not None:
        stmt = stmt.where(AccessCredential.router_id == router_id)

    if status:
        s = status.lower()
        if s in ("active", "revoked"):
            stmt = stmt.where(AccessCredential.status == AccessCredStatus(s))
        elif s == "in_use":
            stmt = stmt.where(
                AccessCredential.bound_mac_address.isnot(None),
                AccessCredential.status == AccessCredStatus.ACTIVE,
            )
        elif s == "idle":
            stmt = stmt.where(
                AccessCredential.bound_mac_address.is_(None),
                AccessCredential.status == AccessCredStatus.ACTIVE,
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="status must be one of: active, revoked, in_use, idle",
            )

    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(
            func.lower(AccessCredential.username).like(like),
            func.lower(AccessCredential.label).like(like),
        ))

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(AccessCredential.created_at.desc()).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(stmt)
    creds: List[AccessCredential] = list(result.scalars().all())

    items = [serialize_credential(c) for c in creds]

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if per_page else 0,
    }


@router.get("/{cred_id}")
async def get_credential(
    cred_id: int,
    reveal: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    cred = await _own_or_admin(db, cred_id, user)

    router_obj = await db.get(Router, cred.router_id)
    live = await fetch_live_usage(cred, router_obj) if router_obj else {"online": False}

    return serialize_credential(cred, include_password=reveal, live=live)


@router.patch("/{cred_id}")
async def update_credential(
    cred_id: int,
    payload: UpdateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    cred = await _own_or_admin(db, cred_id, user)
    router_obj = await db.get(Router, cred.router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    rate_changed = False

    if payload.clear_rate_limit:
        if cred.rate_limit is not None:
            cred.rate_limit = None
            rate_changed = True
    elif payload.rate_limit is not None:
        new_rate = _validate_rate_limit(payload.rate_limit)
        if cred.rate_limit != new_rate:
            cred.rate_limit = new_rate
            rate_changed = True

    if payload.clear_data_cap:
        cred.data_cap_mb = None
    elif payload.data_cap_mb is not None:
        cred.data_cap_mb = payload.data_cap_mb

    if payload.clear_label:
        cred.label = None
    elif payload.label is not None:
        cred.label = payload.label

    await db.commit()
    await db.refresh(cred)

    payload_out = serialize_credential(cred)
    if rate_changed and cred.status == AccessCredStatus.ACTIVE:
        prov = await provision_credential(db, cred, router_obj)
        if prov.get("error"):
            logger.warning(f"Re-provision after rate change failed for cred {cred.id}: {prov}")
            payload_out["warning"] = prov.get("message") or "Router provisioning failed"
            payload_out["provisioned"] = False
        else:
            payload_out["provisioned"] = True
        # If a MAC is currently bound, refresh its queue too
        if cred.bound_mac_address and not prov.get("error"):
            await bind_mac_for_login(cred, router_obj, cred.bound_mac_address)

    return payload_out


@router.post("/{cred_id}/rotate-password")
async def rotate_password(
    cred_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    cred = await _own_or_admin(db, cred_id, user)
    router_obj = await db.get(Router, cred.router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    cred.password = generate_password()
    await db.commit()
    await db.refresh(cred)

    warning: Optional[str] = None
    provisioned = True
    if cred.status == AccessCredStatus.ACTIVE:
        prov = await provision_credential(db, cred, router_obj)
        if prov.get("error"):
            logger.warning(f"Re-provision after password rotation failed for cred {cred.id}: {prov}")
            warning = prov.get("message") or "Router provisioning failed"
            provisioned = False

    payload = serialize_credential(cred, include_password=True)
    payload["provisioned"] = provisioned
    if warning:
        payload["warning"] = warning
    return payload


@router.post("/{cred_id}/revoke")
async def revoke_credential(
    cred_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    cred = await _own_or_admin(db, cred_id, user)
    router_obj = await db.get(Router, cred.router_id)

    if router_obj:
        await deprovision_credential(db, cred, router_obj)

    cred.status = AccessCredStatus.REVOKED
    cred.revoked_at = datetime.utcnow()
    cred.bound_mac_address = None
    cred.bound_at = None
    await db.commit()
    await db.refresh(cred)
    return serialize_credential(cred)


@router.post("/{cred_id}/restore")
async def restore_credential(
    cred_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    cred = await _own_or_admin(db, cred_id, user)
    router_obj = await db.get(Router, cred.router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    cred.status = AccessCredStatus.ACTIVE
    cred.revoked_at = None
    await db.commit()
    await db.refresh(cred)

    prov = await provision_credential(db, cred, router_obj)
    payload = serialize_credential(cred)
    if prov.get("error"):
        logger.warning(f"Re-provision on restore failed for cred {cred.id}: {prov}")
        payload["warning"] = prov.get("message") or "Router provisioning failed"
        payload["provisioned"] = False
    else:
        payload["provisioned"] = True

    return payload


@router.post("/{cred_id}/sync")
async def sync_credential(
    cred_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Re-push an active credential to its router.

    Use this after a create / rotate-password / restore call returned a
    ``warning`` (i.e. ``provisioned: false``) and you have since fixed the
    router (brought it online, fixed the API user/pass/port, etc.). Idempotent:
    safe to call repeatedly.

    Revoked credentials should use ``POST /{id}/restore`` instead, which both
    re-activates the row and re-pushes it.
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    cred = await _own_or_admin(db, cred_id, user)
    router_obj = await db.get(Router, cred.router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    if cred.status != AccessCredStatus.ACTIVE:
        raise HTTPException(
            status_code=409,
            detail="Credential is revoked; use /restore to re-activate it",
        )

    prov = await provision_credential(db, cred, router_obj)

    payload = serialize_credential(cred, include_password=True)
    if prov.get("error"):
        logger.warning(f"Sync failed for cred {cred.id} on router {router_obj.id}: {prov}")
        payload["warning"] = prov.get("message") or "Router provisioning failed"
        payload["provisioned"] = False
    else:
        payload["provisioned"] = True

    # If a MAC is currently bound, refresh its binding/queue too so the user
    # sees the new password / rate-limit immediately without re-login.
    if not prov.get("error") and cred.bound_mac_address:
        bind_result = await bind_mac_for_login(cred, router_obj, cred.bound_mac_address)
        if bind_result.get("error"):
            logger.warning(
                f"Sync MAC re-bind failed for cred {cred.id}: {bind_result.get('message')}"
            )
            # Provisioning succeeded, the MAC bypass refresh didn't — surface
            # both so the caller can decide how to react.
            payload.setdefault("warning", bind_result.get("message", "MAC re-bind failed"))

    return payload


@router.post("/{cred_id}/force-logout")
async def force_logout(
    cred_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Free up a credential immediately by removing the current device's binding/queue."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    cred = await _own_or_admin(db, cred_id, user)
    router_obj = await db.get(Router, cred.router_id)

    if cred.bound_mac_address and router_obj:
        await release_mac(cred, router_obj, cred.bound_mac_address)

    cred.bound_mac_address = None
    cred.bound_at = None
    await db.commit()
    await db.refresh(cred)
    return serialize_credential(cred)


@router.delete("/{cred_id}")
async def delete_credential(
    cred_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    cred = await _own_or_admin(db, cred_id, user)
    router_obj = await db.get(Router, cred.router_id)

    if router_obj:
        await deprovision_credential(db, cred, router_obj)

    await db.delete(cred)
    await db.commit()
    return {"success": True, "id": cred_id}
