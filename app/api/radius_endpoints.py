"""
RADIUS API Endpoints
====================

Management endpoints for RADIUS-enabled routers, prefixed with /api/radius/.

Authentication: every endpoint here needs a normal dashboard login (Bearer
token). Until 29 Oct 2026 none of them checked anything, so anyone on the
internet could switch any router to RADIUS, mint RADIUS logins or disconnect
sessions. Now:

* a reseller only reaches their own routers, their own customers' RADIUS
  users, and sessions/accounting seen on their own routers; anything else is a
  404, the same answer as "does not exist";
* a Bitwave admin reaches everything;
* staff logins act as their reseller, limited by the staff permission map
  (app/services/staff_permissions.py);
* ``POST /cleanup`` sweeps every reseller's expired users, so it is admin-only.

No router, FreeRADIUS module or captive portal calls these routes (FreeRADIUS
talks to Postgres directly through rlm_sql). The public captive-portal flow
lives in radius_hotspot.py (register-and-pay, payment-status, M-Pesa callback)
and is unchanged.

Endpoints:
- POST   /api/radius/routers/{router_id}/enable      - Enable RADIUS for a router
- POST   /api/radius/routers/{router_id}/disable     - Disable RADIUS (back to direct API)
- GET    /api/radius/routers/{router_id}/status      - Get RADIUS status for router
- GET    /api/radius/routers                         - List the caller's routers with RADIUS status
- POST   /api/radius/users                           - Create RADIUS user manually
- GET    /api/radius/users/{username}                - Get RADIUS user info
- DELETE /api/radius/users/{username}                - Delete RADIUS user
- GET    /api/radius/sessions                        - List active sessions
- POST   /api/radius/sessions/{username}/disconnect  - Disconnect user session
- GET    /api/radius/accounting/{username}           - Get accounting stats
- POST   /api/radius/cleanup                         - Cleanup expired users (admin only)
- GET    /api/radius/test/{router_id}                - Test RADIUS connectivity
"""

import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timedelta
import logging
import secrets
import string

from app.db.database import get_db
from app.db.models import Customer, Router, User, UserRole
from app.services.auth import get_current_user, verify_token
from app.services.radius_service import RadiusService, RadiusUserConfig, RadiusCoA
from app.services.router_helpers import get_router_by_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/radius", tags=["RADIUS"])


# ============================================================================
# Pydantic Models
# ============================================================================

class EnableRadiusRequest(BaseModel):
    """Request to enable RADIUS for a router"""
    radius_secret: str = Field(..., min_length=8, description="Shared secret for RADIUS (min 8 chars)")
    nas_identifier: Optional[str] = Field(None, description="NAS-Identifier (optional, defaults to router name)")


class CreateRadiusUserRequest(BaseModel):
    """Request to manually create a RADIUS user"""
    username: str = Field(..., description="Username (typically MAC address without colons)")
    password: Optional[str] = Field(None, description="Password (generated if not provided)")
    rate_limit: str = Field("2M/2M", description="Bandwidth limit (e.g., '5M/5M')")
    session_timeout_hours: Optional[int] = Field(24, description="Session timeout in hours")
    expiry_hours: Optional[int] = Field(24, description="Account expiry in hours from now")
    customer_id: Optional[int] = Field(
        None,
        description="Customer this login belongs to. Required for resellers (must be "
                    "their own customer); optional for admins.",
    )


class RadiusUserResponse(BaseModel):
    """Response for RADIUS user operations"""
    success: bool
    username: str
    password: Optional[str] = None
    rate_limit: Optional[str] = None
    expiry: Optional[str] = None
    message: Optional[str] = None


class RouterRadiusStatus(BaseModel):
    """RADIUS status for a router"""
    router_id: int
    router_name: str
    auth_method: str
    radius_enabled: bool
    radius_secret_set: bool
    nas_identifier: Optional[str]
    active_sessions: int


class ActiveSessionResponse(BaseModel):
    """Active RADIUS session info"""
    session_id: str
    username: str
    nas_ip: str
    client_ip: Optional[str]
    mac_address: Optional[str]
    start_time: Optional[datetime]
    session_time: Optional[int]
    bytes_in: int
    bytes_out: int


# ============================================================================
# Access helpers
# ============================================================================

def _is_admin(user: User) -> bool:
    role = getattr(user, "role", None)
    return (role.value if hasattr(role, "value") else role) == UserRole.ADMIN.value


def _role(user: User) -> Optional[str]:
    role = getattr(user, "role", None)
    return role.value if hasattr(role, "value") else role


async def _owned_router(db: AsyncSession, router_id: int, user: User) -> Router:
    """The router if the caller owns it (admins: any router), else 404."""
    db_router = await get_router_by_id(db, router_id, user.id, _role(user))
    if not db_router:
        raise HTTPException(status_code=404, detail="Router not found")
    return db_router


async def _owned_customer(db: AsyncSession, customer_id: int, user: User) -> Customer:
    stmt = select(Customer).where(Customer.id == customer_id)
    if not _is_admin(user):
        stmt = stmt.where(Customer.user_id == user.id)
    customer = (await db.execute(stmt)).scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


async def _radius_user_owner_id(db: AsyncSession, customer_id: Optional[int]) -> Optional[int]:
    """Reseller who owns the customer a RADIUS login is linked to (None if unlinked)."""
    if not customer_id:
        return None
    return (await db.execute(
        select(Customer.user_id).where(Customer.id == customer_id)
    )).scalar_one_or_none()


async def _owned_radius_user(db: AsyncSession, username: str, user: User) -> dict:
    """The RADIUS user if it belongs to one of the caller's customers, else 404.

    Logins with no customer link (manual/test users) are admin-only.
    """
    radius_user = await RadiusService(db).get_user(username)
    if not radius_user:
        raise HTTPException(status_code=404, detail="User not found")
    if _is_admin(user):
        return radius_user
    owner_id = await _radius_user_owner_id(db, radius_user.get("customer_id"))
    if owner_id is None or owner_id != user.id:
        raise HTTPException(status_code=404, detail="User not found")
    return radius_user


async def _caller_nas_ips(db: AsyncSession, user: User) -> List[str]:
    """Management IPs of the caller's routers: what RADIUS accounting calls the NAS."""
    rows = await db.execute(
        select(Router.ip_address).where(Router.user_id == user.id)
    )
    return [ip for (ip,) in rows.all() if ip]


async def _current_user(db: AsyncSession, token) -> User:
    return await get_current_user(token, db)


# ============================================================================
# Router RADIUS Management
# ============================================================================

@router.post("/routers/{router_id}/enable", response_model=dict)
async def enable_radius_for_router(
    router_id: int,
    request: EnableRadiusRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Enable RADIUS authentication for one of the caller's routers.

    This changes the router's auth_method from DIRECT_API to RADIUS.
    After enabling, new customers on this router will be provisioned via RADIUS.
    Existing customers will continue to work until their sessions expire.

    IMPORTANT: You must also configure the MikroTik router to use RADIUS.
    See the RADIUS_SETUP.md guide for MikroTik configuration.
    """
    user = await _current_user(db, token)
    db_router = await _owned_router(db, router_id, user)

    nas_identifier = request.nas_identifier or db_router.name

    await db.execute(text("""
        UPDATE routers SET
            auth_method = 'RADIUS',
            radius_secret = :secret,
            radius_nas_identifier = :nas_id
        WHERE id = :router_id
    """), {
        'router_id': router_id,
        'secret': request.radius_secret,
        'nas_id': nas_identifier
    })

    await db.commit()

    logger.info(f"RADIUS enabled for router {router_id} by user {user.id}")

    return {
        'success': True,
        'message': f'RADIUS enabled for router "{db_router.name}"',
        'router_id': router_id,
        'auth_method': 'RADIUS',
        'nas_identifier': nas_identifier,
        'next_steps': [
            'Configure MikroTik router to use RADIUS server',
            'Set RADIUS server IP to your ISP Billing server',
            'Use the same shared secret on router',
            'Test with /api/radius/test/{router_id}'
        ]
    }


@router.post("/routers/{router_id}/disable", response_model=dict)
async def disable_radius_for_router(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Disable RADIUS for one of the caller's routers (revert to direct API method).
    """
    user = await _current_user(db, token)
    db_router = await _owned_router(db, router_id, user)

    await db.execute(text("""
        UPDATE routers SET
            auth_method = 'DIRECT_API',
            radius_secret = NULL,
            radius_nas_identifier = NULL
        WHERE id = :router_id
    """), {'router_id': router_id})

    await db.commit()

    logger.info(f"RADIUS disabled for router {router_id} by user {user.id}")

    return {
        'success': True,
        'message': f'RADIUS disabled for router "{db_router.name}". Now using direct API.',
        'router_id': router_id,
        'auth_method': 'DIRECT_API'
    }


async def _active_session_count(db: AsyncSession, auth_method: Optional[str], ip_address: Optional[str]) -> int:
    if auth_method != 'RADIUS':
        return 0
    sessions_result = await db.execute(text("""
        SELECT COUNT(*) as count FROM radius_accounting
        WHERE nasipaddress = :nas_ip AND acctstoptime IS NULL
    """), {'nas_ip': ip_address})
    return sessions_result.fetchone().count


@router.get("/routers/{router_id}/status", response_model=RouterRadiusStatus)
async def get_router_radius_status(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get RADIUS configuration status for one of the caller's routers"""
    user = await _current_user(db, token)
    db_router = await _owned_router(db, router_id, user)

    active_sessions = await _active_session_count(db, db_router.auth_method, db_router.ip_address)

    return RouterRadiusStatus(
        router_id=db_router.id,
        router_name=db_router.name,
        auth_method=db_router.auth_method or 'DIRECT_API',
        radius_enabled=(db_router.auth_method == 'RADIUS'),
        radius_secret_set=bool(db_router.radius_secret),
        nas_identifier=db_router.radius_nas_identifier,
        active_sessions=active_sessions
    )


@router.get("/routers", response_model=List[RouterRadiusStatus])
async def list_radius_enabled_routers(
    user_id: Optional[int] = Query(
        None, description="Admins only: list another reseller's routers. Ignored for resellers."
    ),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List the caller's routers with their RADIUS status"""
    user = await _current_user(db, token)
    owner_id = user_id if (_is_admin(user) and user_id is not None) else user.id

    result = await db.execute(
        select(Router).where(Router.user_id == owner_id).order_by(Router.name)
    )

    routers = []
    for row in result.scalars().all():
        active_sessions = await _active_session_count(db, row.auth_method, row.ip_address)
        routers.append(RouterRadiusStatus(
            router_id=row.id,
            router_name=row.name,
            auth_method=row.auth_method or 'DIRECT_API',
            radius_enabled=(row.auth_method == 'RADIUS'),
            radius_secret_set=bool(row.radius_secret),
            nas_identifier=row.radius_nas_identifier,
            active_sessions=active_sessions
        ))

    return routers


# ============================================================================
# RADIUS User Management
# ============================================================================

@router.post("/users", response_model=RadiusUserResponse)
async def create_radius_user(
    request: CreateRadiusUserRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Manually create a RADIUS user for one of the caller's customers.

    Resellers must pass ``customer_id`` of their own customer, and cannot reuse
    a username that already belongs to someone else's customer (creating a user
    replaces any existing login with the same username).
    """
    user = await _current_user(db, token)
    admin = _is_admin(user)

    if request.customer_id is not None:
        await _owned_customer(db, request.customer_id, user)
    elif not admin:
        raise HTTPException(status_code=400, detail="customer_id is required")

    if not admin:
        existing = await RadiusService(db).get_user(request.username)
        if existing:
            owner_id = await _radius_user_owner_id(db, existing.get("customer_id"))
            if owner_id != user.id:
                raise HTTPException(status_code=409, detail="Username is not available")

    radius = RadiusService(db)

    # Generate password if not provided
    password = request.password
    if not password:
        chars = string.digits + string.ascii_lowercase
        password = ''.join(secrets.choice(chars) for _ in range(8))

    # Calculate expiry
    expiry = None
    if request.expiry_hours:
        expiry = datetime.utcnow() + timedelta(hours=request.expiry_hours)

    # Calculate session timeout in seconds
    session_timeout = None
    if request.session_timeout_hours:
        session_timeout = request.session_timeout_hours * 3600

    config = RadiusUserConfig(
        username=request.username,
        password=password,
        rate_limit=request.rate_limit,
        session_timeout=session_timeout,
        expiry=expiry,
        customer_id=request.customer_id
    )

    try:
        await radius.create_user(config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

    logger.info(f"RADIUS user {request.username} created by user {user.id}")

    return RadiusUserResponse(
        success=True,
        username=request.username,
        password=password,
        rate_limit=request.rate_limit,
        expiry=expiry.isoformat() if expiry else None,
        message="User created successfully"
    )


@router.get("/users/{username}", response_model=dict)
async def get_radius_user(
    username: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get RADIUS user information (includes the login password)"""
    user = await _current_user(db, token)
    return await _owned_radius_user(db, username, user)


async def _disconnect(nas_ip: str, secret: str, username: str) -> dict:
    """CoA Disconnect-Request off the event loop. Call with no DB transaction open."""
    coa = RadiusCoA(nas_ip, secret)
    success, message = await asyncio.to_thread(coa.disconnect_user, username=username)
    return {'success': success, 'message': message}


@router.delete("/users/{username}", response_model=dict)
async def delete_radius_user(
    username: str,
    disconnect: bool = Query(True, description="Attempt to disconnect active sessions"),
    router_id: Optional[int] = Query(None, description="Router ID for disconnect (optional)"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Delete one of the caller's RADIUS users and optionally disconnect active sessions"""
    user = await _current_user(db, token)
    await _owned_radius_user(db, username, user)

    nas = None
    if disconnect and router_id:
        db_router = await _owned_router(db, router_id, user)
        if db_router.radius_secret:
            nas = (db_router.ip_address, db_router.radius_secret)

    disconnect_result = None
    if nas:
        await db.commit()  # release the pooled connection before network I/O
        disconnect_result = await _disconnect(nas[0], nas[1], username)

    deleted = await RadiusService(db).delete_user(username)
    logger.info(f"RADIUS user {username} deleted by user {user.id}")

    return {
        'success': deleted,
        'username': username,
        'deleted': deleted,
        'disconnect_result': disconnect_result
    }


# ============================================================================
# Session Management
# ============================================================================

@router.get("/sessions", response_model=List[ActiveSessionResponse])
async def list_active_sessions(
    router_id: Optional[int] = Query(None, description="Filter by router ID"),
    username: Optional[str] = Query(None, description="Filter by username"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List active RADIUS sessions on the caller's routers"""
    user = await _current_user(db, token)
    radius = RadiusService(db)

    nas_ip = None
    nas_ips = None
    if router_id:
        db_router = await _owned_router(db, router_id, user)
        nas_ip = db_router.ip_address
    elif not _is_admin(user):
        nas_ips = await _caller_nas_ips(db, user)
        if not nas_ips:
            return []

    sessions = await radius.get_active_sessions(username=username, nas_ip=nas_ip, nas_ips=nas_ips)

    return [
        ActiveSessionResponse(
            session_id=s['session_id'],
            username=s['username'],
            nas_ip=s['nas_ip'],
            client_ip=s['client_ip'],
            mac_address=s['mac_address'],
            start_time=s['start_time'],
            session_time=s['session_time'],
            bytes_in=s['bytes_in'],
            bytes_out=s['bytes_out']
        )
        for s in sessions
    ]


@router.post("/sessions/{username}/disconnect", response_model=dict)
async def disconnect_user_session(
    username: str,
    router_id: int = Query(..., description="Router ID to send disconnect to"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Disconnect a user's active session on one of the caller's routers via RADIUS CoA.

    This sends a Disconnect-Request to the MikroTik router to terminate
    the user's session immediately.
    """
    user = await _current_user(db, token)
    db_router = await _owned_router(db, router_id, user)

    if not db_router.radius_secret:
        raise HTTPException(status_code=400, detail="Router does not have RADIUS configured")

    nas_ip, secret = db_router.ip_address, db_router.radius_secret
    await db.commit()  # release the pooled connection before network I/O
    result = await _disconnect(nas_ip, secret, username)
    logger.info(f"RADIUS disconnect of {username} on router {router_id} by user {user.id}")

    return {
        'success': result['success'],
        'username': username,
        'message': result['message']
    }


# ============================================================================
# Accounting & Statistics
# ============================================================================

@router.get("/accounting/{username}", response_model=dict)
async def get_user_accounting(
    username: str,
    days: int = Query(30, description="Number of days to include in stats"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get accounting statistics for a RADIUS user, counting only the caller's routers"""
    user = await _current_user(db, token)
    radius = RadiusService(db)

    nas_ips = None
    if not _is_admin(user):
        nas_ips = await _caller_nas_ips(db, user)

    start_date = datetime.utcnow() - timedelta(days=days)
    stats = await radius.get_session_statistics(username, start_date=start_date, nas_ips=nas_ips)

    # Add human-readable values
    stats['total_bytes_in_mb'] = round(stats['total_bytes_in'] / (1024 * 1024), 2)
    stats['total_bytes_out_mb'] = round(stats['total_bytes_out'] / (1024 * 1024), 2)
    stats['total_time_hours'] = round(stats['total_time_seconds'] / 3600, 2)

    return stats


# ============================================================================
# Maintenance
# ============================================================================

@router.post("/cleanup", response_model=dict)
async def cleanup_expired_users(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Cleanup expired RADIUS users across ALL resellers. Admin only.

    This removes users whose expiry date has passed from the RADIUS tables.
    Active sessions will naturally fail on re-authentication.
    """
    user = await _current_user(db, token)
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="Admin access required")

    radius = RadiusService(db)
    count = await radius.cleanup_expired_users()

    return {
        'success': True,
        'expired_users_removed': count,
        'message': f'Removed {count} expired RADIUS users'
    }


@router.get("/test/{router_id}", response_model=dict)
async def test_radius_connectivity(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Test RADIUS setup for one of the caller's routers.

    This checks:
    1. Router has RADIUS enabled
    2. RADIUS tables exist
    3. Can create/delete test user

    Note: This doesn't test actual authentication from the router -
    that requires the router to send a test auth request.
    """
    user = await _current_user(db, token)
    db_router = await _owned_router(db, router_id, user)
    # Plain values: a rollback below would expire the ORM object.
    router_name, router_ip = db_router.name, db_router.ip_address

    checks = {
        'router_found': True,
        'radius_enabled': db_router.auth_method == 'RADIUS',
        'radius_secret_set': bool(db_router.radius_secret),
        'tables_exist': False,
        'can_create_user': False,
        'can_delete_user': False
    }

    # Check if RADIUS tables exist (by probing; works on Postgres and SQLite)
    try:
        await db.execute(text("SELECT 1 FROM radius_check WHERE 1 = 0"))
        checks['tables_exist'] = True
    except Exception:
        await db.rollback()

    # Try to create and delete a test user
    if checks['tables_exist']:
        test_username = f"_test_{secrets.token_hex(4)}"
        radius = RadiusService(db)

        try:
            config = RadiusUserConfig(
                username=test_username,
                password="testpass",
                rate_limit="1M/1M"
            )
            await radius.create_user(config)
            checks['can_create_user'] = True

            await radius.delete_user(test_username)
            checks['can_delete_user'] = True
        except Exception as e:
            checks['error'] = str(e)

    all_passed = all([
        checks['radius_enabled'],
        checks['radius_secret_set'],
        checks['tables_exist'],
        checks['can_create_user'],
        checks['can_delete_user']
    ])

    return {
        'success': all_passed,
        'router_name': router_name,
        'router_ip': router_ip,
        'checks': checks,
        'message': 'All checks passed' if all_passed else 'Some checks failed - see details'
    }
