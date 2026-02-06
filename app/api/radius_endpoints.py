"""
RADIUS API Endpoints
====================

These endpoints are COMPLETELY SEPARATE from existing endpoints.
They provide management capabilities for RADIUS-enabled routers.

All endpoints are prefixed with /api/radius/

Endpoints:
- POST   /api/radius/routers/{router_id}/enable      - Enable RADIUS for a router
- POST   /api/radius/routers/{router_id}/disable     - Disable RADIUS (back to direct API)
- GET    /api/radius/routers/{router_id}/status      - Get RADIUS status for router
- GET    /api/radius/routers                         - List all RADIUS-enabled routers
- POST   /api/radius/users                           - Create RADIUS user manually
- GET    /api/radius/users/{username}                - Get RADIUS user info
- DELETE /api/radius/users/{username}                - Delete RADIUS user
- GET    /api/radius/sessions                        - List active sessions
- POST   /api/radius/sessions/{username}/disconnect  - Disconnect user session
- GET    /api/radius/accounting/{username}           - Get accounting stats
- POST   /api/radius/cleanup                         - Cleanup expired users
- GET    /api/radius/test/{router_id}                - Test RADIUS connectivity
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timedelta
import logging
import secrets
import string

from app.db.database import get_db
from app.core.deps import get_current_active_user
from app.services.radius_service import RadiusService, RadiusUserConfig, RadiusCoA
from app.services.radius_provisioning import RadiusProvisioning, should_use_radius

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
    customer_id: Optional[int] = Field(None, description="Link to customer ID (optional)")


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
# Router RADIUS Management
# ============================================================================

@router.post("/routers/{router_id}/enable", response_model=dict)
async def enable_radius_for_router(
    router_id: int,
    request: EnableRadiusRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """
    Enable RADIUS authentication for a specific router.
    
    This changes the router's auth_method from DIRECT_API to RADIUS.
    After enabling, new customers on this router will be provisioned via RADIUS.
    Existing customers will continue to work until their sessions expire.
    
    IMPORTANT: You must also configure the MikroTik router to use RADIUS.
    See the RADIUS_SETUP.md guide for MikroTik configuration.
    """
    # Check router exists and belongs to user
    result = await db.execute(text("""
        SELECT id, name, user_id, auth_method FROM routers WHERE id = :router_id
    """), {'router_id': router_id})
    
    router = result.fetchone()
    
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    
    if router.user_id != current_user.user_id and current_user.role != 'admin':
        raise HTTPException(status_code=403, detail="Not authorized to manage this router")
    
    # Update router to use RADIUS
    nas_identifier = request.nas_identifier or router.name
    
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
    
    logger.info(f"RADIUS enabled for router {router_id} by user {current_user.user_id}")
    
    return {
        'success': True,
        'message': f'RADIUS enabled for router "{router.name}"',
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
    current_user = Depends(get_current_active_user)
):
    """
    Disable RADIUS for a router (revert to direct API method).
    
    This is useful if you want to migrate a router back to the original
    direct API provisioning method.
    """
    # Check router exists and belongs to user
    result = await db.execute(text("""
        SELECT id, name, user_id FROM routers WHERE id = :router_id
    """), {'router_id': router_id})
    
    router = result.fetchone()
    
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    
    if router.user_id != current_user.user_id and current_user.role != 'admin':
        raise HTTPException(status_code=403, detail="Not authorized to manage this router")
    
    # Update router to use direct API
    await db.execute(text("""
        UPDATE routers SET 
            auth_method = 'DIRECT_API',
            radius_secret = NULL,
            radius_nas_identifier = NULL
        WHERE id = :router_id
    """), {'router_id': router_id})
    
    await db.commit()
    
    logger.info(f"RADIUS disabled for router {router_id} by user {current_user.user_id}")
    
    return {
        'success': True,
        'message': f'RADIUS disabled for router "{router.name}". Now using direct API.',
        'router_id': router_id,
        'auth_method': 'DIRECT_API'
    }


@router.get("/routers/{router_id}/status", response_model=RouterRadiusStatus)
async def get_router_radius_status(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get RADIUS configuration status for a router"""
    result = await db.execute(text("""
        SELECT id, name, user_id, auth_method, radius_secret, radius_nas_identifier, ip_address
        FROM routers WHERE id = :router_id
    """), {'router_id': router_id})
    
    router = result.fetchone()
    
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    
    if router.user_id != current_user.user_id and current_user.role != 'admin':
        raise HTTPException(status_code=403, detail="Not authorized to view this router")
    
    # Count active sessions for this router
    active_sessions = 0
    if router.auth_method == 'RADIUS':
        sessions_result = await db.execute(text("""
            SELECT COUNT(*) as count FROM radius_accounting 
            WHERE nasipaddress = :nas_ip AND acctstoptime IS NULL
        """), {'nas_ip': router.ip_address})
        active_sessions = sessions_result.fetchone().count
    
    return RouterRadiusStatus(
        router_id=router.id,
        router_name=router.name,
        auth_method=router.auth_method or 'DIRECT_API',
        radius_enabled=(router.auth_method == 'RADIUS'),
        radius_secret_set=bool(router.radius_secret),
        nas_identifier=router.radius_nas_identifier,
        active_sessions=active_sessions
    )


@router.get("/routers", response_model=List[RouterRadiusStatus])
async def list_radius_enabled_routers(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """List all routers with their RADIUS status"""
    result = await db.execute(text("""
        SELECT id, name, auth_method, radius_secret, radius_nas_identifier, ip_address
        FROM routers WHERE user_id = :user_id
        ORDER BY name
    """), {'user_id': current_user.user_id})
    
    routers = []
    for row in result.fetchall():
        # Count active sessions
        active_sessions = 0
        if row.auth_method == 'RADIUS':
            sessions_result = await db.execute(text("""
                SELECT COUNT(*) as count FROM radius_accounting 
                WHERE nasipaddress = :nas_ip AND acctstoptime IS NULL
            """), {'nas_ip': row.ip_address})
            active_sessions = sessions_result.fetchone().count
        
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
    current_user = Depends(get_current_active_user)
):
    """
    Manually create a RADIUS user.
    
    This is useful for testing or creating users outside the normal billing flow.
    """
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
        result = await radius.create_user(config)
        
        return RadiusUserResponse(
            success=True,
            username=request.username,
            password=password,
            rate_limit=request.rate_limit,
            expiry=expiry.isoformat() if expiry else None,
            message="User created successfully"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")


@router.get("/users/{username}", response_model=dict)
async def get_radius_user(
    username: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get RADIUS user information"""
    radius = RadiusService(db)
    user = await radius.get_user(username)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user


@router.delete("/users/{username}", response_model=dict)
async def delete_radius_user(
    username: str,
    disconnect: bool = Query(True, description="Attempt to disconnect active sessions"),
    router_id: Optional[int] = Query(None, description="Router ID for disconnect (optional)"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Delete a RADIUS user and optionally disconnect active sessions"""
    radius = RadiusService(db)
    
    # Check user exists
    user = await radius.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Try to disconnect if requested and router info available
    disconnect_result = None
    if disconnect and router_id:
        result = await db.execute(text("""
            SELECT ip_address, radius_secret FROM routers WHERE id = :router_id
        """), {'router_id': router_id})
        router = result.fetchone()
        
        if router and router.radius_secret:
            coa = RadiusCoA(router.ip_address, router.radius_secret)
            success, message = coa.disconnect_user(username=username)
            disconnect_result = {'success': success, 'message': message}
    
    # Delete user
    deleted = await radius.delete_user(username)
    
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
    current_user = Depends(get_current_active_user)
):
    """List active RADIUS sessions"""
    radius = RadiusService(db)
    
    # Get NAS IP if router_id provided
    nas_ip = None
    if router_id:
        result = await db.execute(text("""
            SELECT ip_address FROM routers WHERE id = :router_id AND user_id = :user_id
        """), {'router_id': router_id, 'user_id': current_user.user_id})
        router = result.fetchone()
        if router:
            nas_ip = router.ip_address
    
    sessions = await radius.get_active_sessions(username=username, nas_ip=nas_ip)
    
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
    current_user = Depends(get_current_active_user)
):
    """
    Disconnect a user's active session via RADIUS CoA.
    
    This sends a Disconnect-Request to the MikroTik router to terminate
    the user's session immediately.
    """
    # Get router info
    result = await db.execute(text("""
        SELECT ip_address, radius_secret FROM routers 
        WHERE id = :router_id AND user_id = :user_id
    """), {'router_id': router_id, 'user_id': current_user.user_id})
    
    router = result.fetchone()
    
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    
    if not router.radius_secret:
        raise HTTPException(status_code=400, detail="Router does not have RADIUS configured")
    
    coa = RadiusCoA(router.ip_address, router.radius_secret)
    success, message = coa.disconnect_user(username=username)
    
    return {
        'success': success,
        'username': username,
        'message': message
    }


# ============================================================================
# Accounting & Statistics
# ============================================================================

@router.get("/accounting/{username}", response_model=dict)
async def get_user_accounting(
    username: str,
    days: int = Query(30, description="Number of days to include in stats"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get accounting statistics for a RADIUS user"""
    radius = RadiusService(db)
    
    start_date = datetime.utcnow() - timedelta(days=days)
    stats = await radius.get_session_statistics(username, start_date=start_date)
    
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
    current_user = Depends(get_current_active_user)
):
    """
    Cleanup expired RADIUS users.
    
    This removes users whose expiry date has passed from the RADIUS tables.
    Active sessions will naturally fail on re-authentication.
    """
    if current_user.role != 'admin':
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
    current_user = Depends(get_current_active_user)
):
    """
    Test RADIUS connectivity to a router.
    
    This checks:
    1. Router has RADIUS enabled
    2. RADIUS tables exist
    3. Can create/delete test user
    
    Note: This doesn't test actual authentication from the router -
    that requires the router to send a test auth request.
    """
    # Get router info
    result = await db.execute(text("""
        SELECT id, name, ip_address, auth_method, radius_secret
        FROM routers WHERE id = :router_id AND user_id = :user_id
    """), {'router_id': router_id, 'user_id': current_user.user_id})
    
    router = result.fetchone()
    
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    
    checks = {
        'router_found': True,
        'radius_enabled': router.auth_method == 'RADIUS',
        'radius_secret_set': bool(router.radius_secret),
        'tables_exist': False,
        'can_create_user': False,
        'can_delete_user': False
    }
    
    # Check if RADIUS tables exist
    try:
        result = await db.execute(text("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_name = 'radius_check'
        """))
        checks['tables_exist'] = result.fetchone() is not None
    except:
        pass
    
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
        'router_name': router.name,
        'router_ip': router.ip_address,
        'checks': checks,
        'message': 'All checks passed' if all_passed else 'Some checks failed - see details'
    }
