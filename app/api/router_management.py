from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func, case
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, field_validator
from typing import Optional, List
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Router, Customer, CustomerStatus, ProvisioningLog, BandwidthSnapshot, User, RouterAvailabilityCheck, ProvisioningToken, Voucher, RouterLogEntry
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.router_availability import build_router_status
import logging
import asyncio
import time

logger = logging.getLogger(__name__)

router = APIRouter(tags=["routers"])


VALID_PAYMENT_METHODS = {"mpesa", "voucher"}


class RouterCreateRequest(BaseModel):
    name: str
    identity: Optional[str] = None
    ip_address: str
    username: str
    password: str
    port: int = 8728
    payment_methods: Optional[List[str]] = None

    @field_validator("name", "identity", "ip_address", "username", "password", mode="before")
    @classmethod
    def strip_and_nullify(cls, v):
        if isinstance(v, str):
            v = v.strip()
            return v if v else None
        return v

    @field_validator("payment_methods")
    @classmethod
    def validate_payment_methods(cls, v):
        if v is None:
            return None
        if not v:
            raise ValueError("payment_methods cannot be empty")
        invalid = set(v) - VALID_PAYMENT_METHODS
        if invalid:
            raise ValueError(f"Invalid payment method(s): {invalid}. Must be: {VALID_PAYMENT_METHODS}")
        return list(set(v))


class RouterUpdateRequest(BaseModel):
    name: str
    ip_address: str
    username: Optional[str] = None
    password: Optional[str] = None
    port: int = 8728
    payment_methods: Optional[List[str]] = None
    emergency_active: Optional[bool] = None
    emergency_message: Optional[str] = None

    @field_validator("name", "ip_address", "username", "password", mode="before")
    @classmethod
    def strip_and_nullify(cls, v):
        if isinstance(v, str):
            v = v.strip()
            return v if v else None
        return v

    @field_validator("payment_methods")
    @classmethod
    def validate_payment_methods(cls, v):
        if v is None:
            return None
        if not v:
            raise ValueError("payment_methods cannot be empty")
        invalid = set(v) - VALID_PAYMENT_METHODS
        if invalid:
            raise ValueError(f"Invalid payment method(s): {invalid}. Must be: {VALID_PAYMENT_METHODS}")
        return list(set(v))


class RouterIdentityUpdate(BaseModel):
    identity: str


@router.get("/api/routers")
async def get_routers(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all routers for a user"""
    user = await get_current_user(token, db)
    stmt = (
        select(Router)
        .where(Router.user_id == user.id)
        .options(selectinload(Router.assigned_payment_method))
    )
    result = await db.execute(stmt)
    routers = result.scalars().all()
    response = []
    now = datetime.utcnow()
    for router_obj in routers:
        pm = router_obj.assigned_payment_method
        router_payload = {
            "id": router_obj.id,
            "name": router_obj.name,
            "identity": router_obj.identity,
            "ip_address": router_obj.ip_address,
            "port": router_obj.port,
            "auth_method": getattr(router_obj, "auth_method", "DIRECT_API") or "DIRECT_API",
            "payment_methods": getattr(router_obj, "payment_methods", None) or ["mpesa", "voucher"],
            "payment_method_id": router_obj.payment_method_id,
            "assigned_payment_method": {
                "id": pm.id,
                "label": pm.label,
                "method_type": pm.method_type.value if hasattr(pm.method_type, "value") else pm.method_type,
                "is_active": pm.is_active,
            } if pm else None,
            "pppoe_ports": getattr(router_obj, "pppoe_ports", None),
            "plain_ports": getattr(router_obj, "plain_ports", None),
            "dual_ports": getattr(router_obj, "dual_ports", None),
            "emergency_active": getattr(router_obj, "emergency_active", False),
            "emergency_message": getattr(router_obj, "emergency_message", None),
        }
        router_payload.update(build_router_status(router_obj, now=now))
        response.append(router_payload)
    return response


@router.get("/api/routers/{router_id}/uptime")
async def get_router_uptime(
    router_id: int,
    hours: int = 24,
    recent_checks: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get availability and uptime statistics for a router."""
    user = await get_current_user(token, db)
    stmt = select(Router).where(Router.id == router_id, Router.user_id == user.id)
    result = await db.execute(stmt)
    router_obj = result.scalar_one_or_none()

    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    hours = max(1, min(hours, 24 * 30))
    recent_checks = max(1, min(recent_checks, 200))
    now = datetime.utcnow()
    since = now - timedelta(hours=hours)

    window_stmt = select(
        func.count(RouterAvailabilityCheck.id),
        func.coalesce(
            func.sum(case((RouterAvailabilityCheck.is_online.is_(True), 1), else_=0)),
            0,
        ),
        func.min(RouterAvailabilityCheck.checked_at),
        func.max(RouterAvailabilityCheck.checked_at),
    ).where(
        RouterAvailabilityCheck.router_id == router_id,
        RouterAvailabilityCheck.checked_at >= since,
    )
    window_result = await db.execute(window_stmt)
    window_total, window_online, window_first, window_last = window_result.one()

    checks_stmt = (
        select(RouterAvailabilityCheck)
        .where(
            RouterAvailabilityCheck.router_id == router_id,
            RouterAvailabilityCheck.checked_at >= since,
        )
        .order_by(RouterAvailabilityCheck.checked_at.desc())
        .limit(recent_checks)
    )
    checks_result = await db.execute(checks_stmt)
    checks = checks_result.scalars().all()

    overall_total = int(router_obj.availability_checks or 0)
    overall_online = int(router_obj.availability_successes or 0)

    return {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "generated_at": now.isoformat(),
        "current_status": build_router_status(router_obj, now=now),
        "overall": {
            "total_checks": overall_total,
            "online_checks": overall_online,
            "uptime_percentage": round((overall_online / overall_total) * 100, 2) if overall_total else None,
        },
        "window": {
            "hours": hours,
            "from": since.isoformat(),
            "to": now.isoformat(),
            "first_check_at": window_first.isoformat() if window_first else None,
            "last_check_at": window_last.isoformat() if window_last else None,
            "total_checks": int(window_total or 0),
            "online_checks": int(window_online or 0),
            "uptime_percentage": round((window_online / window_total) * 100, 2) if window_total else None,
        },
        "recent_checks": [
            {
                "checked_at": check.checked_at.isoformat(),
                "is_online": check.is_online,
                "source": check.source,
            }
            for check in checks
        ],
    }


@router.post("/api/routers/create")
async def create_router_api(
    request: RouterCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Create a new router"""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        existing_router_stmt = select(Router).filter(
            Router.ip_address == request.ip_address,
            Router.user_id == user.id
        )
        existing_result = await db.execute(existing_router_stmt)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Router with this IP address already exists")
        
        
        router_obj = Router(
            user_id=user.id,
            name=request.name,
            identity=request.identity,
            ip_address=request.ip_address,
            username=request.username,
            password=request.password,
            port=request.port,
            payment_methods=request.payment_methods or ["mpesa", "voucher"],
        )
        
        db.add(router_obj)
        await db.commit()
        await db.refresh(router_obj)
        
        logger.info(f"Router created: {router_obj.id} by user {user.id}")
        
        return {
            "id": router_obj.id,
            "name": router_obj.name,
            "identity": router_obj.identity,
            "ip_address": router_obj.ip_address,
            "username": router_obj.username,
            "port": router_obj.port,
            "user_id": router_obj.user_id,
            "payment_methods": router_obj.payment_methods,
            "payment_method_id": router_obj.payment_method_id,
            "pppoe_ports": router_obj.pppoe_ports,
            "plain_ports": router_obj.plain_ports,
            "dual_ports": router_obj.dual_ports,
            "emergency_active": router_obj.emergency_active,
            "emergency_message": router_obj.emergency_message,
            "created_at": router_obj.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create router: {str(e)}")


@router.get("/api/routers/by-identity/{identity}")
async def get_router_by_identity(
    identity: str,
    db: AsyncSession = Depends(get_db)
):
    """Lookup router by MikroTik system identity (for frontend captive portal)"""
    stmt = (
        select(Router, User.business_name)
        .join(User, Router.user_id == User.id)
        .where(Router.identity == identity)
    )
    result = await db.execute(stmt)
    row = result.one_or_none()
    
    if not row:
        raise HTTPException(status_code=404, detail=f"Router with identity '{identity}' not found")
    
    router_obj, business_name = row
    await db.refresh(router_obj, ["assigned_payment_method"])
    pm = router_obj.assigned_payment_method
    return {
        "router_id": router_obj.id,
        "name": router_obj.name,
        "identity": router_obj.identity,
        "user_id": router_obj.user_id,
        "auth_method": getattr(router_obj, 'auth_method', 'DIRECT_API') or 'DIRECT_API',
        "business_name": business_name,
        "payment_methods": getattr(router_obj, 'payment_methods', None) or ["mpesa", "voucher"],
        "payment_method_id": router_obj.payment_method_id,
        "assigned_payment_method": {
            "id": pm.id,
            "label": pm.label,
            "method_type": pm.method_type.value if hasattr(pm.method_type, "value") else pm.method_type,
            "is_active": pm.is_active,
        } if pm else None,
        "pppoe_ports": getattr(router_obj, 'pppoe_ports', None),
        "plain_ports": getattr(router_obj, 'plain_ports', None),
        "dual_ports": getattr(router_obj, 'dual_ports', None),
        "emergency_active": getattr(router_obj, 'emergency_active', False),
        "emergency_message": getattr(router_obj, 'emergency_message', None),
    }


@router.put("/api/routers/{router_id}/identity")
async def update_router_identity(
    router_id: int,
    request: RouterIdentityUpdate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Update router's MikroTik system identity"""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    stmt = select(Router).where(Router.id == router_id, Router.user_id == user.id)
    result = await db.execute(stmt)
    router_obj = result.scalar_one_or_none()
    
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    
    existing_stmt = select(Router).where(Router.identity == request.identity, Router.id != router_id)
    existing_result = await db.execute(existing_stmt)
    if existing_result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Identity already assigned to another router")
    
    router_obj.identity = request.identity
    await db.commit()
    
    return {
        "id": router_obj.id,
        "name": router_obj.name,
        "identity": router_obj.identity,
        "message": "Identity updated successfully"
    }


@router.put("/api/routers/{router_id}")
async def update_router(
    router_id: int,
    request: RouterUpdateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Update router details"""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        stmt = select(Router).where(Router.id == router_id, Router.user_id == user.id)
        result = await db.execute(stmt)
        router_obj = result.scalar_one_or_none()
        
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")
        
        router_obj.name = request.name
        router_obj.ip_address = request.ip_address
        router_obj.port = request.port
        if request.username is not None:
            router_obj.username = request.username
        if request.password is not None:
            router_obj.password = request.password
        if request.payment_methods is not None:
            router_obj.payment_methods = request.payment_methods
        if request.emergency_active is not None:
            router_obj.emergency_active = request.emergency_active
            if not request.emergency_active:
                router_obj.emergency_message = None
        if request.emergency_message is not None:
            router_obj.emergency_message = request.emergency_message
        
        await db.commit()
        await db.refresh(router_obj)
        
        return {
            "id": router_obj.id,
            "name": router_obj.name,
            "ip_address": router_obj.ip_address,
            "username": router_obj.username,
            "port": router_obj.port,
            "user_id": router_obj.user_id,
            "payment_methods": router_obj.payment_methods,
            "payment_method_id": router_obj.payment_method_id,
            "pppoe_ports": router_obj.pppoe_ports,
            "plain_ports": router_obj.plain_ports,
            "dual_ports": router_obj.dual_ports,
            "emergency_active": router_obj.emergency_active,
            "emergency_message": router_obj.emergency_message,
            "updated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update router: {str(e)}")


@router.delete("/api/routers/{router_id}")
async def delete_router(
    router_id: int,
    force: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Delete a router.
    
    Args:
        router_id: ID of the router to delete
        force: If True, reassign customers to no router. If False, fail if customers exist.
    
    Returns:
        Success message with details
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        stmt = select(Router).where(Router.id == router_id, Router.user_id == user.id)
        result = await db.execute(stmt)
        router_obj = result.scalar_one_or_none()
        
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")
        
        router_name = router_obj.name
        router_ip = router_obj.ip_address
        
        customer_count_stmt = select(func.count(Customer.id)).where(Customer.router_id == router_id)
        customer_count_result = await db.execute(customer_count_stmt)
        customer_count = customer_count_result.scalar() or 0
        
        if customer_count > 0:
            if not force:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Router has {customer_count} customer(s) assigned. Use force=true to delete them from the router."
                )
            
            # Fetch active customers to clean them off MikroTik
            active_customers_stmt = select(Customer).where(
                Customer.router_id == router_id,
                Customer.status == CustomerStatus.ACTIVE
            )
            active_result = await db.execute(active_customers_stmt)
            active_customers = active_result.scalars().all()
            
            # Remove each active customer from MikroTik
            mikrotik_cleaned = 0
            if active_customers:
                from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address
                
                router_info = {
                    "ip": router_obj.ip_address,
                    "username": router_obj.username,
                    "password": router_obj.password,
                    "port": router_obj.port,
                    "name": router_obj.name
                }
                
                def _cleanup_router_users(r_info, customers_data):
                    api = MikroTikAPI(r_info["ip"], r_info["username"], r_info["password"], r_info["port"])
                    removed = 0
                    try:
                        if not api.connected:
                            return removed
                        for mac, username in customers_data:
                            try:
                                api.remove_hotspot_user(username)
                                api.remove_ip_binding(mac)
                                api.remove_simple_queue(mac)
                                removed += 1
                            except Exception as e:
                                logger.warning(f"Failed to clean up {mac} from router: {e}")
                    finally:
                        api.disconnect()
                    return removed
                
                customers_data = []
                for c in active_customers:
                    if c.mac_address:
                        normalized = normalize_mac_address(c.mac_address)
                        customers_data.append((normalized, normalized.replace(":", "")))
                
                try:
                    mikrotik_cleaned = await asyncio.to_thread(_cleanup_router_users, router_info, customers_data)
                    logger.info(f"Cleaned {mikrotik_cleaned} users from MikroTik router {router_name}")
                except Exception as e:
                    logger.warning(f"MikroTik cleanup failed for router {router_name}: {e}. Proceeding with DB cleanup.")
            
            # Set all customers on this router to INACTIVE and unassign
            update_customers_stmt = (
                update(Customer)
                .where(Customer.router_id == router_id)
                .values(router_id=None, status=CustomerStatus.INACTIVE)
            )
            await db.execute(update_customers_stmt)
            logger.info(f"Set {customer_count} customers from router {router_name} to INACTIVE")
        
        # Clean up related records that reference this router
        await db.execute(
            update(ProvisioningLog)
            .where(ProvisioningLog.router_id == router_id)
            .values(router_id=None)
        )
        await db.execute(
            update(BandwidthSnapshot)
            .where(BandwidthSnapshot.router_id == router_id)
            .values(router_id=None)
        )
        await db.execute(
            update(ProvisioningToken)
            .where(ProvisioningToken.router_id == router_id)
            .values(router_id=None)
        )
        await db.execute(
            update(Voucher)
            .where(Voucher.router_id == router_id)
            .values(router_id=None)
        )
        from sqlalchemy import delete as sql_delete
        await db.execute(
            sql_delete(RouterLogEntry)
            .where(RouterLogEntry.router_id == router_id)
        )
        
        await db.delete(router_obj)
        await db.commit()
        
        logger.info(f"Deleted router: {router_name} ({router_ip})")
        
        return {
            "success": True,
            "message": f"Router '{router_name}' deleted successfully",
            "router_id": router_id,
            "customers_deactivated": customer_count if force else 0,
            "mikrotik_cleaned": mikrotik_cleaned if force and customer_count > 0 else 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete router: {str(e)}")


# ---------------------------------------------------------------------------
# Captive-portal remediation
#
# Recovers an already-provisioned router from the hEX/v7 hotspot regression
# (commit cef0221, fixed in 1b94872): the .rsc generator was setting
# `html-directory=flash/hotspot` on every non-CHR/non-x86 board, which is
# wrong on RouterOS v7 RouterBOARDs (their filesystem is unified and the
# hotspot service reads from `hotspot/`, not `flash/hotspot/`). The result
# was clients never reaching our captive portal.
#
# This endpoint repairs a deployed router in-place over its existing API
# tunnel, without re-running provisioning. It is idempotent and safe to
# run on healthy routers as well.
# ---------------------------------------------------------------------------


class CaptivePortalRemediateRequest(BaseModel):
    profile_name: str = "hsprof1"
    hotspot_name: str = "hotspot1"
    target_html_directory: str = "hotspot"


@router.post("/api/routers/{router_id}/remediate-captive-portal")
async def remediate_captive_portal(
    router_id: int,
    request: Optional[CaptivePortalRemediateRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Repoint an already-provisioned router's hotspot profile back at the
    correct html-directory, repopulate the default HTML files, redownload
    our custom login.html, and bounce the hotspot interface.

    Use this when a router was provisioned by the buggy hEX/v7 .rsc and
    clients aren't being redirected to the captive portal. Caller must own
    the router. Returns a per-step report so you can see what changed.
    """
    from app.services.mikrotik_api import MikroTikAPI
    from app.config import settings

    req = request or CaptivePortalRemediateRequest()
    user = await get_current_user(token, db)
    enforce_active_subscription(user)

    stmt = select(Router).where(Router.id == router_id, Router.user_id == user.id)
    result = await db.execute(stmt)
    router_obj = result.scalar_one_or_none()
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    # Look up the original provisioning token so the router can /tool fetch
    # its login page from the same URL it used during initial provisioning.
    # The /login-page endpoint accepts PROVISIONED tokens for exactly this
    # remediation use-case.
    pt_stmt = (
        select(ProvisioningToken)
        .where(ProvisioningToken.router_id == router_id)
        .order_by(ProvisioningToken.created_at.desc())
    )
    pt_result = await db.execute(pt_stmt)
    pt = pt_result.scalars().first()
    if not pt:
        raise HTTPException(
            status_code=409,
            detail=(
                "No provisioning token is linked to this router, so we cannot "
                "build the login-page URL for /tool fetch. Re-link a token to "
                "the router or fall back to re-provisioning."
            ),
        )

    base_url = settings.PROVISION_BASE_URL.rstrip("/")
    login_page_url = f"{base_url}/api/provision/{pt.token}/login-page"
    target_dir = req.target_html_directory.rstrip("/")
    login_dst = f"{target_dir}/login.html"

    def _remediate_blocking() -> dict:
        """Synchronous remediation -- runs in a thread to keep the event loop free."""
        report: dict = {
            "router_id": router_id,
            "router_ip": router_obj.ip_address,
            "profile_name": req.profile_name,
            "hotspot_name": req.hotspot_name,
            "target_html_directory": target_dir,
            "steps": [],
        }

        def step(name: str, ok: bool, detail: object = None):
            report["steps"].append({"step": name, "ok": ok, "detail": detail})

        api = MikroTikAPI(
            host=router_obj.ip_address,
            username=router_obj.username,
            password=router_obj.password,
            port=router_obj.port or 8728,
            timeout=30,
        )

        if not api.connect():
            step("connect", False, api.last_connect_error or "connection failed")
            report["success"] = False
            return report
        step("connect", True, f"{router_obj.ip_address}:{router_obj.port or 8728}")

        try:
            # 1. Find the hotspot profile and its current html-directory.
            profiles = api.send_command("/ip/hotspot/profile/print")
            if profiles.get("error"):
                step("profile.print", False, profiles["error"])
                report["success"] = False
                return report

            profile = next(
                (p for p in profiles.get("data", []) if p.get("name") == req.profile_name),
                None,
            )
            if not profile:
                step("profile.find", False, f"profile '{req.profile_name}' not found")
                report["success"] = False
                return report

            previous_dir = profile.get("html-directory") or "(unset)"
            step("profile.find", True, {
                "id": profile.get(".id"),
                "previous_html_directory": previous_dir,
            })

            # 2. Update html-directory if needed.
            if previous_dir == target_dir:
                step("profile.set_html_directory", True, "already correct, skipped")
            else:
                update = api.send_command(
                    "/ip/hotspot/profile/set",
                    {"numbers": profile[".id"], "html-directory": target_dir},
                )
                if update.get("error"):
                    step("profile.set_html_directory", False, update["error"])
                    report["success"] = False
                    return report
                step("profile.set_html_directory", True, f"{previous_dir} -> {target_dir}")

            # 3. Reset (repopulate) the default HTML file set into the new directory.
            #    NOTE: positional profile name on RouterOS, NOT a `numbers=...` arg.
            reset = api.send_command(
                "/ip/hotspot/profile/reset-html-directory",
                {"numbers": profile[".id"]},
            )
            if reset.get("error"):
                # Non-fatal: some RouterOS builds reject this command. We can
                # still drop our login.html on top via /tool fetch below.
                step("profile.reset_html_directory", False, reset["error"])
            else:
                step("profile.reset_html_directory", True)

            # 4. Drive the router itself to /tool/fetch our custom login.html
            #    onto the correct path. send_command blocks until RouterOS
            #    returns !done, which on /tool/fetch is sent only after the
            #    HTTP transaction completes and the file has been written
            #    to disk via dst-path. The login-page URL is the same one
            #    the original .rsc used during provisioning, so it must
            #    already be reachable from the router.
            #
            #    NOTE: do NOT pass keep-result=yes here. With dst-path set
            #    that flag also embeds the fetched bytes in an !re field of
            #    the API response, and the API protocol parser then tries
            #    to UTF-8-decode the binary HTML payload, blowing up on
            #    any non-ASCII byte (e.g. 0x89). dst-path alone is enough
            #    to save the file -- the API response then only carries
            #    text status fields.
            fetch = api.send_command(
                "/tool/fetch",
                {
                    "url": login_page_url,
                    "dst-path": login_dst,
                    "mode": "https",
                },
            )
            if fetch.get("error"):
                step("tool.fetch_login_page", False, {
                    "error": fetch["error"],
                    "url": login_page_url,
                    "dst": login_dst,
                })
                report["success"] = False
                return report
            step("tool.fetch_login_page", True, {
                "url": login_page_url,
                "dst": login_dst,
            })

            # 5. Confirm login.html actually landed on disk (size > 0).
            #    /file/print is small enough on a freshly-provisioned router
            #    that listing-and-filtering is fine; we don't need to
            #    construct an API ?-query (which send_command does not
            #    natively support). Retry once with a short settle delay in
            #    case the FS write hasn't been observed yet on slower
            #    RouterBOARD flash.
            login_size = -1
            for attempt in range(2):
                if attempt:
                    time.sleep(1.0)
                files = api.send_command("/file/print").get("data") or []
                file_row = next(
                    (f for f in files if f.get("name") == login_dst),
                    None,
                )
                if file_row:
                    try:
                        login_size = int(file_row.get("size") or 0)
                    except (TypeError, ValueError):
                        login_size = 0
                    if login_size > 0:
                        break
            if login_size <= 0:
                step("file.verify_login_html", False, {
                    "path": login_dst,
                    "size": login_size,
                    "msg": "login.html missing or empty after fetch",
                })
                report["success"] = False
                return report
            step("file.verify_login_html", True, {"path": login_dst, "size": login_size})

            # 6. Bounce hotspot1 so RouterOS re-reads the profile's
            #    html-directory. We use /ip/hotspot/set disabled=yes|no
            #    rather than the /disable & /enable shortcuts because that
            #    is the pattern every other RouterOS interaction in this
            #    codebase uses (see ensure_hotspot_server_on_interface in
            #    app/services/mikrotik_api.py), and it's the form that has
            #    been tested across our deployed router fleet.
            hotspots = api.send_command("/ip/hotspot/print")
            hs = next(
                (h for h in (hotspots.get("data") or []) if h.get("name") == req.hotspot_name),
                None,
            )
            if not hs:
                step("hotspot.find", False, f"hotspot '{req.hotspot_name}' not found")
                report["success"] = False
                return report
            hs_id = hs.get(".id")

            disable = api.send_command(
                "/ip/hotspot/set",
                {"numbers": hs_id, "disabled": "yes"},
            )
            if disable.get("error"):
                step("hotspot.disable", False, disable["error"])
                # We still try to re-enable -- otherwise we leave the
                # customer's hotspot down on a partial failure.
            else:
                step("hotspot.disable", True)

            time.sleep(0.5)  # let RouterOS fully unbind before re-binding

            enable = api.send_command(
                "/ip/hotspot/set",
                {"numbers": hs_id, "disabled": "no"},
            )
            if enable.get("error"):
                step("hotspot.enable", False, enable["error"])
                report["success"] = False
                return report
            step("hotspot.enable", True)

            report["success"] = True
            return report

        finally:
            api.disconnect()

    try:
        report = await asyncio.to_thread(_remediate_blocking)
    except Exception as e:
        logger.error(
            f"Captive-portal remediation crashed for router_id={router_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"Remediation failed: {type(e).__name__}: {e}",
        )

    if not report.get("success"):
        # Surface the detailed step report to the caller so they can see
        # exactly which command on the router rejected the change.
        raise HTTPException(status_code=502, detail=report)

    logger.info(
        f"Captive-portal remediation succeeded for router_id={router_id} "
        f"({router_obj.ip_address}): html-directory now '{target_dir}'"
    )
    return report
