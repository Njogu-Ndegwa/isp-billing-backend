from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func, case
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, field_validator
from typing import Optional, List
from datetime import datetime, timedelta
import httpx

from app.config import settings
from app.db.database import get_db
from app.db.models import Router, Customer, CustomerStatus, ProvisioningLog, BandwidthSnapshot, User, UserRole, RouterAvailabilityCheck, ProvisioningToken, Voucher, RouterLogEntry
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.router_availability import build_router_status, record_router_availability
from app.services.provisioning import provision_base_url_for_vpn
from app.services.router_helpers import connect_to_router
from app.services.router_remote_access import (
    RouterRemoteAccessError,
    build_remote_access_targets,
    build_webfig_proxy_path,
    configure_router_remote_access_sync,
    create_webfig_proxy_session,
    default_remote_access_source_cidrs,
    get_webfig_proxy_session,
    normalize_remote_access_services,
    normalize_source_cidrs,
    refresh_webfig_proxy_session,
    revoke_webfig_proxy_sessions,
    webfig_access_cookie_name,
)
from app.services.insurance_wireguard import (
    InsuranceWireGuardError,
    backup_ips_from_manager_peers,
    build_plan,
    configure_router_backup_wireguard,
    derive_insurance_ip,
    list_insurance_peers,
    parse_routeros_major_version,
    read_routeros_version,
    register_insurance_peer,
    validate_insurance_settings,
    verify_insurance_router,
)
from app.services.insurance_l2tp import (
    build_l2tp_plan,
    configure_router_backup_l2tp,
    register_insurance_l2tp_peer,
    validate_insurance_l2tp_settings,
)
from app.services.insurance_tunnel_batch import (
    get_current_insurance_tunnel_batch,
    get_insurance_tunnel_batch,
    get_latest_insurance_tunnel_items_by_router,
    preview_insurance_tunnel_batch,
    start_insurance_tunnel_batch,
)
import logging
import asyncio
import time
import re
from urllib.parse import urlencode, urlsplit

logger = logging.getLogger(__name__)

router = APIRouter(tags=["routers"])


_WEBFIG_ROOT_ACCESS_COOKIE = "webfig_active_proxy"


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


class InsuranceWireGuardRequest(BaseModel):
    apply: bool = False
    force_rotate: bool = False
    backup_ip: Optional[str] = None

    @field_validator("backup_ip", mode="before")
    @classmethod
    def strip_backup_ip(cls, v):
        if isinstance(v, str):
            v = v.strip()
            return v if v else None
        return v


class InsuranceTunnelBatchRequest(BaseModel):
    apply: bool = False
    router_ids: Optional[List[int]] = None
    limit: Optional[int] = None
    max_concurrency: int = 2
    force_rotate: bool = False

    @field_validator("router_ids", mode="before")
    @classmethod
    def clean_router_ids(cls, v):
        if v is None:
            return None
        cleaned = [int(item) for item in v if item is not None]
        return cleaned or None

    @field_validator("limit", mode="before")
    @classmethod
    def clean_limit(cls, v):
        if v in (None, ""):
            return None
        value = int(v)
        return value if value > 0 else None


class RouterRemoteAccessRequest(BaseModel):
    enable: bool = True
    services: Optional[List[str]] = None
    source_cidrs: Optional[List[str]] = None

    @field_validator("services", "source_cidrs", mode="before")
    @classmethod
    def split_csv_values(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v


async def _latest_router_provisioning_token(db: AsyncSession, router_id: int) -> Optional[ProvisioningToken]:
    result = await db.execute(
        select(ProvisioningToken)
        .where(ProvisioningToken.router_id == router_id)
        .order_by(ProvisioningToken.created_at.desc())
    )
    return result.scalars().first()


async def _router_accessible_to_user(db: AsyncSession, router_id: int, user: User) -> Optional[Router]:
    stmt = select(Router).where(Router.id == router_id)
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(Router.user_id == user.id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


def _token_tunnel_type(token: Optional[ProvisioningToken]) -> Optional[str]:
    vpn_type = (getattr(token, "vpn_type", None) or "").lower()
    if vpn_type == "l2tp":
        return "l2tp"
    if vpn_type == "wireguard":
        return "wireguard"
    return None


def _planned_tunnel_type_from_token(token: Optional[ProvisioningToken]) -> str:
    return _token_tunnel_type(token) or "auto"


def _insurance_plan_for_tunnel(tunnel_type: str, router_ip: str, backup_ip: str) -> List[str]:
    if tunnel_type == "l2tp":
        return build_l2tp_plan(router_ip, backup_ip)
    if tunnel_type == "auto":
        return [
            f"Connect to router over current management IP {router_ip}",
            "Read RouterOS version live",
            "Use WireGuard insurance tunnel for RouterOS v7+",
            "Use L2TP/IPsec insurance tunnel for RouterOS v6",
            f"Map backup management IP to {backup_ip}",
            "Ask new server to verify ping and TCP 8728 over the backup tunnel",
        ]
    return build_plan(router_ip, backup_ip)


def _missing_insurance_settings_for_tunnel(tunnel_type: str) -> List[str]:
    if tunnel_type == "l2tp":
        return validate_insurance_l2tp_settings()
    if tunnel_type == "auto":
        return sorted(set(validate_insurance_settings("wireguard") + validate_insurance_l2tp_settings()))
    return validate_insurance_settings("wireguard")


def _inspect_routeros_version(router_obj: Router) -> dict:
    api = connect_to_router(router_obj, connect_timeout=5, timeout=20)
    if not api.connect():
        raise InsuranceWireGuardError(api.last_connect_error or "Failed to connect to router")
    try:
        version = read_routeros_version(api)
        major_version = parse_routeros_major_version(version)
        if major_version is None:
            raise InsuranceWireGuardError(f"Could not determine RouterOS major version from '{version}'")
        return {
            "version": version,
            "major_version": major_version,
            "tunnel_type": "wireguard" if major_version >= 7 else "l2tp",
        }
    finally:
        api.disconnect()


@router.post("/api/admin/insurance-tunnels/batch")
async def create_insurance_tunnel_batch(
    request: InsuranceTunnelBatchRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Preview or start a throttled background insurance-tunnel rollout.

    Empty body is a preview. Use {"apply": true} to start the background job.
    The job skips recently-offline routers and uses low-priority router I/O.
    """
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")

    await db.commit()

    if not request.apply:
        return await preview_insurance_tunnel_batch(
            router_ids=request.router_ids,
            limit=request.limit,
        )

    try:
        return await start_insurance_tunnel_batch(
            router_ids=request.router_ids,
            limit=request.limit,
            max_concurrency=request.max_concurrency,
            force_rotate=request.force_rotate,
        )
    except InsuranceWireGuardError as exc:
        detail = str(exc)
        status_code = 409 if "already running" in detail else 400
        raise HTTPException(status_code=status_code, detail=detail)


@router.get("/api/admin/insurance-tunnels/batch")
async def get_current_insurance_tunnel_batch_status(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")
    await db.commit()

    job = await get_current_insurance_tunnel_batch()
    if not job:
        return {"success": True, "job": None}
    return {"success": True, "job": job}


@router.get("/api/admin/insurance-tunnels/batch/{job_id}")
async def get_insurance_tunnel_batch_status(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")
    await db.commit()

    job = await get_insurance_tunnel_batch(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Insurance tunnel batch not found")
    return {"success": True, "job": job}


@router.get("/api/admin/routers/{router_id}/remote-access")
async def get_router_remote_access_options(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Return operator access targets for RouterOS GUI/terminal access.

    This does not contact the router. It only describes the management-VPN
    addresses an operator can use after the POST endpoint opens access.
    """
    user = await get_current_user(token, db)
    router_obj = await _router_accessible_to_user(db, router_id, user)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    try:
        source_cidrs = default_remote_access_source_cidrs()
        services = normalize_remote_access_services(None)
        targets = build_remote_access_targets(
            router_obj.ip_address,
            router_obj.username,
            source_cidrs,
            services,
        )
    except RouterRemoteAccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    await db.commit()
    return {
        "success": True,
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "management_ip": router_obj.ip_address,
        "access_path": "management_vpn",
        "default_source_cidrs": source_cidrs,
        "available_services": ["winbox", "ssh", "webfig"],
        "targets": targets,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.post("/api/admin/routers/{router_id}/remote-access")
async def configure_router_remote_access(
    router_id: int,
    request: RouterRemoteAccessRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Open or close just-in-time RouterOS operator access over the management VPN.

    The access itself is WinBox, SSH, or WebFig; the API is used only to change
    RouterOS service/firewall configuration. No DB transaction is held while the
    router is contacted.
    """
    user = await get_current_user(token, db)

    try:
        services = normalize_remote_access_services(request.services)
        source_cidrs = normalize_source_cidrs(request.source_cidrs)
    except RouterRemoteAccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    router_obj = await _router_accessible_to_user(db, router_id, user)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }

    # Release the DB connection before RouterOS network work.
    await db.commit()

    try:
        remote_result = await asyncio.to_thread(
            configure_router_remote_access_sync,
            router_info,
            services,
            request.enable,
            source_cidrs,
        )
    except RouterRemoteAccessError as exc:
        logger.exception(
            "Remote access configuration failed for router_id=%s name=%s ip=%s services=%s",
            router_obj.id,
            router_obj.name,
            router_obj.ip_address,
            services,
        )
        await record_router_availability(db, router_obj.id, True, "remote_access")
        raise HTTPException(status_code=502, detail=f"Router remote-access setup failed: {exc}")

    if remote_result.get("error") == "connection_failed":
        logger.warning(
            "Remote access connection failed for router_id=%s name=%s ip=%s reason=%s",
            router_obj.id,
            router_obj.name,
            router_obj.ip_address,
            remote_result.get("reason"),
        )
        await record_router_availability(db, router_obj.id, False, "remote_access")
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router '{router_obj.name}' "
                   f"({router_obj.ip_address}): {remote_result.get('reason') or 'unknown'}",
        )
    if remote_result.get("error"):
        raise HTTPException(status_code=500, detail=remote_result.get("reason") or remote_result["error"])

    await record_router_availability(db, router_obj.id, True, "remote_access")

    return {
        "success": True,
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "management_ip": router_obj.ip_address,
        "generated_at": datetime.utcnow().isoformat(),
        **remote_result,
    }


@router.post("/api/admin/routers/{router_id}/webfig/open")
async def open_router_webfig(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Enable WebFig from the management source and return a short-lived proxy URL.

    The returned URL is meant to be opened in a browser tab. It carries a
    temporary proxy token because a browser tab cannot attach the app's bearer
    token to WebFig asset/form requests.
    """
    user = await get_current_user(token, db)
    router_obj = await _router_accessible_to_user(db, router_id, user)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    source_cidrs = default_remote_access_source_cidrs()
    router_name = router_obj.name
    router_ip = router_obj.ip_address

    # Release the DB connection before RouterOS network work.
    await db.commit()

    try:
        remote_result = await asyncio.to_thread(
            configure_router_remote_access_sync,
            router_info,
            ["webfig"],
            True,
            source_cidrs,
        )
    except RouterRemoteAccessError as exc:
        logger.exception(
            "WebFig open failed while configuring RouterOS for router_id=%s name=%s ip=%s source_cidrs=%s",
            router_id,
            router_name,
            router_ip,
            source_cidrs,
        )
        await record_router_availability(db, router_id, True, "webfig_open")
        raise HTTPException(
            status_code=502,
            detail=f"RouterOS WebFig setup failed for '{router_name}' ({router_ip}): {exc}",
        )

    if remote_result.get("error") == "connection_failed":
        logger.warning(
            "WebFig open connection failed for router_id=%s name=%s ip=%s reason=%s",
            router_id,
            router_name,
            router_ip,
            remote_result.get("reason"),
        )
        await record_router_availability(db, router_id, False, "webfig_open")
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router '{router_name}' "
                   f"({router_ip}): {remote_result.get('reason') or 'unknown'}",
        )
    if remote_result.get("error"):
        raise HTTPException(status_code=500, detail=remote_result.get("reason") or remote_result["error"])

    await record_router_availability(db, router_id, True, "webfig_open")
    webfig_scheme, webfig_port = _webfig_endpoint_from_remote_result(remote_result)

    session = create_webfig_proxy_session(
        router_id=router_id,
        router_name=router_name,
        router_ip=router_ip,
        created_by_user_id=user.id,
        webfig_scheme=webfig_scheme,
        webfig_port=webfig_port,
    )
    proxy_path = build_webfig_proxy_path(router_id, session.token)
    return {
        "success": True,
        "router_id": router_id,
        "router_name": router_name,
        "management_ip": router_ip,
        "proxy_path": proxy_path,
        "expires_at": session.expires_at.isoformat(),
        "webfig_target": {
            "scheme": session.webfig_scheme,
            "port": session.webfig_port,
        },
        "message": "WebFig access opened. Use the proxy URL in a browser.",
        "remote_access": remote_result,
    }


@router.post("/api/admin/routers/{router_id}/webfig/close")
async def close_router_webfig(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Disable WebFig access and revoke active in-memory proxy sessions."""
    user = await get_current_user(token, db)
    router_obj = await _router_accessible_to_user(db, router_id, user)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    router_name = router_obj.name
    router_ip = router_obj.ip_address
    revoked_sessions = revoke_webfig_proxy_sessions(router_id)

    # Release the DB connection before RouterOS network work.
    await db.commit()

    try:
        remote_result = await asyncio.to_thread(
            configure_router_remote_access_sync,
            router_info,
            ["webfig"],
            False,
            default_remote_access_source_cidrs(),
        )
    except RouterRemoteAccessError as exc:
        logger.exception(
            "WebFig close failed while configuring RouterOS for router_id=%s name=%s ip=%s",
            router_id,
            router_name,
            router_ip,
        )
        await record_router_availability(db, router_id, True, "webfig_close")
        raise HTTPException(
            status_code=502,
            detail=f"RouterOS WebFig close failed for '{router_name}' ({router_ip}): {exc}",
        )

    if remote_result.get("error") == "connection_failed":
        logger.warning(
            "WebFig close connection failed for router_id=%s name=%s ip=%s reason=%s",
            router_id,
            router_name,
            router_ip,
            remote_result.get("reason"),
        )
        await record_router_availability(db, router_id, False, "webfig_close")
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router '{router_name}' "
                   f"({router_ip}): {remote_result.get('reason') or 'unknown'}",
        )
    if remote_result.get("error"):
        raise HTTPException(status_code=500, detail=remote_result.get("reason") or remote_result["error"])

    await record_router_availability(db, router_id, True, "webfig_close")
    return {
        "success": True,
        "router_id": router_id,
        "router_name": router_name,
        "revoked_sessions": revoked_sessions,
        "message": "WebFig access closed.",
        "remote_access": remote_result,
    }


@router.api_route(
    "/api/admin/routers/{router_id}/webfig",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@router.api_route(
    "/api/admin/routers/{router_id}/webfig/{proxy_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_router_webfig(
    router_id: int,
    request: Request,
    proxy_path: str = "",
):
    """Proxy a short-lived browser session to RouterOS WebFig over management VPN."""
    provided_token = (
        request.query_params.get("remote_access_token")
        or request.cookies.get(webfig_access_cookie_name(router_id))
    )
    session = get_webfig_proxy_session(router_id, provided_token)
    if not session:
        return _webfig_expired_response()

    return await _proxy_webfig_request(
        router_id,
        request,
        proxy_path,
        session,
        refresh_access_cookies=bool(request.query_params.get("remote_access_token")),
    )


@router.api_route(
    "/webfig",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@router.api_route(
    "/webfig/{proxy_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_router_webfig_root_escape(
    request: Request,
    proxy_path: str = "",
):
    """
    Catch RouterOS WebFig redirects/forms that escape to /webfig at our domain root.

    WebFig sometimes posts or redirects to an absolute /webfig/ path after login.
    The root-scoped fallback cookie is only issued after a valid proxy token has
    opened the short-lived session.
    """
    router_id, session = _webfig_session_from_root_cookie(request)
    if not session:
        return _webfig_expired_response()

    escaped_path = "webfig"
    if request.url.path.endswith("/") and not proxy_path:
        escaped_path += "/"
    if proxy_path:
        escaped_path += "/" + proxy_path.lstrip("/")

    return await _proxy_webfig_request(
        router_id,
        request,
        escaped_path,
        session,
        refresh_access_cookies=False,
    )


@router.api_route(
    "/jsproxy",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@router.api_route(
    "/jsproxy/{proxy_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_router_webfig_jsproxy_escape(
    request: Request,
    proxy_path: str = "",
):
    """
    Catch RouterOS WebFig login RPC calls that escape to /jsproxy at our domain root.

    RouterOS WebFig uses /jsproxy after the login page has loaded from /webfig.
    That endpoint is outside our normal /api/admin/routers/{id}/webfig proxy
    prefix, so it needs the same short-lived active-session fallback.
    """
    router_id, session = _webfig_session_from_root_cookie(request)
    if not session:
        return _webfig_expired_response()

    escaped_path = "jsproxy"
    if request.url.path.endswith("/") and not proxy_path:
        escaped_path += "/"
    if proxy_path:
        escaped_path += "/" + proxy_path.lstrip("/")

    return await _proxy_webfig_request(
        router_id,
        request,
        escaped_path,
        session,
        refresh_access_cookies=False,
    )


@router.get("/")
async def proxy_router_webfig_api_root_escape(request: Request):
    """
    Keep active WebFig sessions from falling through to the API root page.

    Browsers do not send URL fragments to the server, so a WebFig navigation to
    /#Interface arrives here as GET /. When no active WebFig session exists this
    preserves the historical API root response.
    """
    router_id, session = _webfig_session_from_root_cookie(request)
    if session:
        return Response(
            status_code=307,
            headers={"location": f"/api/admin/routers/{router_id}/webfig/"},
        )
    return {"message": "ISP Billing SaaS API", "version": "1.0.0", "updated": "2025-11-02-v2"}


async def _proxy_webfig_request(
    router_id: int,
    request: Request,
    proxy_path: str,
    session,
    refresh_access_cookies: bool,
) -> Response:
    """Proxy a request to RouterOS WebFig using an already validated session."""

    query = _forward_webfig_query(request)
    target_url = _build_webfig_upstream_url(session, proxy_path)
    if query:
        target_url = f"{target_url}?{query}"
    host_header = _webfig_upstream_host_header(session)
    request_body = await request.body()
    is_jsproxy = _is_webfig_jsproxy_path(proxy_path)

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=5.0,
                read=_webfig_proxy_read_timeout(proxy_path),
                write=10.0,
                pool=5.0,
            ),
            verify=False if session.webfig_scheme == "https" else True,
        ) as client:
            last_exc = None
            attempts = 2 if is_jsproxy else 1
            for attempt in range(attempts):
                try:
                    upstream = await client.request(
                        request.method,
                        target_url,
                        headers=_forward_webfig_headers(request, host_header),
                        content=request_body,
                    )
                    break
                except httpx.RequestError as exc:
                    last_exc = exc
                    if attempt + 1 < attempts:
                        logger.warning(
                            "WebFig proxy retrying router_id=%s name=%s target=%s after error=%s",
                            router_id,
                            session.router_name,
                            target_url,
                            repr(exc),
                        )
                        continue
                    raise last_exc
    except httpx.RequestError as exc:
        logger.warning(
            "WebFig proxy could not reach router_id=%s name=%s target=%s error=%r",
            router_id,
            session.router_name,
            target_url,
            exc,
        )
        if is_jsproxy:
            response = Response(
                content=b"",
                status_code=200,
                media_type="application/octet-stream",
                headers={"cache-control": "no-store"},
            )
            _set_webfig_access_cookies(response, router_id, session)
            return response
        return Response(
            content=f"Could not reach router WebFig over the management VPN: {exc}",
            status_code=502,
            media_type="text/plain",
        )

    response_headers = _copy_webfig_response_headers(upstream, router_id)
    content = upstream.content
    content_type = upstream.headers.get("content-type", "")
    if _should_rewrite_webfig_content(content_type):
        content = _rewrite_webfig_content(content, content_type, router_id)

    response = Response(
        content=content,
        status_code=upstream.status_code,
        headers=response_headers,
    )
    for cookie in upstream.headers.get_list("set-cookie"):
        response.headers.append("set-cookie", _rewrite_webfig_set_cookie(cookie, router_id))

    _set_webfig_access_cookies(response, router_id, session)
    return response


_WEBFIG_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_WEBFIG_DROP_RESPONSE_HEADERS = _WEBFIG_HOP_BY_HOP_HEADERS | {
    "content-encoding",
    "content-length",
    "set-cookie",
}


def _forward_webfig_query(request: Request) -> str:
    items = [
        (key, value)
        for key, value in request.query_params.multi_items()
        if key != "remote_access_token"
    ]
    return urlencode(items, doseq=True)


def _forward_webfig_headers(request: Request, host_header: str) -> dict[str, str]:
    headers = {}
    for key, value in request.headers.items():
        lower = key.lower()
        if lower in _WEBFIG_HOP_BY_HOP_HEADERS or lower in {"host", "authorization"}:
            continue
        if lower == "cookie":
            value = _strip_webfig_proxy_cookies(value)
            if not value:
                continue
        headers[key] = value
    headers["host"] = host_header
    return headers


def _webfig_endpoint_from_remote_result(remote_result: dict) -> tuple[str, int]:
    for service in remote_result.get("services") or []:
        if service.get("service") != "webfig":
            continue
        scheme = _normalize_webfig_proxy_scheme(
            service.get("scheme") or ("https" if service.get("routeros_service") == "www-ssl" else "http")
        )
        return scheme, _coerce_webfig_proxy_port(
            service.get("port"),
            443 if scheme == "https" else 80,
        )

    for target in remote_result.get("targets") or []:
        if target.get("service") != "webfig":
            continue
        parsed = urlsplit(str(target.get("url") or ""))
        scheme = _normalize_webfig_proxy_scheme(parsed.scheme)
        return scheme, _coerce_webfig_proxy_port(
            parsed.port or target.get("port"),
            443 if scheme == "https" else 80,
        )

    return "http", 80


def _build_webfig_upstream_url(session, proxy_path: str) -> str:
    scheme = _normalize_webfig_proxy_scheme(session.webfig_scheme)
    port = _coerce_webfig_proxy_port(session.webfig_port, 443 if scheme == "https" else 80)
    default_port = 443 if scheme == "https" else 80
    port_part = "" if port == default_port else f":{port}"
    return f"{scheme}://{session.router_ip}{port_part}/{proxy_path.lstrip('/')}"


def _webfig_proxy_read_timeout(proxy_path: str) -> float:
    configured = float(settings.ROUTER_WEBFIG_PROXY_TIMEOUT_SECONDS)
    if _is_webfig_jsproxy_path(proxy_path):
        return max(configured, 300.0)
    return configured


def _is_webfig_jsproxy_path(proxy_path: str) -> bool:
    return proxy_path.lstrip("/").split("/", 1)[0].lower() == "jsproxy"


def _webfig_upstream_host_header(session) -> str:
    scheme = _normalize_webfig_proxy_scheme(session.webfig_scheme)
    port = _coerce_webfig_proxy_port(session.webfig_port, 443 if scheme == "https" else 80)
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return session.router_ip
    return f"{session.router_ip}:{port}"


def _coerce_webfig_proxy_port(value, fallback: int) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return int(fallback)
    if port < 1 or port > 65535:
        return int(fallback)
    return port


def _normalize_webfig_proxy_scheme(value) -> str:
    scheme = str(value or "http").strip().lower()
    if scheme not in {"http", "https"}:
        return "http"
    return scheme


def _strip_webfig_proxy_cookies(cookie_header: str) -> str:
    cookies = []
    for part in cookie_header.split(";"):
        cookie = part.strip()
        cookie_name = cookie.split("=", 1)[0].strip().lower()
        if (
            not cookie
            or cookie_name.startswith("webfig_access_")
            or cookie_name == _WEBFIG_ROOT_ACCESS_COOKIE
        ):
            continue
        cookies.append(cookie)
    return "; ".join(cookies)


def _set_webfig_access_cookies(response: Response, router_id: int, session) -> None:
    refresh_webfig_proxy_session(session)
    max_age = max(1, int((session.expires_at - datetime.utcnow()).total_seconds()))
    response.set_cookie(
        webfig_access_cookie_name(router_id),
        session.token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        path=f"/api/admin/routers/{router_id}/webfig",
    )
    response.set_cookie(
        _WEBFIG_ROOT_ACCESS_COOKIE,
        f"{router_id}:{session.token}",
        max_age=max_age,
        httponly=True,
        samesite="lax",
        path="/",
    )


def _webfig_session_from_root_cookie(request: Request):
    raw = request.cookies.get(_WEBFIG_ROOT_ACCESS_COOKIE) or ""
    router_text, separator, token = raw.partition(":")
    if not separator or not router_text.isdigit() or not token:
        return None, None
    router_id = int(router_text)
    return router_id, get_webfig_proxy_session(router_id, token)


def _webfig_expired_response() -> Response:
    response = Response(
        content=(
            "<!doctype html><title>WebFig access expired</title>"
            "<h1>WebFig access expired</h1>"
            "<p>Close this tab and open WebFig again from the router dashboard.</p>"
        ),
        status_code=403,
        media_type="text/html",
    )
    response.delete_cookie(_WEBFIG_ROOT_ACCESS_COOKIE, path="/")
    return response


def _copy_webfig_response_headers(upstream: httpx.Response, router_id: int) -> dict[str, str]:
    headers = {}
    for key, value in upstream.headers.items():
        lower = key.lower()
        if lower in _WEBFIG_DROP_RESPONSE_HEADERS:
            continue
        if lower == "location":
            headers[key] = _rewrite_webfig_location(value, router_id)
            continue
        headers[key] = value
    return headers


def _rewrite_webfig_location(location: str, router_id: int) -> str:
    return _rewrite_webfig_url(location, router_id)


def _rewrite_webfig_url(url: str, router_id: int) -> str:
    prefix = f"/api/admin/routers/{router_id}/webfig"
    if not url:
        return prefix + "/"
    if url.startswith(prefix):
        return url
    parsed = urlsplit(url)
    if parsed.scheme in {"http", "https"}:
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        if path.startswith(prefix):
            return f"{path}{query}{fragment}"
        return f"{prefix}{path}{query}{fragment}"
    if url.startswith("/"):
        return prefix + url
    return url


def _rewrite_webfig_set_cookie(cookie: str, router_id: int) -> str:
    proxy_path = f"/api/admin/routers/{router_id}/webfig"
    parts = [part.strip() for part in cookie.split(";")]
    if not parts:
        return cookie

    rewritten = [parts[0]]
    path_seen = False
    for part in parts[1:]:
        lower = part.lower()
        if lower.startswith("domain="):
            continue
        if lower.startswith("path="):
            rewritten.append(f"Path={proxy_path}")
            path_seen = True
            continue
        rewritten.append(part)
    if not path_seen:
        rewritten.append(f"Path={proxy_path}")
    return "; ".join(rewritten)


def _should_rewrite_webfig_content(content_type: str) -> bool:
    content_type = (content_type or "").lower()
    return any(
        marker in content_type
        for marker in ("text/html", "text/css", "javascript", "application/json")
    )


def _rewrite_webfig_content(content: bytes, content_type: str, router_id: int) -> bytes:
    encoding = "utf-8"
    lower = (content_type or "").lower()
    if "charset=" in lower:
        encoding = lower.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"

    try:
        text = content.decode(encoding, errors="replace")
    except LookupError:
        encoding = "utf-8"
        text = content.decode(encoding, errors="replace")

    prefix = f"/api/admin/routers/{router_id}/webfig"

    def rewrite(url: str) -> str:
        rewritten = _rewrite_webfig_url(url, router_id)
        if rewritten.startswith(prefix):
            return rewritten
        return url

    quoted_attr = re.compile(
        r"(?i)(?P<lead>\b(?:href|src|action|data-url)\s*=\s*)"
        r"(?P<quote>[\"'])(?P<url>https?://[^\"']+|/[^\"']*)(?P=quote)"
    )
    text = quoted_attr.sub(
        lambda m: f"{m.group('lead')}{m.group('quote')}{rewrite(m.group('url'))}{m.group('quote')}",
        text,
    )

    unquoted_attr = re.compile(
        r"(?i)(?P<lead>\b(?:href|src|action|data-url)\s*=\s*)"
        r"(?P<url>https?://[^\s>\"']+|/[^\s>\"']+)"
    )
    text = unquoted_attr.sub(lambda m: f"{m.group('lead')}{rewrite(m.group('url'))}", text)

    css_url = re.compile(
        r"(?i)(?P<lead>\burl\(\s*)(?P<quote>[\"']?)"
        r"(?P<url>https?://[^)\"']+|/[^)\"']+)(?P=quote)(?P<trail>\s*\))"
    )
    text = css_url.sub(
        lambda m: (
            f"{m.group('lead')}{m.group('quote')}"
            f"{rewrite(m.group('url'))}{m.group('quote')}{m.group('trail')}"
        ),
        text,
    )

    # RouterOS WebFig can redirect after login through JavaScript or meta
    # refresh strings instead of HTTP Location headers.
    quoted_webfig_path = re.compile(
        r"(?P<quote>[\"'])(?P<url>https?://[^\"']+/webfig[^\"']*|/webfig[^\"']*)(?P=quote)",
        re.IGNORECASE,
    )
    text = quoted_webfig_path.sub(
        lambda m: f"{m.group('quote')}{rewrite(m.group('url'))}{m.group('quote')}",
        text,
    )

    meta_refresh_url = re.compile(
        r"(?i)(?P<lead>\burl\s*=\s*)(?P<url>https?://[^\s;\"'>]+|/(?:webfig[^\s;\"'>]*|[#?][^\s;\"'>]*)?)"
    )
    text = meta_refresh_url.sub(lambda m: f"{m.group('lead')}{rewrite(m.group('url'))}", text)

    root_json_redirect = re.compile(
        r"(?i)(?P<lead>[\"'](?:redirect|location|url|path|href)[\"']\s*:\s*)"
        r"(?P<quote>[\"'])(?P<url>/(?:[#?][^\"']*)?)(?P=quote)"
    )
    text = root_json_redirect.sub(
        lambda m: f"{m.group('lead')}{m.group('quote')}{rewrite(m.group('url'))}{m.group('quote')}",
        text,
    )

    root_js_redirect = re.compile(
        r"(?i)(?P<lead>\b(?:window\.|top\.)?location(?:\.href)?\s*=\s*)"
        r"(?P<quote>[\"'])(?P<url>/(?:[#?][^\"']*)?)(?P=quote)"
    )
    text = root_js_redirect.sub(
        lambda m: f"{m.group('lead')}{m.group('quote')}{rewrite(m.group('url'))}{m.group('quote')}",
        text,
    )

    root_location_methods = re.compile(
        r"(?i)(?P<lead>\b(?:window\.|top\.)?location\.(?:assign|replace)\(\s*)"
        r"(?P<quote>[\"'])(?P<url>/(?:[#?][^\"']*)?)(?P=quote)"
    )
    text = root_location_methods.sub(
        lambda m: f"{m.group('lead')}{m.group('quote')}{rewrite(m.group('url'))}{m.group('quote')}",
        text,
    )

    return text.encode(encoding, errors="replace")


@router.get("/api/routers")
async def get_routers(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get routers visible to the current user."""
    user = await get_current_user(token, db)
    is_admin = user.role == UserRole.ADMIN
    stmt = (
        select(Router)
        .options(selectinload(Router.assigned_payment_method))
        .order_by(Router.id)
    )
    if not is_admin:
        stmt = stmt.where(Router.user_id == user.id)
    result = await db.execute(stmt)
    routers = result.scalars().all()
    token_by_router = {}
    owner_by_id = {}
    if routers and is_admin:
        token_result = await db.execute(
            select(ProvisioningToken)
            .where(ProvisioningToken.router_id.in_([router_obj.id for router_obj in routers]))
            .order_by(ProvisioningToken.router_id, ProvisioningToken.created_at.desc())
        )
        for token_obj in token_result.scalars().all():
            token_by_router.setdefault(token_obj.router_id, token_obj)

        owner_ids = sorted({router_obj.user_id for router_obj in routers if router_obj.user_id})
        if owner_ids:
            owner_result = await db.execute(select(User).where(User.id.in_(owner_ids)))
            owner_by_id = {owner.id: owner for owner in owner_result.scalars().all()}

    latest_backup_by_router = (
        await get_latest_insurance_tunnel_items_by_router([router_obj.id for router_obj in routers])
        if is_admin and routers
        else {}
    )
    await db.commit()

    manager_backup_ips = set()
    manager_lookup_error = None
    if is_admin and routers:
        try:
            manager_backup_ips = backup_ips_from_manager_peers(await list_insurance_peers())
        except InsuranceWireGuardError as exc:
            manager_lookup_error = str(exc)
            logger.warning("Could not list insurance WireGuard peers for admin router visibility: %s", exc)
        except Exception as exc:  # noqa: BLE001 - visibility should degrade instead of failing the page
            manager_lookup_error = "Could not read insurance manager peer list"
            logger.exception("Could not list insurance WireGuard peers for admin router visibility: %s", exc)

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
            "hotspot_sharing_blocked": getattr(router_obj, "hotspot_sharing_blocked", False),
        }
        if is_admin:
            token_obj = token_by_router.get(router_obj.id)
            token_tunnel_type = _token_tunnel_type(token_obj)
            owner = owner_by_id.get(router_obj.user_id)
            try:
                backup_ip = derive_insurance_ip(router_obj.ip_address)
                backup_ip_error = None
            except InsuranceWireGuardError as exc:
                backup_ip = None
                backup_ip_error = str(exc)
            backup_item = latest_backup_by_router.get(router_obj.id) or {}
            batch_status = backup_item.get("status")
            backup_source = "batch" if batch_status else "manager"
            backup_error = backup_ip_error or backup_item.get("error")

            if backup_ip_error:
                backup_status = "invalid_ip"
                backup_source = "derived_ip"
            elif batch_status in {"verified", "partial"}:
                backup_status = batch_status
            elif backup_ip and backup_ip in manager_backup_ips:
                backup_status = "registered"
                backup_source = "manager"
                backup_error = None
            elif token_tunnel_type == "l2tp":
                backup_status = "unavailable"
                backup_source = "l2tp"
                backup_error = "L2TP backup status is only available after a batch verification result"
            elif batch_status:
                backup_status = batch_status
            elif manager_lookup_error:
                backup_status = "unavailable"
                backup_source = "manager"
                backup_error = manager_lookup_error
            else:
                backup_status = "missing"
                backup_source = "manager"
                backup_error = None

            router_payload.update({
                "token_vpn_type": token_tunnel_type,
                "planned_insurance_tunnel_type": _planned_tunnel_type_from_token(token_obj),
                "owner_user_id": router_obj.user_id,
                "owner_name": getattr(owner, "organization_name", None),
                "owner_role": owner.role.value if owner and hasattr(owner.role, "value") else (str(owner.role) if owner else None),
                "owner_subscription_status": (
                    owner.subscription_status.value
                    if owner and hasattr(owner.subscription_status, "value")
                    else (str(owner.subscription_status) if owner else None)
                ),
                "backup_ip": backup_ip,
                "backup_ip_error": backup_ip_error,
                "insurance_backup_status": backup_status,
                "insurance_backup_source": backup_source,
                "insurance_backup_active": backup_status in {"verified", "registered"},
                "insurance_backup_checked_at": (
                    backup_item.get("finished_at")
                    or backup_item.get("updated_at")
                    or backup_item.get("job_updated_at")
                ),
                "insurance_backup_error": backup_error,
                "insurance_backup_job_id": backup_item.get("job_id"),
                "insurance_backup_verification": backup_item.get("verification"),
            })
        router_payload.update(build_router_status(router_obj, now=now))
        response.append(router_payload)
    return response


@router.post("/api/admin/routers/{router_id}/insurance-tunnel")
@router.post("/api/admin/routers/{router_id}/insurance-wireguard")
async def configure_router_insurance_wireguard(
    router_id: int,
    request: InsuranceWireGuardRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Superadmin-only creation of a secondary management tunnel.

    Normal operations continue over the router's existing 10.0.0.0/16 tunnel.
    This endpoint connects through that current path and adds/repairs the
    correct insurance tunnel for the router's RouterOS version.
    """
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")

    result = await db.execute(select(Router).where(Router.id == router_id))
    router_obj = result.scalar_one_or_none()
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    token_obj = await _latest_router_provisioning_token(db, router_obj.id)
    token_tunnel_type = _token_tunnel_type(token_obj)

    try:
        backup_ip = request.backup_ip or derive_insurance_ip(router_obj.ip_address)
    except InsuranceWireGuardError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    dry_run_tunnel_type = token_tunnel_type or "auto"
    missing_settings = _missing_insurance_settings_for_tunnel(dry_run_tunnel_type)
    plan = _insurance_plan_for_tunnel(dry_run_tunnel_type, router_obj.ip_address, backup_ip)
    if not request.apply:
        return {
            "success": True,
            "applied": False,
            "router_id": router_obj.id,
            "router_name": router_obj.name,
            "current_ip": router_obj.ip_address,
            "backup_ip": backup_ip,
            "tunnel_type": dry_run_tunnel_type,
            "token_vpn_type": getattr(token_obj, "vpn_type", None),
            "missing_settings": missing_settings,
            "plan": plan,
        }

    # Release the DB connection before router/API network work. No database
    # writes happen in this endpoint after this point.
    await db.commit()

    try:
        inspection = await asyncio.to_thread(_inspect_routeros_version, router_obj)
    except InsuranceWireGuardError as exc:
        logger.error(
            "Insurance tunnel version inspection failed for router %s (%s): %s",
            router_obj.id,
            router_obj.ip_address,
            exc,
        )
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected insurance tunnel inspection error for router %s", router_obj.id)
        raise HTTPException(status_code=500, detail=str(exc))

    tunnel_type = inspection["tunnel_type"]
    missing_settings = _missing_insurance_settings_for_tunnel(tunnel_type)
    if missing_settings:
        raise HTTPException(
            status_code=500,
            detail=f"Missing insurance {tunnel_type} setting(s): {', '.join(missing_settings)}",
        )

    def _configure_wireguard_router():
        api = connect_to_router(router_obj, connect_timeout=5, timeout=20)
        if not api.connect():
            raise InsuranceWireGuardError(api.last_connect_error or "Failed to connect to router")
        try:
            return configure_router_backup_wireguard(
                api,
                backup_ip=backup_ip,
                force_rotate=request.force_rotate,
            )
        finally:
            api.disconnect()

    def _configure_l2tp_router(username: str, password: str):
        api = connect_to_router(router_obj, connect_timeout=5, timeout=20)
        if not api.connect():
            raise InsuranceWireGuardError(api.last_connect_error or "Failed to connect to router")
        try:
            return configure_router_backup_l2tp(
                api,
                backup_ip=backup_ip,
                username=username,
                password=password,
            )
        finally:
            api.disconnect()

    try:
        if tunnel_type == "l2tp":
            if not token_obj or not token_obj.l2tp_username or not token_obj.l2tp_password:
                raise InsuranceWireGuardError(
                    "RouterOS v6 insurance tunnel requires the linked L2TP provisioning token "
                    "so the backup server can reuse the router's L2TP credentials."
                )
            manager_result = await register_insurance_l2tp_peer(
                token_obj.l2tp_username,
                token_obj.l2tp_password,
                backup_ip,
            )
            router_config = await asyncio.to_thread(
                _configure_l2tp_router,
                token_obj.l2tp_username,
                token_obj.l2tp_password,
            )
        else:
            router_config = await asyncio.to_thread(_configure_wireguard_router)
            manager_result = await register_insurance_peer(
                router_config["router_public_key"],
                backup_ip,
            )
        verify_result = await verify_insurance_router(backup_ip, port=router_obj.port)
    except InsuranceWireGuardError as exc:
        logger.error(
            "Insurance tunnel setup failed for router %s (%s): %s",
            router_obj.id,
            router_obj.ip_address,
            exc,
        )
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected insurance tunnel setup error for router %s", router_obj.id)
        raise HTTPException(status_code=500, detail=str(exc))

    response = {
        "success": True,
        "applied": True,
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "current_ip": router_obj.ip_address,
        "backup_ip": backup_ip,
        "tunnel_type": tunnel_type,
        "token_vpn_type": getattr(token_obj, "vpn_type", None),
        "routeros_version": router_config.get("routeros_version") or inspection["version"],
        "router_actions": router_config["actions"],
        "manager": manager_result,
        "verification": verify_result,
    }
    if tunnel_type == "wireguard":
        response["router_public_key"] = router_config["router_public_key"]
    if tunnel_type == "l2tp":
        response["l2tp_username"] = router_config["l2tp_username"]
    return response


@router.get("/api/admin/routers/{router_id}/insurance-tunnel/status")
@router.get("/api/admin/routers/{router_id}/insurance-wireguard/status")
async def get_router_insurance_wireguard_status(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Read-only check that the new server can reach a router over its insurance tunnel."""
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")

    result = await db.execute(select(Router).where(Router.id == router_id))
    router_obj = result.scalar_one_or_none()
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    token_obj = await _latest_router_provisioning_token(db, router_obj.id)
    token_tunnel_type = _token_tunnel_type(token_obj)

    try:
        backup_ip = derive_insurance_ip(router_obj.ip_address)
    except InsuranceWireGuardError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    missing_settings = validate_insurance_settings("status")
    if missing_settings:
        return {
            "success": False,
            "active": False,
            "router_id": router_obj.id,
            "router_name": router_obj.name,
            "current_ip": router_obj.ip_address,
            "backup_ip": backup_ip,
            "tunnel_type": token_tunnel_type,
            "token_vpn_type": getattr(token_obj, "vpn_type", None),
            "missing_settings": missing_settings,
        }

    await db.commit()

    try:
        verification = await verify_insurance_router(backup_ip, port=router_obj.port)
    except InsuranceWireGuardError as exc:
        return {
            "success": False,
            "active": False,
            "router_id": router_obj.id,
            "router_name": router_obj.name,
            "current_ip": router_obj.ip_address,
            "backup_ip": backup_ip,
            "tunnel_type": token_tunnel_type,
            "token_vpn_type": getattr(token_obj, "vpn_type", None),
            "error": str(exc),
        }

    active = bool(verification.get("ping_success") and verification.get("tcp_success"))
    return {
        "success": True,
        "active": active,
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "current_ip": router_obj.ip_address,
        "backup_ip": backup_ip,
        "tunnel_type": token_tunnel_type,
        "token_vpn_type": getattr(token_obj, "vpn_type", None),
        "verification": verification,
    }


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
            "hotspot_sharing_blocked": getattr(router_obj, "hotspot_sharing_blocked", False),
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
                    await db.commit()
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
        # RouterAvailabilityCheck FK is RESTRICT (not CASCADE) — must delete explicitly
        await db.execute(
            sql_delete(RouterAvailabilityCheck)
            .where(RouterAvailabilityCheck.router_id == router_id)
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

    base_url = provision_base_url_for_vpn(pt.vpn_type)
    login_page_url = f"{base_url}/api/provision/{pt.token}/login-page"
    fetch_mode = urlsplit(login_page_url).scheme.lower() or "http"
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
            fetch_params = {
                "url": login_page_url,
                "dst-path": login_dst,
                "mode": fetch_mode,
            }
            if pt.vpn_type == "l2tp" and fetch_mode == "https":
                fetch_params["check-certificate"] = "no"
            fetch = api.send_command("/tool/fetch", fetch_params)
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
        await db.commit()
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


# ---------------------------------------------------------------------------
# Anti-tethering (block hotspot sharing via TTL firewall rules)
# ---------------------------------------------------------------------------

class AntiTetherRequest(BaseModel):
    router_id: int


@router.post("/api/routers/anti-tethering/enable")
async def enable_anti_tethering(
    request: AntiTetherRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Enable anti-tethering on a router: persist the flag and push TTL
    drop rules to MikroTik so tethered devices cannot reach the internet."""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        router_obj = await _get_owned_router(db, request.router_id, user.id)

        was_already_enabled = getattr(router_obj, "hotspot_sharing_blocked", False)

        from app.services.mikrotik_api import MikroTikAPI

        host, usr, pwd, port = (
            router_obj.ip_address,
            router_obj.username,
            router_obj.password,
            router_obj.port,
        )

        def _push_rules():
            api = MikroTikAPI(host, usr, pwd, port)
            if not api.connect():
                return {"error": api.last_connect_error or "Failed to connect to router"}
            try:
                return api.enable_anti_tethering()
            finally:
                api.disconnect()

        await db.commit()
        result = await asyncio.get_event_loop().run_in_executor(None, _push_rules)
        if result.get("error"):
            raise HTTPException(status_code=502, detail=result["error"])

        router_obj.hotspot_sharing_blocked = True
        await db.commit()

        logger.info(f"Anti-tethering enabled on router {router_obj.id} by user {user.id}")
        return {
            "success": True,
            "router_id": router_obj.id,
            "hotspot_sharing_blocked": True,
            "message": (
                "Anti-tethering rules repaired - hotspot sharing remains blocked"
                if was_already_enabled
                else "Anti-tethering enabled - hotspot sharing is now blocked"
            ),
            "mikrotik": result,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error enabling anti-tethering: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to enable anti-tethering: {e}")


@router.post("/api/routers/anti-tethering/disable")
async def disable_anti_tethering(
    request: AntiTetherRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Disable anti-tethering on a router: remove the TTL drop rules from
    MikroTik and clear the flag in the database."""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        router_obj = await _get_owned_router(db, request.router_id, user.id)

        was_already_disabled = not getattr(router_obj, "hotspot_sharing_blocked", False)

        from app.services.mikrotik_api import MikroTikAPI

        host, usr, pwd, port = (
            router_obj.ip_address,
            router_obj.username,
            router_obj.password,
            router_obj.port,
        )

        def _remove_rules():
            api = MikroTikAPI(host, usr, pwd, port)
            if not api.connect():
                return {"error": api.last_connect_error or "Failed to connect to router"}
            try:
                return api.disable_anti_tethering()
            finally:
                api.disconnect()

        await db.commit()
        result = await asyncio.get_event_loop().run_in_executor(None, _remove_rules)
        if result.get("error"):
            raise HTTPException(status_code=502, detail=result["error"])

        router_obj.hotspot_sharing_blocked = False
        await db.commit()

        logger.info(f"Anti-tethering disabled on router {router_obj.id} by user {user.id}")
        return {
            "success": True,
            "router_id": router_obj.id,
            "hotspot_sharing_blocked": False,
            "message": (
                "Anti-tethering rules cleared - hotspot sharing was already allowed"
                if was_already_disabled
                else "Anti-tethering disabled - hotspot sharing is now allowed"
            ),
            "mikrotik": result,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error disabling anti-tethering: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to disable anti-tethering: {e}")


async def _get_owned_router(db: AsyncSession, router_id: int, user_id: int) -> Router:
    stmt = select(Router).where(Router.id == router_id, Router.user_id == user_id)
    result = await db.execute(stmt)
    router_obj = result.scalar_one_or_none()
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or does not belong to you")
    return router_obj
