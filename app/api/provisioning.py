from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, field_validator
from typing import Optional, List
import logging

from app.db.database import get_db
from app.db.models import ProvisioningToken, ProvisioningTokenStatus
from app.services.auth import verify_token, get_current_user
from app.services.provisioning import (
    create_provisioning_token,
    build_provision_command,
    generate_rsc_script,
    get_login_page_html,
    complete_provisioning,
    is_token_expired,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["provisioning"])


class ProvisionCreateRequest(BaseModel):
    router_name: str
    identity: str
    ssid: str = "Bitwave WiFi"
    router_admin_password: str = "admin"
    payment_methods: Optional[List[str]] = None

    @field_validator("router_name", "identity", "ssid", mode="before")
    @classmethod
    def strip_whitespace(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if not v:
                raise ValueError("Field cannot be empty")
            return v
        return v


# ── Authenticated endpoints ──────────────────────────────────────────────


@router.post("/api/provision/create")
async def create_provision_token(
    request: ProvisionCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Generate a provisioning token for a new MikroTik router.
    Returns the one-liner command to paste on a factory-reset router.
    """
    user = await get_current_user(token, db)
    try:
        token_obj = await create_provisioning_token(
            db=db,
            user_id=user.id,
            router_name=request.router_name,
            identity=request.identity,
            ssid=request.ssid,
            router_admin_password=request.router_admin_password,
            payment_methods=request.payment_methods,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Provisioning token creation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create provisioning token: {e}",
        )

    command = build_provision_command(token_obj)

    return {
        "token": token_obj.token,
        "identity": token_obj.identity,
        "wireguard_ip": token_obj.wireguard_ip,
        "ssid": token_obj.ssid,
        "command": command,
        "note": (
            "IMPORTANT: Before running this command on the MikroTik, ensure "
            "device-mode hotspot is enabled. Run: "
            "/system/device-mode/update hotspot=yes  "
            "then tap the physical reset button on the router (quick tap, do NOT hold)."
        ),
        "created_at": token_obj.created_at.isoformat(),
        "expires_in_hours": 24,
    }


@router.get("/api/provision/tokens")
async def list_provision_tokens(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List all provisioning tokens for the current user."""
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ProvisioningToken)
        .where(ProvisioningToken.user_id == user.id)
        .order_by(ProvisioningToken.created_at.desc())
    )
    tokens = result.scalars().all()

    return [
        {
            "id": t.id,
            "token": t.token,
            "router_name": t.router_name,
            "identity": t.identity,
            "wireguard_ip": t.wireguard_ip,
            "ssid": t.ssid,
            "status": t.status.value if hasattr(t.status, "value") else t.status,
            "expired": is_token_expired(t) and t.status == ProvisioningTokenStatus.PENDING,
            "command": build_provision_command(t) if t.status == ProvisioningTokenStatus.PENDING and not is_token_expired(t) else None,
            "created_at": t.created_at.isoformat(),
            "provisioned_at": t.provisioned_at.isoformat() if t.provisioned_at else None,
            "router_id": t.router_id,
        }
        for t in tokens
    ]


# ── Public endpoints (called by the MikroTik during provisioning) ────────


@router.get("/api/provision/{provision_token}", response_class=PlainTextResponse)
async def serve_provision_script(
    provision_token: str,
    db: AsyncSession = Depends(get_db),
):
    """Serve the generated .rsc provisioning script. Called by /tool fetch on the router."""
    token_obj = await _get_valid_token(db, provision_token)
    script = generate_rsc_script(token_obj)
    return PlainTextResponse(content=script, media_type="text/plain")


@router.get("/api/provision/{provision_token}/login-page", response_class=HTMLResponse)
async def serve_login_page(
    provision_token: str,
    db: AsyncSession = Depends(get_db),
):
    """Serve the captive portal login.html. Called by /tool fetch inside the .rsc script."""
    await _get_valid_token(db, provision_token)
    try:
        html = get_login_page_html()
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail="captive-portal-login.html not found on server",
        )
    return HTMLResponse(content=html)


@router.post("/api/provision/{provision_token}/complete")
async def complete_provision(
    provision_token: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Callback from the .rsc script after all steps succeed.
    Creates the Router record in the database.
    """
    result = await db.execute(
        select(ProvisioningToken).where(
            ProvisioningToken.token == provision_token
        )
    )
    token_obj = result.scalar_one_or_none()

    if not token_obj:
        raise HTTPException(status_code=404, detail="Provisioning token not found")

    if token_obj.status == ProvisioningTokenStatus.PROVISIONED:
        return {
            "status": "already_provisioned",
            "router_id": token_obj.router_id,
            "message": "This router was already provisioned",
        }

    if is_token_expired(token_obj):
        raise HTTPException(status_code=410, detail="Provisioning token has expired")

    try:
        router_obj = await complete_provisioning(db, token_obj)
    except Exception as e:
        logger.error(f"Provisioning completion failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to register router: {e}",
        )

    return {
        "status": "provisioned",
        "router_id": router_obj.id,
        "identity": router_obj.identity,
        "wireguard_ip": router_obj.ip_address,
        "message": f"Router '{router_obj.name}' registered successfully",
    }


async def _get_valid_token(
    db: AsyncSession, provision_token: str
) -> ProvisioningToken:
    """Look up a token and validate it hasn't expired or been used."""
    result = await db.execute(
        select(ProvisioningToken).where(
            ProvisioningToken.token == provision_token
        )
    )
    token_obj = result.scalar_one_or_none()

    if not token_obj:
        raise HTTPException(status_code=404, detail="Provisioning token not found")

    if token_obj.status == ProvisioningTokenStatus.PROVISIONED:
        raise HTTPException(status_code=410, detail="Token already used")

    if is_token_expired(token_obj):
        raise HTTPException(status_code=410, detail="Provisioning token has expired")

    return token_obj
