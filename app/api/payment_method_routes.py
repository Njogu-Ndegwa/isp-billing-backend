"""
CRUD endpoints for reseller payment methods.

Resellers configure payment methods here, then assign them to individual routers
via the router management endpoints.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    Router,
)
from app.services.auth import verify_token, get_current_user
from app.services.payment_gateway import (
    decrypt_credential,
    encrypt_credential,
    get_reseller_payment_methods,
    mask_credential,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["payment-methods"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class PaymentMethodCreate(BaseModel):
    method_type: str = Field(..., description="bank_account | mpesa_paybill | mpesa_paybill_with_keys | zenopay")
    label: str = Field(..., max_length=100, description="Display name for this method")

    # Bank Account
    bank_paybill_number: Optional[str] = None
    bank_account_number: Optional[str] = None

    # M-Pesa Paybill (no keys)
    mpesa_paybill_number: Optional[str] = None

    # M-Pesa Paybill/Till (with keys)
    mpesa_shortcode: Optional[str] = None
    mpesa_passkey: Optional[str] = None
    mpesa_consumer_key: Optional[str] = None
    mpesa_consumer_secret: Optional[str] = None

    # ZenoPay
    zenopay_api_key: Optional[str] = None
    zenopay_account_id: Optional[str] = None


class PaymentMethodUpdate(BaseModel):
    label: Optional[str] = None
    is_active: Optional[bool] = None

    bank_paybill_number: Optional[str] = None
    bank_account_number: Optional[str] = None
    mpesa_paybill_number: Optional[str] = None
    mpesa_shortcode: Optional[str] = None
    mpesa_passkey: Optional[str] = None
    mpesa_consumer_key: Optional[str] = None
    mpesa_consumer_secret: Optional[str] = None
    zenopay_api_key: Optional[str] = None
    zenopay_account_id: Optional[str] = None


class AssignPaymentMethodRequest(BaseModel):
    payment_method_id: Optional[int] = Field(
        None, description="Payment method ID to assign. Pass null to revert to legacy."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_fields(method_type: ResellerPaymentMethodType, data: PaymentMethodCreate):
    if method_type == ResellerPaymentMethodType.BANK_ACCOUNT:
        if not data.bank_paybill_number or not data.bank_account_number:
            raise HTTPException(
                status_code=400,
                detail="bank_paybill_number and bank_account_number are required for Bank Account",
            )

    elif method_type == ResellerPaymentMethodType.MPESA_PAYBILL:
        if not data.mpesa_paybill_number:
            raise HTTPException(
                status_code=400,
                detail="mpesa_paybill_number is required for M-Pesa Paybill (no keys)",
            )

    elif method_type == ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS:
        missing = []
        if not data.mpesa_shortcode:
            missing.append("mpesa_shortcode")
        if not data.mpesa_passkey:
            missing.append("mpesa_passkey")
        if not data.mpesa_consumer_key:
            missing.append("mpesa_consumer_key")
        if not data.mpesa_consumer_secret:
            missing.append("mpesa_consumer_secret")
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required fields for M-Pesa with keys: {', '.join(missing)}",
            )

    elif method_type == ResellerPaymentMethodType.ZENOPAY:
        if not data.zenopay_api_key:
            raise HTTPException(
                status_code=400,
                detail="zenopay_api_key is required for ZenoPay",
            )


def _serialize_payment_method(pm: ResellerPaymentMethod) -> dict:
    method_type = pm.method_type
    if isinstance(method_type, str):
        method_type_value = method_type
    else:
        method_type_value = method_type.value

    result = {
        "id": pm.id,
        "user_id": pm.user_id,
        "method_type": method_type_value,
        "label": pm.label,
        "is_active": pm.is_active,
        "created_at": pm.created_at.isoformat() if pm.created_at else None,
        "updated_at": pm.updated_at.isoformat() if pm.updated_at else None,
    }

    if method_type_value == ResellerPaymentMethodType.BANK_ACCOUNT.value:
        result["bank_paybill_number"] = pm.bank_paybill_number
        result["bank_account_number"] = pm.bank_account_number

    elif method_type_value == ResellerPaymentMethodType.MPESA_PAYBILL.value:
        result["mpesa_paybill_number"] = pm.mpesa_paybill_number

    elif method_type_value == ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS.value:
        result["mpesa_shortcode"] = pm.mpesa_shortcode
        result["mpesa_passkey"] = mask_credential(
            decrypt_credential(pm.mpesa_passkey_encrypted)
            if pm.mpesa_passkey_encrypted else None
        )
        result["mpesa_consumer_key"] = mask_credential(
            decrypt_credential(pm.mpesa_consumer_key_encrypted)
            if pm.mpesa_consumer_key_encrypted else None
        )
        result["mpesa_consumer_secret"] = mask_credential(
            decrypt_credential(pm.mpesa_consumer_secret_encrypted)
            if pm.mpesa_consumer_secret_encrypted else None
        )

    elif method_type_value == ResellerPaymentMethodType.ZENOPAY.value:
        result["zenopay_api_key"] = mask_credential(
            decrypt_credential(pm.zenopay_api_key_encrypted)
            if pm.zenopay_api_key_encrypted else None
        )
        result["zenopay_account_id"] = pm.zenopay_account_id

    return result


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/payment-methods")
async def create_payment_method(
    request: PaymentMethodCreate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Create a new payment method for the current reseller."""
    user = await get_current_user(token, db)

    try:
        method_type = ResellerPaymentMethodType(request.method_type)
    except ValueError:
        valid = [t.value for t in ResellerPaymentMethodType]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid method_type. Must be one of: {', '.join(valid)}",
        )

    _validate_fields(method_type, request)

    pm = ResellerPaymentMethod(
        user_id=user.id,
        method_type=method_type,
        label=request.label,
        is_active=True,
        bank_paybill_number=request.bank_paybill_number,
        bank_account_number=request.bank_account_number,
        mpesa_paybill_number=request.mpesa_paybill_number,
        mpesa_shortcode=request.mpesa_shortcode,
        mpesa_passkey_encrypted=(
            encrypt_credential(request.mpesa_passkey) if request.mpesa_passkey else None
        ),
        mpesa_consumer_key_encrypted=(
            encrypt_credential(request.mpesa_consumer_key) if request.mpesa_consumer_key else None
        ),
        mpesa_consumer_secret_encrypted=(
            encrypt_credential(request.mpesa_consumer_secret) if request.mpesa_consumer_secret else None
        ),
        zenopay_api_key_encrypted=(
            encrypt_credential(request.zenopay_api_key) if request.zenopay_api_key else None
        ),
        zenopay_account_id=request.zenopay_account_id,
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)

    logger.info(
        "Payment method created: id=%s, type=%s, user=%s",
        pm.id, method_type.value, user.id,
    )

    return _serialize_payment_method(pm)


@router.get("/api/payment-methods")
async def list_payment_methods(
    include_inactive: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List all payment methods for the current reseller."""
    user = await get_current_user(token, db)
    methods = await get_reseller_payment_methods(
        db, user.id, active_only=not include_inactive
    )
    return [_serialize_payment_method(pm) for pm in methods]


@router.get("/api/payment-methods/{method_id}")
async def get_payment_method(
    method_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get a single payment method (secrets masked)."""
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ResellerPaymentMethod).where(
            ResellerPaymentMethod.id == method_id,
            ResellerPaymentMethod.user_id == user.id,
        )
    )
    pm = result.scalar_one_or_none()
    if not pm:
        raise HTTPException(status_code=404, detail="Payment method not found")
    return _serialize_payment_method(pm)


@router.put("/api/payment-methods/{method_id}")
async def update_payment_method(
    method_id: int,
    request: PaymentMethodUpdate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Update an existing payment method."""
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ResellerPaymentMethod).where(
            ResellerPaymentMethod.id == method_id,
            ResellerPaymentMethod.user_id == user.id,
        )
    )
    pm = result.scalar_one_or_none()
    if not pm:
        raise HTTPException(status_code=404, detail="Payment method not found")

    if request.label is not None:
        pm.label = request.label
    if request.is_active is not None:
        pm.is_active = request.is_active

    # Update plain-text fields
    if request.bank_paybill_number is not None:
        pm.bank_paybill_number = request.bank_paybill_number
    if request.bank_account_number is not None:
        pm.bank_account_number = request.bank_account_number
    if request.mpesa_paybill_number is not None:
        pm.mpesa_paybill_number = request.mpesa_paybill_number
    if request.mpesa_shortcode is not None:
        pm.mpesa_shortcode = request.mpesa_shortcode

    # Update encrypted fields (only if a new value is provided)
    if request.mpesa_passkey is not None:
        pm.mpesa_passkey_encrypted = encrypt_credential(request.mpesa_passkey)
    if request.mpesa_consumer_key is not None:
        pm.mpesa_consumer_key_encrypted = encrypt_credential(request.mpesa_consumer_key)
    if request.mpesa_consumer_secret is not None:
        pm.mpesa_consumer_secret_encrypted = encrypt_credential(request.mpesa_consumer_secret)
    if request.zenopay_api_key is not None:
        pm.zenopay_api_key_encrypted = encrypt_credential(request.zenopay_api_key)
    if request.zenopay_account_id is not None:
        pm.zenopay_account_id = request.zenopay_account_id

    await db.commit()
    await db.refresh(pm)

    logger.info("Payment method updated: id=%s, user=%s", pm.id, user.id)
    return _serialize_payment_method(pm)


@router.delete("/api/payment-methods/{method_id}")
async def delete_payment_method(
    method_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Deactivate a payment method. Routers using it will fall back to legacy behavior.
    """
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ResellerPaymentMethod).where(
            ResellerPaymentMethod.id == method_id,
            ResellerPaymentMethod.user_id == user.id,
        )
    )
    pm = result.scalar_one_or_none()
    if not pm:
        raise HTTPException(status_code=404, detail="Payment method not found")

    pm.is_active = False

    # Unassign from any routers using this method
    await db.execute(
        update(Router)
        .where(Router.payment_method_id == method_id)
        .values(payment_method_id=None)
    )

    await db.commit()

    logger.info("Payment method deactivated: id=%s, user=%s", pm.id, user.id)
    return {"message": "Payment method deactivated", "id": pm.id}


@router.post("/api/payment-methods/{method_id}/test")
async def test_payment_method(
    method_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Validate that stored credentials work.
    For M-Pesa: tries to fetch an OAuth access token.
    For ZenoPay: tries to call the order-status endpoint.
    """
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ResellerPaymentMethod).where(
            ResellerPaymentMethod.id == method_id,
            ResellerPaymentMethod.user_id == user.id,
        )
    )
    pm = result.scalar_one_or_none()
    if not pm:
        raise HTTPException(status_code=404, detail="Payment method not found")

    method_type = pm.method_type
    if isinstance(method_type, str):
        method_type = ResellerPaymentMethodType(method_type)

    if method_type == ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS:
        from app.services.mpesa import get_access_token

        try:
            consumer_key = decrypt_credential(pm.mpesa_consumer_key_encrypted)
            consumer_secret = decrypt_credential(pm.mpesa_consumer_secret_encrypted)
            await get_access_token(
                consumer_key=consumer_key,
                consumer_secret=consumer_secret,
            )
            return {"status": "success", "message": "M-Pesa credentials are valid"}
        except Exception as e:
            return {"status": "failed", "message": f"M-Pesa credential test failed: {str(e)}"}

    elif method_type == ResellerPaymentMethodType.ZENOPAY:
        from app.services.zenopay import check_zenopay_order_status

        try:
            api_key = decrypt_credential(pm.zenopay_api_key_encrypted)
            await check_zenopay_order_status(api_key, "test-nonexistent-order")
            return {"status": "success", "message": "ZenoPay API key is valid"}
        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg or "Unauthorized" in error_msg:
                return {"status": "failed", "message": "ZenoPay API key is invalid"}
            return {"status": "success", "message": "ZenoPay API key accepted (order not found is expected)"}

    elif method_type in (
        ResellerPaymentMethodType.MPESA_PAYBILL,
        ResellerPaymentMethodType.BANK_ACCOUNT,
    ):
        return {
            "status": "success",
            "message": "No credentials to test for this method type. Configuration saved.",
        }

    return {"status": "skipped", "message": "No test available for this method type"}


# ---------------------------------------------------------------------------
# Router assignment
# ---------------------------------------------------------------------------

@router.put("/api/routers/{router_id}/payment-method")
async def assign_payment_method_to_router(
    router_id: int,
    request: AssignPaymentMethodRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Assign a payment method to a specific router.
    Pass payment_method_id=null to revert to legacy (system default) behavior.
    """
    user = await get_current_user(token, db)

    result = await db.execute(
        select(Router).where(Router.id == router_id, Router.user_id == user.id)
    )
    router_obj = result.scalar_one_or_none()
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    if request.payment_method_id is not None:
        pm_result = await db.execute(
            select(ResellerPaymentMethod).where(
                ResellerPaymentMethod.id == request.payment_method_id,
                ResellerPaymentMethod.user_id == user.id,
                ResellerPaymentMethod.is_active == True,
            )
        )
        pm = pm_result.scalar_one_or_none()
        if not pm:
            raise HTTPException(
                status_code=404,
                detail="Payment method not found or inactive",
            )

    router_obj.payment_method_id = request.payment_method_id
    await db.commit()

    logger.info(
        "Router %s payment method updated to %s",
        router_id, request.payment_method_id,
    )

    return {
        "router_id": router_id,
        "payment_method_id": request.payment_method_id,
        "message": (
            "Payment method assigned"
            if request.payment_method_id
            else "Reverted to legacy (system default) payment"
        ),
    }
