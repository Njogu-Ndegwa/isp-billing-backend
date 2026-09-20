"""API for SMS gateway provider accounts, admin and reseller.

A reseller who brings their own SMS gateway — a different vendor on their own
contract and sender ID — gets a row here. `user_id` NULL is the platform's own
account: the fallback for every reseller who has not configured one.

Two ways in. An admin configures any account, including the platform's, under
/api/admin/messaging. A reseller manages only their own under /api/messaging,
and only while an admin has turned self-service on
(MessagingSettings.allow_reseller_gateways) — a reseller on their own gateway
is still charged portal SMS credits, so opening that door is a commercial
decision. Both paths share the serialization, validation and secret-merge
helpers below; the reseller path additionally pins user_id to the caller.

The form an operator fills in is not hardcoded anywhere. It comes from the
provider's own `ProviderSpec.fields` via `GET /api/admin/messaging/providers`,
so installing a new provider module is enough to make it configurable here.

Credentials are stored Fernet-encrypted and only ever read back masked.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    MessagingProviderAccount,
    MessagingSettings,
    User,
    UserRole,
)
from app.services.auth import get_current_user, verify_token
from app.services.messaging import accounts as provider_accounts
from app.services.messaging import registry, resolve_sender_id

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-messaging-providers"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


class ProviderAccountIn(BaseModel):
    provider: str
    label: str = Field(min_length=1, max_length=100)
    # Omit for the platform-wide account.
    user_id: Optional[int] = None
    sender_id: Optional[str] = None
    credentials: dict = Field(default_factory=dict)
    is_default: bool = True
    is_active: bool = True


class ProviderAccountUpdate(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=100)
    sender_id: Optional[str] = None
    # Secrets may be omitted, sent empty, or echoed back as their mask to keep
    # the stored value — so a UI can PUT back the form it rendered.
    credentials: Optional[dict] = None
    is_default: Optional[bool] = None
    is_active: Optional[bool] = None


class ProviderTestIn(BaseModel):
    phone: str = Field(min_length=6, max_length=20)
    body: str = Field(default="Test message from your ISP billing portal.",
                      min_length=1, max_length=320)


def _account_json(account: MessagingProviderAccount) -> dict:
    try:
        spec = registry.get_spec(account.provider)
        credentials = provider_accounts.masked_config(spec, account.credentials or {})
        problems = provider_accounts.validate_stored(spec, account.credentials or {})
        provider_label = spec.label
    except ValueError:
        # The module that defined this provider is no longer installed. Show
        # the row anyway — hiding it would hide a config the operator must fix.
        credentials, problems = {}, ["Provider is not installed"]
        provider_label = account.provider
    return {
        "id": account.id,
        "user_id": account.user_id,
        "scope": "platform" if account.user_id is None else "reseller",
        "provider": account.provider,
        "provider_label": provider_label,
        "label": account.label,
        "sender_id": account.sender_id,
        "credentials": credentials,
        "is_default": account.is_default,
        "is_active": account.is_active,
        "config_problems": problems,
        "last_test_at": account.last_test_at.isoformat() if account.last_test_at else None,
        "last_test_ok": account.last_test_ok,
        "last_test_error": account.last_test_error,
        "created_at": account.created_at.isoformat() if account.created_at else None,
        "updated_at": account.updated_at.isoformat() if account.updated_at else None,
    }


async def _create_account(
    db: AsyncSession, *, provider: str, user_id: Optional[int], label: str,
    sender_id: Optional[str], credentials: dict, is_default: bool, is_active: bool,
) -> MessagingProviderAccount:
    try:
        spec = registry.get_spec(provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    problems = spec.validate(credentials or {})
    if problems:
        raise HTTPException(status_code=400,
                            detail={"message": "Invalid provider configuration",
                                    "problems": problems})
    account = MessagingProviderAccount(
        user_id=user_id,
        provider=spec.name,
        label=label.strip(),
        sender_id=(sender_id or "").strip() or None,
        credentials=provider_accounts.encrypt_config(spec, credentials or {}),
        is_default=is_default,
        is_active=is_active,
    )
    db.add(account)
    await db.flush()
    if account.is_default:
        await provider_accounts.clear_other_defaults(db, account.user_id, account.id)
    await db.commit()
    logger.info("Messaging provider account %s created (%s, owner=%s)",
                account.id, account.provider, account.user_id)
    return account


async def _update_account(
    db: AsyncSession, account: MessagingProviderAccount, body: "ProviderAccountUpdate",
) -> MessagingProviderAccount:
    try:
        spec = registry.get_spec(account.provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if body.credentials is not None:
        merged = provider_accounts.merge_config(
            spec, account.credentials or {}, body.credentials
        )
        problems = provider_accounts.validate_stored(spec, merged)
        if problems:
            raise HTTPException(status_code=400,
                                detail={"message": "Invalid provider configuration",
                                        "problems": problems})
        account.credentials = merged
    if body.label is not None:
        account.label = body.label.strip()
    if body.sender_id is not None:
        account.sender_id = body.sender_id.strip() or None
    if body.is_active is not None:
        account.is_active = body.is_active
    if body.is_default is not None:
        account.is_default = body.is_default
    if account.is_default:
        await provider_accounts.clear_other_defaults(db, account.user_id, account.id)
    await db.commit()
    return account


async def _test_account(
    db: AsyncSession, account: MessagingProviderAccount, body: "ProviderTestIn",
) -> dict:
    """Send one real SMS through this account and record the outcome.

    Spends one message of the gateway account's own balance. Charges no portal
    credits — it is a configuration check, not a customer send.
    """
    account_id = account.id
    try:
        spec = registry.get_spec(account.provider)
        config = provider_accounts.decrypt_config(spec, account.credentials or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    problems = spec.validate(config)
    if problems:
        raise HTTPException(status_code=400,
                            detail={"message": "Invalid provider configuration",
                                    "problems": problems})
    provider = spec.build(config)
    sender_id = (account.sender_id or "").strip() or resolve_sender_id(None)
    # Everything needed is in hand; release the connection before the network
    # call (Database Session Discipline).
    await db.commit()

    result = None
    try:
        results = await provider.send_bulk([body.phone], body.body, sender_id)
        result = results[0] if results else None
        ok = bool(result and result.success)
        error = None if ok else ((result.error if result else None) or "no_response")
    except Exception as exc:
        logger.exception("Provider account %s test send crashed", account_id)
        ok, error = False, str(exc)[:255]

    fresh = await db.get(MessagingProviderAccount, account_id)
    if fresh is not None:
        fresh.last_test_at = datetime.utcnow()
        fresh.last_test_ok = ok
        fresh.last_test_error = error[:255] if error else None
        await db.commit()

    return {
        "ok": ok,
        "provider": provider.name,
        "sender_id": sender_id,
        "recipient": body.phone,
        "provider_message_id": result.provider_message_id if result else None,
        "status": result.status if result else None,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Admin routes — any account, including the platform's own
# ---------------------------------------------------------------------------

@router.get("/api/admin/messaging/providers")
async def list_provider_catalogue(db: AsyncSession = Depends(get_db),
                                  token: str = Depends(verify_token)):
    """Installed providers and the fields each one needs. Drives the admin form."""
    await _require_admin(token, db)
    return {"providers": registry.describe()}


@router.get("/api/admin/messaging/provider-accounts")
async def list_provider_accounts(
    user_id: Optional[int] = Query(None),
    scope: str = Query("all", pattern="^(all|platform|reseller)$"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    stmt = select(MessagingProviderAccount)
    if user_id is not None:
        stmt = stmt.where(MessagingProviderAccount.user_id == user_id)
    elif scope == "platform":
        stmt = stmt.where(MessagingProviderAccount.user_id.is_(None))
    elif scope == "reseller":
        stmt = stmt.where(MessagingProviderAccount.user_id.isnot(None))
    stmt = stmt.order_by(MessagingProviderAccount.user_id.nulls_first(),
                         MessagingProviderAccount.id)
    rows = (await db.execute(stmt)).scalars().all()
    return {"accounts": [_account_json(a) for a in rows]}


@router.post("/api/admin/messaging/provider-accounts")
async def create_provider_account(body: ProviderAccountIn,
                                  db: AsyncSession = Depends(get_db),
                                  token: str = Depends(verify_token)):
    await _require_admin(token, db)
    if body.user_id is not None and await db.get(User, body.user_id) is None:
        raise HTTPException(status_code=404, detail="Reseller not found")
    account = await _create_account(
        db, provider=body.provider, user_id=body.user_id, label=body.label,
        sender_id=body.sender_id, credentials=body.credentials,
        is_default=body.is_default, is_active=body.is_active,
    )
    return {"message": "Provider account created", "account": _account_json(account)}


@router.put("/api/admin/messaging/provider-accounts/{account_id}")
async def update_provider_account(account_id: int, body: ProviderAccountUpdate,
                                  db: AsyncSession = Depends(get_db),
                                  token: str = Depends(verify_token)):
    await _require_admin(token, db)
    account = await db.get(MessagingProviderAccount, account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Provider account not found")
    account = await _update_account(db, account, body)
    return {"message": "Provider account updated", "account": _account_json(account)}


@router.delete("/api/admin/messaging/provider-accounts/{account_id}")
async def delete_provider_account(account_id: int,
                                  db: AsyncSession = Depends(get_db),
                                  token: str = Depends(verify_token)):
    await _require_admin(token, db)
    account = await db.get(MessagingProviderAccount, account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Provider account not found")
    # sms_messages rows point at this account for audit, so deactivate rather
    # than delete: the record of which gateway carried which message survives.
    account.is_active = False
    account.is_default = False
    await db.commit()
    logger.info("Messaging provider account %s deactivated", account_id)
    return {"message": "Provider account deactivated"}


@router.post("/api/admin/messaging/provider-accounts/{account_id}/test")
async def test_provider_account(account_id: int, body: ProviderTestIn,
                                db: AsyncSession = Depends(get_db),
                                token: str = Depends(verify_token)):
    await _require_admin(token, db)
    account = await db.get(MessagingProviderAccount, account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Provider account not found")
    return await _test_account(db, account, body)


# ---------------------------------------------------------------------------
# Reseller routes — a reseller's own accounts only
#
# Every handler below pins user_id to the caller and refuses any row it does
# not own, so a reseller can neither see nor edit another tenant's
# credentials, nor touch the platform account.
# ---------------------------------------------------------------------------

class ResellerProviderAccountIn(BaseModel):
    """Same as the admin form minus user_id — the caller is always the owner."""

    provider: str
    label: str = Field(min_length=1, max_length=100)
    sender_id: Optional[str] = None
    credentials: dict = Field(default_factory=dict)
    is_default: bool = True
    is_active: bool = True


async def _require_reseller(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Resellers only")
    return user


async def _require_self_service(db: AsyncSession) -> None:
    row = await db.get(MessagingSettings, 1)
    if row is None or not row.allow_reseller_gateways:
        raise HTTPException(
            status_code=403,
            detail="Self-service SMS gateways are disabled. "
                   "Ask support to configure your gateway.",
        )


async def _own_account(
    db: AsyncSession, account_id: int, user: User
) -> MessagingProviderAccount:
    account = await db.get(MessagingProviderAccount, account_id)
    # Same 404 whether the row is missing or belongs to someone else: a
    # reseller must not be able to probe for other tenants' account ids.
    if account is None or account.user_id != user.id:
        raise HTTPException(status_code=404, detail="Provider account not found")
    return account


@router.get("/api/messaging/providers")
async def reseller_provider_catalogue(db: AsyncSession = Depends(get_db),
                                      token: str = Depends(verify_token)):
    """Providers this reseller can choose from, and the fields each one needs."""
    await _require_reseller(token, db)
    row = await db.get(MessagingSettings, 1)
    return {
        "self_service_enabled": bool(row and row.allow_reseller_gateways),
        "providers": registry.describe(),
    }


@router.get("/api/messaging/provider-accounts")
async def list_own_provider_accounts(db: AsyncSession = Depends(get_db),
                                     token: str = Depends(verify_token)):
    """This reseller's own gateways, and which gateway their sends use today.

    Readable even with self-service off, so a reseller can see the gateway an
    admin configured for them.
    """
    user = await _require_reseller(token, db)
    row = await db.get(MessagingSettings, 1)
    rows = await provider_accounts.list_accounts(db, user.id)
    resolved = await provider_accounts.resolve(db, user.id)
    return {
        "self_service_enabled": bool(row and row.allow_reseller_gateways),
        "accounts": [_account_json(a) for a in rows],
        "effective": {
            # "platform" and "env" both mean: sending on the platform gateway.
            "source": resolved.source,
            "provider": resolved.provider.name,
            "sender_id": resolved.sender_id,
            "account_id": resolved.account_id,
        },
    }


@router.post("/api/messaging/provider-accounts")
async def create_own_provider_account(body: ResellerProviderAccountIn,
                                      db: AsyncSession = Depends(get_db),
                                      token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    await _require_self_service(db)
    account = await _create_account(
        db, provider=body.provider, user_id=user.id, label=body.label,
        sender_id=body.sender_id, credentials=body.credentials,
        is_default=body.is_default, is_active=body.is_active,
    )
    return {"message": "Provider account created", "account": _account_json(account)}


@router.put("/api/messaging/provider-accounts/{account_id}")
async def update_own_provider_account(account_id: int, body: ProviderAccountUpdate,
                                      db: AsyncSession = Depends(get_db),
                                      token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    await _require_self_service(db)
    account = await _own_account(db, account_id, user)
    account = await _update_account(db, account, body)
    return {"message": "Provider account updated", "account": _account_json(account)}


@router.delete("/api/messaging/provider-accounts/{account_id}")
async def delete_own_provider_account(account_id: int,
                                      db: AsyncSession = Depends(get_db),
                                      token: str = Depends(verify_token)):
    """Deactivate one of this reseller's gateways.

    Their sends fall back to the platform gateway on the next message, so
    turning off a gateway never leaves a reseller unable to send.
    """
    user = await _require_reseller(token, db)
    await _require_self_service(db)
    account = await _own_account(db, account_id, user)
    account.is_active = False
    account.is_default = False
    await db.commit()
    logger.info("Reseller %s deactivated messaging provider account %s",
                user.id, account_id)
    return {"message": "Provider account deactivated"}


@router.post("/api/messaging/provider-accounts/{account_id}/test")
async def test_own_provider_account(account_id: int, body: ProviderTestIn,
                                    db: AsyncSession = Depends(get_db),
                                    token: str = Depends(verify_token)):
    """Send one real SMS through this gateway. Costs no portal credits."""
    user = await _require_reseller(token, db)
    await _require_self_service(db)
    account = await _own_account(db, account_id, user)
    return await _test_account(db, account, body)
