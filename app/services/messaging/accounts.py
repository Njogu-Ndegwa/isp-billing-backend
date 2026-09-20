"""Per-tenant gateway accounts: storage, secrets, and resolution.

Who sends a given SMS is resolved here, in this order:

    1. the reseller's own default active account
    2. any other active account the reseller owns (most recently updated)
    3. the platform default active account (user_id IS NULL)
    4. the environment fallback (settings.SMS_PROVIDER + its env credentials)

Step 4 means a deployment with no accounts configured behaves exactly as it
did before this module existed, so the feature ships dark and each tenant is
migrated onto their own gateway one row at a time.

Session discipline: every function here is pure DB + CPU. Resolution decrypts
credentials and builds a provider object, but never touches the network — so
a caller can resolve inside a short session, close it, and only then send.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.models import MessagingProviderAccount, MessagingSettings
from app.services.messaging import default_sender_id, get_provider, registry
from app.services.messaging.base import MessagingProvider, ProviderSpec

# One key derivation for the whole app. Reusing the payment layer's helpers
# rather than deriving a second Fernet key keeps credential encryption on a
# single, already-audited path tied to settings.SECRET_KEY.
from app.services.payment_gateway import (  # noqa: E402
    decrypt_credential,
    encrypt_credential,
    mask_credential,
)

logger = logging.getLogger(__name__)

MASKED_SENTINEL = "__unchanged__"


@dataclass
class ResolvedProvider:
    """A provider ready to send, plus where it came from (for logs/audit)."""

    provider: MessagingProvider
    sender_id: str
    account_id: Optional[int]
    source: str  # "reseller" | "platform" | "env"


# ---------------------------------------------------------------------------
# Credential storage
# ---------------------------------------------------------------------------

def encrypt_config(spec: ProviderSpec, config: dict) -> dict:
    """Plaintext config -> storable config, with declared secrets encrypted."""
    secrets = spec.secret_keys()
    stored: dict[str, str] = {}
    for key, value in spec.apply_defaults(config).items():
        value = "" if value is None else str(value)
        stored[key] = encrypt_credential(value) if (key in secrets and value) else value
    return stored


def decrypt_config(spec: ProviderSpec, stored: dict) -> dict:
    """Stored config -> plaintext config for building a provider."""
    secrets = spec.secret_keys()
    config: dict[str, str] = {}
    for key, value in (stored or {}).items():
        if key in secrets and value:
            try:
                config[key] = decrypt_credential(str(value))
            except ValueError:
                # A rotated SECRET_KEY must fail the send loudly, not send
                # with a garbage credential.
                raise
        else:
            config[key] = "" if value is None else str(value)
    return spec.apply_defaults(config)


def masked_config(spec: ProviderSpec, stored: dict) -> dict:
    """Stored config -> API-safe config. Secrets become last-4 masks."""
    secrets = spec.secret_keys()
    out: dict[str, Optional[str]] = {}
    for f in spec.fields:
        value = (stored or {}).get(f.key)
        if f.key not in secrets:
            out[f.key] = "" if value is None else str(value)
            continue
        if not value:
            out[f.key] = None
            continue
        try:
            out[f.key] = mask_credential(decrypt_credential(str(value)))
        except ValueError:
            out[f.key] = "****"
    return out


def merge_config(spec: ProviderSpec, stored: dict, incoming: dict) -> dict:
    """Apply an update without forcing the client to resend every secret.

    A secret field omitted, left empty, or sent back as its mask keeps its
    stored value — so a UI can render masks and PUT the form unchanged.
    """
    secrets = spec.secret_keys()
    merged = dict(stored or {})
    current_masks = masked_config(spec, stored)
    for f in spec.fields:
        if f.key not in incoming:
            continue
        value = incoming.get(f.key)
        value = "" if value is None else str(value)
        if f.key in secrets:
            unchanged = (
                value == ""
                or value == MASKED_SENTINEL
                or (current_masks.get(f.key) and value == current_masks[f.key])
            )
            if unchanged:
                continue
            merged[f.key] = encrypt_credential(value)
        else:
            merged[f.key] = value
    # Drop keys the provider no longer declares.
    return {f.key: merged.get(f.key, f.default) for f in spec.fields}


def validate_stored(spec: ProviderSpec, stored: dict) -> list[str]:
    """Validate a stored config without exposing plaintext to the caller."""
    try:
        return spec.validate(decrypt_config(spec, stored))
    except ValueError:
        return ["Stored credentials could not be decrypted (SECRET_KEY changed?)"]


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

async def list_accounts(
    db: AsyncSession, user_id: Optional[int], *, include_inactive: bool = True
) -> list[MessagingProviderAccount]:
    stmt = select(MessagingProviderAccount).where(
        MessagingProviderAccount.user_id.is_(None)
        if user_id is None
        else MessagingProviderAccount.user_id == user_id
    )
    if not include_inactive:
        stmt = stmt.where(MessagingProviderAccount.is_active.is_(True))
    stmt = stmt.order_by(
        MessagingProviderAccount.is_default.desc(),
        MessagingProviderAccount.id,
    )
    return list((await db.execute(stmt)).scalars().all())


async def _pick(
    db: AsyncSession, user_id: Optional[int]
) -> Optional[MessagingProviderAccount]:
    """The active account that should send for this owner, or None."""
    rows = [a for a in await list_accounts(db, user_id) if a.is_active]
    if not rows:
        return None
    for row in rows:
        if row.is_default:
            return row
    # No flag set (hand-edited row, or the default was deactivated): fall back
    # to the most recently touched active account rather than refusing to send.
    return max(rows, key=lambda a: (a.updated_at or a.created_at or datetime.min, a.id))


async def clear_other_defaults(
    db: AsyncSession, user_id: Optional[int], keep_id: Optional[int]
) -> None:
    for row in await list_accounts(db, user_id):
        if row.id != keep_id and row.is_default:
            row.is_default = False


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def _build(account: MessagingProviderAccount) -> MessagingProvider:
    spec = registry.get_spec(account.provider)
    return spec.build(decrypt_config(spec, account.credentials or {}))


async def resolve(
    db: AsyncSession,
    user_id: Optional[int],
    *,
    configured_sender_id: Optional[str] = None,
) -> ResolvedProvider:
    """Resolve who sends for `user_id`. Pass None for platform-owned sends.

    Raises ValueError only when nothing at all is usable; a broken reseller
    account falls through to the platform account rather than silently
    dropping the reseller's messages.
    """
    for owner, source in ((user_id, "reseller"), (None, "platform")):
        if owner is None and source == "reseller":
            continue  # platform sends are handled by the second pass only
        account = await _pick(db, owner)
        if account is None:
            continue
        try:
            provider = _build(account)
        except Exception as exc:
            logger.error(
                "Messaging account %s (%s, owner=%s) unusable, falling through: %s",
                account.id, account.provider, owner, exc,
            )
            continue
        return ResolvedProvider(
            provider=provider,
            sender_id=(account.sender_id or "").strip() or default_sender_id(),
            account_id=account.id,
            source=source,
        )

    return ResolvedProvider(
        provider=get_provider(),
        # The SMS_SENDER_ID env override is an operational lever for the
        # platform's own gateway migrations, so it only applies on this path.
        # A reseller's account carries its own sender ID and is never
        # overridden by it.
        sender_id=(
            settings.SMS_SENDER_ID
            or (configured_sender_id or "").strip()
            or default_sender_id()
        ),
        account_id=None,
        source="env",
    )


async def resolve_sender_id_for(
    db: AsyncSession,
    user_id: Optional[int],
    configured_sender_id: Optional[str] = None,
) -> str:
    """The sender ID a send for `user_id` will go out with.

    Used at queue time so the stamped sender ID matches the gateway that will
    actually carry the message. Never raises: an unresolvable provider still
    has to produce a sender ID for the row, and the send itself will report
    the real failure.
    """
    account = await _pick(db, user_id) if user_id is not None else None
    if account is None:
        account = await _pick(db, None)
    if account is not None and (account.sender_id or "").strip():
        return account.sender_id.strip()
    if settings.SMS_SENDER_ID:
        return settings.SMS_SENDER_ID
    return (configured_sender_id or "").strip() or default_sender_id()


async def platform_sender_id(db: AsyncSession) -> str:
    """Convenience for callers that already read MessagingSettings."""
    row = await db.get(MessagingSettings, 1)
    return await resolve_sender_id_for(db, None, row.sender_id if row else None)
