"""Messaging provider factory + segment helper re-export.

Two ways to get a provider:

    get_provider()                      environment-configured, no tenancy
    accounts.resolve(db, user_id)       the reseller's own gateway, with
                                        platform and environment fallbacks

New code should use `accounts.resolve`. `get_provider()` remains for callers
with no tenant context and as the fallback path inside resolution.

Adding a provider: drop one module in this package that defines a `SPEC`
(see base.ProviderSpec). Nothing here needs to change.
"""

from app.config import settings
from app.services.messaging import registry
from app.services.messaging.base import (
    MessagingProvider,
    ProviderField,
    ProviderSpec,
    SendResult,
)
from app.services.messaging.segments import count_segments

__all__ = [
    "default_sender_id",
    "resolve_sender_id",
    "get_provider",
    "count_segments",
    "registry",
    "MessagingProvider",
    "ProviderField",
    "ProviderSpec",
    "SendResult",
]


def default_sender_id() -> str:
    """Return the provider-aware default sender id from environment settings."""
    if settings.SMS_SENDER_ID:
        return settings.SMS_SENDER_ID
    provider = (settings.SMS_PROVIDER or "").lower()
    if provider == "talksasa":
        return settings.TALKSASA_SENDER_ID
    return settings.AT_SENDER_ID


def resolve_sender_id(configured_sender_id: str | None = None) -> str:
    """Return the sender ID to use for a send with no tenant context.

    SMS_SENDER_ID is an operational override. It must win over the DB setting so
    a provider migration cannot keep using a sender ID registered only with the
    previous provider.

    Tenant-aware callers should use `accounts.resolve_sender_id_for` instead:
    a reseller on their own gateway has their own approved sender ID, and this
    override must not reach across to it.
    """
    if settings.SMS_SENDER_ID:
        return settings.SMS_SENDER_ID
    return configured_sender_id or default_sender_id()


def get_provider() -> MessagingProvider:
    """Build the provider named by SMS_PROVIDER from environment credentials.

    Only the two providers that predate per-tenant accounts have environment
    credentials. Anything added since is configured as an account row, so
    pointing SMS_PROVIDER at one is a configuration error worth naming.
    """
    name = (settings.SMS_PROVIDER or "").lower()
    spec = registry.get_spec(name)
    if name == "africastalking":
        config = {
            "username": settings.AT_USERNAME,
            "api_key": settings.AT_API_KEY,
            "base_url": settings.AT_BASE_URL,
        }
    elif name == "talksasa":
        config = {
            "api_token": settings.TALKSASA_API_TOKEN,
            "base_url": settings.TALKSASA_BASE_URL,
        }
    else:
        raise ValueError(
            f"SMS provider {name!r} has no environment credentials; "
            "configure it as a messaging provider account instead"
        )
    return spec.build(config)
