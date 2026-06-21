"""Messaging provider factory + segment helper re-export."""

from app.config import settings
from app.services.messaging.base import MessagingProvider, SendResult
from app.services.messaging.segments import count_segments

__all__ = [
    "default_sender_id",
    "resolve_sender_id",
    "get_provider",
    "count_segments",
    "MessagingProvider",
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
    """Return the sender ID to use for a send.

    SMS_SENDER_ID is an operational override. It must win over the DB setting so
    a provider migration cannot keep using a sender ID registered only with the
    previous provider.
    """
    if settings.SMS_SENDER_ID:
        return settings.SMS_SENDER_ID
    return configured_sender_id or default_sender_id()


def get_provider() -> MessagingProvider:
    provider = (settings.SMS_PROVIDER or "").lower()
    if provider == "africastalking":
        from app.services.messaging.africas_talking import AfricasTalkingProvider
        return AfricasTalkingProvider(
            username=settings.AT_USERNAME,
            api_key=settings.AT_API_KEY,
            base_url=settings.AT_BASE_URL,
        )
    if provider == "talksasa":
        from app.services.messaging.talksasa import TalksasaProvider
        return TalksasaProvider(
            api_token=settings.TALKSASA_API_TOKEN,
            base_url=settings.TALKSASA_BASE_URL,
        )
    raise ValueError(f"Unsupported SMS provider: {settings.SMS_PROVIDER!r}")
