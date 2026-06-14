"""Messaging provider factory + segment helper re-export."""

from app.config import settings
from app.services.messaging.base import MessagingProvider, SendResult
from app.services.messaging.segments import count_segments

__all__ = ["get_provider", "count_segments", "MessagingProvider", "SendResult"]


def get_provider() -> MessagingProvider:
    provider = (settings.SMS_PROVIDER or "").lower()
    if provider == "africastalking":
        from app.services.messaging.africas_talking import AfricasTalkingProvider
        return AfricasTalkingProvider(
            username=settings.AT_USERNAME,
            api_key=settings.AT_API_KEY,
            base_url=settings.AT_BASE_URL,
        )
    raise ValueError(f"Unsupported SMS provider: {settings.SMS_PROVIDER!r}")
