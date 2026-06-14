"""Provider-agnostic messaging interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class SendResult:
    recipient: str
    success: bool
    provider_message_id: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    cost: Optional[str] = None


class MessagingProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        """Send one body to many recipients; return one result per recipient."""
        raise NotImplementedError
