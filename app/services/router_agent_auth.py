"""Derived authentication token for the outbound router command agent."""

from __future__ import annotations

import hashlib
import hmac

from app.config import settings


_PURPOSE = b"router-command-agent:v1:"
TOKEN_LENGTH = 32


def derive_router_agent_token(identity: str) -> str:
    key = settings.SECRET_KEY.encode("utf-8")
    message = _PURPOSE + str(identity or "").strip().encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:TOKEN_LENGTH]


def verify_router_agent_token(identity: str, presented: str) -> bool:
    if not identity or not presented:
        return False
    return hmac.compare_digest(
        derive_router_agent_token(identity),
        str(presented).strip(),
    )
