"""Router authentication for the usage-push endpoint — derived, not stored.

A router calling in from the field has to prove it is the router it claims to be.
The obvious approach is a per-router secret column, but that costs a schema change
(and, since 2026-07-28, a refreshed ``tests/schema_snapshot.json`` and an
idempotent migration in ``main.py`` alongside it) for something that is not a fact
worth remembering — it is derivable.

So the token is an HMAC of the router's identity under the server secret. Nothing
is persisted: the server recomputes and compares on every call. The router never
computes it either; the value is baked into the script we generate at install
time, and the router just echoes it back.

Properties worth knowing:

* Rotating ``SECRET_KEY`` invalidates every router token at once. That is the
  revocation story — there is no per-router revoke without adding storage, which
  is a deliberate trade for keeping this schema-free.
* The token sits in a script on the router, readable by anyone with router access
  — but that person already has the router.
* Comparison is constant-time, so the endpoint does not leak a token by timing.
"""

from __future__ import annotations

import hashlib
import hmac

from app.config import settings

# Namespaced so a token minted here can never be confused with, or replayed
# against, anything else signed with the same server secret.
_PURPOSE = b"usage-push:v1:"

TOKEN_LENGTH = 32


def derive_router_token(identity: str) -> str:
    """Return the push token for a router identity.

    Deterministic: the same identity and server secret always yield the same
    token, which is what lets the server verify without storing anything.
    """
    key = settings.SECRET_KEY.encode("utf-8")
    message = _PURPOSE + str(identity or "").strip().encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:TOKEN_LENGTH]


def verify_router_token(identity: str, presented: str) -> bool:
    """Constant-time check of a presented token against the derived one.

    Binding the token to the identity is what stops router A reporting as router
    B: B's token simply does not verify against A's identity.
    """
    if not identity or not presented:
        return False
    return hmac.compare_digest(derive_router_token(identity), str(presented).strip())
