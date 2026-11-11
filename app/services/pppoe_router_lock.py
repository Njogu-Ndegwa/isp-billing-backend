"""Opt-in PPPoE router lock: a PPPoE login stays on the router it was first put on.

Off by default (``User.pppoe_router_lock_enabled``), so nothing changes for a
reseller who has not turned it on. When on:

* A login is locked to ``Customer.pppoe_locked_router_id``. Turning the lock on
  stamps every existing PPPoE customer of that reseller with their current
  router; a customer registered while it is on is stamped at registration;
  a customer with no stamp yet is stamped the first time the lock is checked.
* Moving a locked login to another router (the customer edit form) is refused
  with 409. The PPPoE secret only ever exists on ``Customer.router_id`` (the
  edit path removes it from the old router, the recovery sweep removes moved
  secrets), so refusing the move is what keeps the login from working on a
  second router.
* The reseller can release one account (``release``): its stamp is cleared,
  the next move is allowed and the new router becomes the locked one.
* A whole-router transfer (replacing a router's hardware) carries the lock
  over to the target router, since the customers are not choosing a router.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Customer


class PppoeRouterLocked(Exception):
    """Raised when a locked PPPoE login would move to another router."""

    def __init__(self, customer_id: int, locked_router_id: int, target_router_id: int):
        self.customer_id = customer_id
        self.locked_router_id = locked_router_id
        self.target_router_id = target_router_id
        super().__init__(
            "This PPPoE account is locked to its first router. Release the router "
            "lock on this customer before moving them to another router."
        )


def lock_enabled(owner) -> bool:
    return bool(getattr(owner, "pppoe_router_lock_enabled", False))


def applies_to(owner, customer: Customer) -> bool:
    return lock_enabled(owner) and bool(customer.pppoe_username)


def stamp_if_unlocked(owner, customer: Customer, router_id: Optional[int] = None) -> None:
    """Lock the customer to ``router_id`` (default: their current router) if the
    reseller has the lock on and the customer is not stamped yet."""
    if not applies_to(owner, customer) or customer.pppoe_locked_router_id is not None:
        return
    target = router_id if router_id is not None else customer.router_id
    if target is not None:
        customer.pppoe_locked_router_id = target


def check_router_change(owner, customer: Customer, target_router_id: Optional[int]) -> None:
    """Refuse moving a locked PPPoE login to a router other than its locked one.

    Call before applying an edit. A customer with no stamp may move once (they
    were released, or were never stamped); ``stamp_if_unlocked`` after the edit
    locks them to wherever they ended up.
    """
    if target_router_id is None or not applies_to(owner, customer):
        return
    locked = customer.pppoe_locked_router_id
    if locked is not None and target_router_id != locked:
        raise PppoeRouterLocked(customer.id, locked, target_router_id)


async def lock_existing_customers(db: AsyncSession, user_id: int) -> int:
    """Stamp every PPPoE customer of this reseller with their current router
    (only those not stamped yet). Returns how many were stamped. Caller commits."""
    result = await db.execute(
        update(Customer)
        .where(
            Customer.user_id == user_id,
            Customer.pppoe_username.isnot(None),
            Customer.pppoe_username != "",
            Customer.router_id.isnot(None),
            Customer.pppoe_locked_router_id.is_(None),
        )
        .values(pppoe_locked_router_id=Customer.router_id)
        .execution_options(synchronize_session=False)
    )
    return int(result.rowcount or 0)


def lock_fields(owner, customer: Customer) -> dict:
    """What the customer detail view shows about the lock."""
    return {
        "pppoe_router_lock_enabled": lock_enabled(owner),
        "pppoe_locked_router_id": customer.pppoe_locked_router_id,
    }
