"""How a customer pays by M-Pesa paybill: the "Pay by M-Pesa" card.

The admin customer page shows a reseller what to tell a customer: "Paybill X,
Account Y, Amount Z". Every value here is what the C2B confirmation handler
(app/services/c2b_handler.handle_confirmation) needs to renew that customer
on its own, so a customer who follows the card never lands in Unmatched
Payments:

* Paybill: from ``resolve_paybills`` (the rule the reminders and the M-Pesa
  prompt share), then checked against the handler's own shortcode lookup
  (``_resolve_reseller_from_shortcode``). A reseller paybill is only kept
  when the handler would scope it to this reseller; the platform paybill is
  kept as is (the handler matches it across resellers).
* Account: the customer's ``account_number``, only when it passes the same
  Luhn check the handler runs before its lookup (it then matches exactly).
* Amount: the price of the plan the handler will charge, which is the
  pending plan when the customer has a plan change queued.
* Customer type: PPPoE (with a login) and static IP are renewed by the
  handler, which provisions them. Hotspot is not: the payment is recorded but
  no device is authorised, so hotspot customers pay on the login page (the
  reminders leave the paybill out for them for the same reason). A customer
  with no plan or no router can't be renewed either.

Read-only: nothing here changes how a payment is matched or applied.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Iterable, Optional

from sqlalchemy import select

from app.config import settings
from app.db.models import ConnectionType, Plan
from app.services.account_numbers import is_valid_account_number

logger = logging.getLogger(__name__)

# Why a customer has no paybill + account to pay with.
REASON_HOTSPOT = "hotspot"
REASON_NO_PLAN = "no_plan"
REASON_NO_ROUTER = "no_router"
REASON_NO_PPPOE_LOGIN = "no_pppoe_login"
REASON_NO_ACCOUNT_NUMBER = "no_account_number"
REASON_NO_PAYBILL = "no_paybill"


async def matchable_paybills(
    db, reseller_id: int, paybills: dict[Any, Optional[str]]
) -> dict[Any, Optional[str]]:
    """``paybills`` with every paybill the C2B handler would not match for
    this reseller replaced by None.

    The platform shortcode routes by account number alone. Any other
    shortcode must resolve, through the handler's own lookup, to this
    reseller; otherwise the payment would be rejected or scoped to someone
    else (a shortcode saved with stray spaces, an inactive method, two
    resellers on one shortcode).
    """
    from app.services.c2b_handler import _resolve_reseller_from_shortcode

    verdicts: dict[str, bool] = {}
    for paybill in {p for p in paybills.values() if p}:
        if paybill == settings.MPESA_SHORTCODE:
            verdicts[paybill] = True
            continue
        try:
            owner_id, is_platform = await _resolve_reseller_from_shortcode(db, paybill)
        except Exception:
            logger.exception("Could not check paybill %s against the C2B lookup", paybill)
            owner_id, is_platform = None, False
        verdicts[paybill] = is_platform or owner_id == reseller_id
    return {key: (p if p and verdicts.get(p) else None) for key, p in paybills.items()}


def _pending_plan_id(customer) -> Optional[int]:
    """The plan a queued plan change will charge, as the C2B handler reads it."""
    data = customer.pending_update_data
    if not data:
        return None
    try:
        data = json.loads(data) if isinstance(data, str) else data
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("source") == "pppoe_expired_page":
        # Only counts for its own prompt, so paybill renews the customer's plan.
        return None
    plan_id = data.get("plan_id")
    if isinstance(plan_id, str) and plan_id.isdigit():
        plan_id = int(plan_id)
    return plan_id if isinstance(plan_id, int) and not isinstance(plan_id, bool) else None


async def pending_plans(db, customers: Iterable) -> dict[int, Plan]:
    """{plan_id: Plan} for every pending plan change among ``customers``."""
    ids = {pid for pid in (_pending_plan_id(c) for c in customers) if pid}
    if not ids:
        return {}
    rows = (await db.execute(select(Plan).where(Plan.id.in_(ids)))).scalars().all()
    return {plan.id: plan for plan in rows}


def pay_by_mpesa(customer, paybill: Optional[str], plans: dict[int, Plan] | None = None) -> dict:
    """The card for one customer.

    ``paybill`` is the matchable paybill for the customer's router (see
    ``matchable_paybills``). Returns paybill, account_number and amount when
    the customer can pay with them, else all three None and the reason.
    """
    pending = (plans or {}).get(_pending_plan_id(customer) or -1)
    plan = pending or customer.plan
    reason = _unavailable_reason(customer, plan, paybill)
    if reason:
        return {
            "paybill": None,
            "account_number": None,
            "amount": None,
            "unavailable_reason": reason,
        }
    return {
        "paybill": paybill,
        "account_number": customer.account_number,
        "amount": plan.price,
        "unavailable_reason": None,
    }


def _unavailable_reason(customer, plan, paybill: Optional[str]) -> Optional[str]:
    if plan is None:
        return REASON_NO_PLAN
    if plan.connection_type == ConnectionType.PPPOE:
        if not customer.pppoe_username:
            return REASON_NO_PPPOE_LOGIN
    elif plan.connection_type != ConnectionType.STATIC_IP:
        return REASON_HOTSPOT
    if customer.router_id is None:
        return REASON_NO_ROUTER
    # Unstripped on purpose: the handler strips the BillRefNumber and then
    # compares it with the stored value exactly.
    if not is_valid_account_number(customer.account_number or ""):
        return REASON_NO_ACCOUNT_NUMBER
    if not paybill:
        return REASON_NO_PAYBILL
    return None
