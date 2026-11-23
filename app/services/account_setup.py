"""Where a reseller account stands in its first setup (GET /api/profile/setup-status).

Four steps, each ``done``, ``missing`` or ``problem``:

1. router: a MikroTik router connected and online;
2. plans: at least one plan people can see (not hidden, not past its end date);
3. payments: where customer payments go, linked to every router that takes M-Pesa;
4. support_phone: a number customers can call.

``next`` is the first step that is not done, with what to do about it: either
an exact request to propose (``propose``) or one question to ask first
(``ask``, then ``then``). A done step never has a ``next``, so nothing proposes
a router setup code to an account that already has a router.

One short DB session of plain reads; no router or network I/O.
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Plan, PortalSettings, ResellerPaymentMethod, Router, User
from app.services.markets import get_market, reseller_market
from app.services.router_availability import derive_router_status

# What a Kenyan hotspot reseller commonly sells: 1 hour about KES 10, 3 hours 20,
# a day 50, a week 250. Other markets get the same prices converted at the
# market's fixed rate and rounded to a price people quote.
STARTER_KES = {"price_1_hour": 10, "price_3_hours": 20, "price_24_hours": 50, "price_1_week": 250}
STARTER_SPEED = "5M/5M"

# How customers pay, per market: the one question asked before the payment-method form.
_PAYMENT_QUESTION = {
    "KE": ("Do your customers pay to a Paybill, a Till, or a bank?",
           {"Paybill": "mpesa_paybill", "Till": "mpesa_till", "Bank": "bank_account"}),
    "TZ": ("Do your customers pay with ZenoPay?", {"ZenoPay": "zenopay"}),
    "UG": ("Do your customers pay with MTN Mobile Money?", {"MTN MoMo": "mtn_momo"}),
    "CM": ("Do your customers pay with MTN Mobile Money or Fapshi?",
           {"MTN MoMo": "mtn_momo", "Fapshi": "fapshi"}),
}


def _nice(amount: float) -> int:
    """The nearest price people quote: 1, 1.5, 2, 2.5, 3, 5 or 7.5 times a power of ten."""
    if amount <= 1:
        return 1
    power = 1
    while power * 10 <= amount:
        power *= 10
    candidates = [step * power for step in (1, 1.5, 2, 2.5, 3, 5, 7.5, 10)]
    return int(min((c for c in candidates if c == int(c)), key=lambda c: abs(c - amount)))


def starter_prices(market_code: Optional[str]) -> dict:
    """The starter set's prices in the market's own currency."""
    market = get_market(market_code)
    if market.currency == "KES":
        return dict(STARTER_KES)
    kes = get_market("KE").usd_rate
    if not (market.usd_rate and kes):
        return dict(STARTER_KES)
    return {k: _nice(v / kes * market.usd_rate) for k, v in STARTER_KES.items()}


def _step(key: str, title: str, state: str, detail: str) -> dict:
    return {"key": key, "title": title, "state": state, "detail": detail}


def build_status(user, routers: list, plans: list, methods: list, portal_phone: Optional[str],
                 now: Optional[datetime] = None) -> dict:
    """The setup status from plain rows (routers, plans, active payment methods)."""
    now = now or datetime.utcnow()
    market = reseller_market(user)
    steps: list[dict] = []
    todo: dict[str, dict] = {}

    # 1. router
    status = {r.id: derive_router_status(r, now=now) for r in routers}
    online = [r for r in routers if status[r.id] == "online"]
    if not routers:
        steps.append(_step("router", "Router connected", "missing", "No router yet."))
        todo["router"] = {"say": "Connect the first MikroTik router with a setup code.",
                          "propose": {"method": "POST", "path": "/api/provision/create", "form": True, "body": {},
                                      "summary": "Create a setup code to connect your MikroTik router"}}
    elif not online:
        r = routers[0]
        detail = (f"{r.name} is offline" if status[r.id] == "offline" else f"{r.name} has not reported in lately")
        if getattr(r, "last_online_at", None):
            detail += f" (last online {r.last_online_at.isoformat()}Z)"
        steps.append(_step("router", "Router connected", "problem", detail + "."))
        todo["router"] = {"say": "The router is added but not online: check it, do not make a new setup code.",
                          "read": {"method": "GET", "path": f"/api/routers/{r.id}/checkup"}}
    else:
        names = ", ".join(r.name for r in online[:3])
        steps.append(_step("router", "Router connected", "done", f"Online: {names}."))

    # 2. plans
    visible = [p for p in plans if not p.is_hidden and (p.valid_until is None or p.valid_until > now)]
    if not plans:
        prices = starter_prices(getattr(user, "market_code", None))
        steps.append(_step("plans", "Plans people can buy", "missing", "No plan yet."))
        todo["plans"] = {
            "say": ("Offer the starter hotspot plans below, already filled in: one Confirm creates them all, "
                    "and any price can be changed first. Never open a blank plan form."),
            "propose": {"method": "POST", "path": "/api/plans/starter-set", "form": True,
                        "body": {**prices, "speed": STARTER_SPEED, "max_shared_users": 1},
                        "summary": ("Create 4 hotspot plans: " + ", ".join(
                            f"{label} {market.currency} {prices[key]:,}" for key, label in (
                                ("price_1_hour", "1 hour"), ("price_3_hours", "3 hours"),
                                ("price_24_hours", "24 hours"), ("price_1_week", "1 week"))))},
            "currency": market.currency,
        }
    elif not visible:
        hidden = [p for p in plans if p.is_hidden]
        what = (f"All {len(plans)} plans are hidden" if len(hidden) == len(plans)
                else f"All {len(plans)} plans are hidden or past their end date")
        steps.append(_step("plans", "Plans people can buy", "problem", what + ", so nobody new can buy them."))
        todo["plans"] = {
            "say": "The plans exist but nobody can see them: offer to show them again, do not create new plans.",
            "propose": {"method": "POST", "path": "/api/plans/unhide", "form": False,
                        "body": {"plan_ids": [p.id for p in hidden]},
                        "summary": f"Show {len(hidden)} hidden plan(s) again: "
                                   + ", ".join(p.name for p in hidden[:6]) + ("…" if len(hidden) > 6 else "")},
        }
    else:
        steps.append(_step("plans", "Plans people can buy", "done", f"{len(visible)} plan(s) on sale."))

    # 3. payments (routers that sell by voucher only need no payment method)
    selling = [r for r in routers if "mpesa" in [str(m).lower() for m in (r.payment_methods or ["mpesa"])]]
    question = _PAYMENT_QUESTION.get(market.code)
    if (routers and not selling) or not question:
        steps.append(_step("payments", "Where payments go", "done", "Customers buy vouchers: no payment method needed."))
    elif not methods:
        ask, answers = question
        steps.append(_step("payments", "Where payments go", "missing", "No payment method yet."))
        todo["payments"] = {
            "say": ("Ask this one question first and stop. Once answered, open the form with method_type "
                    "set to the answer's value."),
            "ask": ask, "answers": answers,
            "then": {"method": "POST", "path": "/api/payment-methods", "form": True,
                     "body": {"label": f"{user.organization_name or 'My'} payments"[:100]},
                     "answer_sets": "method_type"},
        }
    else:
        unlinked = [r for r in selling if not r.payment_method_id]
        if unlinked:
            r = unlinked[0]
            steps.append(_step("payments", "Where payments go", "problem",
                               f"{methods[0].label} is added but not linked to {r.name}."))
            body = {"payment_method_id": methods[0].id} if len(methods) == 1 else {}
            todo["payments"] = {"say": "Link the payment method to the router.",
                                "propose": {"method": "PUT", "path": f"/api/routers/{r.id}/payment-method",
                                            "form": True, "body": body,
                                            "summary": f"Send {r.name}'s customer payments to "
                                                       + (methods[0].label if len(methods) == 1 else "a payment method")}}
        else:
            steps.append(_step("payments", "Where payments go", "done", f"{methods[0].label}."))

    # 4. support phone
    phone = (portal_phone or "").strip() or (getattr(user, "support_phone", None) or "").strip()
    if phone:
        steps.append(_step("support_phone", "Support phone", "done", "Set."))
    else:
        steps.append(_step("support_phone", "Support phone", "missing", "No number customers can call."))
        todo["support_phone"] = {"say": "Add the number customers call for help.",
                                 "propose": {"method": "PATCH", "path": "/api/profile", "form": True,
                                             "body": {"support_phone": ""},
                                             "summary": "Add your support phone number"}}

    first = next((s for s in steps if s["state"] != "done"), None)
    return {
        "set_up": first is None,
        "steps": steps,
        "next": {"step": first["key"], **todo[first["key"]]} if first else None,
        "currency": market.currency,
    }


async def setup_status(db: AsyncSession, user: User, now: Optional[datetime] = None) -> dict:
    routers = (await db.execute(
        select(Router.id, Router.name, Router.last_status, Router.last_checked_at, Router.last_online_at,
               Router.payment_methods, Router.payment_method_id)
        .where(Router.user_id == user.id).order_by(Router.id)
    )).all()
    plans = (await db.execute(
        select(Plan.id, Plan.name, Plan.is_hidden, Plan.valid_until)
        .where(Plan.user_id == user.id).order_by(Plan.id)
    )).all()
    methods = (await db.execute(
        select(ResellerPaymentMethod.id, ResellerPaymentMethod.label)
        .where(ResellerPaymentMethod.user_id == user.id, ResellerPaymentMethod.is_active.is_(True))
        .order_by(ResellerPaymentMethod.id)
    )).all()
    portal_phone = (await db.execute(
        select(PortalSettings.portal_support_phone).where(PortalSettings.user_id == user.id)
    )).scalar_one_or_none()
    rows = lambda result: [SimpleNamespace(**row._mapping) for row in result]  # noqa: E731
    return build_status(user, rows(routers), rows(plans), rows(methods), portal_phone, now=now)
