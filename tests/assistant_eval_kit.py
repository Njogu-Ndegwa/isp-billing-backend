"""Shared kit for real-model scenario evals of the assistant (opt-in, never in CI).

A scenario is an account in a given state, one or more messages from a reseller,
and checks on what came back: the words, the cards (forms or confirms), each form's
fields as the page would show them (conditions applied), each picker's options,
and the tools the assistant used. Every run is appended to ASSISTANT_EVAL_REPORT
(JSON Lines) when set, so a team can compare runs.

    ASSISTANT_EVAL_KEY=... python -m pytest tests/workflow_eval -s -n 4 -p no:warnings

Building an account (all optional, names are free):

    await build(db, reseller, routers=["Main Tower"],
                plans=[plan("Daily 50", 50, days=1), plan("Home 10M", 2000, days=30, kind="pppoe")],
                customers=[customer("Amina", "254711000001", "Daily 50", hours_left=5)],
                payment_methods=["mpesa_paybill"], sms_credits=200, healthy_routers=monkeypatch)
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

from app.config import settings
from app.db.models import ConnectionType, CustomerStatus
from app.services.assistant import agent as agent_mod
from tests.factories import make_customer, make_plan, make_router
from tests.test_assistant import auth, sse_events, visible_text

KEY = os.environ.get("ASSISTANT_EVAL_KEY", "")


# -- accounts ------------------------------------------------------------------------

@dataclass
class PlanSpec:
    name: str
    price: int
    days: int = 1
    kind: str = "hotspot"          # hotspot | pppoe | static_ip
    speed: str = "5M/5M"
    plan_type: str = "regular"     # regular | free_trial | emergency
    data_cap_mb: Optional[int] = None


def plan(name, price, days=1, kind="hotspot", speed="5M/5M", plan_type="regular", data_cap_mb=None) -> PlanSpec:
    return PlanSpec(name, price, days, kind, speed, plan_type, data_cap_mb)


@dataclass
class CustomerSpec:
    name: str
    phone: str
    plan: str
    router: Optional[str] = None
    hours_left: Optional[float] = 24
    status: str = "active"         # active | inactive | pending
    extra: dict = field(default_factory=dict)


def customer(name, phone, plan_name, router=None, hours_left=24, status="active", **extra) -> CustomerSpec:
    return CustomerSpec(name, phone, plan_name, router, hours_left, status, extra)


async def build(db, reseller, *, routers=(), plans=(), customers=(), payment_methods=(), sms_credits=None,
                portal=None, healthy_routers=None) -> dict:
    """Make the account; returns {"routers": {name: Router}, "plans": {...}, "customers": {...}}."""
    from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType

    made = {"routers": {}, "plans": {}, "customers": {}}
    for name in routers:
        made["routers"][name] = await make_router(db, reseller, name=name)
    kinds = {"hotspot": ConnectionType.HOTSPOT, "pppoe": ConnectionType.PPPOE, "static_ip": ConnectionType.STATIC_IP}
    for p in plans:
        extra = {}
        if p.plan_type != "regular":
            from app.db.models import PlanType
            extra["plan_type"] = PlanType(p.plan_type)
        if p.data_cap_mb:
            extra["data_cap_mb"] = p.data_cap_mb
        made["plans"][p.name] = await make_plan(db, reseller, name=p.name, price=p.price, duration_value=p.days,
                                                connection_type=kinds[p.kind], speed=p.speed, **extra)
    statuses = {"active": CustomerStatus.ACTIVE, "inactive": CustomerStatus.INACTIVE, "pending": CustomerStatus.PENDING}
    now = datetime.utcnow()
    first_router = next(iter(made["routers"].values()), None)
    for c in customers:
        router = made["routers"].get(c.router) if c.router else first_router
        made["customers"][c.name] = await make_customer(
            db, reseller, made["plans"][c.plan], router, name=c.name, phone=c.phone, status=statuses[c.status],
            expiry=None if c.hours_left is None else now + timedelta(hours=c.hours_left), **c.extra)
    for kind in payment_methods:
        fields = {"mpesa_paybill": {"mpesa_paybill_number": "600980"}, "mpesa_till": {"mpesa_till_number": "123456"},
                  "bank_account": {"bank_paybill_number": "247247", "bank_account_number": "0170299999999"}}[kind]
        db.add(ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType(kind),
                                     label=kind.replace("_", " ").title(), is_active=True, **fields))
    if sms_credits is not None:
        from tests.factories import make_sms_account
        await make_sms_account(db, reseller, balance=sms_credits)
    if portal:
        from app.db.models import PortalSettings
        db.add(PortalSettings(user_id=reseller.id, **portal))
    await db.flush()
    if healthy_routers is not None:
        await _healthy_routers(db, reseller, healthy_routers)
    await db.commit()
    return made


async def _healthy_routers(db, reseller, monkeypatch):
    """Routers answer like healthy ones: online all day, a RouterOS stand-in for live reads."""
    from sqlalchemy import select

    from app.db.models import Router, RouterAvailabilityCheck
    from app.services.mikrotik_api import MikroTikAPI
    from tests.fake_routeros import FakeRouterOS, typical_router_menus

    now = datetime.utcnow()
    for router in (await db.execute(select(Router).where(Router.user_id == reseller.id))).scalars():
        for minutes in range(0, 24 * 60, 30):
            db.add(RouterAvailabilityCheck(router_id=router.id, checked_at=now - timedelta(minutes=minutes),
                                           is_online=True, source="eval"))
    menus = typical_router_menus()
    menus.update({
        "/system/resource": [{"uptime": "6d4h", "cpu-load": "18", "free-memory": "41943040",
                              "total-memory": "134217728", "board-name": "hAP ac2", "version": "7.16.2"}],
        "/interface": [{"name": f"ether{i}", "type": "ether", "running": "true", "disabled": "false",
                        "rx-byte": "900000000", "tx-byte": "200000000"} for i in range(1, 6)],
        "/ip/hotspot/active": [], "/ip/hotspot/host": [], "/log": [],
    })

    def init(self, *a, **k):
        FakeRouterOS.__init__(self, menus)

    monkeypatch.setattr(MikroTikAPI, "__init__", init)
    for name in ("connect", "disconnect", "send_command", "send_command_optimized"):
        monkeypatch.setattr(MikroTikAPI, name, getattr(FakeRouterOS, name))


# -- running a scenario --------------------------------------------------------------

def use_real_model(monkeypatch) -> None:
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", KEY)
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", KEY if settings.ASSISTANT_PROVIDER == "claude" else "")
    agent_mod.set_client(None)


def _shown(card: dict) -> list[str]:
    """The fields the page shows: conditions applied, a record picker's kind read from its option_attrs."""
    form = card.get("form") or []
    values = {f["name"]: f.get("value") for f in form}

    def holds(choice, allowed):
        base, _, attr = choice.partition(".")
        v = values.get(base)
        if attr:
            picker = next((f for f in form if f["name"] == base), {})
            v = (picker.get("option_attrs") or {}).get(attr, {}).get(str(v)) if v not in (None, "") else None
        if isinstance(v, bool):
            v = "true" if v else ""
        if v in (None, "", []):
            return False
        return "*" in allowed or str(v).lower() in {a.lower() for a in allowed}

    return [f["name"] for f in form if all(holds(c, a) for c, a in (f.get("when") or {}).items())]


def _card(e: dict) -> dict:
    form = e.get("form") or []
    pickers = {f["name"]: [f.get("option_labels", {}).get(o, o) for o in f.get("options", [])]
               for f in form if f.get("option_labels")}
    prefilled = {f["name"]: f.get("option_labels", {}).get(str(f.get("value")), f.get("value"))
                 for f in form if f.get("value") not in (None, "", [])}
    return {"method": e["method"], "path": e["path"], "summary": e.get("summary", ""), "form": bool(form),
            "shown": _shown(e), "pickers": pickers, "prefilled": prefilled, "body": e.get("body")}


async def ask(client, token, question: str, monkeypatch, conversation_id: Optional[str] = None) -> dict:
    """One message; returns what reached the screen and how the assistant got there."""
    tools: list[str] = []
    errors: list[str] = []
    original_run, original_result = agent_mod.Turn._run_tool, agent_mod.Turn._tool_result

    async def run_tool(self, block):
        args = block.get("input") if isinstance(block.get("input"), dict) else {}
        tools.append(f"{block.get('name')} {args.get('method', '')} {args.get('path') or args.get('symptom') or args.get('id') or ''}".strip())
        return await original_run(self, block)

    def tool_result(tool_use_id, payload, is_error=False):
        if is_error:
            errors.append(str(payload.get("error", payload) if isinstance(payload, dict) else payload)[:300])
        return original_result(tool_use_id, payload, is_error)

    monkeypatch.setattr(agent_mod.Turn, "_run_tool", run_tool)
    monkeypatch.setattr(agent_mod.Turn, "_tool_result", staticmethod(tool_result))
    r = await client.post("/api/assistant/chat",
                          json={"message": question, **({"conversation_id": conversation_id} if conversation_id else {})},
                          headers=auth(token), timeout=240)
    events = sse_events(r.text)
    monkeypatch.setattr(agent_mod.Turn, "_run_tool", original_run)
    monkeypatch.setattr(agent_mod.Turn, "_tool_result", staticmethod(original_result))
    cards = [_card(e) for e in events if e["type"] == "action"]
    conv = next((e.get("id") for e in events if e["type"] == "conversation"), None) or         next((e.get("conversation_id") for e in events if e["type"] == "done"), None)
    said = re.sub(r"\s+", " ", visible_text(events)).strip()
    said = re.split(r"\s*\[?NEXT:", said)[0].strip()  # the suggested follow-ups are not the answer
    return {"question": question, "said": said,
            "cards": cards, "tools": tools, "errors": errors, "conversation_id": conv}


def report(scenario: str, row: dict, problems: list[str]) -> None:
    out = {"scenario": scenario, **{k: row[k] for k in ("question", "said", "tools", "errors")},
           "cards": row["cards"], "problems": problems}
    print(json.dumps(out, ensure_ascii=False, default=str)[:4000])
    path = os.environ.get("ASSISTANT_EVAL_REPORT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(out, ensure_ascii=False, default=str) + "\n")


# -- checks: each returns a problem in words, or None --------------------------------

Check = Callable[[dict], Optional[str]]


def card_for(method: str, path_part: str) -> Check:
    def check(row):
        return None if any(c["method"] == method and path_part in c["path"] for c in row["cards"]) \
            else f"wanted a {method} card for ...{path_part}, got {[c['method'] + ' ' + c['path'] for c in row['cards']]}"
    return check


def no_card(row) -> Optional[str]:
    return None if not row["cards"] else f"proposed {[c['path'] for c in row['cards']]} where nothing should be proposed"


def picker_only(field_name: str, allowed: list[str], forbidden: list[str] = ()) -> Check:
    """The form's picker for field_name offers these options (by label) and none of the forbidden ones."""
    def check(row):
        for c in row["cards"]:
            opts = c["pickers"].get(field_name)
            if opts is None:
                continue
            missing = [a for a in allowed if not any(a.lower() in o.lower() for o in opts)]
            wrong = [o for o in opts if any(f.lower() in o.lower() for f in forbidden)]
            if missing or wrong:
                return f"{field_name} picker offers {opts}" + (f", missing {missing}" if missing else "") + (f", should not offer {wrong}" if wrong else "")
            return None
        return f"no {field_name} picker on any card"
    return check


def prefilled(**expected) -> Check:
    def check(row):
        got = {}
        for c in row["cards"]:
            got.update(c["prefilled"])
        bad = [f"{k}={got.get(k)!r} (wanted {v!r})" for k, v in expected.items()
               if v is not ... and str(v).lower() not in str(got.get(k, "")).lower() or (v is ... and k not in got)]
        return None if not bad else "prefilled wrong: " + ", ".join(bad)
    return check


def shows(*names, never=()) -> Check:
    def check(row):
        shown = set(n for c in row["cards"] for n in c["shown"])
        missing = [n for n in names if n not in shown]
        wrong = sorted(n for n in shown if any(n.startswith(p) for p in never))
        if missing:
            return f"form should show {missing}"
        return f"form shows {wrong} which do not apply" if wrong else None
    return check


def says(*words, any_=False) -> Check:
    def check(row):
        text = row["said"].lower()
        hits = [w for w in words if w.lower() in text]
        ok = bool(hits) if any_ else len(hits) == len(words)
        return None if ok else f"should mention {' or '.join(words) if any_ else ' and '.join(words)}"
    return check


def never_says(*words) -> Check:
    def check(row):
        bad = [w for w in words if w.lower() in row["said"].lower()]
        return None if not bad else f"wrongly says {bad}"
    return check


def any_of(*checks: Check) -> Check:
    def check(row):
        results = [c(row) for c in checks]
        return None if any(r is None for r in results) else " / ".join(r for r in results if r)
    return check


def evaluate(row: dict, checks: list[Check]) -> list[str]:
    problems = [p for p in (c(row) for c in checks) if p]
    if not row["said"] and not row["cards"]:
        problems.append("said nothing and proposed nothing")
    return problems
