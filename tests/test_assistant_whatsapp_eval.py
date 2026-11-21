"""Opt-in check against the real model: does the assistant answer like Bitwave support did?

The questions are real ones resellers sent on WhatsApp, each with the answer Bitwave
support gave (the "gold"). They live in the WhatsApp corpus on the support laptop,
not in this repo: ASSISTANT_WHATSAPP_CASES points at eval-set.md (default: the
whatsapp-corpus folder beside this repo). Skipped unless that file and
ASSISTANT_EVAL_KEY (a real model key) are both there.

Each question is asked in a fresh chat on a lived-in account (routers, plans,
customers, payments). A second model call grades the reply against the gold on
what matters to the reseller: the same diagnosis or first move, the same facts,
the right action (a form, a lookup, telling them to contact Bitwave), not the
wording. The gold is support's reply on the day: prices and features may have
moved on since, and the grader is told so. Pre-sales questions are left out (a
signed-in reseller asks them rarely, and their answers are mostly prices).

    ASSISTANT_EVAL_KEY=... python -m pytest tests/test_assistant_whatsapp_eval.py -s -n 4 -p no:warnings

A report goes to ASSISTANT_EVAL_REPORT if set; ASSISTANT_EVAL_ONLY picks cases by text.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from app.config import settings
from app.services.assistant import agent as agent_mod
from tests.test_assistant import auth, client, owner, sse_events, visible_text  # noqa: F401  (fixtures)
from tests.test_assistant_answers_eval import _lived_in

KEY = os.environ.get("ASSISTANT_EVAL_KEY", "")
CASES_FILE = Path(os.environ.get("ASSISTANT_WHATSAPP_CASES")
                  or Path(__file__).resolve().parents[2] / "whatsapp-corpus" / "eval-set.md")
# Only conversations support saw through to a resolution: pre-sales leads (prices,
# not the dashboard) and bug/feature reports (captured, not resolved) are left out,
# and so is any case whose gold is a target answer or says it went unanswered.
SKIP_CATEGORIES = ("pre-sales", "bugs & features")
UNRESOLVED = re.compile(r"(?i)\bunanswered\b|author target|GOLD\(target\)|not captured|none existed")


def load_cases() -> list[dict]:
    """'N. IN: "question" [context] → GOLD: answer (THREAD)' lines, under '## Category: x' headings."""
    if not CASES_FILE.is_file():
        return []
    cases, category = [], ""
    for line in CASES_FILE.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^## Category:\s*(.+)$", line)
        if heading:
            category = heading.group(1).strip().lower()
            continue
        m = re.match(r"^\d+\.\s+IN:\s*(.+?)\s*→\s*GOLD:\s*(.+)$", line)
        if not m or category.startswith(SKIP_CATEGORIES) or UNRESOLVED.search(m.group(2)):
            continue
        said = " ".join(re.findall(r'"([^"]+)"', m.group(1)))
        context = " ".join(re.findall(r"\[([^\]]+)\]", m.group(1)))
        if not said:
            continue  # only a description of what was sent, nothing to ask
        gold = re.sub(r"\s*\((?:[A-Z]+-\d+)[^)]*\)\s*$", "", m.group(2)).strip()  # drop the thread name
        gold = re.sub(r"\s*\+\s*\(target\)[^.]*", "", gold)  # what support wished it had done, not what it did
        cases.append({"category": category, "question": said, "context": context, "gold": gold})
    return cases


RESOLVED_FILE = CASES_FILE.with_name("eval-resolved.jsonl")


def load_resolved() -> list[dict]:
    """More resolved conversations, mined from the raw threads (one JSON object per line)."""
    if not RESOLVED_FILE.is_file():
        return []
    out = []
    for line in RESOLVED_FILE.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("question") and row.get("gold"):
            out.append({"category": row.get("category", ""), "question": row["question"],
                        "context": row.get("context", ""), "gold": row["gold"]})
    return out


CASES = load_cases() + load_resolved()


async def _healthy_routers(db, reseller, monkeypatch):
    """The account's routers answer like healthy ones: online all day, and a RouterOS
    stand-in for live reads (the test routers do not exist, and "the router is
    unreachable" would otherwise be the answer to every router question)."""
    from datetime import datetime, timedelta

    from sqlalchemy import select

    from app.db.models import Router, RouterAvailabilityCheck
    from app.services.mikrotik_api import MikroTikAPI
    from tests.fake_routeros import FakeRouterOS, typical_router_menus

    now = datetime.utcnow()
    for router in (await db.execute(select(Router).where(Router.user_id == reseller.id))).scalars():
        for minutes in range(0, 24 * 60, 10):
            db.add(RouterAvailabilityCheck(router_id=router.id, checked_at=now - timedelta(minutes=minutes),
                                           is_online=True, source="eval"))
    menus = typical_router_menus()
    menus.update({
        "/system/resource": [{"uptime": "6d4h12m", "cpu-load": "18", "free-memory": "41943040",
                              "total-memory": "134217728", "board-name": "hAP ac2", "version": "7.16.2",
                              "architecture-name": "arm"}],
        "/system/identity": [{"name": "Main Tower"}],
        "/system/routerboard": [{"model": "RBD52G-5HacD2HnD", "routerboard": "true"}],
        "/interface": [{"name": n, "type": "ether", "running": "true", "disabled": "false",
                        "rx-byte": str(9_000_000_000 // (i + 1)), "tx-byte": str(2_000_000_000 // (i + 1)),
                        "rx-packet": str(9_000_000 // (i + 1)), "tx-packet": str(4_000_000 // (i + 1)),
                        "rx-error": "0", "tx-error": "0", "link-downs": "1"}
                       for i, n in enumerate(("ether1", "ether2", "ether3", "ether4", "ether5"))]
                      + [{"name": "pwr-line1", "type": "plc", "running": "false", "disabled": "false"}],
        "/ip/hotspot/active": [{"user": f"c{i}", "address": f"192.168.88.{20 + i}", "mac-address": f"AA:BB:CC:00:00:{i:02X}",
                                "uptime": "1h2m"} for i in range(12)],
        "/ip/hotspot/host": [], "/log": [],
        "/interface/bridge/host": [{"mac-address": f"AA:BB:CC:00:00:{i:02X}", "on-interface": f"ether{2 + i % 3}",
                                    "bridge": "bridge"} for i in range(12)],
    })

    def init(self, *args, **kwargs):
        FakeRouterOS.__init__(self, menus)

    monkeypatch.setattr(MikroTikAPI, "__init__", init)
    for name in ("connect", "disconnect", "send_command", "send_command_optimized"):
        monkeypatch.setattr(MikroTikAPI, name, getattr(FakeRouterOS, name))
pytestmark = pytest.mark.skipif(not (KEY and CASES), reason="needs ASSISTANT_EVAL_KEY and the WhatsApp eval set")

JUDGE = """You grade an AI assistant built into an ISP billing dashboard (Bitwave) for resellers who run
hotspot and PPPoE WiFi businesses in Kenya. A reseller sent this on WhatsApp; Bitwave support's
own answer is the gold. Grade the assistant's reply against the gold on substance:
- the same diagnosis, cause or first move (the question support asked first counts as the move);
- the same facts (how the product works, what to do);
- the right action: opening a form, looking up the account, or saying Bitwave must check / will fix it.
Wording, language and length do not matter. The gold is support's reply on that day: prices,
features and bugs may have changed since, so do not mark down a reply for a newer fact, only for
contradicting how things work, for a wrong cause, for inventing a capability, or for missing the
point. A reply that asks one good question that tells the causes apart is as good as the gold's.
The test account's data is made up (two routers, a few plans and customers): judge the reasoning
and the advice, not whether its figures match the reseller's real account.

Reply with JSON only: {"score": 0|1|2, "why": "one sentence"}
2 = same substance as the gold (or better); 1 = partly right or vaguer; 0 = wrong, misleading or off-topic."""


async def _grade(question: str, context: str, gold: str, reply: str, actions: list[str]) -> dict:
    import anthropic

    judge = anthropic.AsyncAnthropic(api_key=KEY, base_url=agent_mod.PROVIDERS["deepseek"]["base_url"])
    shown = f"\n[Cards it showed: {', '.join(actions)}]" if actions else ""
    message = await judge.messages.create(
        model=agent_mod.PROVIDERS["deepseek"]["model"], max_tokens=1500, system=JUDGE,
        thinking={"type": "disabled"},
        messages=[{"role": "user", "content": (
            f"Reseller's message: {question}\n" + (f"[Context: {context}]\n" if context else "")
            + f"\nGold (support's answer): {gold}\n\nAssistant's reply: {reply}{shown}")}])
    text = "".join(getattr(b, "text", "") for b in message.content)
    m = re.search(r"\{.*\}", text, re.S)
    try:
        return json.loads(m.group(0)) if m else {"score": 0, "why": f"unreadable grade: {text[:120]}"}
    except json.JSONDecodeError:
        return {"score": 0, "why": f"unreadable grade: {text[:120]}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=[f"{i:02d}-{c['question'][:36]}" for i, c in enumerate(CASES)])
async def test_answers_like_bitwave_support_did(client, owner, db, monkeypatch, case):  # noqa: F811
    only = os.environ.get("ASSISTANT_EVAL_ONLY")
    if only and only.lower() not in case["question"].lower():
        pytest.skip("not selected")
    reseller, token = owner
    await _lived_in(db, reseller)
    from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType

    # a working business takes payments: customers pay into the reseller's paybill
    db.add(ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_PAYBILL,
                                 label="Shop Paybill", mpesa_paybill_number="600980", is_active=True))
    await db.flush()
    await _healthy_routers(db, reseller, monkeypatch)
    await db.commit()
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", KEY)
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", KEY if settings.ASSISTANT_PROVIDER == "claude" else "")
    agent_mod.set_client(None)

    tools_used: list[str] = []
    original = agent_mod.Turn._run_tool

    async def recording(self, block):
        tools_used.append(block.get("name") + (f" {block['input'].get('path') or block['input'].get('symptom') or block['input'].get('id') or ''}"
                                               if isinstance(block.get("input"), dict) else ""))
        return await original(self, block)

    monkeypatch.setattr(agent_mod.Turn, "_run_tool", recording)
    r = await client.post("/api/assistant/chat", json={"message": case["question"]}, headers=auth(token), timeout=240)
    events = sse_events(r.text)
    reply = visible_text(events).strip()
    actions = [f"{e['method']} {e['path']}" for e in events if e["type"] == "action"]
    grade = await _grade(case["question"], case["context"], case["gold"], reply or "(said nothing)", actions)
    row = {"category": case["category"], "question": case["question"][:160], "gold": case["gold"][:300],
           "said": re.sub(r"\s+", " ", reply)[:500], "cards": actions, "tools": tools_used[:12],
           "score": grade.get("score"), "why": grade.get("why")}
    print(json.dumps(row, ensure_ascii=False))
    if os.environ.get("ASSISTANT_EVAL_REPORT"):
        with open(os.environ["ASSISTANT_EVAL_REPORT"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    assert grade.get("score", 0) >= 1, f"{grade.get('why')} | said: {row['said'][:200]}"
