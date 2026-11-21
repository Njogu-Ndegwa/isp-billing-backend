"""Opt-in check against the real model: is a direct question answered directly?

Skipped unless ASSISTANT_EVAL_KEY holds a model key (the provider is the app's own
setting). One lived-in account (two routers, four plans, customers whose time ends
at different moments, some expired, one never paid, a few payments) and questions
asked from many angles: counts, names, yes/no, money, one person, an empty answer,
Swahili, and a couple of broad ones where a table is the right answer.

For each answer it checks what reached the screen, not only the words: how many
results were drawn (a direct question needs at most one), whether the same lookup
was drawn twice, whether the reply is short, and whether it names the right people
and leaves out the wrong ones. A report is written to ASSISTANT_EVAL_REPORT if set;
ASSISTANT_EVAL_ONLY runs the cases whose question contains that text.

    ASSISTANT_EVAL_KEY=... python -m pytest tests/test_assistant_answers_eval.py -s -n 4 -p no:warnings
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta

import pytest

from app.config import settings
from app.db.models import ConnectionType, CustomerPayment, CustomerStatus, PaymentMethod, PaymentStatus
from app.services.assistant import agent as agent_mod
from tests.factories import make_customer, make_plan, make_router
from tests.test_assistant import auth, client, owner, sse_events, visible_text  # noqa: F401  (fixtures)

KEY = os.environ.get("ASSISTANT_EVAL_KEY", "")
pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")


async def _lived_in(db, reseller):
    now = datetime.utcnow()
    main = await make_router(db, reseller, name="Main Tower")
    kahawa = await make_router(db, reseller, name="Kahawa AP")
    daily = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    weekly = await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    monthly = await make_plan(db, reseller, name="Monthly 1000", price=1000, duration_value=30)
    await make_plan(db, reseller, name="Diamond", price=2000, duration_value=30,
                    connection_type=ConnectionType.PPPOE, speed="10M/10M")
    people = [
        # name, phone, plan, router, status, hours until the time ends
        ("Amina Wanjiru", "254711000001", daily, main, CustomerStatus.ACTIVE, 5),
        ("Brian Otieno", "254711000002", weekly, main, CustomerStatus.ACTIVE, 30),
        ("Chebet Kiprop", "254711000003", weekly, main, CustomerStatus.ACTIVE, 60),
        ("David Mwangi", "254711000004", monthly, main, CustomerStatus.ACTIVE, 24 * 5),
        ("Esther Njeri", "254711000005", monthly, main, CustomerStatus.ACTIVE, 24 * 20),
        ("Faith Achieng", "254711000006", weekly, kahawa, CustomerStatus.ACTIVE, 24 * 4),
        ("George Kamau", "254711000007", weekly, main, CustomerStatus.INACTIVE, -48),
        ("Hassan Ali", "254711000008", daily, kahawa, CustomerStatus.INACTIVE, -24 * 10),
        ("Irene Wambui", "254711000009", daily, main, CustomerStatus.PENDING, None),
    ]
    made = {}
    for name, phone, plan, router, status, hours in people:
        made[name] = await make_customer(
            db, reseller, plan, router, name=name, phone=phone, status=status,
            expiry=None if hours is None else now + timedelta(hours=hours))
    for name, amount, days, ago_hours in [
        ("Amina Wanjiru", 50, 1, 2), ("Brian Otieno", 300, 7, 3),
        ("Chebet Kiprop", 300, 7, 30), ("Faith Achieng", 300, 7, 72), ("David Mwangi", 1000, 30, 24 * 25),
    ]:
        c = made[name]
        db.add(CustomerPayment(
            customer_id=c.id, reseller_id=reseller.id, amount=amount, payment_method=PaymentMethod.MOBILE_MONEY,
            days_paid_for=days, status=PaymentStatus.COMPLETED, plan_id=c.plan_id, router_id=c.router_id,
            customer_name=name, payment_date=now - timedelta(hours=ago_hours), created_at=now - timedelta(hours=ago_hours)))


# -- what counts as a good answer ----------------------------------------------------

def says(*words, all_=True):
    """The reply names these (all of them, or any one)."""
    def check(row):
        said = row["said_full"].lower()
        hits = [w for w in words if w.lower() in said]
        ok = len(hits) == len(words) if all_ else bool(hits)
        return None if ok else f"should mention {' and '.join(words) if all_ else ' or '.join(words)}"
    return check


def never_says(*words):
    def check(row):
        said = row["said_full"].lower()
        bad = [w for w in words if w.lower() in said]
        return f"wrongly mentions {', '.join(bad)}" if bad else None
    return check


def says_number(n):
    def check(row):
        return None if re.search(rf"(?<![\d,.]){n}(?![\d])", row["said_full"].replace(",", "")) else f"should say {n}"
    return check


def says_nothing_matches(row):
    return None if re.search(r"\b(no|none|nobody|hakuna|zero|0)\b", row["said_full"], re.I) else "should say plainly that there are none"


# (question, at most this many results drawn, checks)
CASES = [
    # who: a list of people, filtered
    ("Which customers expire within 3 days?", 1,
     [says("Amina", "Brian", "Chebet"), never_says("David", "Esther", "George")]),
    ("Who runs out today?", 1, [says("Amina"), never_says("Chebet", "David", "Esther")]),
    ("Nani ataisha leo?", 1, [says("Amina"), never_says("David", "Esther")]),
    ("Which customers have expired?", 1, [says("George", "Hassan"), never_says("Esther")]),
    ("Which customers are on Kahawa AP?", 1, [says("Faith"), never_says("Esther", "Brian")]),
    ("Who has never paid?", 1, [says("Irene")]),
    # how many: a figure, no table needed
    ("How many active customers do I have?", 1, [says_number(6)]),
    ("Wateja wangapi wako active?", 1, [says_number(6)]),
    ("How many plans do I have?", 1, [says_number(4)]),
    # one person or one thing
    ("Is Amina still active?", 1, [says("yes", "active", all_=False)]),
    ("When does Esther's time end?", 1, [says("Esther")]),
    ("What is Brian's phone number?", 1, [says("711000002")]),
    ("How much is the Weekly 300 plan?", 1, [says_number(300)]),
    ("Which router is Faith on?", 1, [says("Kahawa")]),
    # money
    ("How much did I make today?", 1, [says_number(350)]),
    ("What's my best selling plan?", 1, [says("Weekly")]),
    # nothing matches: say so, draw nothing
    ("Who expires in the next 2 hours?", 0, [says_nothing_matches, never_says("Amina", "Brian")]),
    ("Do I have any customers on the Diamond plan?", 0, [says_nothing_matches]),
    # broad: here a table or two is the answer
    ("Show me all my customers", 2, [says("9", "nine", all_=False)]),
    ("How is my business doing this week?", 2, []),
]

# a direct answer is a sentence or two; a broad one may use a short paragraph
WORD_LIMIT = {0: 60, 1: 70, 2: 140}


@pytest.mark.asyncio
@pytest.mark.parametrize("question,max_drawn,checks", CASES, ids=[q[:45] for q, _, _ in CASES])
async def test_a_direct_question_gets_a_direct_answer(client, owner, db, monkeypatch, question, max_drawn, checks):  # noqa: F811
    only = os.environ.get("ASSISTANT_EVAL_ONLY")
    if only and only.lower() not in question.lower():
        pytest.skip("not selected")
    reseller, token = owner
    await _lived_in(db, reseller)
    await db.commit()
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", KEY)
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", KEY if settings.ASSISTANT_PROVIDER == "claude" else "")
    agent_mod.set_client(None)

    r = await client.post("/api/assistant/chat", json={"message": question}, headers=auth(token), timeout=180)
    events = sse_events(r.text)
    data = [e for e in events if e["type"] == "data"]
    replaced = {e["replaces"] for e in data if e.get("replaces")}
    drawn = [e for e in data if e.get("show") != "none" and e["call_id"] not in replaced]
    looked = [e for e in events if e["type"] == "tool" or e["type"] == "trace"]
    text = visible_text(events)
    # what the person can read: the reply, and the names in what was drawn
    shown = json.dumps([e.get("payload") for e in drawn], ensure_ascii=False, default=str)
    row = {
        "question": question,
        "drawn": [f"{e['method']} {e['path']}{'?' + '&'.join(f'{k}={v}' for k, v in (e.get('query') or {}).items()) if e.get('query') else ''} [{e['show']}]" for e in drawn],
        "lookups": len(data),
        "words": len(text.split()),
        "said": re.sub(r"\s+", " ", text)[:400],
        "said_full": text + "\n" + shown,
        "steps": len(looked),
    }
    problems = [p for p in (c(row) for c in checks) if p]
    if len(drawn) > max_drawn:
        problems.append(f"drew {len(drawn)} results, wanted at most {max_drawn}")
    paths = [d.split(" [")[0] for d in row["drawn"]]
    if len(set(paths)) < len(paths):
        problems.append("drew the same lookup twice")
    if row["words"] > WORD_LIMIT[max_drawn]:
        problems.append(f"{row['words']} words, wanted at most {WORD_LIMIT[max_drawn]}")
    if not text:
        problems.append("said nothing")
    row["problem"] = "; ".join(problems) or None
    row.pop("said_full")
    print(json.dumps(row, ensure_ascii=False))
    if os.environ.get("ASSISTANT_EVAL_REPORT"):
        with open(os.environ["ASSISTANT_EVAL_REPORT"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    assert not problems, row["problem"]
