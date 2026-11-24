"""The right route, and so the right picture, for the questions resellers really ask.

The cases come from the admin frontend's app/lib/assistantIntents.json: real questions of
19-24 Nov 2026 (paraphrased, no names), each with its intent, the route that answers it and
the display that route always gets (the frontend's route rules in app/lib/assistantTables.ts
decide the drawing; the model's `show` is a hint). The page's side is tested there, without a
model. Here a real model gets each question in an account with routers, plans, customers and
payments, and must read the intent's route for whatever it draws (never, for example, the
router's raw account list or the bare ids of /api/realtime/customers/online for "who is online").

Found at ASSISTANT_INTENTS_FILE, else next to this repository
(../isp-billing-admin/app/lib/assistantIntents.json). Adding a case is one line in that file.
"""
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.assistant_eval_kit import KEY, ask, build, customer, plan, report, use_real_model
from tests.test_assistant import auth, client, owner, sse_events  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")

_HERE = Path(__file__).resolve()
_CANDIDATES = [os.environ.get("ASSISTANT_INTENTS_FILE", "")] + [
    str(p / "isp-billing-admin" / "app" / "lib" / "assistantIntents.json") for p in _HERE.parents[2:4]]
_FILE = next((p for p in _CANDIDATES if p and os.path.exists(p)), None)
_DATA = json.loads(Path(_FILE).read_text(encoding="utf-8")) if _FILE else {"intents": {}, "cases": []}

# a question that follows another ("show it in a table") or needs a record found first is asked once,
# alone; follow-ups are left to the deterministic page tests
_ALONE = [c for c in _DATA["cases"] if not re.match(r"^(show it|can you tell me their|show her|break down)", c["q"], re.I)]
_CASES = list({c["q"]: c for c in _ALONE}.values())


def _route_re(route: str) -> re.Pattern:
    path = route.split(" ", 1)[-1]
    return re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(path)) + "$")


@pytest.mark.skipif(not _FILE, reason="assistantIntents.json not found (set ASSISTANT_INTENTS_FILE)")
@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CASES, ids=[f"{c['intent']}:{c['q'][:40]}" for c in _CASES])
async def test_the_question_reads_the_intents_route(case, client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower", "River Road"],
                plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7), plan("Home 10M", 2500, days=30, kind="pppoe")],
                customers=[customer("Amina", "254700000101", "Daily 50", hours_left=5),
                           customer("Brian", "254700000102", "Weekly 300", hours_left=20),
                           customer("Carol", "254700000103", "Home 10M", hours_left=24 * 12,
                                    pppoe_username="carol-home"),
                           customer("Dan", "254700000104", "Daily 50", hours_left=-30, status="inactive")])
    use_real_model(monkeypatch)
    row = await ask(client, token, case["q"], monkeypatch)
    intent = _DATA["intents"][case["intent"]]
    want = _route_re(intent["route"])
    drawn = [d for d in row["drawn"] if d.get("show") not in (None, "none")]
    problems = []
    if drawn and not any(want.match((d.get("path") or "").split("?")[0]) for d in drawn):
        problems.append(f"drew {[d['path'] for d in drawn]}, wanted {intent['route']} ({intent['display']})")
    if any("/api/realtime/customers/online" in t for t in row["tools"]) and case["intent"] == "who_online" and not drawn:
        problems.append("answered who is online from bare ids")
    report(f"display-intents/{case['intent']}", row, problems)
    assert not problems, problems
