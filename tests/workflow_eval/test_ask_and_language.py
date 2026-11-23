"""Unclear messages and the reply language (CR-1123-F5).

A message that can be read two ways gets one short question back, not a guess; a short
English message gets an English answer, never a Kiswahili opener.
"""
import re

import pytest

from tests.assistant_eval_kit import KEY, ask, build, customer, evaluate, no_card, plan, report, use_real_model
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")

SWAHILI_OPENERS = {"nimeangalia", "sawa", "habari", "pole", "ndio", "hakuna", "wateja", "kuna", "hapana", "nimeona"}


def asks_one_question(row) -> str | None:
    """Ends on a question to the person, with no invented plan-price comparison."""
    said = row["said"]
    if "?" not in said:
        return f"should ask what they meant, said {said[:200]!r}"
    if len(re.findall(r"KES\s*\d+", said)) >= 2:
        return "compared prices instead of asking"
    return None


def english_from_the_first_word(row) -> str | None:
    words = re.findall(r"[a-z]+", row["said"].lower())[:2]
    hit = [w for w in words if w in SWAHILI_OPENERS]
    return f"opened in Kiswahili: {row['said'][:60]!r}" if hit else None


@pytest.mark.asyncio
async def test_two_figures_that_disagree_get_a_clarifying_question(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"],
                plans=[plan("8 Hours 40", 40, days=1), plan("Daily 70", 70, days=1)],
                customers=[customer("Amina", "254711000001", "Daily 70", hours_left=5)])
    use_real_model(monkeypatch)
    row = await ask(client, token, "Why is toda in 25 while sm seeing 40", monkeypatch)
    problems = evaluate(row, [asks_one_question, no_card])
    report("ask/two-figures-disagree", row, problems)
    assert not problems, problems


@pytest.mark.asyncio
async def test_short_english_gets_an_english_answer(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50)],
                customers=[customer("Amina", "254711000001", "Daily 50", hours_left=5),
                           customer("Brian", "254711000002", "Daily 50", hours_left=-3, status="inactive")],
                healthy_routers=monkeypatch)
    use_real_model(monkeypatch)
    row = await ask(client, token, "There is any clint are go discanted", monkeypatch)
    problems = evaluate(row, [english_from_the_first_word])
    report("language/short-english-stays-english", row, problems)
    assert not problems, problems
