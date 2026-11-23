"""Asks for things Bitwave cannot do yet, phrased as questions (chat review CR-1123-F7).

A "no" about what the product does is written down for Bitwave in the same turn
(POST /api/feedback/requests); a "no" that a setup step fixes is not (the person is
told what to set up). The scripted-model checks of the same rule are in
tests/test_assistant_record_asks.py.
"""
import pytest

from tests.assistant_eval_kit import KEY, ask, build, customer, evaluate, plan, report, use_real_model
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")

RECORD = "call_api POST /api/feedback/requests"
HOTSPOT = [plan("3 Hour Boost", 10, days=1), plan("Daily pass", 35), plan("Weekly unlimited", 180, days=7)]


def records_the_ask(row):
    return None if any(t.startswith(RECORD) for t in row["tools"]) else f"did not record the ask; tools {row['tools']}"


def records_nothing(row):
    return f"recorded a request for a setup gap; tools {row['tools']}" if any(t.startswith(RECORD) for t in row["tools"]) else None


@pytest.mark.asyncio
async def test_whatsapp_messages_question_is_recorded(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT, sms_credits=200)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Can we send automatic whatsapp messages?", monkeypatch)
    problems = evaluate(row, [records_the_ask])
    report("feature-ask/whatsapp", row, problems)
    assert not problems, problems


@pytest.mark.asyncio
async def test_price_comparison_question_is_recorded_as_a_benchmark(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Comparing it to other hotspoters....how affordable are my plans?", monkeypatch)
    problems = evaluate(row, [records_the_ask])
    report("feature-ask/price-benchmark", row, problems)
    assert not problems, problems


@pytest.mark.asyncio
async def test_rebooting_a_home_router_without_its_password_is_a_setup_step(client, owner, db, monkeypatch):  # noqa: F811
    """Rebooting a customer's own router works once its admin password is saved: say what to set
    up, offer the session reset; nothing to record."""
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[plan("Home 10M", 2000, days=30, kind="pppoe")],
                customers=[customer("Amina", "254711000001", "Home 10M", hours_left=300,
                                    pppoe_username="ACC0001")])
    use_real_model(monkeypatch)
    row = await ask(client, token, "Can you restart Amina's home router?", monkeypatch)
    problems = evaluate(row, [records_nothing])
    report("feature-ask/home-router-reboot", row, problems)
    assert not problems, problems
