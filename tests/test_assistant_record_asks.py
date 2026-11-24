"""A reseller asks for something Bitwave cannot do yet, phrased as a question.

The rule in the system prompt says to write the ask down (POST /api/feedback/requests)
whenever the answer is "no / not yet / I can't / Bitwave doesn't" about what the person
wants the product to do, questions included. When the model says no and records
nothing, the turn gets a ``review_flag`` transcript entry the daily chat review counts
(the chat screen does not draw it). Nothing is recorded automatically.

The model is scripted here; the real-model versions of these asks are in
tests/workflow_eval/test_feature_asks.py.
"""
import pytest
from sqlalchemy import select

from app.services.assistant import agent as agent_mod
from tests.test_assistant import (auth, client, owner, sse_events, text_reply, tool_reply,  # noqa: F401
                                  use_model)

FLAG = "capability_no_unrecorded"


def test_the_rule_covers_questions_and_names_what_not_to_record():
    prompt = agent_mod.SYSTEM_TEMPLATE
    for phrase in ('"Can we...?"', '"Is it possible...?"', '"Does Bitwave...?"', "in the same turn",
                   "anonymous price benchmark", "sets it up"):
        assert phrase in prompt, phrase
    # the how-to rule no longer ends the matter at "no"
    assert "it is a feature request too" in prompt


@pytest.mark.parametrize("answer", [
    "No — Bitwave sends SMS messages (expiry reminders), not WhatsApp. The nearest thing is SMS.",
    "I can't see other resellers' price lists — Bitwave doesn't share them — so I can't rank you.",
    "I can’t reboot the customer's home router yet — Bitwave has no saved admin password for it.",
    "Not yet: Bitwave has no way to post to Facebook for you.",
])
def test_a_capability_no_is_spotted(answer):
    assert agent_mod.capability_no(answer)


@pytest.mark.parametrize("answer", [
    "No customers are online right now on Main Tower.",
    "No, nobody has paid since 20:06 last night.",
    "Yes — open Messaging, pick the customers and write the SMS.",
    "I can't find a customer named Wanjiru; did you mean Wanjiku?",
    "45 customers are online right now. I can't say why one dropped without the router log.",
])
def test_ordinary_answers_are_not_spotted(answer):
    assert agent_mod.capability_no(answer) is None


async def _transcript(client, token, events):
    conv = next(e["conversation_id"] for e in events if e["type"] == "done")
    r = await client.get(f"/api/assistant/conversations/{conv}", headers=auth(token))
    return r.json()["transcript"]


@pytest.mark.asyncio
async def test_a_no_without_a_recorded_ask_is_flagged_for_the_review(client, owner, db):  # noqa: F811
    from app.db.models import FeedbackPost

    reseller, token = owner
    use_model([text_reply("No — Bitwave sends SMS messages, not WhatsApp. The nearest thing is SMS "
                          "through the messaging page.\n\nNEXT: How many SMS credits do I have?")])
    r = await client.post("/api/assistant/chat", json={"message": "Can we send automatic whatsapp messages?"},
                          headers=auth(token))
    events = sse_events(r.text)
    assert not any(e["type"] == "review_flag" for e in events)    # never sent to the screen
    flags = [t for t in await _transcript(client, token, events) if t["type"] == "review_flag"]
    assert [f["flag"] for f in flags] == [FLAG]
    assert (await db.execute(select(FeedbackPost))).scalars().all() == []   # nothing recorded by itself


@pytest.mark.asyncio
async def test_a_no_with_the_ask_recorded_is_not_flagged(client, owner, db, monkeypatch):  # noqa: F811
    import app.api.feedback_routes as fr
    from app.db.models import FeedbackPost

    async def _no_triage(_post_id):
        return None
    monkeypatch.setattr(fr, "run_feedback_triage", _no_triage)

    reseller, token = owner
    use_model([
        tool_reply("call_api", {"method": "POST", "path": "/api/feedback/requests",
                                "body": {"title": "Automatic WhatsApp messages",
                                         "asked": "Can we send automatic whatsapp messages?"}}),
        text_reply("No — Bitwave sends SMS, not WhatsApp yet. I've noted it for Bitwave."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Can we send automatic whatsapp messages?"},
                          headers=auth(token))
    events = sse_events(r.text)
    assert not any(t["type"] == "review_flag" for t in await _transcript(client, token, events))
    [post] = (await db.execute(select(FeedbackPost))).scalars().all()
    assert post.source == "assistant"


@pytest.mark.asyncio
async def test_a_how_to_answer_is_not_flagged(client, owner):  # noqa: F811
    reseller, token = owner
    use_model([text_reply("Yes — open Messaging, pick who gets it and write the SMS.")])
    r = await client.post("/api/assistant/chat", json={"message": "Can I send an SMS to my customers?"},
                          headers=auth(token))
    events = sse_events(r.text)
    assert not any(t["type"] == "review_flag" for t in await _transcript(client, token, events))


@pytest.mark.asyncio
async def test_an_answer_written_with_the_recorded_ask_stays_on_screen(client, owner, monkeypatch):  # noqa: F811
    """CR-1124-T1: the model answered and recorded the ask in one message; the answer was
    taken back as a working note and only "Noted for Bitwave" was left on screen."""
    import app.api.feedback_routes as fr
    from tests.test_assistant import visible_text

    async def _no_triage(_post_id):
        return None
    monkeypatch.setattr(fr, "run_feedback_triage", _no_triage)

    reseller, token = owner
    use_model([
        tool_reply("call_api", {"method": "POST", "path": "/api/feedback/requests",
                                "body": {"title": "Automatic WhatsApp messages",
                                         "asked": "Can we send automatic whatsapp messages?"}},
                   text="No — Bitwave can't send WhatsApp messages yet. Automatic customer messages "
                        "(welcome, payment receipt, expiry reminder) go out by SMS."),
        text_reply("Passed to Bitwave; another reseller asked for it too."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Can we send automatic whatsapp messages?"},
                          headers=auth(token))
    shown = visible_text(sse_events(r.text))
    assert shown.startswith("No — Bitwave can't send WhatsApp messages yet.")
    assert "go out by SMS" in shown and shown.endswith("another reseller asked for it too.")


def test_the_rule_says_answer_first_then_the_note():
    prompt = agent_mod.SYSTEM_TEMPLATE
    assert "never the whole reply" in prompt
