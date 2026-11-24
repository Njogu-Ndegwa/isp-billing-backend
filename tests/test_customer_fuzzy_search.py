"""Customer search that survives a typo (CR-1123-F5): "fordowsa" finds no one by "contains",
so the list offers Fardowsa as a close match in `did_you_mean`, and the assistant offers it."""
import json
import time

import pytest

from app.services import customer_fuzzy
from tests.factories import make_customer, make_plan
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, sse_events, text_reply, tool_reply, tool_results, use_model,
)


async def _account(db, reseller):
    plan = await make_plan(db, reseller, name="Home 5M", price=1500, duration_value=30)
    await make_customer(db, reseller, plan, name="Fardowsa", phone="254711222333", account_number="KH1001")
    await make_customer(db, reseller, plan, name="Mary Wanjiru", phone="254722000111", account_number="KH1002")
    await make_customer(db, reseller, plan, name="Otieno Brian", phone="254733444555", account_number="KH1003")
    await db.commit()


async def _get(client, token, q):
    r = await client.get(f"/api/customers?{q}", headers=auth(token))
    assert r.status_code == 200, r.text
    return r.json()


def test_both_misspellings_score_fardowsa_first():
    rows = [(1, "Fardowsa", "254711222333", "KH1001"), (2, "Mary Wanjiru", "254722000111", "KH1002"),
            (3, "Faraji Ali", "254700000009", "KH1004")]
    for typo in ("fordowsa", "fardows", "Fardowsa"):
        found = customer_fuzzy.close_matches(typo, rows)
        assert found and found[0]["id"] == 1 and found[0]["matched_on"] == "name", (typo, found)
    assert customer_fuzzy.close_matches("zzqx", rows) == []
    assert customer_fuzzy.close_matches("fa", rows) == []   # too short to guess from


@pytest.mark.asyncio
async def test_a_misspelt_name_suggests_the_customer(client, owner, db):
    reseller, token = owner
    await _account(db, reseller)
    body = await _get(client, token, "search=fordowsa")
    assert body["data"] == [] and body["total"] == 0
    assert [s["name"] for s in body["did_you_mean"]][:1] == ["Fardowsa"]
    assert body["did_you_mean"][0]["matched_on"] == "name"

    paged = await _get(client, token, "search=fordowsa&page=1&per_page=50")
    assert paged["data"] == [] and paged["total"] == 0
    assert paged["did_you_mean"][0]["name"] == "Fardowsa"


@pytest.mark.asyncio
async def test_an_exact_search_is_unchanged(client, owner, db):
    reseller, token = owner
    await _account(db, reseller)
    found = await _get(client, token, "search=fardows")
    assert isinstance(found, list) and [c["name"] for c in found] == ["Fardowsa"]
    paged = await _get(client, token, "search=wanjiru&page=1&per_page=50")
    assert [c["name"] for c in paged["data"]] == ["Mary Wanjiru"] and "did_you_mean" not in paged
    # nothing close at all: still the plain empty list
    assert await _get(client, token, "search=qqqzzz") == []
    assert await _get(client, token, "") != []


@pytest.mark.asyncio
async def test_a_phone_with_one_wrong_digit_suggests_the_customer(client, owner, db):
    reseller, token = owner
    await _account(db, reseller)
    body = await _get(client, token, "search=0711222433")
    assert body["did_you_mean"][0]["name"] == "Fardowsa"
    assert body["did_you_mean"][0]["matched_on"] == "phone"
    acct = await _get(client, token, "search=KH1O01")
    assert acct["did_you_mean"][0]["name"] == "Fardowsa"


@pytest.mark.asyncio
async def test_suggestions_stay_inside_the_reseller_and_its_filters(client, owner, db):
    from app.db.models import CustomerStatus
    from tests.factories import make_reseller

    reseller, token = owner
    await _account(db, reseller)
    other = await make_reseller(db, email="other-fuzzy@example.com", organization_name="Other")
    plan = await make_plan(db, other, name="Other plan")
    await make_customer(db, other, plan, name="Fordowsa Other", phone="254799000000")
    await db.commit()
    body = await _get(client, token, "search=fordowsa")
    assert [s["name"] for s in body["did_you_mean"]] == ["Fardowsa"]
    assert await _get(client, token, f"search=fordowsa&status={CustomerStatus.ACTIVE.value}") == []


def test_the_search_stays_bounded_on_a_large_account():
    rows = [(i, f"Customer {i} Mwangi", f"2547{i:08d}", f"ACC{i:05d}") for i in range(customer_fuzzy.MAX_POOL)]
    rows.append((99999, "Fardowsa", "254711222333", "KH1001"))
    started = time.perf_counter()
    found = customer_fuzzy.close_matches("fordowsa", rows)
    elapsed = time.perf_counter() - started
    assert found[0]["id"] == 99999
    assert len(found) <= customer_fuzzy.MAX_SUGGESTIONS
    assert elapsed < 3.0, elapsed


@pytest.mark.asyncio
async def test_the_pool_read_is_capped(client, owner, db, monkeypatch):
    reseller, token = owner
    await _account(db, reseller)
    monkeypatch.setattr(customer_fuzzy, "MAX_POOL", 1)   # only the first customer is read
    body = await _get(client, token, "search=wanjru")
    assert body == [] or all(s["name"] != "Mary Wanjiru" for s in body.get("did_you_mean", []))


def test_the_instructions_ask_when_unclear_and_keep_the_persons_language():
    from app.services.assistant.agent import SYSTEM_TEMPLATE

    text = SYSTEM_TEMPLATE.lower()
    assert "ask one short question and stop, with the likely readings as the next choices" in text
    assert "never ask just to be safe" in text
    assert "never switch to kiswahili or sheng" in text
    assert "did_you_mean" in text


@pytest.mark.asyncio
async def test_the_assistant_offers_the_close_match_instead_of_nothing_found(client, owner, db):
    reseller, token = owner
    await _account(db, reseller)
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/customers", "query": {"search": "fordowsa"},
                                "show": "table"}, "tu_1"),
        text_reply("Did you mean Fardowsa?\nNEXT: Yes, show Fardowsa | No, search again"),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "Seach me fordowsa"},
                                           headers=auth(token))).text)
    assert not [e for e in events if e["type"] == "data"]   # suggestions are said, not drawn as results
    told = [res for req in model.requests for res in tool_results(req)]
    result = next(r for r in told if "data" in r)
    assert result["data"]["did_you_mean"][0]["name"] == "Fardowsa"
    assert "Did you mean" in result.get("display", "")
    assert "Empty" not in json.dumps(result.get("display", ""))
