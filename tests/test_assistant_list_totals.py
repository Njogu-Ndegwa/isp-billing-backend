"""A list cut for the model still gives it the server's totals for every row.

"Show today's payments" once returned 13 rows of which the model was shown 8 and a
count of the rest. It added up the completed rows it could see and gave that as the
day's total. Now the closing note of a cut list carries ``list_totals``: the count of
every row and, for rows with a status and an amount, the count and sum per status
(app/services/assistant/shaping.py). A list short enough to be shown whole is as before.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.db.models import MpesaTransaction, MpesaTransactionStatus
from app.services.assistant import agent as agent_mod
from app.services.assistant import listing, shaping
from tests.factories import make_customer, make_plan, make_router
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, text_reply, tool_reply, tool_results, use_model,
)


def payment(i: int, status: str, amount: float, **extra) -> dict:
    """One row shaped like GET /api/mpesa/transactions returns it (made-up people)."""
    done = status == "completed"
    return {
        "transaction_id": 9000 + i, "checkout_request_id": f"ws_CO_0101202612000000070000{i:04d}",
        "phone_number": f"25470000{i:04d}", "amount": float(amount), "reference": f"HOTSPOT-{700 + i}-20260101120000",
        "lipay_tx_no": None, "status": status, "payment_method": "mobile_money", "settlement": "direct",
        "payment_reference": f"TESTRCPT{i:02d}" if done else None,
        "mpesa_receipt_number": f"TESTRCPT{i:02d}" if done else None,
        "result_code": "0" if done else "1032",
        "result_desc": "The service request is processed successfully." if done else "Request Cancelled by user.",
        "failure_source": None if done else "client", "transaction_date": None,
        "created_at": f"2026-01-01T09:{i:02d}:28.759070",
        "customer": {"id": 700 + i, "name": f"Guest {i:04d}", "phone": f"25470000{i:04d}",
                     "mac_address": f"AA:BB:CC:00:00:{i:02X}", "status": "active"},
        "router": {"id": 7, "name": "Main Tower", "ip_address": "10.0.9.9", "auth_method": "DIRECT_API"},
        "plan": {"id": 70, "name": "2 hours unlimited", "price": int(amount), "duration_value": 2,
                 "duration_unit": "HOURS", "connection_type": "hotspot"},
        "manual_provision_supported": True, "manual_provision_reason": None, "counts_as_revenue": True,
        "source": "mpesa_stk",
        "delivery": {"attempt_id": 4000 + i, "delivery_status": "online" if done else None,
                     "provisioning_state": "router_updated" if done else None, "online_state": "online" if done else None,
                     "attempt_count": 1, "last_error": None, "last_attempt_at": f"2026-01-01T09:{i:02d}:40.500944"},
        **extra,
    }


def thirteen() -> list[dict]:
    """3 completed worth 110 scattered among 10 failed worth 400: the newest rows are mostly failures."""
    paid = {4: 50, 9: 40, 11: 20}
    return [payment(i, "completed", paid[i]) if i in paid else payment(i, "failed", 40) for i in range(13)]


def test_a_cut_payment_list_gives_the_model_totals_for_every_row():
    rows = thirteen()
    out = shaping.for_model(rows)
    shown, note = out[:-1], out[-1]
    assert 0 < len(shown) < 13                                # too big to show whole: cut
    assert [r["transaction_id"] for r in shown] == [r["transaction_id"] for r in rows[:len(shown)]]
    totals = note["list_totals"]
    assert totals["rows"] == 13
    assert totals["by_status"] == {"completed": {"rows": 3, "amount": 110}, "failed": {"rows": 10, "amount": 400}}
    assert "partial" not in totals
    # the rows the model can see do not add up to the day: that is why the totals are there
    assert sum(r["amount"] for r in shown if r["status"] == "completed") != 110
    assert f"first {len(shown)} of 13" in note["_note"] and "list_totals" in note["_note"]


def test_a_list_short_enough_not_to_be_cut_is_unchanged():
    few = [payment(0, "completed", 25), payment(1, "failed", 25), payment(2, "failed", 25)]
    assert shaping.for_model(few) == few
    envelope = {"total_failed": 2, "total_amount_lost": 50.0, "transactions": few[1:]}
    assert shaping.for_model(envelope) == envelope
    thirty = [{"id": i, "status": "active", "amount": 10} for i in range(30)]   # the most a list keeps
    assert shaping.for_model(thirty) == thirty
    assert "list_totals" not in json.dumps([shaping.for_model(few), shaping.for_model(thirty)])


def test_an_envelopes_own_list_carries_the_totals():
    """GET /api/mpesa/transactions/failed: the figures ride on the cut list, the rest is as before."""
    failed = [payment(i, "expired" if i % 4 == 0 else "failed", 30) for i in range(40)]
    data = {"total_failed": 40, "total_amount_lost": 1200.0,
            "failure_summary": [{"reason": "Request Cancelled by user.", "count": 40, "total_amount_lost": 1200.0}],
            "transactions": failed}
    out = shaping.for_model(data)
    assert {k: v for k, v in out.items() if k != "transactions"} == {k: v for k, v in data.items() if k != "transactions"}
    note = out["transactions"][-1]
    assert len(out["transactions"]) - 1 < 40
    assert note["list_totals"] == {"rows": 40, "by_status": {"expired": {"rows": 10, "amount": 300},
                                                              "failed": {"rows": 30, "amount": 900}}}


def test_money_that_is_not_revenue_is_counted_apart():
    """As GET /api/mpesa/transactions/summary does: a comp is a completed row, but not money received."""
    rows = [payment(i, "completed", 100) for i in range(38)]
    rows += [payment(38, "completed", 100, counts_as_revenue=False), payment(39, "completed", 60, counts_as_revenue=False)]
    totals = shaping.for_model(rows)[-1]["list_totals"]
    assert totals["by_status"] == {"completed": {"rows": 40, "amount": 3800}}
    assert totals["not_counted_as_revenue"] == {"rows": 2, "amount": 160}


def test_rows_without_a_status_get_their_sums_and_the_best_and_worst():
    """Revenue per day: the best day of 90 is the server's to name, not the model's from the 30 it sees."""
    start = datetime(2026, 1, 1)
    days = [{"date": (start + timedelta(days=i)).strftime("%Y-%m-%d"), "label": f"day {i}",
             "revenue": float(100 + i), "transactions": 2} for i in range(90)]
    days[70]["revenue"], days[80]["revenue"] = 5000.0, 0.0     # both past what the model is shown
    out = shaping.for_model({"currency": "KES", "group_by": "daily", "data": days})
    assert len(out["data"]) == 31
    totals = out["data"][-1]["list_totals"]
    assert totals["rows"] == 90 and "by_status" not in totals
    assert totals["revenue"] == {"sum": sum(d["revenue"] for d in days), "highest": 5000, "highest_at": days[70]["date"],
                                 "lowest": 0, "lowest_at": days[80]["date"]}
    assert totals["transactions"]["sum"] == 180


def test_a_free_text_status_or_no_amount_still_gives_the_count():
    notes = [{"id": i, "status": f"note number {i}", "title": "x"} for i in range(40)]
    assert shaping.for_model(notes)[-1]["list_totals"] == {"rows": 40}
    routers = [{"id": i, "name": f"R{i}", "status": "offline" if i < 3 else "online", "port": 8728} for i in range(40)]
    assert shaping.for_model(routers)[-1]["list_totals"] == {
        "rows": 40, "by_status": {"offline": {"rows": 3}, "online": {"rows": 37}}}


def test_other_lists_and_the_screen_are_as_before():
    words = [f"word {i}" for i in range(40)]
    assert shaping.for_model(words)[-1] == {"_note": "10 more items not shown (40 in total). Narrow with filters or paging."}
    # a list inside each record is cut as before; only the result's own list gets figures
    nested = shaping.for_model([{"id": i, "ports": [{"n": j, "status": "up"} for j in range(40)]} for i in range(3)])
    assert "list_totals" not in json.dumps(nested) and "more items not shown" in json.dumps(nested)
    assert "list_totals" not in json.dumps(shaping.for_screen([payment(i, "failed", 5) for i in range(400)]))
    # secrets stay hidden, and nothing is built from them
    secret = shaping.for_model([{"id": i, "status": "ok", "amount": 1, "api_key": "k"} for i in range(40)])
    assert secret[0]["api_key"] == shaping.MASK and secret[-1]["list_totals"]["by_status"] == {"ok": {"rows": 40, "amount": 40}}


def test_totals_of_one_page_say_they_are_not_the_whole_list():
    rows = [payment(i, "completed", 10) for i in range(50)]
    note = shaping.for_model(rows, partial="one read returns at most 50 rows and this one is full")[-1]
    assert note["list_totals"]["rows"] == 50
    assert "at most 50 rows" in note["list_totals"]["partial"] and "summary" in note["list_totals"]["partial"]
    assert "not the whole list" in note["_note"]


def test_a_read_that_is_one_page_of_more_is_recognised():
    limit = [{"name": "limit", "required": False, "schema": {"type": "integer", "default": 200}},
             {"name": "offset", "required": False, "schema": {"type": "integer", "default": 0}},
             {"name": "page", "required": False, "schema": {"type": "integer", "nullable": True}},
             {"name": "per_page", "required": False, "schema": {"type": "integer", "nullable": True}}]
    rows = [{"id": i} for i in range(200)]
    assert listing.partial_read(limit, None, rows[:13]) is None               # fewer than a read holds: all of it
    assert "at most 200" in listing.partial_read(limit, {"date": "2026-01-01"}, rows)
    assert "at most 50" in listing.partial_read(limit, {"limit": 50}, rows[:50])
    assert listing.partial_read(limit, {"limit": 500}, rows) is None
    assert "skipped" in listing.partial_read(limit, {"offset": 200}, rows[:13])
    paged = {"data": rows[:50], "page": 1, "per_page": 50, "total": 950, "total_pages": 19}
    assert "19 pages" in listing.partial_read(limit, {"page": 1, "per_page": 50}, paged)
    assert "950" in listing.partial_read(limit, {"page": 1, "per_page": 50}, paged)
    assert "more rows" in listing.partial_read([], None, {"rows": rows[:5], "has_more": True})
    assert listing.partial_read([], None, {"data": rows[:5], "total": 5, "total_pages": 1, "page": 1}) is None
    assert listing.partial_read([], None, rows) is None                       # no paging at all: everything
    assert listing.partial_read(limit, None, {"revenue": 100}) is None        # not a list


def test_the_instructions_tie_every_figure_to_the_servers_own():
    system = agent_mod.SYSTEM_TEMPLATE
    assert "list_totals" in system and "/api/mpesa/transactions/summary" in system
    assert "the first 8 of 13" in system
    assert "never add up" in system.lower()


async def _payments(db, reseller, statuses_and_amounts):
    plan = await make_plan(db, reseller, name="2 hours", price=20, duration_value=1)
    router = await make_router(db, reseller, name="Main Tower")
    customer = await make_customer(db, reseller, plan, router, name="Guest 0001", phone="254700000001")
    now = datetime.utcnow()
    for i, (status, amount) in enumerate(statuses_and_amounts):
        db.add(MpesaTransaction(
            checkout_request_id=f"ws_CO_test_{i:04d}", phone_number="254700000001", amount=amount,
            reference=f"HOTSPOT-{customer.id}-{i}", status=MpesaTransactionStatus(status),
            customer_id=customer.id, reseller_id=reseller.id, router_id=router.id, plan_id=plan.id,
            mpesa_receipt_number=f"TESTRCPT{i:03d}" if status == "completed" else None,
            result_desc="Request Cancelled by user." if status == "failed" else None,
            created_at=now - timedelta(minutes=i + 1)))
    await db.commit()


@pytest.mark.asyncio
async def test_the_model_is_given_the_payment_lists_totals_and_they_match_the_summary(client, owner, db):
    reseller, token = owner
    # the newest rows, the ones the model is shown, are failures; the money sits further down
    await _payments(db, reseller, [("failed", 20)] * 30 + [("completed", 20), ("completed", 50), ("failed", 20),
                                                            ("completed", 100), ("pending", 20)])
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/mpesa/transactions", "show": "table"}, "tu_1"),
        tool_reply("call_api", {"method": "GET", "path": "/api/mpesa/transactions", "query": {"limit": 32}}, "tu_2"),
        tool_reply("call_api", {"method": "GET", "path": "/api/mpesa/transactions", "query": {"status": "completed"}},
                   "tu_3"),
        text_reply("3 payments came in, KES 170."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Show today's payments"}, headers=auth(token))
    assert r.status_code == 200
    whole, page, short = [res for req in model.requests for res in tool_results(req)]

    shown, note = whole["data"][:-1], whole["data"][-1]
    assert len(shown) < 35 and not any(row["status"] == "completed" for row in shown)
    totals = note["list_totals"]
    assert totals["rows"] == 35 and "partial" not in totals
    assert totals["by_status"] == {"failed": {"rows": 31, "amount": 620}, "completed": {"rows": 3, "amount": 170},
                                   "pending": {"rows": 1, "amount": 20}}
    summary = (await client.get("/api/mpesa/transactions/summary", headers=auth(token))).json()
    assert {s: {"rows": v["count"], "amount": v["amount"]} for s, v in summary["status_breakdown"].items()} \
        == totals["by_status"]

    # a read that fills its page is one page: its figures say they are not the whole list
    assert page["data"][-1]["list_totals"]["rows"] == 32 and "at most 32" in page["data"][-1]["list_totals"]["partial"]
    # three rows are shown whole, exactly as the API gave them
    assert [row["amount"] for row in short["data"]] == [20, 50, 100] and "list_totals" not in json.dumps(short)

    assert "list_totals" in model.requests[0]["system"][0]["text"]
