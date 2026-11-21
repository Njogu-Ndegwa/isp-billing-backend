"""Money workflows: receiving payments, payouts, finding a payment, the Bitwave subscription.

Each scenario is an account in a given state, what a Kenyan reseller would type
(English or Kiswahili), and what a GOOD answer has to contain. Any reasonable
correct path is accepted; the checks name the step that must not be missed.
"""
import re
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    AssistantAction, C2BTransaction, C2BTransactionStatus, CollectionMode, CustomerPayment, InvoiceStatus,
    MpesaTransaction, MpesaTransactionStatus, PaymentMethod, PaymentStatus, ResellerFinancials,
    ResellerPaymentMethod, SubscriptionInvoice, SubscriptionStatus, UnmatchedC2BPayment, UnmatchedC2BReason,
)
from app.services.assistant import agent as agent_mod
from tests.assistant_eval_kit import (
    KEY, _card, any_of, ask, build, card_for, customer, evaluate, never_says, no_card, plan, prefilled, report,
    says, use_real_model,
)
from tests.test_assistant import auth, client, owner, sse_events, visible_text  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")


# -- local helpers ---------------------------------------------------------------------

async def pay(db, reseller, cust, plan_row, router, amount, receipt, when):
    """One completed STK payment, as the callback records it (both ledgers)."""
    db.add(MpesaTransaction(
        checkout_request_id=f"ws_CO_{receipt}", phone_number=cust.phone, amount=amount, reference=cust.phone,
        status=MpesaTransactionStatus.completed, customer_id=cust.id, reseller_id=reseller.id,
        router_id=router.id, plan_id=plan_row.id, mpesa_receipt_number=receipt, result_code="0",
        result_desc="The service request is processed successfully.", transaction_date=when,
        collection_mode=CollectionMode.SYSTEM_COLLECTED, created_at=when, updated_at=when))
    db.add(CustomerPayment(
        customer_id=cust.id, reseller_id=reseller.id, amount=amount, payment_method=PaymentMethod.MOBILE_MONEY,
        payment_reference=receipt, payment_date=when, days_paid_for=max(plan_row.duration_value or 1, 1),
        plan_id=plan_row.id, router_id=router.id, status=PaymentStatus.COMPLETED, customer_name=cust.name,
        collection_mode=CollectionMode.SYSTEM_COLLECTED, created_at=when))


async def methods(db, reseller) -> dict:
    rows = (await db.execute(select(ResellerPaymentMethod).where(ResellerPaymentMethod.user_id == reseller.id))).scalars()
    return {r.method_type.value if hasattr(r.method_type, "value") else r.method_type: r for r in rows}


async def confirm_pending(client, token, db, row, monkeypatch, values=None) -> dict:  # noqa: F811
    """Tap Confirm on every pending card of the chat (with form values), and return the next answer."""
    conv = row["conversation_id"]
    db.expire_all()
    pending = (await db.execute(select(AssistantAction).where(
        AssistantAction.conversation_id == conv, AssistantAction.status == "pending"))).scalars().all()
    tools, errors = [], []
    original_run = agent_mod.Turn._run_tool

    async def run_tool(self, block):
        args = block.get("input") if isinstance(block.get("input"), dict) else {}
        tools.append(f"{block.get('name')} {args.get('method', '')} {args.get('path') or args.get('symptom') or ''}".strip())
        return await original_run(self, block)

    monkeypatch.setattr(agent_mod.Turn, "_run_tool", run_tool)
    r = await client.post(f"/api/assistant/conversations/{conv}/decide", headers=auth(token), timeout=240, json={
        "decisions": [{"action_id": a.id, "approve": True, **({"values": values} if values else {})} for a in pending]})
    monkeypatch.setattr(agent_mod.Turn, "_run_tool", original_run)
    events = sse_events(r.text)
    results = [f"{e.get('status')} ok={e.get('ok')} {str(e.get('detail', ''))[:200]}"
               for e in events if e["type"] == "action_result"]
    return {"question": f"[Confirm] {values or ''}", "said": re.sub(r"\s+", " ", visible_text(events)).strip(),
            "cards": [_card(e) for e in events if e["type"] == "action"], "tools": tools,
            "errors": errors + results, "conversation_id": conv}


def used(*parts):
    """The assistant read (or proposed) one of these paths."""
    def check(row):
        return None if any(p in t for t in row["tools"] for p in parts) else f"never looked at {' or '.join(parts)}; tools {row['tools']}"
    return check


def body_has(path_part, **expected):
    """A card for path_part whose body holds these values."""
    def check(row):
        for c in row["cards"]:
            if path_part in c["path"]:
                body = c.get("body") or {}
                bad = {k: body.get(k) for k, v in expected.items() if str(body.get(k)).lower() != str(v).lower()}
                return None if not bad else f"{c['path']} body has {bad}, wanted {expected}"
        return f"no card for ...{path_part}"
    return check


def no_card_for(*parts):
    def check(row):
        bad = [c["method"] + " " + c["path"] for c in row["cards"] if any(p in c["path"] for p in parts)]
        return None if not bad else f"proposed {bad}, which is the wrong action here"
    return check


def finish(name, row, checks):
    problems = evaluate(row, checks)
    report(name, row, problems)
    return problems


# -- receiving payments ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_setup_from_scratch_adds_till_then_links_router(client, owner, db, monkeypatch):  # noqa: F811
    """No payment method yet: add the till, then (second step) put the router on it."""
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50)])
    rid = made["routers"]["Main Tower"].id
    use_real_model(monkeypatch)
    row = await ask(client, token, "Nataka wateja walipe kwa till yangu 5123456. Nisaidie kuweka.", monkeypatch)
    p1 = finish("setup-scratch/add-till", row, [card_for("POST", "/api/payment-methods"),
                                                 prefilled(mpesa_till_number="5123456")])
    assert not p1, p1
    row2 = await confirm_pending(client, token, db, row, monkeypatch,
                                 values={"method_type": "mpesa_till", "label": "My Till", "mpesa_till_number": "5123456"})
    p2 = finish("setup-scratch/then-link-router", row2, [
        any_of(card_for("PUT", f"/api/routers/{rid}/payment-method"), says("Main Tower")),
    ])
    assert not p2, p2


@pytest.mark.asyncio
async def test_switch_bank_to_till_moves_the_routers(client, owner, db, monkeypatch):  # noqa: F811
    """On a bank today; wants a till. The till is a new method (a bank record cannot become a till), and the routers must move to it."""
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower", "Kahawa AP"], plans=[plan("Daily 50", 50)],
                       payment_methods=["bank_account"])
    bank = (await methods(db, reseller))["bank_account"]
    for r in made["routers"].values():
        r.payment_method_id = bank.id
    await db.commit()
    use_real_model(monkeypatch)
    row = await ask(client, token, "I want to stop using the bank and receive on my M-Pesa till 5123456 instead.", monkeypatch)
    problems = finish("switch-bank-to-till/new-method", row, [
        card_for("POST", "/api/payment-methods"),
        prefilled(mpesa_till_number="5123456"),
        no_card_for("/api/payment-methods/"),  # editing the bank record into a till is the wrong action
        any_of(card_for("PUT", "/payment-method"), says("router", "Main Tower", "Kahawa AP", any_=True)),
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_router_still_on_old_bank_is_moved_to_till(client, owner, db, monkeypatch):  # noqa: F811
    """Till added already; Main Tower is on it, Kahawa AP still on the old bank."""
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower", "Kahawa AP"], plans=[plan("Daily 50", 50)],
                       payment_methods=["bank_account", "mpesa_till"])
    m = await methods(db, reseller)
    made["routers"]["Main Tower"].payment_method_id = m["mpesa_till"].id
    made["routers"]["Kahawa AP"].payment_method_id = m["bank_account"].id
    await db.commit()
    kahawa = made["routers"]["Kahawa AP"].id
    use_real_model(monkeypatch)
    row = await ask(client, token, "Nilihama kutoka bank kwenda till lakini pesa za Kahawa AP bado zinaenda bank. Rekebisha.",
                    monkeypatch)
    problems = finish("old-method/router-still-on-bank", row, [
        card_for("PUT", f"/api/routers/{kahawa}/payment-method"),
        body_has(f"/api/routers/{kahawa}/payment-method", payment_method_id=m["mpesa_till"].id),
    ])
    assert not problems, problems


# -- payouts ---------------------------------------------------------------------------

async def _collected(db, reseller, amounts, hours_ago, frequency=None):
    made = await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50)],
                       customers=[customer("Amina", "254711000001", "Daily 50")], payment_methods=["mpesa_till"])
    cust, p, r = made["customers"]["Amina"], made["plans"]["Daily 50"], made["routers"]["Main Tower"]
    now = datetime.utcnow()
    for i, amount in enumerate(amounts):
        await pay(db, reseller, cust, p, r, amount, f"TKA{i:02d}PAYX{i}", now - timedelta(hours=hours_ago, minutes=i * 7))
    if frequency:
        db.add(ResellerFinancials(user_id=reseller.id, payout_frequency=frequency))
    await db.commit()
    return made


@pytest.mark.asyncio
async def test_when_do_i_get_paid(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _collected(db, reseller, [50] * 8, hours_ago=3)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Pesa ya wateja wangu nitapata lini? Na ni ngapi inanisubiri?", monkeypatch)
    problems = finish("payout/when", row, [
        used("/api/reseller/payout-settings", "/api/reseller/account-statement"),
        says("daily", "kila siku", "every day", "each day", "once a day", "kila sik", any_=True),
        says("400", any_=True),
        no_card,
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_switch_to_direct_settlement(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _collected(db, reseller, [50], hours_ago=2)
    reseller.settlement_mode = "platform"  # the column defaults to direct
    await db.commit()
    use_real_model(monkeypatch)
    row = await ask(client, token, "I don't want to wait for payouts. Can customer payments go straight to my till?", monkeypatch)
    problems = finish("payout/switch-direct", row, [
        card_for("PUT", "/api/reseller/settlement-mode"),
        body_has("/api/reseller/settlement-mode", settlement_mode="direct"),
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_payout_not_received_on_manual_schedule(client, owner, db, monkeypatch):  # noqa: F811
    """Yesterday's KES 2,350 sits in the balance because payouts are set to manual."""
    reseller, token = owner
    await _collected(db, reseller, [500, 500, 300, 300, 250, 500], hours_ago=20, frequency="manual")
    use_real_model(monkeypatch)
    row = await ask(client, token, "Sijapokea pesa ya jana, ilikuwa kama 2350. Iko wapi?", monkeypatch)
    problems = finish("payout/not-received-manual", row, [
        used("/api/reseller/payout-settings", "/api/reseller/account-statement"),
        says("manual", "mwenyewe", any_=True),
        any_of(card_for("POST", "/api/reseller/withdraw"), card_for("PUT", "/api/reseller/payout-settings"),
               says("withdraw", "toa pesa", any_=True)),
        no_card_for("/api/payment-methods"),
    ])
    assert not problems, problems


# -- finding a payment -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_payment_by_mpesa_code(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7)],
                       customers=[customer("Amina Wairimu", "254711000001", "Daily 50"),
                                  customer("Brian Otieno", "254722000002", "Weekly 300"),
                                  customer("Chebet Kirui", "254733000003", "Daily 50")])
    r, now = made["routers"]["Main Tower"], datetime.utcnow()
    c, p = made["customers"], made["plans"]
    await pay(db, reseller, c["Amina Wairimu"], p["Daily 50"], r, 50, "TKL1AB2CD3", now - timedelta(hours=5))
    await pay(db, reseller, c["Brian Otieno"], p["Weekly 300"], r, 300, "TKL3XY9Q2M", now - timedelta(hours=4))
    await pay(db, reseller, c["Chebet Kirui"], p["Daily 50"], r, 50, "TKL7GH8JK1", now - timedelta(hours=3))
    await db.commit()
    use_real_model(monkeypatch)
    row = await ask(client, token, "Who paid with M-Pesa code TKL3XY9Q2M?", monkeypatch)
    problems = finish("find-payment/by-code", row, [says("Brian"), never_says("Amina", "Chebet"), no_card])
    assert not problems, problems


@pytest.mark.asyncio
async def test_unmatched_paybill_payment_attributed_to_customer(client, owner, db, monkeypatch):  # noqa: F811
    """Paid to the paybill with a typo in the account number: match it, do not record a second payment."""
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"],
                       plans=[plan("Home 5M", 1500, days=30, kind="pppoe")],
                       customers=[customer("Wanjiru Mwangi", "254722000111", "Home 5M", hours_left=-30, status="inactive",
                                           account_number="BW40217", pppoe_username="wanjiru"),
                                  customer("Otieno Ouma", "254733555222", "Home 5M", pppoe_username="otieno",
                                           account_number="BW40333")],
                       payment_methods=["mpesa_paybill"])
    txn = C2BTransaction(trans_id="TKM9QW2E3R", bill_ref_number="BW4O217", trans_amount=1500, msisdn="254722000111",
                         business_shortcode="600980", status=C2BTransactionStatus.UNMATCHED,
                         received_at=datetime.utcnow() - timedelta(hours=16))
    db.add(txn)
    await db.flush()
    db.add(UnmatchedC2BPayment(c2b_transaction_id=txn.id, reason=UnmatchedC2BReason.UNKNOWN_ACCOUNT,
                               assigned_reseller_id=reseller.id))
    await db.commit()
    wanjiru = made["customers"]["Wanjiru Mwangi"].id
    use_real_model(monkeypatch)
    row = await ask(client, token, "Wanjiru Mwangi says she paid 1500 to the paybill yesterday but she is still off. "
                                   "She thinks she typed the account number wrong.", monkeypatch)
    problems = finish("find-payment/unmatched-c2b", row, [
        used("/api/c2b/unmatched"),
        card_for("POST", "/attribute"),
        body_has("/attribute", customer_id=wanjiru),
        no_card_for("/activate-pppoe", "/manual-provision", "/extend"),  # would count the money twice
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_double_payment_refund(client, owner, db, monkeypatch):  # noqa: F811
    """Paid twice by mistake. The dashboard moves no money back; say how it is handled, never fake a refund."""
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50)],
                       customers=[customer("Peter Kamau", "254711222333", "Daily 50", hours_left=47)])
    r, cust, p, now = made["routers"]["Main Tower"], made["customers"]["Peter Kamau"], made["plans"]["Daily 50"], datetime.utcnow()
    await pay(db, reseller, cust, p, r, 50, "TKP1DUP001", now - timedelta(minutes=50))
    await pay(db, reseller, cust, p, r, 50, "TKP1DUP002", now - timedelta(minutes=48))
    await db.commit()
    use_real_model(monkeypatch)
    row = await ask(client, token, "Peter Kamau amelipa 50 mara mbili kwa makosa. Nataka kumrudishia 50 moja.", monkeypatch)
    problems = finish("find-payment/double-refund", row, [
        used("/api/mpesa/transactions", "/payment-summary", "/api/customers"),
        says("TKP1DUP002", "mara mbili", "twice", "two payments", "malipo mawili", "2 ", any_=True),
        says("Bitwave", "support", "revers", "M-Pesa", "mwenyewe", "yourself", "siku", "day", any_=True),
        no_card_for("/refund"),  # the ad-sales refund is a different thing entirely
    ])
    assert not problems, problems


# -- the money picture -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_todays_money(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower", "Kahawa AP"],
                       plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7), plan("Hourly 10", 10)],
                       customers=[customer("Amina", "254711000001", "Daily 50"),
                                  customer("Brian", "254722000002", "Weekly 300", router="Kahawa AP"),
                                  customer("Chebet", "254733000003", "Hourly 10")])
    c, p, r, now = made["customers"], made["plans"], made["routers"], datetime.utcnow()
    await pay(db, reseller, c["Amina"], p["Daily 50"], r["Main Tower"], 50, "TKT0DAY001", now - timedelta(minutes=10))
    await pay(db, reseller, c["Brian"], p["Weekly 300"], r["Kahawa AP"], 300, "TKT0DAY002", now - timedelta(minutes=20))
    await pay(db, reseller, c["Chebet"], p["Hourly 10"], r["Main Tower"], 10, "TKT0DAY003", now - timedelta(minutes=30))
    await pay(db, reseller, c["Brian"], p["Weekly 300"], r["Kahawa AP"], 300, "TKY0DAY004", now - timedelta(hours=40))
    await db.commit()
    use_real_model(monkeypatch)
    row = await ask(client, token, "Nimeingiza pesa ngapi leo?", monkeypatch)
    problems = finish("money/today", row, [says("360"), never_says("660"), no_card])
    assert not problems, problems


@pytest.mark.asyncio
async def test_best_plan_this_week_by_money(client, owner, db, monkeypatch):  # noqa: F811
    """Hourly 10 sells most often; Weekly 300 brings the most money."""
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"],
                       plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7), plan("Hourly 10", 10)],
                       customers=[customer("Amina", "254711000001", "Daily 50"),
                                  customer("Brian", "254722000002", "Weekly 300"),
                                  customer("Chebet", "254733000003", "Hourly 10")])
    c, p, r, now = made["customers"], made["plans"], made["routers"]["Main Tower"], datetime.utcnow()
    n = 0
    for name, cust, price, count in (("Daily 50", "Amina", 50, 6), ("Weekly 300", "Brian", 300, 3), ("Hourly 10", "Chebet", 10, 15)):
        for i in range(count):
            n += 1
            await pay(db, reseller, c[cust], p[name], r, price, f"TKW{n:03d}BEST", now - timedelta(hours=2 + i * 5))
    await db.commit()
    use_real_model(monkeypatch)
    row = await ask(client, token, "Which plan made me the most money this week?", monkeypatch)
    problems = finish("money/best-plan", row, [says("Weekly 300"), no_card])
    assert not problems, problems


# -- the Bitwave subscription ----------------------------------------------------------

@pytest.mark.asyncio
async def test_suspended_subscription_is_the_cause_and_gets_paid(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50)],
                customers=[customer("Amina", "254711000001", "Daily 50", hours_left=-3, status="inactive")],
                payment_methods=["mpesa_till"])
    now = datetime.utcnow()
    reseller.subscription_status = SubscriptionStatus.SUSPENDED
    reseller.subscription_expires_at = now - timedelta(days=2)
    db.add(SubscriptionInvoice(user_id=reseller.id, period_start=now - timedelta(days=32), period_end=now - timedelta(days=2),
                               hotspot_revenue=30000, hotspot_charge=1500, gross_charge=1500, final_charge=1500,
                               currency="KES", status=InvoiceStatus.OVERDUE, due_date=now - timedelta(days=2),
                               created_at=now - timedelta(days=2)))
    await db.commit()
    use_real_model(monkeypatch)
    row = await ask(client, token, "Wateja wanasema hawawezi kununua bundle tangu jana. Shida ni nini?", monkeypatch)
    problems = finish("subscription/suspended-pay", row, [
        says("subscription", "usajili", "Bitwave", any_=True),
        says("1,500", "1500", any_=True),
        any_of(card_for("POST", "/api/subscription/pay"), card_for("POST", "/api/subscription/pay-card")),
    ])
    assert not problems, problems
