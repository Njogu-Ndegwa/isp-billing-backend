"""Loyalty points v1 (board post 5): earn, redeem, expire, adjust, portal and assistant.

Phone numbers and MACs here are obviously fake test values.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerExpirySmsSettings,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    LoyaltyCode,
    LoyaltyLedger,
    LoyaltySettings,
    MessagingSettings,
    PaymentMethod,
    PaymentStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    SmsMessage,
)
from app.services import loyalty
from tests.factories import make_customer, make_plan, make_reseller, make_router, make_sms_account

pytestmark = pytest.mark.asyncio

PHONE = "0700000001"
OTHER_PHONE = "0700000002"
MAC = "AA:BB:CC:00:00:01"
OTHER_MAC = "AA:BB:CC:00:00:02"
IDENTITY = "LOYALTY-TEST"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_limiters(monkeypatch):
    from app.services import code_attempt_limiter, voucher_service

    loyalty.reset_send_limiter()
    code_attempt_limiter.reset_code_attempt_limiter()

    async def _fake_provision(*args, **kwargs):
        return {"success": True}

    monkeypatch.setattr(voucher_service, "provision_hotspot_customer", _fake_provision)
    yield
    loyalty.reset_send_limiter()
    code_attempt_limiter.reset_code_attempt_limiter()


async def _setup(db, **settings):
    reseller = await make_reseller(db, business_name="Test WiFi")
    router = await make_router(db, reseller, identity=IDENTITY)
    plan = await make_plan(db, reseller, price=50, duration_value=1, duration_unit=DurationUnit.DAYS, name="Daily")
    reward_plan = await make_plan(db, reseller, price=20, duration_value=2, duration_unit=DurationUnit.HOURS, name="2 Hours")
    values = dict(
        enabled=True,
        enabled_at=datetime.utcnow() - timedelta(hours=1),
        rewards=[{"plan_id": reward_plan.id, "points_cost": 10}],
    )
    values.update(settings)
    db.add(LoyaltySettings(user_id=reseller.id, **values))
    await db.commit()
    return reseller, router, plan, reward_plan


async def _customer(db, reseller, plan, router=None, *, phone=PHONE, mac=MAC, **kw):
    return await make_customer(
        db, reseller, plan, router, phone=phone, mac_address=mac,
        status=kw.pop("status", CustomerStatus.ACTIVE),
        expiry=kw.pop("expiry", datetime.utcnow() + timedelta(hours=5)), **kw,
    )


async def _pay(db, reseller, customer, plan, *, amount=50.0, method=PaymentMethod.MOBILE_MONEY,
               reference=None, counts_as_revenue=True, created_at=None, status=PaymentStatus.COMPLETED):
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=method,
        payment_reference=reference,
        days_paid_for=1,
        plan_id=plan.id,
        status=status,
        counts_as_revenue=counts_as_revenue,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(payment)
    await db.commit()
    await db.refresh(payment)
    return payment


async def _ledger(db, **where):
    stmt = select(LoyaltyLedger).order_by(LoyaltyLedger.id)
    for key, value in where.items():
        stmt = stmt.where(getattr(LoyaltyLedger, key) == value)
    return (await db.execute(stmt.execution_options(populate_existing=True))).scalars().all()


async def _earned(db, reseller, customer, plan, session_factory, **pay):
    payment = await _pay(db, reseller, customer, plan, **pay)
    awards = await loyalty.ensure_awards([payment.id], session_factory=session_factory)
    return payment, awards.get(payment.id)


# ---------------------------------------------------------------------------
# earning
# ---------------------------------------------------------------------------

async def test_per_kes_earns_floor_of_amount(db, session_factory):
    reseller, router, plan, _ = await _setup(db, kes_per_point=10)
    customer = await _customer(db, reseller, plan, router)
    _, award = await _earned(db, reseller, customer, plan, session_factory, amount=59)
    assert award == {"earned": 5, "balance": 5}
    [row] = await _ledger(db)
    assert (row.kind, row.points, row.remaining, row.phone_key) == ("earn", 5, 5, "700000001")
    assert row.expires_at is not None


async def test_per_purchase_and_plan_overrides(db, session_factory):
    reseller, router, plan, _ = await _setup(db, earn_mode="per_purchase", points_per_purchase=2)
    big = await make_plan(db, reseller, price=500, name="Monthly")
    free = await make_plan(db, reseller, price=30, name="No points")
    settings_row = await db.get(LoyaltySettings, reseller.id)
    settings_row.plan_points = {str(big.id): 25, str(free.id): 0}
    await db.commit()
    customer = await _customer(db, reseller, plan, router)

    _, a = await _earned(db, reseller, customer, plan, session_factory, amount=50)
    _, b = await _earned(db, reseller, customer, big, session_factory, amount=500)
    _, c = await _earned(db, reseller, customer, free, session_factory, amount=30)
    assert a["earned"] == 2
    assert b == {"earned": 25, "balance": 27}
    assert c is None


async def test_min_paid_amount(db, session_factory):
    reseller, router, plan, _ = await _setup(db, min_paid_amount=40)
    customer = await _customer(db, reseller, plan, router)
    _, small = await _earned(db, reseller, customer, plan, session_factory, amount=30)
    _, enough = await _earned(db, reseller, customer, plan, session_factory, amount=40)
    assert small is None
    assert enough["earned"] == 4


@pytest.mark.parametrize("case", [
    "cash", "comp", "voucher", "free_trial", "pending", "before_enabled", "no_phone",
])
async def test_non_earning_payments(db, session_factory, case):
    reseller, router, plan, _ = await _setup(db)
    customer = await _customer(db, reseller, plan, router, phone="" if case == "no_phone" else PHONE)
    pay = {
        "cash": dict(method=PaymentMethod.CASH),
        "comp": dict(method=PaymentMethod.CASH, counts_as_revenue=False, reference="VOUCHER-11112222"),
        "voucher": dict(method=PaymentMethod.CASH, reference="VOUCHER-12345678"),
        "free_trial": dict(method=PaymentMethod.CASH, amount=0, reference="FREE-TRIAL-1"),
        "pending": dict(status=PaymentStatus.PENDING),
        "before_enabled": dict(created_at=datetime.utcnow() - timedelta(hours=2)),
        "no_phone": dict(),
    }[case]
    _, award = await _earned(db, reseller, customer, plan, session_factory, **pay)
    assert award is None
    assert await _ledger(db) == []


async def test_companion_and_pppoe_payments_do_not_earn(db, session_factory):
    reseller, router, plan, _ = await _setup(db)
    owner = await _customer(db, reseller, plan, router)
    companion = await _customer(db, reseller, plan, router, mac=OTHER_MAC, subscription_owner_id=owner.id)
    pppoe_plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, name="Home")
    pppoe = await _customer(db, reseller, pppoe_plan, router, mac="AA:BB:CC:00:00:03", pppoe_username="home1")
    _, a = await _earned(db, reseller, companion, plan, session_factory)
    _, b = await _earned(db, reseller, pppoe, pppoe_plan, session_factory, amount=1000)
    assert a is None and b is None


async def test_loyalty_off_earns_nothing(db, session_factory):
    reseller, router, plan, _ = await _setup(db, enabled=False)
    customer = await _customer(db, reseller, plan, router)
    _, award = await _earned(db, reseller, customer, plan, session_factory)
    assert award is None


async def test_awards_are_exactly_once(db, session_factory):
    reseller, router, plan, _ = await _setup(db)
    customer = await _customer(db, reseller, plan, router)
    payment = await _pay(db, reseller, customer, plan)

    assert await loyalty.award_recent_payments(session_factory=session_factory) == 1
    again = await loyalty.ensure_awards([payment.id], session_factory=session_factory)
    assert await loyalty.award_recent_payments(session_factory=session_factory) == 0
    assert again[payment.id] == {"earned": 5, "balance": 5}
    assert len(await _ledger(db)) == 1


async def test_same_receipt_recorded_twice_earns_once(db, session_factory):
    reseller, router, plan, _ = await _setup(db)
    customer = await _customer(db, reseller, plan, router)
    await _pay(db, reseller, customer, plan, reference="TESTREF001")
    await _pay(db, reseller, customer, plan, reference="TESTREF001")
    await loyalty.award_recent_payments(session_factory=session_factory)
    assert len(await _ledger(db)) == 1


async def test_points_never_cross_resellers(db, session_factory):
    reseller, router, plan, _ = await _setup(db)
    customer = await _customer(db, reseller, plan, router)
    await _earned(db, reseller, customer, plan, session_factory)
    other, other_router, other_plan, _ = await _setup_other(db)
    assert await loyalty.current_balance(db, other.id, "700000001") == 0
    assert await loyalty.current_balance(db, reseller.id, "700000001") == 5


async def _setup_other(db):
    other = await make_reseller(db)
    router = await make_router(db, other, identity="OTHER-ROUTER")
    plan = await make_plan(db, other)
    return other, router, plan, None


# ---------------------------------------------------------------------------
# balances: FIFO, expiry, adjustments
# ---------------------------------------------------------------------------

async def test_fifo_spend_and_expiry(db, session_factory):
    reseller, router, plan, _ = await _setup(db)
    customer = await _customer(db, reseller, plan, router)
    now = datetime.utcnow()
    old = LoyaltyLedger(user_id=reseller.id, phone_key="700000001", kind="earn", points=6, remaining=6,
                        expires_at=now + timedelta(days=1), created_at=now - timedelta(days=89))
    new = LoyaltyLedger(user_id=reseller.id, phone_key="700000001", kind="earn", points=8, remaining=8,
                        expires_at=now + timedelta(days=60), created_at=now - timedelta(days=30))
    db.add_all([old, new])
    await db.commit()

    async with session_factory() as s:
        taken = await loyalty._consume(s, reseller.id, "700000001", 10, now)
        await s.commit()
    assert taken == 10
    rows = await _ledger(db, kind="earn")
    assert [r.remaining for r in rows] == [0, 4]

    # The old row is used up; expire the newer one by moving time on.
    expired = await loyalty.expire_points(session_factory=session_factory, now=now + timedelta(days=61))
    assert expired == 4
    [expire_row] = await _ledger(db, kind="expire")
    assert expire_row.points == -4
    assert await loyalty.current_balance(db, reseller.id, "700000001", now + timedelta(days=61)) == 0
    # Running again finds nothing more.
    assert await loyalty.expire_points(session_factory=session_factory, now=now + timedelta(days=62)) == 0


async def test_expired_points_do_not_count_before_the_job_runs(db):
    reseller, *_ = await _setup(db)
    now = datetime.utcnow()
    db.add(LoyaltyLedger(user_id=reseller.id, phone_key="700000001", kind="earn", points=9, remaining=9,
                         expires_at=now - timedelta(minutes=1), created_at=now - timedelta(days=91)))
    await db.commit()
    assert await loyalty.current_balance(db, reseller.id, "700000001") == 0


async def test_expiry_zero_means_never(db, session_factory):
    reseller, router, plan, _ = await _setup(db, expiry_days=0)
    customer = await _customer(db, reseller, plan, router)
    await _earned(db, reseller, customer, plan, session_factory)
    [row] = await _ledger(db)
    assert row.expires_at is None


async def test_adjust_adds_and_never_goes_below_zero(db):
    reseller, *_ = await _setup(db)
    added = await loyalty.adjust(db, reseller.id, PHONE, 7, "Welcome bonus", reseller.id)
    assert added == {"applied": 7, "balance": 7}
    removed = await loyalty.adjust(db, reseller.id, PHONE, -50, "Mistake", reseller.id)
    assert removed == {"applied": -7, "balance": 0}
    nothing = await loyalty.adjust(db, reseller.id, PHONE, -1, "Again", reseller.id)
    assert nothing["applied"] == 0
    assert await loyalty.current_balance(db, reseller.id, "700000001") == 0
    assert [r.points for r in await _ledger(db, kind="adjust")] == [7, -7]


# ---------------------------------------------------------------------------
# public endpoints
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def portal(session_factory):
    from app.api.loyalty_routes import router as loyalty_router
    from app.api.payment_routes import router as payment_router
    from app.db.database import get_db

    application = FastAPI()
    application.include_router(loyalty_router)
    application.include_router(payment_router)

    async def _get_db():
        async with session_factory() as s:
            yield s

    application.dependency_overrides[get_db] = _get_db
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


async def _member(db, session_factory, points_amount=200.0, **settings):
    reseller, router, plan, reward_plan = await _setup(db, **settings)
    customer = await _customer(db, reseller, plan, router)
    await _earned(db, reseller, customer, plan, session_factory, amount=points_amount)
    return reseller, router, plan, reward_plan, customer


async def test_balance_needs_the_paying_device(db, session_factory, portal):
    reseller, router, plan, reward_plan, _ = await _member(db, session_factory)
    ok = await portal.post("/api/public/loyalty/balance", json={"identity": IDENTITY, "phone": "+254700000001", "mac": MAC})
    body = ok.json()
    assert body["ok"] is True and body["balance"] == 20
    assert body["rewards"][0]["plan_id"] == reward_plan.id
    assert body["rewards"][0]["affordable"] is True
    assert body["expiring"]["points"] == 20

    other = await portal.post("/api/public/loyalty/balance", json={"identity": IDENTITY, "phone": PHONE, "mac": OTHER_MAC})
    assert other.json() == {"ok": False, "code": "needs_code"}


async def test_balance_when_off(db, session_factory, portal):
    await _setup(db, enabled=False)
    r = await portal.post("/api/public/loyalty/balance", json={"identity": IDENTITY, "phone": PHONE, "mac": MAC})
    assert r.json() == {"ok": False, "code": "loyalty_off"}


async def test_redeem_from_paying_device(db, session_factory, portal):
    reseller, router, plan, reward_plan, customer = await _member(db, session_factory)
    r = await portal.post("/api/public/loyalty/redeem", json={
        "identity": IDENTITY, "phone": PHONE, "mac": MAC, "plan_id": reward_plan.id,
    })
    body = r.json()
    assert body["ok"] is True, body
    assert body["customer_id"] == customer.id
    assert body["balance"] == 10

    payment = (await db.execute(
        select(CustomerPayment).where(CustomerPayment.payment_reference.like("LOYALTY-%"))
    )).scalar_one()
    assert payment.amount == 0
    assert payment.counts_as_revenue is False
    assert payment.plan_id == reward_plan.id
    redeem_row = (await _ledger(db, kind="redeem"))[0]
    assert redeem_row.points == -10
    assert redeem_row.customer_payment_id == payment.id
    attempt = (await db.execute(select(ProvisioningAttempt))).scalar_one()
    assert attempt.entrypoint == ProvisioningAttemptEntrypoint.LOYALTY_REDEMPTION

    # The redemption payment never earns.
    assert await loyalty.ensure_awards([payment.id], session_factory=session_factory) == {}


async def test_redeem_errors(db, session_factory, portal):
    reseller, router, plan, reward_plan, customer = await _member(db, session_factory, points_amount=150.0)

    async def redeem(**extra):
        body = {"identity": IDENTITY, "phone": PHONE, "mac": MAC, "plan_id": reward_plan.id}
        body.update(extra)
        return (await portal.post("/api/public/loyalty/redeem", json=body)).json()

    assert (await redeem(plan_id=plan.id))["code"] == "not_a_reward"
    assert (await redeem(mac=OTHER_MAC))["code"] == "needs_code"
    assert (await redeem(mac=OTHER_MAC, code="123456"))["code"] == "bad_code"
    assert (await redeem())["ok"] is True          # 15 -> 5 points
    assert (await redeem())["code"] == "limit_reached"

    settings_row = await db.get(LoyaltySettings, reseller.id)
    settings_row.max_redemptions_per_day = 5
    await db.commit()
    assert (await redeem())["code"] == "not_enough_points"

    settings_row.enabled = False
    await db.commit()
    assert (await redeem())["code"] == "loyalty_off"


async def test_otp_flow_sends_sms_and_lets_another_device_redeem(db, session_factory, portal, monkeypatch):
    from app.services import customer_expiry_notifications

    dispatched = []
    monkeypatch.setattr(customer_expiry_notifications, "spawn_expiry_campaign_dispatch", dispatched.extend)
    reseller, router, plan, reward_plan, customer = await _member(db, session_factory)
    await make_sms_account(db, reseller, balance=5)
    db.add(MessagingSettings(id=1, enabled=True))
    await db.commit()

    captured = {}
    real_hash = loyalty._code_hash

    def _spy(user_id, key, mac, code):
        captured.setdefault("code", code)
        return real_hash(user_id, key, mac, code)

    monkeypatch.setattr(loyalty, "_code_hash", _spy)

    sent = await portal.post("/api/public/loyalty/send-code", json={"identity": IDENTITY, "phone": PHONE, "mac": OTHER_MAC})
    assert sent.json() == {"ok": True}
    assert len(dispatched) == 1
    [message] = (await db.execute(select(SmsMessage))).scalars().all()
    code = captured["code"]
    assert len(code) == 6 and code in message.body
    assert message.customer_id == customer.id
    assert message.credits_charged == 1

    balance = await portal.post("/api/public/loyalty/balance", json={
        "identity": IDENTITY, "phone": PHONE, "mac": OTHER_MAC, "code": code,
    })
    assert balance.json()["balance"] == 20

    redeemed = await portal.post("/api/public/loyalty/redeem", json={
        "identity": IDENTITY, "phone": PHONE, "mac": OTHER_MAC, "plan_id": reward_plan.id, "code": code,
    })
    assert redeemed.json()["ok"] is True
    # The code is single use.
    row = (await db.execute(select(LoyaltyCode).execution_options(populate_existing=True))).scalar_one()
    assert row.used_at is not None


async def test_send_code_without_credits_says_use_paying_device(db, session_factory, portal, monkeypatch):
    from app.services import customer_expiry_notifications

    monkeypatch.setattr(customer_expiry_notifications, "spawn_expiry_campaign_dispatch", lambda ids: None)
    await _member(db, session_factory)
    db.add(MessagingSettings(id=1, enabled=True))
    await db.commit()
    r = await portal.post("/api/public/loyalty/send-code", json={"identity": IDENTITY, "phone": PHONE, "mac": OTHER_MAC})
    assert r.json() == {"ok": False, "code": "use_paying_device"}
    assert (await db.execute(select(func.count(LoyaltyCode.id)))).scalar() == 0
    assert (await db.execute(select(func.count(SmsMessage.id)))).scalar() == 0


async def test_send_code_is_rate_limited_and_silent_for_non_members(db, session_factory, portal, monkeypatch):
    from app.services import customer_expiry_notifications

    monkeypatch.setattr(customer_expiry_notifications, "spawn_expiry_campaign_dispatch", lambda ids: None)
    reseller, *_ = await _member(db, session_factory)
    await make_sms_account(db, reseller, balance=50)
    db.add(MessagingSettings(id=1, enabled=True))
    await db.commit()

    body = {"identity": IDENTITY, "phone": PHONE, "mac": OTHER_MAC}
    replies = [(await portal.post("/api/public/loyalty/send-code", json=body)).json() for _ in range(4)]
    assert replies[:3] == [{"ok": True}] * 3
    assert replies[3] == {"ok": False, "code": "rate_limited"}

    stranger = await portal.post("/api/public/loyalty/send-code", json={
        "identity": IDENTITY, "phone": "0700000099", "mac": "AA:BB:CC:00:00:09",
    })
    assert stranger.json() == {"ok": True}
    assert (await db.execute(select(func.count(SmsMessage.id)))).scalar() == 3


async def test_balance_accepts_code_without_using_it(db, session_factory, portal):
    reseller, router, plan, reward_plan, _ = await _member(db, session_factory)
    now = datetime.utcnow()
    db.add(LoyaltyCode(user_id=reseller.id, phone_key="700000001", mac=OTHER_MAC,
                       code_hash=loyalty._code_hash(reseller.id, "700000001", OTHER_MAC, "246810"),
                       expires_at=now + timedelta(minutes=10)))
    await db.commit()
    body = {"identity": IDENTITY, "phone": PHONE, "mac": OTHER_MAC}

    bad = await portal.post("/api/public/loyalty/balance", json=dict(body, code="135790"))
    assert bad.status_code == 200 and bad.json() == {"ok": False, "code": "bad_code"}

    for _ in range(2):  # a balance check never uses the code up
        ok = await portal.post("/api/public/loyalty/balance", json=dict(body, code="246810"))
        assert ok.status_code == 200 and ok.json()["ok"] is True and ok.json()["balance"] == 20
    row = (await db.execute(select(LoyaltyCode).execution_options(populate_existing=True))).scalar_one()
    assert row.used_at is None and row.attempts == 1  # the bad try counted

    # The code is for this phone and this device only.
    other_device = await portal.post("/api/public/loyalty/balance", json=dict(body, mac="AA:BB:CC:00:00:07", code="246810"))
    assert other_device.json() == {"ok": False, "code": "bad_code"}

    redeemed = await portal.post("/api/public/loyalty/redeem", json=dict(body, plan_id=reward_plan.id, code="246810"))
    assert redeemed.status_code == 200 and redeemed.json()["ok"] is True
    again = await portal.post("/api/public/loyalty/balance", json=dict(body, code="246810"))
    assert again.json() == {"ok": False, "code": "bad_code"}


async def test_balance_code_expires(db, session_factory, portal):
    reseller, *_ = await _member(db, session_factory)
    db.add(LoyaltyCode(user_id=reseller.id, phone_key="700000001", mac=OTHER_MAC,
                       code_hash=loyalty._code_hash(reseller.id, "700000001", OTHER_MAC, "246810"),
                       expires_at=datetime.utcnow() - timedelta(seconds=1)))
    await db.commit()
    r = await portal.post("/api/public/loyalty/balance", json={
        "identity": IDENTITY, "phone": PHONE, "mac": OTHER_MAC, "code": "246810",
    })
    assert r.status_code == 200 and r.json() == {"ok": False, "code": "bad_code"}


async def test_code_allows_five_tries(db, session_factory):
    reseller, *_ = await _member(db, session_factory)
    now = datetime.utcnow()
    mac = "AA:BB:CC:00:00:02"
    db.add(LoyaltyCode(user_id=reseller.id, phone_key="700000001", mac=mac,
                       code_hash=loyalty._code_hash(reseller.id, "700000001", mac, "111111"),
                       expires_at=now + timedelta(minutes=10)))
    await db.commit()
    for _ in range(5):
        valid, _row = await loyalty.check_code(db, reseller.id, "700000001", mac, "222222", now)
        assert not valid
    valid, _row = await loyalty.check_code(db, reseller.id, "700000001", mac, "111111", now)
    assert not valid  # used up


async def test_expired_code_is_refused(db, session_factory):
    reseller, *_ = await _member(db, session_factory)
    now = datetime.utcnow()
    mac = "AA:BB:CC:00:00:02"
    db.add(LoyaltyCode(user_id=reseller.id, phone_key="700000001", mac=mac,
                       code_hash=loyalty._code_hash(reseller.id, "700000001", mac, "111111"),
                       expires_at=now - timedelta(seconds=1)))
    await db.commit()
    valid, _row = await loyalty.check_code(db, reseller.id, "700000001", mac, "111111", now)
    assert not valid


async def test_payment_status_carries_loyalty_for_the_paying_device(db, session_factory, portal):
    from app.services import mpesa_transactions as mt

    mt._ondemand_cooldown_until = float("inf")
    try:
        reseller, router, plan, _ = await _setup(db)
        customer = await _customer(db, reseller, plan, router)
        await _pay(db, reseller, customer, plan, amount=70)

        r = await portal.get(f"/api/hotspot/payment-status/{customer.id}", params={"mac": MAC})
        assert r.json()["loyalty"] == {"earned": 7, "balance": 7}
        other = await portal.get(f"/api/hotspot/payment-status/{customer.id}", params={"mac": OTHER_MAC})
        assert other.json()["loyalty"] is None
        none = await portal.get(f"/api/hotspot/payment-status/{customer.id}")
        assert none.json()["loyalty"] is None
    finally:
        mt._ondemand_cooldown_until = 0.0


async def test_public_portal_payload(db, session_factory):
    from app.api.public_routes import get_portal_data

    reseller, router, plan, reward_plan = await _setup(db)
    elsewhere = await make_plan(db, reseller, name="Other site", router_ids=[router.id + 999])
    settings_row = await db.get(LoyaltySettings, reseller.id)
    settings_row.rewards = [
        {"plan_id": reward_plan.id, "points_cost": 10},
        {"plan_id": elsewhere.id, "points_cost": 5},
    ]
    await db.commit()

    data = await get_portal_data(IDENTITY, None, db)
    block = data["loyalty"]
    assert block["enabled"] is True
    assert block["earn_mode"] == "per_kes"
    assert block["kes_per_point"] == 10
    assert block["expiry_days"] == 90
    assert [(r["plan_id"], r["points_cost"]) for r in block["rewards"]] == [(reward_plan.id, 10)]

    settings_row.enabled = False
    await db.commit()
    assert (await get_portal_data(IDENTITY, None, db))["loyalty"] is None


# ---------------------------------------------------------------------------
# receipt SMS
# ---------------------------------------------------------------------------

async def test_receipt_template_can_show_points(db, session_factory):
    from app.services import customer_notifications
    from app.services import customer_sms_templates as templates

    reseller, router, plan, _ = await _setup(db)
    await make_sms_account(db, reseller, balance=5)
    db.add(MessagingSettings(id=1, enabled=True))
    db.add(CustomerExpirySmsSettings(
        user_id=reseller.id, payment_receipt_enabled=True, receipt_include_hotspot=True,
        reminder_offsets_minutes=[1440],
        custom_templates={templates.EVENT_RECEIPT: "Paid {amount}. You earned {points_earned} points, balance {points_balance}. - {brand}"},
    ))
    await db.commit()
    customer = await _customer(db, reseller, plan, router)
    await _pay(db, reseller, customer, plan, amount=50, reference="TESTREF002")

    await customer_notifications.queue_payment_receipts(session_factory=session_factory)
    [message] = (await db.execute(select(SmsMessage))).scalars().all()
    assert message.body == "Paid KES 50. You earned 5 points, balance 5. - Test WiFi"
    assert templates.validate_template(templates.EVENT_RECEIPT, "{points_earned} {points_balance}") is None


def test_points_sentence_dropped_when_nothing_earned():
    from app.services import customer_sms_templates as templates

    context = templates.build_context(reseller=None, tz_name=None, amount="KES 50")
    text = templates.render_custom("Paid {amount}. You earned {points_earned} points.", context, templates.EVENT_RECEIPT)
    assert text == "Paid KES 50."


# ---------------------------------------------------------------------------
# reseller API, assistant catalog, staff rules
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def reseller_api(session_factory):
    from app.api.loyalty_routes import router as loyalty_router
    from app.db.database import get_db
    from app.services.auth import verify_token

    application = FastAPI()
    application.include_router(loyalty_router)

    async def _get_db():
        async with session_factory() as s:
            yield s

    application.dependency_overrides[get_db] = _get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    import app.api.loyalty_routes as routes

    async def _fake(token, db):
        return user

    monkeypatch.setattr(routes, "get_current_user", _fake)


async def test_settings_get_does_not_create_and_put_validates(db, reseller_api, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)
    plan = await make_plan(db, reseller, price=50, name="Daily")
    pppoe = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, name="Home")
    foreign = await make_plan(db, await make_reseller(db), name="Theirs")

    got = await reseller_api.get("/api/loyalty/settings")
    assert got.json()["enabled"] is False
    assert await db.get(LoyaltySettings, reseller.id) is None

    for bad in (
        {"rewards": [{"plan_id": pppoe.id, "points_cost": 5}]},
        {"rewards": [{"plan_id": foreign.id, "points_cost": 5}]},
        {"plan_points": {str(foreign.id): 3}},
        {"rewards": [{"plan_id": plan.id, "points_cost": 5}] * 2},
    ):
        assert (await reseller_api.put("/api/loyalty/settings", json=bad)).status_code == 400, bad

    put = await reseller_api.put("/api/loyalty/settings", json={
        "enabled": True, "rewards": [{"plan_id": plan.id, "points_cost": 250}],
    })
    body = put.json()
    assert body["enabled"] is True and body["enabled_at"]
    assert body["rewards"][0]["value_percent"] == 2.0
    # Partial: a later change keeps the rewards.
    later = (await reseller_api.put("/api/loyalty/settings", json={"expiry_days": 30})).json()
    assert later["rewards"][0]["plan_id"] == plan.id and later["expiry_days"] == 30
    assert later["enabled_at"] == body["enabled_at"]


async def test_members_adjust_and_summary(db, session_factory, reseller_api, monkeypatch):
    reseller, router, plan, reward_plan, customer = await _member(db, session_factory)
    _auth_as(monkeypatch, reseller)

    adjusted = await reseller_api.post("/api/loyalty/adjust", json={"phone": PHONE, "points": 5, "note": "Bonus"})
    assert adjusted.json()["balance"] == 25
    assert "700000001" not in adjusted.json()["phone"]

    listing = (await reseller_api.get("/api/loyalty/members")).json()["members"]
    assert listing[0]["balance"] == 25
    assert listing[0]["phone"].endswith("001") and "700000" not in listing[0]["phone"]
    assert listing[0]["customer_id"] == customer.id

    detail = (await reseller_api.get("/api/loyalty/members", params={"phone": PHONE})).json()
    assert detail["balance"] == 25
    assert [r["kind"] for r in detail["recent"]] == ["adjust", "earn"]

    summary = (await reseller_api.get("/api/loyalty/summary")).json()
    assert summary == {
        "enabled": True, "members": 1, "points_outstanding": 25,
        "points_earned_30d": 20, "points_redeemed_30d": 0, "redemptions_30d": 0,
    }


def test_catalog_exposes_loyalty_endpoints_with_descriptions():
    import main
    from app.services.assistant.catalog import Catalog

    catalog = Catalog.from_openapi(main.app.openapi())
    keys = {a.key: a for a in catalog.actions}
    for key in (
        "GET /api/loyalty/settings", "PUT /api/loyalty/settings", "GET /api/loyalty/members",
        "POST /api/loyalty/adjust", "GET /api/loyalty/summary",
    ):
        assert key in keys, key
        assert keys[key].description
        assert keys[key].staff_rule is not None
    props = keys["PUT /api/loyalty/settings"].body_schema["properties"]
    assert "kes_per_point" in props["kes_per_point"]["description"]
    assert "per_kes" in props["earn_mode"]["description"]
    reward = props["rewards"]["items"]["properties"]
    assert "hotspot" in reward["plan_id"]["description"].lower()
    # Public portal routes are not assistant actions.
    assert not any(k.startswith("POST /api/public/loyalty") for k in keys)


def test_staff_rules_for_loyalty():
    from app.services import staff_permissions as perms

    for method, path, needed in (
        ("GET", "/api/loyalty/settings", "customers.view"),
        ("PUT", "/api/loyalty/settings", "customers.manage"),
        ("GET", "/api/loyalty/members", "customers.view"),
        ("POST", "/api/loyalty/adjust", "customers.manage"),
        ("GET", "/api/loyalty/summary", "customers.view"),
    ):
        rule, _ = perms.match_rule(method, path)
        assert rule is not None and rule.requirement == needed
        assert not rule.allows(["routers.view"])
    rule, _ = perms.match_rule("PUT", "/api/loyalty/settings")
    assert not rule.allows(["customers.view"])
