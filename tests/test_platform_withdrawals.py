"""Withdrawals ledger (app/services/platform_withdrawals.py).

Collected since 1 Oct 2026 per bucket, withdrawn, available; create / void /
audit; the "can't take more than is available" rule; admin-only routes; and
the startup migration that creates the two tables.
"""

from datetime import date, datetime, timedelta

import pytest
import pytest_asyncio
import time_machine
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.db.models import (
    CollectionMode,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    PlatformWithdrawal,
    PlatformWithdrawalEvent,
    SmsCreditOrder,
    SmsCreditOrderStatus,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
)
from app.services import admin_metrics
from app.services import platform_withdrawals as ledger
from tests.factories import make_admin, make_reseller

pytestmark = pytest.mark.asyncio

NOW = datetime(2026, 10, 29, 9, 0)
IN_OCTOBER = datetime(2026, 10, 15, 12, 0)
BEFORE_START = datetime(2026, 9, 30, 23, 0)


@pytest.fixture(autouse=True)
def _frozen_clock():
    with time_machine.travel(NOW, tick=False):
        yield


async def _sub_payment(db, user_id, amount, at=IN_OCTOBER, status=SubscriptionPaymentStatus.COMPLETED):
    db.add(SubscriptionPayment(
        user_id=user_id, amount=amount, payment_method="mpesa", currency="KES",
        status=status, created_at=at,
    ))
    await db.commit()


async def _sms_order(db, user_id, amount, at=IN_OCTOBER):
    db.add(SmsCreditOrder(
        user_id=user_id, quantity=amount, unit_price=1, amount=amount,
        phone_number="254700000000", status=SmsCreditOrderStatus.COMPLETED, created_at=at,
    ))
    await db.commit()


async def _customer_payment(db, reseller_id, amount, at=IN_OCTOBER):
    db.add(CustomerPayment(
        customer_id=None, reseller_id=reseller_id, amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY, collection_mode=CollectionMode.SYSTEM_COLLECTED,
        days_paid_for=30, counts_as_revenue=True, status=PaymentStatus.COMPLETED, created_at=at,
    ))
    await db.commit()


async def _setup_money(db):
    """Platform 1,000 (800 subscriptions + 200 SMS) and my business 5,000 since 1 Oct."""
    admin = await make_admin(db)
    mine = await make_reseller(db)
    other = await make_reseller(db)
    await admin_metrics.set_own_reseller_ids(db, [mine.id])
    await _sub_payment(db, other.id, 800)
    await _sms_order(db, other.id, 200)
    await _customer_payment(db, mine.id, 5_000)
    return admin, mine, other


async def _record(db, admin, amount, bucket="platform", **kw):
    return await ledger.create_withdrawal(
        db, actor=admin, amount=amount, withdrawn_on=kw.pop("on", date(2026, 10, 20)),
        method=kw.pop("method", "mpesa"), bucket=bucket, **kw,
    )


# ---------------------------------------------------------------------------
# Collected since 1 Oct
# ---------------------------------------------------------------------------

async def test_empty_ledger_starts_on_1_october(db):
    summary = await ledger.ledger_summary(db)

    assert summary["start_date"] == "2026-10-01"
    assert summary["total"] == {"collected": 0, "withdrawn": 0, "available": 0}
    assert summary["buckets"]["platform"] == {"collected": 0, "withdrawn": 0, "available": 0}


async def test_collected_counts_only_money_from_1_october(db):
    _, mine, other = await _setup_money(db)
    await _sub_payment(db, other.id, 999, at=BEFORE_START)
    await _sms_order(db, other.id, 999, at=BEFORE_START)
    await _customer_payment(db, mine.id, 999, at=BEFORE_START)
    await _sub_payment(db, other.id, 999, status=SubscriptionPaymentStatus.PENDING)

    summary = await ledger.ledger_summary(db)

    assert summary["buckets"]["platform"]["collected"] == 1_000
    assert summary["buckets"]["reseller_business"]["collected"] == 5_000
    assert summary["total"]["collected"] == 6_000


async def test_my_own_subscription_payments_are_not_platform_money(db):
    _, mine, _ = await _setup_money(db)
    await _sub_payment(db, mine.id, 500)

    assert (await ledger.ledger_summary(db))["buckets"]["platform"]["collected"] == 1_000


# ---------------------------------------------------------------------------
# Withdrawn and available
# ---------------------------------------------------------------------------

async def test_withdrawal_reduces_its_bucket_and_the_total(db):
    admin, _, _ = await _setup_money(db)
    await _record(db, admin, 300, "platform")
    await _record(db, admin, 1_000, "reseller_business", method="bank")

    summary = await ledger.ledger_summary(db)

    assert summary["buckets"]["platform"] == {"collected": 1_000, "withdrawn": 300, "available": 700}
    assert summary["buckets"]["reseller_business"] == {
        "collected": 5_000, "withdrawn": 1_000, "available": 4_000,
    }
    assert summary["total"] == {"collected": 6_000, "withdrawn": 1_300, "available": 4_700}


async def test_cannot_withdraw_more_than_the_bucket_has(db):
    admin, _, _ = await _setup_money(db)
    await _record(db, admin, 600, "platform")

    with pytest.raises(ledger.WithdrawalError) as err:
        await _record(db, admin, 400.01, "platform")
    assert err.value.status == 422
    await db.rollback()
    await db.refresh(admin)

    # Exactly what is left is fine.
    await _record(db, admin, 400, "platform")
    assert (await ledger.ledger_summary(db))["buckets"]["platform"]["available"] == 0


async def test_withdrawal_from_all_is_limited_by_the_total_and_caps_each_bucket(db):
    admin, _, _ = await _setup_money(db)

    with pytest.raises(ledger.WithdrawalError):
        await _record(db, admin, 6_000.01, "all")
    await db.rollback()
    await db.refresh(admin)

    await _record(db, admin, 5_500, "all", method="cash")
    summary = await ledger.ledger_summary(db)

    assert summary["withdrawn_from_all"] == 5_500
    assert summary["total"]["available"] == 500
    # Neither bucket can show more than what is left in total.
    assert summary["buckets"]["platform"]["available"] == 500
    assert summary["buckets"]["reseller_business"]["available"] == 500
    with pytest.raises(ledger.WithdrawalError):
        await _record(db, admin, 501, "reseller_business")


async def test_void_keeps_the_row_and_gives_the_money_back(db):
    admin, _, _ = await _setup_money(db)
    row = await _record(db, admin, 900, "platform", reference="QAB12CD34", note="Rent")

    voided = await ledger.void_withdrawal(db, actor=admin, withdrawal_id=row["id"], reason="Typed 900, meant 90")

    assert voided["voided"] is True
    assert voided["void_reason"] == "Typed 900, meant 90"
    assert voided["voided_by"] == admin.id
    assert (await ledger.ledger_summary(db))["buckets"]["platform"]["available"] == 1_000
    stored = (await db.execute(select(PlatformWithdrawal))).scalars().all()
    assert len(stored) == 1 and stored[0].voided is True


async def test_void_twice_unknown_or_without_a_reason_is_refused(db):
    admin, _, _ = await _setup_money(db)
    row = await _record(db, admin, 100)

    with pytest.raises(ledger.WithdrawalError) as err:
        await ledger.void_withdrawal(db, actor=admin, withdrawal_id=row["id"], reason="  ")
    assert err.value.status == 400
    await ledger.void_withdrawal(db, actor=admin, withdrawal_id=row["id"], reason="duplicate")
    with pytest.raises(ledger.WithdrawalError) as err:
        await ledger.void_withdrawal(db, actor=admin, withdrawal_id=row["id"], reason="duplicate")
    assert err.value.status == 409
    with pytest.raises(ledger.WithdrawalError) as err:
        await ledger.void_withdrawal(db, actor=admin, withdrawal_id=9_999, reason="nope")
    assert err.value.status == 404


async def test_create_and_void_are_in_the_audit_trail(db):
    admin, _, _ = await _setup_money(db)
    row = await _record(db, admin, 250, reference="QAB12CD34")
    await ledger.void_withdrawal(db, actor=admin, withdrawal_id=row["id"], reason="wrong bucket")

    events = await ledger.audit_trail(db, row["id"])

    assert [e["action"] for e in events] == ["created", "voided"]
    assert all(e["actor_id"] == admin.id for e in events)
    assert events[0]["details"]["amount"] == 250
    assert events[0]["details"]["available_before"] == 1_000
    assert events[1]["details"]["reason"] == "wrong bucket"
    assert len((await db.execute(select(PlatformWithdrawalEvent))).scalars().all()) == 2


@pytest.mark.parametrize("kwargs,message", [
    ({"amount": 0}, "more than zero"),
    ({"amount": -5}, "more than zero"),
    ({"amount": "abc"}, "number"),
    ({"method": "paypal"}, "Method"),
    ({"bucket": "savings"}, "Bucket"),
    ({"on": date(2026, 9, 30)}, "starts on 2026-10-01"),
    ({"on": date(2026, 10, 31)}, "future"),
    ({"reference": "x" * 101}, "Reference"),
])
async def test_bad_input_is_refused(db, kwargs, message):
    admin, _, _ = await _setup_money(db)
    amount = kwargs.pop("amount", 10)
    bucket = kwargs.pop("bucket", "platform")

    with pytest.raises(ledger.WithdrawalError) as err:
        await _record(db, admin, amount, bucket, **kwargs)

    assert message in err.value.message
    assert (await db.execute(select(PlatformWithdrawal))).scalars().all() == []


async def test_list_shows_newest_first_with_voided_rows_and_names(db):
    admin, _, _ = await _setup_money(db)
    first = await _record(db, admin, 100, on=date(2026, 10, 5))
    second = await _record(db, admin, 200, on=date(2026, 10, 25), method="bank")
    await ledger.void_withdrawal(db, actor=admin, withdrawal_id=first["id"], reason="test entry")

    listing = await ledger.list_withdrawals(db)

    assert listing["records_only"] is True
    assert [w["id"] for w in listing["withdrawals"]] == [second["id"], first["id"]]
    assert listing["withdrawals"][1]["voided"] is True
    assert listing["withdrawals"][0]["created_by_name"] == admin.organization_name
    assert listing["total"]["withdrawn"] == 200


# ---------------------------------------------------------------------------
# Routes: admin only
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(engine):
    import main

    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as c:
        yield c


def _bearer(user) -> dict:
    from app.services.auth import create_access_token

    claims = {
        "sub": str(user.id), "user_code": user.user_code, "user_id": user.id,
        "role": user.role.value, "organization_name": user.organization_name,
    }
    return {"Authorization": f"Bearer {create_access_token(claims, timedelta(minutes=30))}"}


URL = "/api/admin/metrics/platform-withdrawals"
BODY = {"amount": 300, "date": "2026-10-20", "method": "mpesa", "bucket": "platform",
        "reference": "QAB12CD34", "note": "October rent"}


async def test_routes_are_admin_only(db, client):
    admin, mine, other = await _setup_money(db)
    row = await _record(db, admin, 100)

    for user in (mine, other):
        headers = _bearer(user)
        assert (await client.get(URL, headers=headers)).status_code == 403
        assert (await client.post(URL, json=BODY, headers=headers)).status_code == 403
        assert (await client.post(f"{URL}/{row['id']}/void", json={"reason": "x" * 5},
                                  headers=headers)).status_code == 403
        assert (await client.get(f"{URL}/{row['id']}/audit", headers=headers)).status_code == 403
    assert (await client.get(URL)).status_code in (401, 403)
    assert len((await db.execute(select(PlatformWithdrawal))).scalars().all()) == 1


async def test_admin_records_lists_and_voids_through_the_api(db, client):
    admin, _, _ = await _setup_money(db)
    headers = _bearer(admin)

    created = await client.post(URL, json=BODY, headers=headers)
    assert created.status_code == 201, created.text
    wid = created.json()["id"]

    listing = (await client.get(URL, headers=headers)).json()
    assert listing["buckets"]["platform"]["available"] == 700
    assert listing["withdrawals"][0]["reference"] == "QAB12CD34"

    too_much = await client.post(URL, json={**BODY, "amount": 701}, headers=headers)
    assert too_much.status_code == 422
    assert "available" in too_much.json()["detail"]

    voided = await client.post(f"{URL}/{wid}/void", json={"reason": "recorded twice"}, headers=headers)
    assert voided.status_code == 200 and voided.json()["voided"] is True
    audit = (await client.get(f"{URL}/{wid}/audit", headers=headers)).json()
    assert [e["action"] for e in audit["events"]] == ["created", "voided"]
    assert (await client.get(URL, headers=headers)).json()["buckets"]["platform"]["available"] == 1_000


# ---------------------------------------------------------------------------
# Startup migration
# ---------------------------------------------------------------------------

async def test_migration_creates_both_tables_and_is_idempotent(monkeypatch):
    import main

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    monkeypatch.setattr(main, "async_engine", engine)
    try:
        async with engine.begin() as conn:
            # An existing database: users is there, the ledger tables are not.
            await conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR NOT NULL)"))
            await conn.execute(text("INSERT INTO users(id, email) VALUES (1, 'admin@example.com')"))
        await main.run_platform_withdrawal_migrations()
        async with engine.begin() as conn:
            await conn.execute(text(
                "INSERT INTO platform_withdrawals (amount, currency, withdrawn_on, method, bucket, "
                "created_by, created_at, voided) VALUES (100, 'KES', '2026-10-20', 'mpesa', "
                "'platform', 1, '2026-10-20 10:00:00', 0)"
            ))
        await main.run_platform_withdrawal_migrations()  # second boot: no-op, data kept
        async with engine.connect() as conn:
            tables = set((await conn.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ))).scalars().all())
            assert {"platform_withdrawals", "platform_withdrawal_events"} <= tables
            assert (await conn.execute(text("SELECT count(*) FROM platform_withdrawals"))).scalar() == 1
            assert (await conn.execute(text("SELECT email FROM users"))).scalar() == "admin@example.com"
            # Amount must be positive (no negative "withdrawals").
            with pytest.raises(Exception):
                await conn.execute(text(
                    "INSERT INTO platform_withdrawals (amount, currency, withdrawn_on, method, bucket, "
                    "created_at, voided) VALUES (-1, 'KES', '2026-10-20', 'mpesa', 'platform', "
                    "'2026-10-20 10:00:00', 0)"
                ))
    finally:
        await engine.dispose()
