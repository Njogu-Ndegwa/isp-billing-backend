"""Reseller self-service withdrawals + per-reseller payout frequency.

Covers:
- run_daily_payouts honoring payout_frequency ('manual' opt-out, weekly/monthly
  widened dedupe windows, daily semantics unchanged).
- The /api/reseller/withdraw endpoint guards (role, in-flight B2B, low balance,
  missing payment method, concurrent-request lock) and its success path.
- GET/PUT /api/reseller/payout-settings.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    ResellerFinancials,
    UserRole,
)
from tests.factories import make_reseller

pytestmark = pytest.mark.asyncio


async def _make_txn(
    db,
    reseller_id,
    *,
    age: timedelta,
    conversation_id: str,
    triggered_by: str = "scheduled",
    status: B2BTransactionStatus = B2BTransactionStatus.COMPLETED,
):
    txn = B2BTransaction(
        reseller_id=reseller_id,
        conversation_id=conversation_id,
        amount=100.0,
        fee=5.0,
        net_amount=95.0,
        party_a="4159825",
        party_b="247247",
        status=status,
        triggered_by=triggered_by,
        created_at=datetime.utcnow() - age,
    )
    db.add(txn)
    await db.commit()
    return txn


async def _set_frequency(db, reseller_id, frequency):
    db.add(ResellerFinancials(user_id=reseller_id, payout_frequency=frequency))
    await db.commit()


def _patch_payout_env(b2b, monkeypatch, session_factory, balance=500.0):
    monkeypatch.setattr(b2b, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_DAILY_PAYOUT_ENABLED", True, raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "tester", raising=False)
    monkeypatch.setattr(b2b, "get_unpaid_balance", AsyncMock(return_value=balance))
    monkeypatch.setattr(
        b2b, "resolve_b2b_payment_method", AsyncMock(return_value=object())
    )
    attempted = []

    async def fake_payout(db_, reseller_id, payment_method, balance=None, triggered_by="manual"):
        attempted.append(reseller_id)
        return SimpleNamespace(
            status=B2BTransactionStatus.PENDING,
            amount=balance, net_amount=balance, fee=0, party_b="247247",
        )

    monkeypatch.setattr(b2b, "payout_reseller", fake_payout)
    return attempted


# ---------------------------------------------------------------------------
# Scheduled job: payout_frequency gating
# ---------------------------------------------------------------------------

async def test_manual_frequency_is_never_auto_paid(
    engine, db, session_factory, monkeypatch
):
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _set_frequency(db, r1.id, "manual")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    await b2b.run_daily_payouts()

    assert attempted == []


async def test_weekly_reseller_skipped_inside_window(
    engine, db, session_factory, monkeypatch
):
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _set_frequency(db, r1.id, "weekly")
    await _make_txn(db, r1.id, age=timedelta(days=3), conversation_id="AG_wk_recent")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    await b2b.run_daily_payouts()

    assert attempted == []


async def test_weekly_reseller_paid_after_window(
    engine, db, session_factory, monkeypatch
):
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _set_frequency(db, r1.id, "weekly")
    # 7 full days old: outside the 164h (7d - 4h) weekly window.
    await _make_txn(db, r1.id, age=timedelta(days=7), conversation_id="AG_wk_old")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    await b2b.run_daily_payouts()

    assert attempted == [r1.id]


async def test_weekly_self_withdrawal_restarts_the_clock(
    engine, db, session_factory, monkeypatch
):
    """A reseller on a weekly schedule who withdrew manually two days ago
    should not be auto-paid tonight — any balance payout counts."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    await _set_frequency(db, r1.id, "weekly")
    await _make_txn(
        db, r1.id, age=timedelta(days=2),
        conversation_id="AG_selfwd", triggered_by="reseller",
    )

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    await b2b.run_daily_payouts()

    assert attempted == []


async def test_monthly_reseller_gating(
    engine, db, session_factory, monkeypatch
):
    from app.services import mpesa_b2b as b2b

    inside = await make_reseller(db)
    await _set_frequency(db, inside.id, "monthly")
    await _make_txn(db, inside.id, age=timedelta(days=15), conversation_id="AG_mo_recent")

    due = await make_reseller(db)
    await _set_frequency(db, due.id, "monthly")
    await _make_txn(db, due.id, age=timedelta(days=30), conversation_id="AG_mo_old")

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    await b2b.run_daily_payouts()

    assert attempted == [due.id]


async def test_daily_semantics_unchanged_manual_txn_does_not_block(
    engine, db, session_factory, monkeypatch
):
    """Historical daily behavior: an admin-manual payout earlier today does
    not stop the nightly run from paying the remaining balance. Only a
    scheduled payout inside 20h dedupes."""
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)  # no financials row -> defaults to daily
    await _make_txn(
        db, r1.id, age=timedelta(hours=5),
        conversation_id="AG_admin_manual", triggered_by="manual",
    )

    attempted = _patch_payout_env(b2b, monkeypatch, session_factory)
    await b2b.run_daily_payouts()

    assert attempted == [r1.id]


async def test_frequency_helpers_roundtrip(engine, db):
    from app.services import mpesa_b2b as b2b

    r1 = await make_reseller(db)
    assert await b2b.get_payout_frequency(db, r1.id) == "daily"

    await b2b.set_payout_frequency(db, r1.id, "monthly")
    await db.commit()
    assert await b2b.get_payout_frequency(db, r1.id) == "monthly"

    # Update path (row already exists)
    await b2b.set_payout_frequency(db, r1.id, "manual")
    await db.commit()
    assert await b2b.get_payout_frequency(db, r1.id) == "manual"

    with pytest.raises(ValueError):
        await b2b.set_payout_frequency(db, r1.id, "hourly")


# ---------------------------------------------------------------------------
# Reseller endpoints
# ---------------------------------------------------------------------------

def _login_as(monkeypatch, routes, user):
    monkeypatch.setattr(routes, "get_current_user", AsyncMock(return_value=user))


async def test_withdraw_requires_reseller_role(engine, db, monkeypatch):
    from app.api import b2b_routes as routes

    admin = await make_reseller(db, role=UserRole.ADMIN)
    _login_as(monkeypatch, routes, admin)

    with pytest.raises(HTTPException) as exc:
        await routes.reseller_withdraw(db=db, token="t")
    assert exc.value.status_code == 403


async def test_withdraw_blocked_by_unresolved_txn(engine, db, monkeypatch):
    from app.api import b2b_routes as routes

    r1 = await make_reseller(db)
    await _make_txn(
        db, r1.id, age=timedelta(minutes=30),
        conversation_id="AG_inflight", status=B2BTransactionStatus.PENDING,
    )
    _login_as(monkeypatch, routes, r1)

    with pytest.raises(HTTPException) as exc:
        await routes.reseller_withdraw(db=db, token="t")
    assert exc.value.status_code == 409


async def test_withdraw_blocked_by_low_balance(engine, db, monkeypatch):
    from app.api import b2b_routes as routes

    r1 = await make_reseller(db)  # no payments -> real balance is 0
    _login_as(monkeypatch, routes, r1)

    with pytest.raises(HTTPException) as exc:
        await routes.reseller_withdraw(db=db, token="t")
    assert exc.value.status_code == 400


async def test_withdraw_blocked_without_payment_method(engine, db, monkeypatch):
    from app.api import b2b_routes as routes

    r1 = await make_reseller(db)
    _login_as(monkeypatch, routes, r1)
    monkeypatch.setattr(routes, "get_unpaid_balance", AsyncMock(return_value=500.0))

    with pytest.raises(HTTPException) as exc:
        await routes.reseller_withdraw(db=db, token="t")
    assert exc.value.status_code == 400
    assert "destination" in exc.value.detail.lower()


async def test_withdraw_rejected_while_lock_held(engine, db, monkeypatch):
    from app.api import b2b_routes as routes

    r1 = await make_reseller(db)
    _login_as(monkeypatch, routes, r1)

    lock = routes._payout_lock(r1.id)
    await lock.acquire()
    try:
        with pytest.raises(HTTPException) as exc:
            await routes.reseller_withdraw(db=db, token="t")
        assert exc.value.status_code == 409
    finally:
        lock.release()


async def test_withdraw_success_records_reseller_trigger(engine, db, monkeypatch):
    from app.api import b2b_routes as routes

    r1 = await make_reseller(db)
    _login_as(monkeypatch, routes, r1)
    monkeypatch.setattr(routes, "get_unpaid_balance", AsyncMock(return_value=500.0))
    monkeypatch.setattr(
        routes, "resolve_b2b_payment_method",
        AsyncMock(return_value=SimpleNamespace(id=1, label="My Paybill")),
    )

    seen = {}

    async def fake_payout(db_, reseller_id, pm, balance=None, triggered_by="manual"):
        seen["triggered_by"] = triggered_by
        txn = B2BTransaction(
            reseller_id=reseller_id,
            conversation_id="AG_ok",
            amount=balance, fee=13.0, net_amount=487.0,
            party_a="4159825", party_b="247247",
            status=B2BTransactionStatus.PENDING,
            triggered_by=triggered_by,
        )
        db_.add(txn)
        await db_.flush()
        return txn

    monkeypatch.setattr(routes, "payout_reseller", fake_payout)

    result = await routes.reseller_withdraw(db=db, token="t")

    assert seen["triggered_by"] == "reseller"
    assert result["balance_before"] == 500.0
    assert result["net_payout"] == 487.0
    assert result["transaction"]["status"] == "pending"
    assert result["destination_label"] == "My Paybill"


async def test_withdraw_synchronous_safaricom_rejection_is_surfaced(
    engine, db, monkeypatch
):
    from app.api import b2b_routes as routes

    r1 = await make_reseller(db)
    _login_as(monkeypatch, routes, r1)
    monkeypatch.setattr(routes, "get_unpaid_balance", AsyncMock(return_value=500.0))
    monkeypatch.setattr(
        routes, "resolve_b2b_payment_method",
        AsyncMock(return_value=SimpleNamespace(id=1, label="My Paybill")),
    )

    async def fake_payout(db_, reseller_id, pm, balance=None, triggered_by="manual"):
        txn = B2BTransaction(
            reseller_id=reseller_id,
            conversation_id=None,
            amount=balance, fee=0, net_amount=balance,
            party_a="4159825", party_b="000000",
            status=B2BTransactionStatus.FAILED,
            result_desc="Receiver party is invalid",
            triggered_by=triggered_by,
        )
        db_.add(txn)
        await db_.flush()
        return txn

    monkeypatch.setattr(routes, "payout_reseller", fake_payout)

    with pytest.raises(HTTPException) as exc:
        await routes.reseller_withdraw(db=db, token="t")
    assert exc.value.status_code == 502
    assert "Receiver party is invalid" in exc.value.detail


async def test_payout_settings_get_and_put(engine, db, monkeypatch):
    from app.api import b2b_routes as routes

    r1 = await make_reseller(db)
    _login_as(monkeypatch, routes, r1)

    settings_before = await routes.get_reseller_payout_settings(db=db, token="t")
    assert settings_before["payout_frequency"] == "daily"
    assert settings_before["can_withdraw"] is False
    assert settings_before["blocked_reason"] == "no_payment_method"
    assert set(settings_before["available_frequencies"]) == {
        "daily", "weekly", "monthly", "manual",
    }

    resp = await routes.update_reseller_payout_settings(
        routes.PayoutSettingsUpdate(payout_frequency="Weekly "), db=db, token="t"
    )
    assert resp["payout_frequency"] == "weekly"

    settings_after = await routes.get_reseller_payout_settings(db=db, token="t")
    assert settings_after["payout_frequency"] == "weekly"

    with pytest.raises(HTTPException) as exc:
        await routes.update_reseller_payout_settings(
            routes.PayoutSettingsUpdate(payout_frequency="hourly"), db=db, token="t"
        )
    assert exc.value.status_code == 400
