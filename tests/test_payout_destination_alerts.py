"""Payout-destination audit trail + owner alerts.

Regression cover for the 2026-06-11 Kennice Networks incident: a reseller's real
payout destination was deactivated, a third-party paybill was added, and four
days of payouts were aimed at it with no record of who did it and no warning to
the owner. Every test here asserts one half of that: the trail, or the alert.
"""

import pytest
from sqlalchemy import select

from app.db.models import (
    PayoutDestinationAction,
    PayoutDestinationChangeLog,
    ResellerInboxMessage,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    User, UserRole,
)
from app.services import payout_destination_alerts as alerts
from tests.factories import make_admin, make_reseller


async def _make_method(db, user, **overrides):
    fields = dict(
        user_id=user.id,
        method_type=ResellerPaymentMethodType.BANK_ACCOUNT,
        label="my mpesa",
        is_active=True,
        bank_paybill_number="852648",
        bank_account_number="139738",
    )
    fields.update(overrides)
    pm = ResellerPaymentMethod(**fields)
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    return pm


async def _logs(db, user_id):
    rows = await db.execute(
        select(PayoutDestinationChangeLog)
        .where(PayoutDestinationChangeLog.user_id == user_id)
        .order_by(PayoutDestinationChangeLog.id)
    )
    return rows.scalars().all()


async def _inbox(db, user_id):
    rows = await db.execute(
        select(ResellerInboxMessage)
        .where(ResellerInboxMessage.recipient_user_id == user_id)
        .order_by(ResellerInboxMessage.id)
    )
    return rows.scalars().all()


# --------------------------------------------------------------------------
# describe_destination -- the snapshot text that ends up in the audit row
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_describe_destination_bank_account(db):
    reseller = await make_reseller(db)
    pm = await _make_method(db, reseller)
    assert alerts.describe_destination(pm) == "paybill 852648 / acct 139738"


@pytest.mark.asyncio
async def test_describe_destination_paybill_and_till(db):
    reseller = await make_reseller(db)
    paybill = await _make_method(
        db, reseller, method_type=ResellerPaymentMethodType.MPESA_PAYBILL,
        bank_paybill_number=None, bank_account_number=None,
        mpesa_paybill_number="5652581")
    assert alerts.describe_destination(paybill) == "paybill 5652581"

    till = await _make_method(
        db, reseller, method_type=ResellerPaymentMethodType.MPESA_TILL,
        bank_paybill_number=None, bank_account_number=None,
        mpesa_till_number="4159825")
    assert alerts.describe_destination(till) == "till 4159825"


def test_describe_destination_handles_none():
    assert alerts.describe_destination(None) == "none"


# --------------------------------------------------------------------------
# render_change_notification -- pure, so assert on the words the reseller reads
# --------------------------------------------------------------------------

def test_render_shows_before_and_after():
    subject, body = render = alerts.render_change_notification(
        PayoutDestinationAction.UPDATED, "my mpesa",
        "paybill 852648 / acct 139738", "paybill 5652581",
        actor_is_owner=True)
    assert "changed" in subject
    assert "Was: paybill 852648 / acct 139738" in body
    assert "Now: paybill 5652581" in body
    assert "contact support immediately" in body
    assert "Made by" not in body  # owner acted on their own account


def test_render_names_a_non_owner_actor():
    _, body = alerts.render_change_notification(
        PayoutDestinationAction.DEACTIVATED, "my mpesa",
        "paybill 852648 / acct 139738", None,
        actor_is_owner=False, actor_email="staff@bitwave.co.ke")
    assert "Made by: staff@bitwave.co.ke" in body
    assert "switched off" in body


def test_render_deactivation_subject_distinct_from_update():
    deact, _ = alerts.render_change_notification(
        PayoutDestinationAction.DEACTIVATED, "x", "paybill 1", None,
        actor_is_owner=True)
    upd, _ = alerts.render_change_notification(
        PayoutDestinationAction.UPDATED, "x", "paybill 1", "paybill 2",
        actor_is_owner=True)
    assert deact != upd


# --------------------------------------------------------------------------
# record_and_notify -- the trail and the alert
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_records_audit_row_and_notifies_owner(db):
    await make_admin(db)
    reseller = await make_reseller(db)

    log_id = await alerts.record_and_notify(
        user_id=reseller.id,
        actor_user_id=reseller.id,
        action=PayoutDestinationAction.UPDATED,
        payment_method_id=7,
        method_type="bank_account",
        label="my mpesa",
        destination_before="paybill 852648 / acct 139738",
        destination_after="paybill 5652581",
    )
    assert log_id is not None

    rows = await _logs(db, reseller.id)
    assert len(rows) == 1
    row = rows[0]
    assert row.action == PayoutDestinationAction.UPDATED
    assert row.actor_user_id == reseller.id
    assert row.destination_before == "paybill 852648 / acct 139738"
    assert row.destination_after == "paybill 5652581"
    assert row.notified is True

    messages = await _inbox(db, reseller.id)
    assert len(messages) == 1
    assert "5652581" in messages[0].body
    assert "852648" in messages[0].body


@pytest.mark.asyncio
async def test_audit_row_written_even_when_no_admin_sender_exists(db):
    """The trail is the safety net -- it must survive a failed notification."""
    reseller = await make_reseller(db)  # deliberately no admin in the DB

    log_id = await alerts.record_and_notify(
        user_id=reseller.id,
        actor_user_id=reseller.id,
        action=PayoutDestinationAction.DEACTIVATED,
        payment_method_id=7,
        destination_before="paybill 852648 / acct 139738",
    )

    assert log_id is not None
    rows = await _logs(db, reseller.id)
    assert len(rows) == 1
    assert rows[0].notified is False
    assert await _inbox(db, reseller.id) == []


@pytest.mark.asyncio
async def test_records_admin_actor_separately_from_owner(db):
    admin = await make_admin(db)
    reseller = await make_reseller(db)

    await alerts.record_and_notify(
        user_id=reseller.id,
        actor_user_id=admin.id,
        action=PayoutDestinationAction.UPDATED,
        payment_method_id=7,
        destination_before="paybill 1",
        destination_after="paybill 2",
    )

    rows = await _logs(db, reseller.id)
    assert rows[0].actor_user_id == admin.id
    assert rows[0].user_id == reseller.id
    messages = await _inbox(db, reseller.id)
    assert admin.email in messages[0].body


@pytest.mark.asyncio
async def test_log_is_append_only_across_a_sequence_of_changes(db):
    """Replays the incident shape: add decoy -> deactivate real -> restore."""
    await make_admin(db)
    reseller = await make_reseller(db)

    await alerts.record_and_notify(
        user_id=reseller.id, actor_user_id=reseller.id,
        action=PayoutDestinationAction.CREATED, payment_method_id=109,
        label="Mpesa till", destination_after="paybill 5652581")
    await alerts.record_and_notify(
        user_id=reseller.id, actor_user_id=reseller.id,
        action=PayoutDestinationAction.DEACTIVATED, payment_method_id=91,
        label="my mpesa", destination_before="paybill 852648 / acct 139738")
    await alerts.record_and_notify(
        user_id=reseller.id, actor_user_id=reseller.id,
        action=PayoutDestinationAction.CREATED, payment_method_id=120,
        label="bannk", destination_after="paybill 852648 / acct 139738")

    rows = await _logs(db, reseller.id)
    assert [r.action for r in rows] == [
        PayoutDestinationAction.CREATED,
        PayoutDestinationAction.DEACTIVATED,
        PayoutDestinationAction.CREATED,
    ]
    # The whole point: the decoy is attributable and reconstructable.
    assert rows[0].destination_after == "paybill 5652581"
    assert rows[1].destination_before == "paybill 852648 / acct 139738"
    assert len(await _inbox(db, reseller.id)) == 3


@pytest.mark.asyncio
async def test_never_raises_on_missing_owner(db):
    """An alert failure must not break the edit the reseller just made."""
    log_id = await alerts.record_and_notify(
        user_id=999999,  # no such user
        actor_user_id=999999,
        action=PayoutDestinationAction.UPDATED,
        payment_method_id=1,
    )
    # Either it wrote nothing (FK rejected) or it wrote the row; what matters
    # is that it returned instead of propagating.
    assert log_id is None or isinstance(log_id, int)
