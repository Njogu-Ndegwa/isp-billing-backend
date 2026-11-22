"""A withdrawal is followed until the money arrives: the chat's card says Sent, Not sent or still sending."""
from types import SimpleNamespace

import pytest

from app.api import b2b_routes
from app.api.b2b_routes import withdrawal_state
from app.db.models import B2BTransaction, B2BTransactionStatus
from tests.factories import make_reseller


def txn(status, net=166.0, ref=None, desc=None):
    return SimpleNamespace(status=B2BTransactionStatus(status), net_amount=net, transaction_id=ref, result_desc=desc)


def test_sent_says_how_much_and_the_mpesa_reference():
    s = withdrawal_state([txn("completed", ref="UKM552TU3P")])
    assert s["paid"] is True and s["status"] == "completed"
    assert s["summary"] == "Sent: KES 166 reached your account (M-Pesa ref UKM552TU3P)."


def test_not_sent_gives_the_reason_and_says_the_money_stayed():
    s = withdrawal_state([txn("failed", desc="The receiver account is invalid")])
    assert s["status"] == "failed" and s["paid"] is False
    assert "The receiver account is invalid" in s["summary"] and "still in your balance" in s["summary"]


def test_still_on_its_way_and_unconfirmed_are_not_answers_yet():
    assert withdrawal_state([txn("pending")])["status"] == "pending"
    assert "checking" in withdrawal_state([txn("timeout")])["summary"]
    # one transfer done, the other still going: not finished
    assert withdrawal_state([txn("completed"), txn("pending")])["status"] == "pending"


def test_a_split_withdrawal_that_partly_failed_says_which_part():
    s = withdrawal_state([txn("completed", net=100), txn("failed", net=66, desc="Rejected")])
    assert s["status"] == "failed" and "KES 100 was sent; KES 66 was not" in s["summary"]


@pytest.mark.asyncio
async def test_status_is_read_only_for_the_account_that_withdrew(db, monkeypatch):
    from fastapi import HTTPException

    owner, other = await make_reseller(db), await make_reseller(db)
    t = B2BTransaction(reseller_id=owner.id, amount=171, fee=5, net_amount=166, party_a="1", party_b="247247",
                       status=B2BTransactionStatus.COMPLETED, transaction_id="UKM552TU3P")
    db.add(t)
    await db.commit()

    async def as_owner(_t, _d):
        return owner

    async def as_other(_t, _d):
        return other

    monkeypatch.setattr(b2b_routes, "get_current_user", as_owner)
    out = await b2b_routes.withdrawal_status(str(t.id), db=db, token="t")
    assert out["paid"] is True and out["transfers"][0]["transaction_id"] == "UKM552TU3P"
    monkeypatch.setattr(b2b_routes, "get_current_user", as_other)
    with pytest.raises(HTTPException) as exc:
        await b2b_routes.withdrawal_status(str(t.id), db=db, token="t")
    assert exc.value.status_code == 404


def test_the_chat_follows_a_withdrawal_as_a_payout():
    import main
    from app.services.assistant.catalog import get_catalog

    spec = next(a for a in get_catalog(main.app).actions if a.template == "/api/reseller/withdraw")
    assert spec.payment_status == "/api/reseller/withdrawals/{withdrawal_ids}/status"
    assert spec.payment_kind == "payout"
