"""initiate_b2b_payment write-ahead intent — the authoritative double-spend guard.

The invariant under test: a PENDING intent row is COMMITTED before any network
I/O, so no matter where the Safaricom call fails (or the app dies), the ledger
can never show an unspent balance while money may be moving. Definitely-not-sent
failures release the balance (FAILED); ambiguous failures stay PENDING and
block further payouts until manually reconciled.
"""

from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import select

from app.db.models import B2BTransaction, B2BTransactionStatus
from tests.factories import make_reseller

pytestmark = pytest.mark.asyncio


def _patch_env(b2b, monkeypatch):
    monkeypatch.setattr(b2b, "_get_access_token", AsyncMock(return_value="token"))
    monkeypatch.setattr(b2b, "generate_security_credential", lambda: "credential")
    monkeypatch.setattr(b2b.settings, "MPESA_SHORTCODE", "600980", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_INITIATOR_NAME", "initiator", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_RESULT_URL", "https://example.com/result", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_B2B_TIMEOUT_URL", "https://example.com/timeout", raising=False)
    monkeypatch.setattr(b2b.settings, "MPESA_ENVIRONMENT", "sandbox", raising=False)


def _install_client(monkeypatch, b2b, post_fn):
    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json, headers):
            return await post_fn(url, json, headers)

    monkeypatch.setattr(b2b.httpx, "AsyncClient", FakeAsyncClient)


async def _initiate(b2b, db, reseller_id):
    return await b2b.initiate_b2b_payment(
        db=db,
        reseller_id=reseller_id,
        amount=500,
        party_b="247247",
        account_reference="ref-1",
        fee=13,
    )


async def _sole_txn(session_factory):
    """Read the single committed transaction from a FRESH session, proving the
    intent survived the caller's session (i.e. it was committed, not flushed)."""
    async with session_factory() as other:
        return (await other.execute(select(B2BTransaction))).scalar_one()


async def test_lost_ack_keeps_intent_pending_and_blocks_next_payout(
    engine, db, session_factory, monkeypatch
):
    """Read timeout after the request may have reached Safaricom: money may be
    moving. The committed intent must stay PENDING and block any further
    payout for this reseller."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    _patch_env(b2b, monkeypatch)

    async def post_fn(url, json, headers):
        raise httpx.ReadTimeout("read timed out")

    _install_client(monkeypatch, b2b, post_fn)

    with pytest.raises(RuntimeError):
        await _initiate(b2b, db, reseller.id)

    txn = await _sole_txn(session_factory)
    assert txn.status == B2BTransactionStatus.PENDING
    assert txn.conversation_id is None
    assert "no ack" in (txn.result_desc or "")

    assert await b2b.has_unresolved_b2b(db, reseller.id) is True
    with pytest.raises(b2b.PayoutInFlightError):
        await _initiate(b2b, db, reseller.id)


async def test_connect_error_fails_intent_and_releases_balance(
    engine, db, session_factory, monkeypatch
):
    """Connection never established: the request cannot have reached Safaricom,
    so the intent is FAILED and the reseller is NOT blocked."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    _patch_env(b2b, monkeypatch)

    async def post_fn(url, json, headers):
        raise httpx.ConnectError("connection refused")

    _install_client(monkeypatch, b2b, post_fn)

    with pytest.raises(RuntimeError):
        await _initiate(b2b, db, reseller.id)

    txn = await _sole_txn(session_factory)
    assert txn.status == B2BTransactionStatus.FAILED
    assert "not sent" in (txn.result_desc or "")
    assert await b2b.has_unresolved_b2b(db, reseller.id) is False


async def test_token_failure_fails_intent_before_send(
    engine, db, session_factory, monkeypatch
):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    _patch_env(b2b, monkeypatch)
    monkeypatch.setattr(
        b2b, "_get_access_token", AsyncMock(side_effect=RuntimeError("token svc down"))
    )

    async def post_fn(url, json, headers):  # pragma: no cover - must not be reached
        raise AssertionError("must not send without a token")

    _install_client(monkeypatch, b2b, post_fn)

    with pytest.raises(RuntimeError):
        await _initiate(b2b, db, reseller.id)

    txn = await _sole_txn(session_factory)
    assert txn.status == B2BTransactionStatus.FAILED
    assert "failed before send" in (txn.result_desc or "")
    assert await b2b.has_unresolved_b2b(db, reseller.id) is False


async def test_non_json_ack_keeps_intent_pending(
    engine, db, session_factory, monkeypatch
):
    """A gateway error page instead of the API's JSON: whether the payment was
    queued is unknowable — stay PENDING (blocked) rather than risk a re-send."""
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    _patch_env(b2b, monkeypatch)

    class GatewayErrorResponse:
        status_code = 502
        text = "<html>Bad Gateway</html>"

        def json(self):
            raise ValueError("not json")

    async def post_fn(url, json, headers):
        return GatewayErrorResponse()

    _install_client(monkeypatch, b2b, post_fn)

    with pytest.raises(RuntimeError):
        await _initiate(b2b, db, reseller.id)

    txn = await _sole_txn(session_factory)
    assert txn.status == B2BTransactionStatus.PENDING
    assert "non-JSON ack" in (txn.result_desc or "")
    assert await b2b.has_unresolved_b2b(db, reseller.id) is True


async def test_accepted_send_commits_pending_intent_with_ids_and_blocks_next(
    engine, db, session_factory, monkeypatch
):
    from app.services import mpesa_b2b as b2b

    reseller = await make_reseller(db)
    _patch_env(b2b, monkeypatch)

    class OkResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {
                "ResponseCode": "0",
                "ConversationID": "conv-9",
                "OriginatorConversationID": "orig-9",
            }

    async def post_fn(url, json, headers):
        return OkResponse()

    _install_client(monkeypatch, b2b, post_fn)

    txn = await _initiate(b2b, db, reseller.id)
    assert txn.status == B2BTransactionStatus.PENDING

    committed = await _sole_txn(session_factory)
    assert committed.status == B2BTransactionStatus.PENDING
    assert committed.conversation_id == "conv-9"
    assert committed.originator_conversation_id == "orig-9"

    # The pending payout blocks a second initiation until a verdict arrives.
    with pytest.raises(b2b.PayoutInFlightError):
        await _initiate(b2b, db, reseller.id)
