"""AI triage service: persistence, spam flip, critical alert, failure paths.

Drives run_feedback_triage()/draft_status_reply() directly against the test
DB (conftest rebinds database.async_session), monkeypatching the single
Anthropic seam feedback_ai._call_model — no network involved.
"""

import pytest
from sqlalchemy import select

from app.db.models import (
    FeedbackKind,
    FeedbackPost,
    FeedbackStatus,
    ResellerInboxMessage,
)
from app.services import feedback_ai
from tests.factories import make_admin, make_reseller


def _triage_result(**overrides):
    result = {
        "is_spam": False,
        "kind": "bug",
        "severity": 3,
        "summary": "Hotspot login page not loading for customers",
        "affected_area": "hotspot",
        "duplicate_candidate_ids": [],
        "rationale": "Broken but likely scoped to one router.",
    }
    result.update(overrides)
    return result


def _patch_model(monkeypatch, result):
    calls = []

    async def _fake(**kwargs):
        calls.append(kwargs)
        if isinstance(result, Exception):
            raise result
        return dict(result)
    monkeypatch.setattr(feedback_ai, "_call_model", _fake)
    return calls


def _enable_ai(monkeypatch):
    monkeypatch.setattr(feedback_ai.settings, "ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(feedback_ai.settings, "FEEDBACK_AI_ENABLED", True)


async def _make_post(db, user, **overrides):
    defaults = dict(user_id=user.id, kind=FeedbackKind.BUG,
                    title="Portal down", body="Customers cannot log in at all.")
    defaults.update(overrides)
    post = FeedbackPost(**defaults)
    db.add(post)
    await db.commit()
    await db.refresh(post)
    return post


@pytest.mark.asyncio
async def test_triage_persists_verdict(db, monkeypatch):
    r = await make_reseller(db)
    post = await _make_post(db, r)
    _enable_ai(monkeypatch)
    _patch_model(monkeypatch, _triage_result())

    await feedback_ai.run_feedback_triage(post.id)

    await db.refresh(post)
    assert post.ai_triaged_at is not None
    assert post.ai_severity == 3
    assert post.ai_kind == "bug"
    assert post.ai_affected_area == "hotspot"
    assert post.ai_error is None
    assert post.status == FeedbackStatus.NEW  # non-spam stays new


@pytest.mark.asyncio
async def test_spam_verdict_flips_status(db, monkeypatch):
    r = await make_reseller(db)
    post = await _make_post(db, r)
    _enable_ai(monkeypatch)
    _patch_model(monkeypatch, _triage_result(is_spam=True, kind="other",
                                             severity=1))

    await feedback_ai.run_feedback_triage(post.id)

    await db.refresh(post)
    assert post.ai_spam is True
    assert post.status == FeedbackStatus.SPAM


@pytest.mark.asyncio
async def test_critical_bug_alerts_admin_inbox(db, monkeypatch):
    r = await make_reseller(db)
    admin = await make_admin(db)
    post = await _make_post(db, r)
    _enable_ai(monkeypatch)
    _patch_model(monkeypatch, _triage_result(severity=5))

    await feedback_ai.run_feedback_triage(post.id)

    msgs = (await db.execute(select(ResellerInboxMessage))).scalars().all()
    assert len(msgs) == 1
    assert msgs[0].recipient_user_id == admin.id
    assert "Critical bug report" in msgs[0].subject


@pytest.mark.asyncio
async def test_low_severity_does_not_alert(db, monkeypatch):
    r = await make_reseller(db)
    await make_admin(db)
    post = await _make_post(db, r)
    _enable_ai(monkeypatch)
    _patch_model(monkeypatch, _triage_result(severity=2))

    await feedback_ai.run_feedback_triage(post.id)

    msgs = (await db.execute(select(ResellerInboxMessage))).scalars().all()
    assert msgs == []


@pytest.mark.asyncio
async def test_model_failure_records_error_and_never_raises(db, monkeypatch):
    r = await make_reseller(db)
    post = await _make_post(db, r)
    _enable_ai(monkeypatch)
    _patch_model(monkeypatch, RuntimeError("api exploded"))

    await feedback_ai.run_feedback_triage(post.id)  # must not raise

    await db.refresh(post)
    assert post.ai_error == "api exploded"
    assert post.ai_triaged_at is None
    assert post.status == FeedbackStatus.NEW


@pytest.mark.asyncio
async def test_disabled_ai_is_a_noop(db, monkeypatch):
    r = await make_reseller(db)
    post = await _make_post(db, r)
    monkeypatch.setattr(feedback_ai.settings, "ANTHROPIC_API_KEY", "")
    calls = _patch_model(monkeypatch, _triage_result())

    await feedback_ai.run_feedback_triage(post.id)

    await db.refresh(post)
    assert calls == []
    assert post.ai_triaged_at is None
    assert post.status == FeedbackStatus.NEW


@pytest.mark.asyncio
async def test_invented_duplicate_ids_are_rejected(db, monkeypatch):
    r = await make_reseller(db)
    other = await _make_post(db, r, title="Existing report")
    post = await _make_post(db, r)
    _enable_ai(monkeypatch)
    # 999999 was never offered as a candidate; `other` was.
    _patch_model(monkeypatch, _triage_result(
        duplicate_candidate_ids=[999999, other.id]))

    await feedback_ai.run_feedback_triage(post.id)

    await db.refresh(post)
    assert post.ai_duplicate_of_id == other.id


@pytest.mark.asyncio
async def test_draft_reply_requires_ai(db, monkeypatch):
    r = await make_reseller(db)
    post = await _make_post(db, r)
    monkeypatch.setattr(feedback_ai.settings, "ANTHROPIC_API_KEY", "")
    with pytest.raises(RuntimeError):
        await feedback_ai.draft_status_reply(post.id)


@pytest.mark.asyncio
async def test_draft_reply_returns_subject_and_body(db, monkeypatch):
    r = await make_reseller(db)
    post = await _make_post(db, r)
    _enable_ai(monkeypatch)
    _patch_model(monkeypatch, {"subject": "Fixed: Portal down",
                               "body": "We deployed a fix this morning."})

    draft = await feedback_ai.draft_status_reply(post.id, "fixed")
    assert draft == {"subject": "Fixed: Portal down",
                     "body": "We deployed a fix this morning."}
