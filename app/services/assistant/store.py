"""Conversations and pending actions. Every function is one short DB session.

Never call these with a session of your own held open, and never hold one
across a model or API call (AGENTS.md, Database Session Discipline).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import and_, delete, select, update

from app.config import settings
from app.db import database as db_module
from app.db.models import AssistantAction, AssistantConversation
from app.services.assistant.caller import Caller

TRANSCRIPT_LIMIT = 400  # UI events kept per conversation


def _model_name() -> str:
    from app.services.assistant.agent import model_name

    return model_name()


def _owner_filter(model, caller: Caller):
    return and_(
        model.user_id == caller.user_id,
        model.staff_id.is_(None) if caller.staff_id is None else model.staff_id == caller.staff_id,
        model.viewer_sid.is_(None) if caller.viewer_sid is None else model.viewer_sid == caller.viewer_sid,
    )


# -- conversations ------------------------------------------------------------

async def create_conversation(caller: Caller, title: str) -> dict:
    now = datetime.utcnow()
    conv = AssistantConversation(
        id=str(uuid.uuid4()), user_id=caller.user_id, staff_id=caller.staff_id,
        viewer_sid=caller.viewer_sid, title=(title or "New chat")[:200],
        messages=[], transcript=[], model=_model_name(),
        created_at=now, updated_at=now,
    )
    async with db_module.async_session() as db:
        db.add(conv)
        await db.commit()
    await purge_old()
    return {"id": conv.id, "title": conv.title, "messages": [], "transcript": []}


async def load_conversation(caller: Caller, conversation_id: str) -> Optional[dict]:
    async with db_module.async_session() as db:
        conv = (await db.execute(
            select(AssistantConversation).where(
                AssistantConversation.id == conversation_id,
                _owner_filter(AssistantConversation, caller),
            )
        )).scalar_one_or_none()
        if conv is None:
            return None
        return {
            "id": conv.id, "title": conv.title,
            "messages": list(conv.messages or []),
            "transcript": list(conv.transcript or []),
            "updated_at": conv.updated_at,
        }


async def save_conversation(caller: Caller, conversation_id: str, *, messages: list,
                            transcript: list, input_tokens: int = 0, output_tokens: int = 0,
                            title: Optional[str] = None) -> None:
    values: dict[str, Any] = {
        "messages": messages,
        "transcript": transcript[-TRANSCRIPT_LIMIT:],
        "updated_at": datetime.utcnow(),
        "input_tokens": AssistantConversation.input_tokens + int(input_tokens or 0),
        "output_tokens": AssistantConversation.output_tokens + int(output_tokens or 0),
    }
    if title:
        values["title"] = title[:200]
    async with db_module.async_session() as db:
        await db.execute(
            update(AssistantConversation)
            .where(AssistantConversation.id == conversation_id,
                   _owner_filter(AssistantConversation, caller))
            .values(**values)
        )
        await db.commit()


async def list_conversations(caller: Caller, limit: int = 50) -> list[dict]:
    async with db_module.async_session() as db:
        rows = (await db.execute(
            select(AssistantConversation.id, AssistantConversation.title,
                   AssistantConversation.updated_at, AssistantConversation.created_at)
            .where(_owner_filter(AssistantConversation, caller))
            .order_by(AssistantConversation.updated_at.desc())
            .limit(limit)
        )).all()
    return [{"id": r[0], "title": r[1], "updated_at": r[2], "created_at": r[3]} for r in rows]


async def delete_conversation(caller: Caller, conversation_id: str) -> bool:
    async with db_module.async_session() as db:
        result = await db.execute(
            delete(AssistantConversation).where(
                AssistantConversation.id == conversation_id,
                _owner_filter(AssistantConversation, caller),
            )
        )
        await db.execute(
            update(AssistantAction)
            .where(AssistantAction.conversation_id == conversation_id,
                   AssistantAction.status == "pending")
            .values(status="expired", decided_at=datetime.utcnow())
        )
        await db.commit()
    return (result.rowcount or 0) > 0


async def purge_old() -> None:
    cutoff = datetime.utcnow() - timedelta(days=max(1, settings.ASSISTANT_RETENTION_DAYS))
    async with db_module.async_session() as db:
        old = select(AssistantConversation.id).where(AssistantConversation.updated_at < cutoff)
        await db.execute(delete(AssistantAction).where(AssistantAction.conversation_id.in_(old)))
        await db.execute(delete(AssistantConversation).where(AssistantConversation.updated_at < cutoff))
        await db.commit()


# -- pending actions ----------------------------------------------------------

async def create_action(caller: Caller, conversation_id: str, *, method: str, path: str,
                        template: str, query: Optional[dict], body: Any, title: str,
                        permission: Optional[str], tool_use_id: Optional[str]) -> dict:
    now = datetime.utcnow()
    action = AssistantAction(
        id=str(uuid.uuid4()), conversation_id=conversation_id,
        user_id=caller.user_id, staff_id=caller.staff_id, viewer_sid=caller.viewer_sid,
        method=method, path=path, template=template, query=query or None, body=body,
        title=title[:200], permission=permission, status="pending", tool_use_id=tool_use_id,
        created_at=now,
        expires_at=now + timedelta(minutes=max(1, settings.ASSISTANT_ACTION_TTL_MINUTES)),
    )
    async with db_module.async_session() as db:
        db.add(action)
        await db.commit()
    return action_view(action)


def action_view(a: AssistantAction) -> dict:
    return {
        "id": a.id, "conversation_id": a.conversation_id, "method": a.method, "path": a.path,
        "template": a.template, "query": a.query, "body": a.body, "title": a.title,
        "permission": a.permission, "status": a.status,
        "created_at": a.created_at.isoformat() + "Z" if a.created_at else None,
        "expires_at": a.expires_at.isoformat() + "Z" if a.expires_at else None,
        "result_status": a.result_status, "result_summary": a.result_summary,
    }


async def actions_for(caller: Caller, conversation_id: str) -> dict[str, dict]:
    async with db_module.async_session() as db:
        rows = (await db.execute(
            select(AssistantAction).where(
                AssistantAction.conversation_id == conversation_id,
                _owner_filter(AssistantAction, caller),
            )
        )).scalars().all()
    now = datetime.utcnow()
    out = {}
    for a in rows:
        view = action_view(a)
        if a.status == "pending" and a.expires_at < now:
            view["status"] = "expired"
        out[a.id] = view
    return out


async def pending_actions(caller: Caller, conversation_id: str) -> list[dict]:
    """This caller's pending, unexpired actions in the conversation, oldest first."""
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        rows = (await db.execute(
            select(AssistantAction).where(
                AssistantAction.conversation_id == conversation_id,
                AssistantAction.status == "pending",
                AssistantAction.expires_at >= now,
                _owner_filter(AssistantAction, caller),
            ).order_by(AssistantAction.created_at)
        )).scalars().all()
    return [action_view(a) for a in rows]


def _comparable(body: Any) -> Any:
    if isinstance(body, dict):
        return {k: v for k, v in body.items() if k != "idempotency_key"}
    return body


def same_change(old: dict, new: dict) -> bool:
    """Whether a new proposal is for the same change as an older one.

    Same method and concrete path. A path naming a record or setting (a router's
    anti-bypass, customer 47532, the portal settings) is one target, so a newer body
    for it supersedes the older one. A create (POST to a path with no id in it) makes
    a new record each time: it is the same change only when the request is the same,
    or names the same record (the same ``name``).
    """
    if old["method"] != new["method"] or old["path"] != new["path"]:
        return False
    if new["method"] != "POST" or "{" in (new.get("template") or ""):
        return True
    a, b = _comparable(old.get("body")), _comparable(new.get("body"))
    if a == b and (old.get("query") or None) == (new.get("query") or None):
        return True
    return (isinstance(a, dict) and isinstance(b, dict) and bool(a.get("name"))
            and str(a.get("name")).strip().lower() == str(b.get("name") or "").strip().lower())


async def retire_superseded(caller: Caller, conversation_id: str, newest: dict) -> list[dict]:
    """Close the older pending cards for the same change as ``newest`` (status expired).

    Only the newest card can then be confirmed; confirming a retired one is refused
    like any expired card. Returns the retired actions.
    """
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        rows = (await db.execute(
            select(AssistantAction).where(
                AssistantAction.conversation_id == conversation_id,
                AssistantAction.id != newest["id"],
                AssistantAction.status == "pending",
                AssistantAction.method == newest["method"],
                AssistantAction.path == newest["path"],
                _owner_filter(AssistantAction, caller),
            )
        )).scalars().all()
        older = [a for a in rows if same_change(action_view(a), newest)]
        if not older:
            return []
        await db.execute(
            update(AssistantAction)
            .where(AssistantAction.id.in_([a.id for a in older]), AssistantAction.status == "pending")
            .values(status="expired", decided_at=now, result_summary="replaced by a newer card")
        )
        await db.commit()
        return [{"id": a.id, "title": a.title} for a in older]


async def claim_action(caller: Caller, conversation_id: str, action_id: str,
                       new_status: str) -> Optional[dict]:
    """Atomically move a pending, unexpired action of this caller to ``new_status``.

    Returns the action, or None if it is not this caller's, already decided, or
    expired (an expired one is marked so). Exactly one of two racing confirms wins.
    """
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        result = await db.execute(
            update(AssistantAction)
            .where(
                AssistantAction.id == action_id,
                AssistantAction.conversation_id == conversation_id,
                AssistantAction.status == "pending",
                AssistantAction.expires_at >= now,
                _owner_filter(AssistantAction, caller),
            )
            .values(status=new_status, decided_at=now)
        )
        if (result.rowcount or 0) == 0:
            await db.execute(
                update(AssistantAction)
                .where(AssistantAction.id == action_id, AssistantAction.status == "pending",
                       AssistantAction.expires_at < now, _owner_filter(AssistantAction, caller))
                .values(status="expired", decided_at=now)
            )
            await db.commit()
            return None
        await db.commit()
        action = (await db.execute(
            select(AssistantAction).where(AssistantAction.id == action_id)
        )).scalar_one()
        return action_view(action)


async def pending_action(caller: Caller, conversation_id: str, action_id: str) -> Optional[dict]:
    """A pending, unexpired action of this caller, without deciding it."""
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        action = (await db.execute(
            select(AssistantAction).where(
                AssistantAction.id == action_id,
                AssistantAction.conversation_id == conversation_id,
                AssistantAction.status == "pending",
                AssistantAction.expires_at >= now,
                _owner_filter(AssistantAction, caller),
            )
        )).scalar_one_or_none()
        return action_view(action) if action is not None else None


async def set_action_body(action_id: str, body: Any) -> None:
    """Keep what the person filled in on the action, so the record shows what really ran."""
    async with db_module.async_session() as db:
        await db.execute(
            update(AssistantAction)
            .where(AssistantAction.id == action_id, AssistantAction.status == "pending")
            .values(body=body)
        )
        await db.commit()


async def finish_action(action_id: str, *, status: str, result_status: Optional[int],
                        result_summary: str) -> None:
    async with db_module.async_session() as db:
        await db.execute(
            update(AssistantAction).where(AssistantAction.id == action_id).values(
                status=status, result_status=result_status, result_summary=result_summary[:500],
            )
        )
        await db.commit()


# -- Bitwave support view (platform admins only; routes check the role) -------

async def admin_list(*, reseller_id: Optional[int] = None, limit: int = 100) -> list[dict]:
    from app.db.models import ResellerStaff, User

    async with db_module.async_session() as db:
        stmt = (
            select(AssistantConversation.id, AssistantConversation.title,
                   AssistantConversation.user_id, AssistantConversation.staff_id,
                   AssistantConversation.viewer_sid, AssistantConversation.updated_at,
                   AssistantConversation.created_at, User.organization_name, User.email,
                   ResellerStaff.name)
            .join(User, User.id == AssistantConversation.user_id, isouter=True)
            .join(ResellerStaff, ResellerStaff.id == AssistantConversation.staff_id, isouter=True)
            .order_by(AssistantConversation.updated_at.desc())
            .limit(limit)
        )
        if reseller_id is not None:
            stmt = stmt.where(AssistantConversation.user_id == reseller_id)
        rows = (await db.execute(stmt)).all()
    return [{
        "id": r[0], "title": r[1], "user_id": r[2], "staff_id": r[3], "view_as": r[4] is not None,
        "updated_at": r[5], "created_at": r[6], "organization_name": r[7], "email": r[8],
        "staff_name": r[9],
    } for r in rows]


async def admin_load(conversation_id: str) -> Optional[dict]:
    from app.db.models import User

    async with db_module.async_session() as db:
        conv = await db.get(AssistantConversation, conversation_id)
        if conv is None:
            return None
        owner = await db.get(User, conv.user_id)
        actions = (await db.execute(
            select(AssistantAction).where(AssistantAction.conversation_id == conversation_id)
        )).scalars().all()
        return {
            "id": conv.id, "title": conv.title, "user_id": conv.user_id, "staff_id": conv.staff_id,
            "organization_name": owner.organization_name if owner else None,
            "email": owner.email if owner else None,
            "transcript": list(conv.transcript or []),
            "actions": {a.id: action_view(a) for a in actions},
            "updated_at": conv.updated_at,
            "usage": {"input_tokens": conv.input_tokens, "output_tokens": conv.output_tokens},
        }


async def admin_name(user_id: int) -> str:
    from app.db.models import User

    async with db_module.async_session() as db:
        user = await db.get(User, user_id)
    if user is None:
        return "Bitwave support"
    return (getattr(user, "organization_name", None) or user.email or "Bitwave support")[:80]


async def append_support_note(conversation_id: str, *, author: str, author_id: int,
                              text: str) -> Optional[dict]:
    """Add a support note to the chat and to the model's history (append-only)."""
    now = datetime.utcnow()
    note = {"type": "support", "at": now.isoformat() + "Z", "author": author, "text": text}
    async with db_module.async_session() as db:
        conv = await db.get(AssistantConversation, conversation_id)
        if conv is None:
            return None
        messages = list(conv.messages or [])
        messages.append({"role": "user", "content": [{
            "type": "text",
            "text": f"[Bitwave support note from {author}] {text}",
        }]})
        conv.messages = messages
        conv.transcript = (list(conv.transcript or []) + [note])[-TRANSCRIPT_LIMIT:]
        conv.updated_at = now
        await db.commit()
    return note


async def notify_support_note(conversation_id: str, *, sender_id: int, text: str) -> None:
    """Tell the account in its dashboard inbox that support wrote in the chat."""
    from app.db.models import ResellerInboxMessage

    async with db_module.async_session() as db:
        conv = await db.get(AssistantConversation, conversation_id)
        if conv is None:
            return
        db.add(ResellerInboxMessage(
            recipient_user_id=conv.user_id,
            sender_user_id=sender_id,
            subject="Bitwave support replied in your assistant chat",
            body=(f"{text[:1700]}\n\nOpen the chat: /assistant?c={conversation_id}")[:2000],
        ))
        await db.commit()
