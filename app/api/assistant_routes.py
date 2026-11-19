"""Dashboard assistant API (see app/services/assistant/__init__.py).

POST /api/assistant/chat and POST /api/assistant/conversations/{id}/decide
answer with a Server-Sent Events stream: text deltas, tool steps, data blocks,
confirm cards and results, then ``done``. The work runs in its own task, so a
dropped connection does not lose a proposed action or the conversation.

These routes hold no DB session while the model or an action runs.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.services.assistant import store, usage
from app.services.assistant.agent import Turn, assistant_ready, conversation_lock, model_name, provider
from app.services.assistant.caller import Caller, caller_from_request
from app.services.assistant.executor import ASSISTANT_HEADER

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/assistant", tags=["assistant"])

_TASKS: set = set()
PING_SECONDS = 15


IMAGE_TYPES = ("image/jpeg", "image/png", "image/webp", "image/gif")
_MAGIC = {"image/jpeg": (b"\xff\xd8\xff",), "image/png": (b"\x89PNG",),
          "image/gif": (b"GIF87a", b"GIF89a"), "image/webp": (b"RIFF",)}
MAX_IMAGE_BYTES = 4 * 1024 * 1024      # the model takes up to 5 MB per image
MAX_THUMBNAIL_CHARS = 80_000


class ImageIn(BaseModel):
    media_type: str = Field(..., max_length=20)
    data: str = Field(..., max_length=6_000_000)          # base64
    thumbnail: Optional[str] = Field(None, max_length=MAX_THUMBNAIL_CHARS)  # small data: URL for the screen


class ChatRequest(BaseModel):
    message: str = Field("", max_length=6000)
    conversation_id: Optional[str] = Field(None, max_length=36)
    images: list[ImageIn] = Field(default_factory=list, max_length=4)


class NoteRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)
    notify: bool = True


def _check_images(images: list[ImageIn]) -> list[dict]:
    """Photos must really be images of an allowed type and size."""
    import base64
    import binascii

    out = []
    for image in images:
        if image.media_type not in IMAGE_TYPES:
            raise HTTPException(status_code=422, detail="Photos must be JPEG, PNG, WebP or GIF.")
        try:
            raw = base64.b64decode(image.data, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=422, detail="A photo could not be read.")
        if len(raw) > MAX_IMAGE_BYTES:
            raise HTTPException(status_code=413, detail="A photo is too large (4 MB at most).")
        if not raw.startswith(_MAGIC[image.media_type]):
            raise HTTPException(status_code=422, detail="A photo is not the type it claims to be.")
        thumb = image.thumbnail
        if thumb and not thumb.startswith(("data:image/jpeg;base64,", "data:image/png;base64,",
                                           "data:image/webp;base64,")):
            thumb = None
        out.append({"media_type": image.media_type, "data": image.data, "thumbnail": thumb})
    return out


class Decision(BaseModel):
    action_id: str = Field(..., max_length=36)
    approve: bool


class DecideRequest(BaseModel):
    decisions: list[Decision] = Field(..., min_length=1, max_length=20)


async def _caller(request: Request) -> Caller:
    if request.headers.get(ASSISTANT_HEADER):
        raise HTTPException(status_code=403, detail="The assistant cannot call itself.")
    return await caller_from_request(request)


def _require_ready() -> None:
    ready, reason = assistant_ready()
    if not ready:
        raise HTTPException(status_code=503, detail={"code": "assistant_not_configured", "message": reason})


def _sse(item: dict) -> str:
    kind = item.get("type", "message")
    return f"event: {kind}\ndata: {json.dumps(item, default=str, ensure_ascii=False)}\n\n"


async def _stream(queue: asyncio.Queue):
    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=PING_SECONDS)
        except asyncio.TimeoutError:
            yield ": ping\n\n"
            continue
        if item is None:
            return
        yield _sse(item)


def _respond(queue: asyncio.Queue) -> StreamingResponse:
    return StreamingResponse(
        _stream(queue),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


async def _run(turn: Turn, caller: Caller, conversation: dict, queue: asyncio.Queue, work, *,
               title: Optional[str] = None) -> None:
    lock = conversation_lock(conversation["id"])
    try:
        if lock.locked():
            await queue.put({"type": "notice", "level": "error",
                             "message": "Still working on the previous message in this chat."})
            return
        async with lock:
            fresh = await store.load_conversation(caller, conversation["id"])
            if fresh is None:
                await queue.put({"type": "notice", "level": "error", "message": "This chat was deleted."})
                return
            turn.reload(fresh)
            try:
                await work()
            finally:
                await store.save_conversation(
                    caller, conversation["id"], messages=turn.messages, transcript=turn.transcript,
                    input_tokens=turn.input_tokens, output_tokens=turn.output_tokens, title=title,
                )
                try:
                    owner_id, owner_staff = caller.usage_owner
                    await usage.record(owner_id, owner_staff, turn.usage, question=turn.is_question)
                except Exception:
                    logger.exception("[assistant] usage record failed (the answer was not affected)")
    except Exception:
        logger.exception("[assistant] turn failed for conversation %s", conversation["id"])
        await queue.put({"type": "notice", "level": "error", "message": "Something went wrong. Try again."})
    finally:
        await queue.put({"type": "done", "conversation_id": conversation["id"],
                         "usage": {"input_tokens": turn.input_tokens, "output_tokens": turn.output_tokens}})
        await queue.put(None)


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)


@router.get("/status")
async def assistant_status(request: Request):
    caller = await _caller(request)
    ready, reason = assistant_ready()
    return {
        "enabled": ready,
        "reason": reason or None,
        "model": model_name() if ready else None,
        "provider": provider() if ready else None,
        "read_only": caller.read_only,
        "action_ttl_minutes": settings.ASSISTANT_ACTION_TTL_MINUTES,
        "retention_days": settings.ASSISTANT_RETENTION_DAYS,
    }


@router.get("/conversations")
async def list_conversations(request: Request):
    caller = await _caller(request)
    return {"conversations": await store.list_conversations(caller)}


@router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str, request: Request):
    caller = await _caller(request)
    conv = await store.load_conversation(caller, conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {
        "id": conv["id"], "title": conv["title"], "transcript": conv["transcript"],
        "actions": await store.actions_for(caller, conversation_id),
    }


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str, request: Request):
    caller = await _caller(request)
    if not await store.delete_conversation(caller, conversation_id):
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"deleted": True}


@router.post("/chat")
async def chat(payload: ChatRequest, request: Request):
    caller = await _caller(request)
    _require_ready()
    message = payload.message.strip()
    images = _check_images(payload.images)
    if not message and not images:
        raise HTTPException(status_code=422, detail="Message is empty")
    title = None
    if payload.conversation_id:
        conversation = await store.load_conversation(caller, payload.conversation_id)
        if conversation is None:
            raise HTTPException(status_code=404, detail="Conversation not found")
    else:
        title = (message.splitlines()[0][:80] if message else "Photo")
        conversation = await store.create_conversation(caller, title)

    queue: asyncio.Queue = asyncio.Queue()
    await queue.put({"type": "conversation", "id": conversation["id"], "title": conversation["title"]})
    turn = Turn(request.app, caller, conversation, queue)
    _spawn(_run(turn, caller, conversation, queue, lambda: turn.user_message(message, images), title=title))
    return _respond(queue)


@router.post("/conversations/{conversation_id}/decide")
async def decide(conversation_id: str, payload: DecideRequest, request: Request):
    caller = await _caller(request)
    _require_ready()
    if caller.read_only:
        raise HTTPException(status_code=403, detail="View-as is read-only: changes are disabled.")
    conversation = await store.load_conversation(caller, conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    queue: asyncio.Queue = asyncio.Queue()
    await queue.put({"type": "conversation", "id": conversation["id"], "title": conversation["title"]})
    turn = Turn(request.app, caller, conversation, queue)
    decisions = [d.model_dump() for d in payload.decisions]
    _spawn(_run(turn, caller, conversation, queue, lambda: turn.decide(decisions)))
    return _respond(queue)


# ---------------------------------------------------------------------------
# Bitwave support view (platform admins): read any chat, add a note to it.
# ---------------------------------------------------------------------------

admin_router = APIRouter(prefix="/api/admin/assistant", tags=["assistant"])


async def _admin(request: Request) -> Caller:
    caller = await _caller(request)
    if not caller.is_admin:
        raise HTTPException(status_code=403, detail="Admins only")
    return caller


@admin_router.get("/conversations")
async def admin_list_conversations(request: Request, reseller_id: Optional[int] = None,
                                   limit: int = 100):
    """Recent chats across accounts, newest first, so support can see who is stuck."""
    await _admin(request)
    return {"conversations": await store.admin_list(reseller_id=reseller_id,
                                                    limit=max(1, min(limit, 300)))}


@admin_router.get("/conversations/{conversation_id}")
async def admin_get_conversation(conversation_id: str, request: Request):
    await _admin(request)
    conv = await store.admin_load(conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


@admin_router.get("/usage")
async def admin_usage(request: Request, days: int = 30):
    """Questions, active accounts and estimated cost: per day, and the busiest accounts."""
    await _admin(request)
    return await usage.report(days=days)


@admin_router.post("/conversations/{conversation_id}/notes")
async def admin_add_note(conversation_id: str, payload: NoteRequest, request: Request):
    """Bitwave support writes into a reseller's chat; the assistant reads it next turn."""
    caller = await _admin(request)
    author = await store.admin_name(caller.user_id)
    async with conversation_lock(conversation_id):
        note = await store.append_support_note(conversation_id, author=author,
                                               author_id=caller.user_id, text=payload.text.strip())
    if note is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if payload.notify:
        await store.notify_support_note(conversation_id, sender_id=caller.user_id,
                                        text=payload.text.strip())
    return {"note": note}
