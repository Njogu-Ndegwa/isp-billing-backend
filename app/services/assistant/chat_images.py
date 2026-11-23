"""Pictures sent in the chat, kept for a short while so a form can use one.

A reseller sends their logo as a photo and asks for it on the login page. The
photo is already on this box (it came with the message), so instead of asking
them to find the file again, the form offers "Use the picture you sent". On
Confirm the picture goes through the same upload the classic portal page uses:
a ticket from POST /api/ads/media/upload-url (type and size checked there, as
the caller), then a PUT of the bytes to the signed storage URL, and the stored
address becomes the field's value.

Kept in memory only (this app runs one worker): the last few pictures of each
conversation, for KEEP_SECONDS, tied to the conversation and to the person who
sent them. A reference from another conversation or another account is refused
exactly like an expired one. A restart forgets them; the form then still lets
the person pick the file from their phone.
"""
from __future__ import annotations

import base64
import re
import secrets
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from app.services.assistant import executor
from app.services.assistant.caller import Caller

PREFIX = "chat-image:"
KEEP_SECONDS = 30 * 60
PER_CONVERSATION = 4
MAX_TOTAL_BYTES = 48 * 1024 * 1024   # every kept picture together, oldest dropped first
TICKET_PATH = "/api/ads/media/upload-url"
PUT_TIMEOUT_SECONDS = 30

_REF = re.compile(r"^chat-image:([A-Za-z0-9_-]{8,40})$")

GONE = ("The picture you sent is no longer kept (pictures are kept {minutes} minutes). "
        "Send it again, or pick it from your phone in the form.")


class Refused(Exception):
    """The picture cannot be used; the message is for the person."""


@dataclass
class _Kept:
    ref: str
    conversation_id: str
    owner: tuple
    media_type: str
    data: str            # base64, as it came with the message
    thumbnail: Optional[str]
    at: float


_KEPT: dict[str, _Kept] = {}


def reset() -> None:
    _KEPT.clear()


def is_ref(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def _prune(now: float) -> None:
    for ref in [r for r, k in _KEPT.items() if now - k.at > KEEP_SECONDS]:
        _KEPT.pop(ref, None)
    total = sum(len(k.data) for k in _KEPT.values())
    for kept in sorted(_KEPT.values(), key=lambda k: k.at):
        if total <= MAX_TOTAL_BYTES:
            break
        total -= len(kept.data)
        _KEPT.pop(kept.ref, None)


def remember(caller: Caller, conversation_id: str, image: dict) -> str:
    """Keep one checked photo of a message; returns the reference the model and the form use."""
    now = time.monotonic()
    ref = PREFIX + secrets.token_urlsafe(12)
    _KEPT[ref] = _Kept(ref=ref, conversation_id=conversation_id, owner=caller.owner_key,
                       media_type=image["media_type"], data=image["data"],
                       thumbnail=image.get("thumbnail"), at=now)
    mine = sorted((k for k in _KEPT.values() if k.conversation_id == conversation_id), key=lambda k: k.at)
    for old in mine[:-PER_CONVERSATION]:
        _KEPT.pop(old.ref, None)
    _prune(now)
    return ref


def available(caller: Caller, conversation_id: str) -> list[dict]:
    """This conversation's kept pictures, newest first, as the form shows them."""
    _prune(time.monotonic())
    mine = [k for k in _KEPT.values() if k.conversation_id == conversation_id and k.owner == caller.owner_key]
    return [{"ref": k.ref, "thumbnail": k.thumbnail}
            for k in sorted(mine, key=lambda k: k.at, reverse=True) if k.thumbnail]


def is_image_upload(prop) -> bool:
    upload = prop.get("x-upload") if isinstance(prop, dict) else None
    return isinstance(upload, dict) and str(upload.get("accept", "")).startswith("image")


def offer(fields: list[dict], caller: Caller, conversation_id: str) -> None:
    """Put the conversation's pictures on each photo field of a form card."""
    photo_fields = [f for f in fields if str((f.get("upload") or {}).get("accept", "")).startswith("image")]
    if not photo_fields:
        return
    pictures = available(caller, conversation_id)
    if pictures:
        for f in photo_fields:
            f["chat_images"] = pictures


def _lookup(caller: Caller, conversation_id: str, value: str) -> _Kept:
    _prune(time.monotonic())
    gone = Refused(GONE.format(minutes=KEEP_SECONDS // 60))
    if not _REF.match(value or ""):
        raise gone
    kept = _KEPT.get(value)
    # another conversation's or another person's picture reads exactly like one that expired
    if kept is None or kept.conversation_id != conversation_id or kept.owner != caller.owner_key:
        raise gone
    return kept


async def _put(url: str, headers: dict, content: bytes) -> int:
    async with httpx.AsyncClient(timeout=PUT_TIMEOUT_SECONDS) as client:
        response = await client.put(url, headers=headers, content=content)
    return response.status_code


async def upload(app, caller: Caller, conversation_id: str, value: str) -> str:
    """Store the referenced picture the way the classic page does; returns its public address.

    No DB session is held here: the ticket request opens and closes its own.
    """
    kept = _lookup(caller, conversation_id, value)
    raw = base64.b64decode(kept.data)
    ticket = await executor.call_api(app, caller, "POST", TICKET_PATH, None,
                                     {"content_type": kept.media_type, "size": len(raw)})
    if not ticket.ok or not isinstance(ticket.data, dict):
        if ticket.status == 503:
            raise Refused("Picture uploads are not switched on yet. Paste a link to the picture in the form instead.")
        raise Refused(f"The picture you sent cannot be used: {ticket.detail()}")
    url = str(ticket.data.get("upload_url") or "")
    public = str(ticket.data.get("public_url") or "")
    if not url.startswith("https://") or not public:
        raise Refused("The picture could not be stored. Try again, or pick it from your phone in the form.")
    headers = {"Content-Type": kept.media_type}
    try:
        status = await _put(url, headers, raw)
    except httpx.HTTPError:
        status = 0
    if not 200 <= status < 300:
        raise Refused("The picture could not be stored. Try again, or pick it from your phone in the form.")
    return public
