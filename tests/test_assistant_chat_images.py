"""A picture sent in the assistant chat can be used for a form's photo field (CR-1123-F6).

A reseller sent their logo as a photo and asked for it on the login page; the assistant said
the file had to come from their device and opened the same empty card three times. Now the
card offers the picture, and Confirm uploads it through the same ticket the classic portal
page uses -- but only within the conversation it was sent in, and only for its sender.
"""
from __future__ import annotations

import base64
import re
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.config import settings
from app.db.models import PortalSettings
from app.services.assistant import chat_images
from app.services.auth import create_access_token
from tests.factories import make_reseller
from tests.test_assistant import (  # noqa: F401  (fixtures)
    PNG, auth, client, owner, sse_events, text_reply, tool_reply, use_model,
)

THUMB = "data:image/jpeg;base64,AAAA"
LOGO = "/api/portal/settings"


@pytest.fixture(autouse=True)
def storage(monkeypatch):
    """Storage set up as in production; the PUT to it is recorded instead of sent."""
    chat_images.reset()
    for name, value in (("R2_ACCOUNT_ID", "acct"), ("R2_ACCESS_KEY_ID", "key"),
                        ("R2_SECRET_ACCESS_KEY", "secret"), ("R2_BUCKET", "media"),
                        ("AD_MEDIA_PUBLIC_BASE", "https://cdn.example.com/media")):
        monkeypatch.setattr(settings, name, value)
    puts: list[tuple] = []

    async def fake_put(url, headers, content):
        puts.append((url, headers, content))
        return 200
    monkeypatch.setattr(chat_images, "_put", fake_put)
    yield puts
    chat_images.reset()


def _ref(model) -> str:
    text = model.requests[0]["messages"][-1]["content"][-1]["text"]
    return re.search(r"chat-image:[A-Za-z0-9_-]+", text).group(0)


def _logo_card(ref: str):
    return [
        tool_reply("describe_action", {"method": "PUT", "path": LOGO}, "tu_d"),
        tool_reply("call_api", {"method": "PUT", "path": LOGO, "form": True,
                                "body": {"header_style": "hero", "company_logo_url": ref},
                                "summary": "Use the picture you sent as your logo"}, "tu_c"),
        text_reply("Your picture is in the logo field. Tap Confirm."),
    ]


async def _send_photo(client, token) -> tuple[str, str]:
    """A message with a photo; returns its conversation and the picture's reference."""
    model = use_model([text_reply("Got the picture.")])
    events = sse_events((await client.post("/api/assistant/chat", headers=auth(token), json={
        "message": "Add this portal logo",
        "images": [{"media_type": "image/png", "data": base64.b64encode(PNG).decode(), "thumbnail": THUMB}],
    })).text)
    return events[0]["id"], _ref(model)


async def _card(client, token, ref, conversation_id=None) -> tuple[str, dict]:
    use_model(_logo_card(ref))
    events = sse_events((await client.post("/api/assistant/chat", headers=auth(token), json={
        "message": "Use it", **({"conversation_id": conversation_id} if conversation_id else {}),
    })).text)
    return events[0]["id"], next(e for e in events if e["type"] == "action")


async def _confirm(client, token, conversation_id, card) -> dict:
    use_model([text_reply("Done.")])
    r = await client.post(f"/api/assistant/conversations/{conversation_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"header_style": "hero", "company_logo_url": card["body"]["company_logo_url"]}}]})
    return next(e for e in sse_events(r.text) if e["type"] == "action_result")


async def _logo(db, user_id):
    db.expire_all()
    row = (await db.execute(select(PortalSettings).where(PortalSettings.user_id == user_id))).scalar_one_or_none()
    return row.company_logo_url if row else None


@pytest.mark.asyncio
async def test_the_logo_card_uses_the_picture_sent_in_the_same_chat(client, owner, db, storage):
    reseller, token = owner
    conv, ref = await _send_photo(client, token)
    _, card = await _card(client, token, ref, conv)

    logo = next(f for f in card["form"] if f["name"] == "company_logo_url")
    assert logo["value"] == ref                                   # pre-selected: they said to use it
    assert logo["chat_images"] == [{"ref": ref, "thumbnail": THUMB}]
    photo = next(f for f in card["form"] if f["name"] == "header_bg_image_url")
    assert photo["chat_images"] == logo["chat_images"]           # the hero photo is offered it too

    result = await _confirm(client, token, conv, card)
    assert result["status"] == "done" and result["ok"], result
    # the same upload as the classic page: a signed PUT of the exact bytes, then its public address
    [(url, headers, content)] = storage
    assert url.startswith("https://acct.r2.cloudflarestorage.com/media/c/") and content == PNG
    assert headers == {"Content-Type": "image/png"}
    saved = await _logo(db, reseller.id)
    assert saved.startswith("https://cdn.example.com/media/c/") and saved.endswith(".png")


@pytest.mark.asyncio
async def test_a_picture_from_another_chat_is_refused(client, owner, db, storage):
    reseller, token = owner
    _, ref = await _send_photo(client, token)
    other_conv, card = await _card(client, token, ref)            # a new chat, same person

    assert "chat_images" not in next(f for f in card["form"] if f["name"] == "company_logo_url")
    result = await _confirm(client, token, other_conv, card)
    assert result["status"] == "pending" and not result["ok"]
    assert "no longer kept" in result["detail"]
    assert storage == [] and await _logo(db, reseller.id) is None


@pytest.mark.asyncio
async def test_a_picture_from_another_account_is_refused(client, owner, db, storage):
    _, token = owner
    _, ref = await _send_photo(client, token)
    other = await make_reseller(db, email="other@example.com", organization_name="Other WiFi")
    other_token = create_access_token(login_token_claims(other), timedelta(hours=1))
    other_conv, card = await _card(client, other_token, ref)

    result = await _confirm(client, other_token, other_conv, card)
    assert result["status"] == "pending" and not result["ok"]
    assert "no longer kept" in result["detail"]
    assert storage == [] and await _logo(db, other.id) is None


@pytest.mark.asyncio
async def test_a_chat_picture_only_goes_in_a_photo_field(client, owner, db, storage):
    _, token = owner
    conv, ref = await _send_photo(client, token)
    use_model([
        tool_reply("describe_action", {"method": "PUT", "path": LOGO}, "tu_d"),
        tool_reply("call_api", {"method": "PUT", "path": LOGO, "form": True,
                                "body": {"footer_text": ref}, "summary": "Footer"}, "tu_c"),
        text_reply("Tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", headers=auth(token), json={
        "message": "put it in the footer", "conversation_id": conv})).text)
    card = next(e for e in events if e["type"] == "action")
    use_model([text_reply("Not done.")])
    r = await client.post(f"/api/assistant/conversations/{conv}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True}]})
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert result["status"] == "pending" and "only go in a photo field" in result["detail"]
    assert storage == []


def test_the_assistant_is_told_it_can_use_a_sent_picture():
    from app.services.assistant.agent import SYSTEM_TEMPLATE

    assert "chat-image:" in SYSTEM_TEMPLATE and "Use the picture you sent" in SYSTEM_TEMPLATE
    assert "One card per change" in SYSTEM_TEMPLATE
