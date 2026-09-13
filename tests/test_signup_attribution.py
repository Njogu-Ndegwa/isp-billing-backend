"""A reseller signup must record which channel it came from.

Paid campaigns on TikTok and Google Search only pay for themselves if you can
answer "which of these accounts came from the ad?". GA4 counts sessions by
channel and stops there, so the source has to land on the user row at signup —
once. There is no second chance: the visitor's first-touch data lives in their
browser and is gone the moment they clear it.

Three things are load-bearing here and each has its own test below:

1. The source is persisted, broken out into the indexed reporting columns.
2. A signup NEVER fails because of attribution. It is visitor-supplied junk
   from a query string — hostile, oversized, or absent — and a report field
   must never be able to take signup down.
3. The auto-created lead is filed under the channel, so the pipeline the team
   already uses can count signups per channel without a new screen.
"""

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import router as auth_router
from app.db.database import get_db
from app.db.models import Lead, LeadSource, User
from app.services import attribution
from tests.factories import make_admin

pytestmark = pytest.mark.asyncio


TIKTOK_AD_CLICK = {
    "utm_source": "TikTok",
    "utm_medium": "cpc",
    "utm_campaign": "test_sep",
    "utm_content": "setup_video",
    "ttclid": "EAAbbCC123",
    "referrer": "tiktok.com",
    "landing_path": "/pricing",
    "seen_at": "2026-09-10T18:22:04.113Z",
}


@pytest.fixture(autouse=True)
def no_welcome_sms(monkeypatch):
    """Signup queues a welcome SMS and dispatches it in a background task that
    opens its own session against the real engine, which no test harness binds.
    Not what this module is about — stub the dispatch out."""
    import app.services.sms_dispatch as sms_dispatch
    monkeypatch.setattr(sms_dispatch, "dispatch_admin_sms_messages", AsyncMock())


@pytest_asyncio.fixture
async def app(session_factory):
    app = FastAPI()
    app.include_router(auth_router)

    async def _get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _get_db
    return app


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def signup_payload(**overrides):
    payload = {
        "email": f"reseller{id(overrides)}@example.com",
        "password": "hunter2hunter2",
        "role": "reseller",
        "organization_name": "Soko WiFi",
        "support_phone": "+254712345678",
    }
    payload.update(overrides)
    return payload


async def _user(db, email):
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one()


# --- 1. the source is persisted -------------------------------------------

async def test_signup_records_the_channel_it_came_from(client, db):
    payload = signup_payload(email="paid@example.com", attribution=TIKTOK_AD_CLICK)

    response = await client.post("/api/users/register", json=payload)
    assert response.status_code == 200, response.text

    user = await _user(db, "paid@example.com")
    # Lowercased so TikTok/tiktok/TIKTOK are one row in a report, not three.
    assert user.acquisition_source == "tiktok"
    assert user.acquisition_campaign == "test_sep"
    # The click id is the part that lets Google/TikTok be told later which
    # click became a paying reseller, so it has to survive the round trip.
    assert user.acquisition_details["ttclid"] == "EAAbbCC123"
    assert user.acquisition_details["landing_path"] == "/pricing"


async def test_signup_without_attribution_still_works(client, db):
    response = await client.post(
        "/api/users/register", json=signup_payload(email="organic@example.com")
    )
    assert response.status_code == 200, response.text

    user = await _user(db, "organic@example.com")
    assert user.acquisition_source is None
    assert user.acquisition_details is None


# --- 2. attribution can never break signup --------------------------------

@pytest.mark.parametrize(
    "hostile",
    [
        pytest.param({"utm_source": "x" * 5000}, id="oversized-value"),
        pytest.param({"utm_source": {"nested": "object"}}, id="wrong-type"),
        pytest.param({"utm_source": "tik\ntok\r\n"}, id="control-characters"),
        pytest.param({f"junk{i}": str(i) for i in range(200)}, id="key-flood"),
        pytest.param({}, id="empty"),
        pytest.param("not-an-object", id="not-an-object"),
    ],
)
async def test_hostile_attribution_never_fails_the_signup(client, db, hostile):
    email = "hostile@example.com"
    response = await client.post(
        "/api/users/register",
        json=signup_payload(email=email, attribution=hostile),
    )
    assert response.status_code == 200, response.text

    user = await _user(db, email)
    if user.acquisition_source is not None:
        assert len(user.acquisition_source) <= attribution.MAX_SOURCE_LEN
    if user.acquisition_details is not None:
        assert len(user.acquisition_details) <= attribution.MAX_KEYS
        for key, value in user.acquisition_details.items():
            assert isinstance(value, str)
            assert len(value) <= attribution.MAX_VALUE_LEN
            assert "\n" not in value and "\r" not in value


async def test_unknown_keys_are_kept_so_new_click_ids_need_no_backend_release():
    cleaned = attribution.sanitize_attribution(
        {"utm_source": "snapchat", "sccid": "abc123"}
    )
    assert cleaned["sccid"] == "abc123"


async def test_paid_and_organic_are_distinguishable():
    assert attribution.is_paid({"utm_source": "tiktok", "utm_medium": "cpc"})
    assert attribution.is_paid({"utm_source": "google", "gclid": "xyz"})
    assert not attribution.is_paid({"utm_source": "tiktok", "utm_medium": "social"})


# --- 3. the lead lands under the right channel ----------------------------

async def test_paid_signup_files_the_lead_under_the_paid_channel(client, db):
    await make_admin(db)

    response = await client.post(
        "/api/users/register",
        json=signup_payload(email="lead@example.com", attribution=TIKTOK_AD_CLICK),
    )
    assert response.status_code == 200, response.text

    user = await _user(db, "lead@example.com")
    lead = (
        await db.execute(select(Lead).where(Lead.converted_user_id == user.id))
    ).scalar_one()
    source = await db.get(LeadSource, lead.source_id)

    # "TikTok Ads", not "TikTok" and not "Website": while money is running, the
    # question is whether this reseller came from the ad or from an organic post.
    assert source.name == "TikTok Ads"
    assert "test_sep" in lead.source_detail


async def test_untagged_signup_keeps_the_old_website_source(client, db):
    await make_admin(db)
    db.add(LeadSource(name="Website", is_active=True, user_id=1))
    await db.commit()

    response = await client.post(
        "/api/users/register", json=signup_payload(email="plain@example.com")
    )
    assert response.status_code == 200, response.text

    user = await _user(db, "plain@example.com")
    lead = (
        await db.execute(select(Lead).where(Lead.converted_user_id == user.id))
    ).scalar_one()
    source = await db.get(LeadSource, lead.source_id)
    assert source.name == "Website"
