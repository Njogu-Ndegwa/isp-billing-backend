"""Review rules for reseller ads (Dennis, 4 Nov 2026).

Every reseller submit (create, or an edit that changes what customers see)
runs the automatic checks first:

  * no blocked words in any text a customer reads. The list is configurable
    by a Bitwave admin (app_settings key ``ads_blocked_words``, comma
    separated); DEFAULT_BLOCKED_WORDS applies until one is saved. Words match
    whole words only, so "bet" blocks "bet now" but not "better", and "loan"
    does not block "loaned";
  * a valid phone number: a Kenyan mobile (07.., 01.., +254..) for Kenyan
    resellers, any plausible number elsewhere;
  * media present (a photo for a photo ad, a video for a video ad) - checked
    in ads_routes._check_media_complete.

Nobody reviews an ad before it runs (Dennis, 5 Nov 2026: "ensure ads dont need
my review"). After the automatic checks:

  * "house" (the reseller's own promo) is free and goes live at once. To stop
    it being used to sell other businesses' ads for free, its seller name is
    locked to the reseller's network name and its phone numbers must be the
    reseller's own support numbers (``apply_house_lock``).
  * "reseller" (an ad they sold) is approved at once but has no paid period
    until the shop pays, so no portal shows it before then. The paid weeks
    start when the payment is confirmed (ad_sales.confirm_payment).
  * Editing a live ad keeps it live: the automatic checks run again, but it
    does not wait for anybody.
  * An admin's takedown is the safety net. An ad Bitwave took down stays down
    whatever its owner edits; only an admin can put it back.

Rows from before this rule can still say "pending" (nothing bulk-publishes
them). Such an ad goes live when its owner changes it, when its shop pays, or
when an admin approves it. Admins check new ads afterwards with
GET /api/ads/manage?newly_live=true.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AdReviewEvent, PortalSettings, User

BLOCKED_WORDS_KEY = "ads_blocked_words"
DEFAULT_BLOCKED_WORDS = (
    "bet", "bets", "betting", "odds", "jackpot", "casino", "sportpesa", "betika",
    "loan", "loans", "mkopo", "mikopo", "crypto", "bitcoin", "forex",
    "adult", "xxx", "porn", "escort",
)
# app_settings.value is VARCHAR(500).
BLOCKED_WORDS_MAX_CHARS = 500

# Ad text a customer sees on the portal.
TEXT_FIELDS = (
    "title", "description", "seller_name", "seller_location", "price",
    "badge_text", "category",
)

ACTION_APPROVE = "approve"
ACTION_REJECT = "reject"
ACTION_AUTO_APPROVE = "auto_approve"
ACTION_TAKEDOWN = "takedown"

_GENERIC_PHONE_RE = re.compile(r"^\+?[0-9 ]{9,16}$")


# ---------------------------------------------------------------------------
# Blocked words
# ---------------------------------------------------------------------------

def parse_blocked_words(raw: Optional[str]) -> list[str]:
    if raw is None:
        return list(DEFAULT_BLOCKED_WORDS)
    words = []
    for part in re.split(r"[,\n]", raw):
        word = " ".join(part.strip().lower().split())
        if word and word not in words:
            words.append(word)
    return words


def serialize_blocked_words(words: Iterable[str]) -> str:
    cleaned = parse_blocked_words(",".join(words))
    value = ",".join(cleaned)
    if len(value) > BLOCKED_WORDS_MAX_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"The blocked-word list is too long (max {BLOCKED_WORDS_MAX_CHARS} characters)",
        )
    return value


async def get_blocked_words(db: AsyncSession) -> list[str]:
    from app.services.app_settings import get_setting
    return parse_blocked_words(await get_setting(db, BLOCKED_WORDS_KEY))


def find_blocked_words(texts: Iterable[Optional[str]], words: Iterable[str]) -> list[str]:
    """The blocked words that appear as whole words in any of the texts."""
    haystack = " ".join(t for t in texts if t).lower()
    if not haystack:
        return []
    hits = []
    for word in words:
        pattern = r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])"
        if re.search(pattern, haystack):
            hits.append(word)
    return hits


async def check_blocked_words(db: AsyncSession, ad) -> None:
    hits = find_blocked_words((getattr(ad, f, None) for f in TEXT_FIELDS), await get_blocked_words(db))
    if hits:
        raise HTTPException(
            status_code=400,
            detail=(
                "This ad can't run on Bitwave portals: it mentions "
                + ", ".join(f'"{w}"' for w in hits)
                + ". Betting, loans, crypto, forex and adult ads are not allowed."
            ),
        )


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

def normalize_ke_phone(raw: Optional[str]) -> Optional[str]:
    from app.api.subscription_routes import normalize_kenyan_msisdn
    return normalize_kenyan_msisdn(raw or "")


def _phone_key(raw: Optional[str], kenyan: bool) -> Optional[str]:
    if not raw:
        return None
    if kenyan:
        return normalize_ke_phone(raw)
    digits = re.sub(r"\D", "", raw)
    return digits or None


def is_kenyan(user: User) -> bool:
    return (getattr(user, "market_code", None) or "KE").upper() == "KE"


def check_phone(raw: Optional[str], field: str, kenyan: bool) -> None:
    if not raw:
        return
    if kenyan:
        if normalize_ke_phone(raw) is None:
            raise HTTPException(
                status_code=400,
                detail=f"{field} must be a Kenyan mobile number, e.g. 0712 345 678",
            )
    elif not _GENERIC_PHONE_RE.match(raw.strip()):
        raise HTTPException(status_code=400, detail=f"{field} must be a phone number, e.g. 0712 345 678")


def check_ad_phones(ad, user: User) -> None:
    kenyan = is_kenyan(user)
    check_phone(ad.phone_number, "phone_number", kenyan)
    check_phone(ad.whatsapp_number, "whatsapp_number", kenyan)


# ---------------------------------------------------------------------------
# House ads: the reseller's own network only
# ---------------------------------------------------------------------------

def network_name(user: User) -> str:
    return ((user.business_name or "").strip() or (user.organization_name or "").strip())[:100]


async def portal_shows_ads(db: AsyncSession, reseller_id: int) -> bool:
    """The reseller's "Show ads" portal switch. Off (the default) means their
    portals show no ads at all, whatever is approved and paid."""
    return bool((await db.execute(
        select(PortalSettings.show_ads).where(PortalSettings.user_id == reseller_id)
    )).scalar_one_or_none())


async def support_numbers(db: AsyncSession, user: User) -> list[str]:
    """The reseller's own support numbers, as typed, first one preferred."""
    numbers = [user.support_phone]
    row = (await db.execute(
        select(PortalSettings.portal_support_phone, PortalSettings.portal_support_whatsapp)
        .where(PortalSettings.user_id == user.id)
    )).first()
    if row:
        numbers = [row[0], row[1], user.support_phone]
    seen, out = set(), []
    for n in numbers:
        n = (n or "").strip()
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


async def apply_house_lock(db: AsyncSession, ad, user: User) -> None:
    """A free "own promo" must advertise the reseller's own network.

    Seller name is set to the network name whatever was sent. The phone (and
    WhatsApp, if given) must be one of the reseller's support numbers; an
    empty phone is filled in with the first one."""
    name = network_name(user)
    if name:
        ad.seller_name = name
    own = await support_numbers(db, user)
    if not own:
        raise HTTPException(
            status_code=400,
            detail=(
                "Add your support phone number in Settings first: your own promo "
                "shows your network's support number."
            ),
        )
    kenyan = is_kenyan(user)
    own_keys = {_phone_key(n, kenyan) for n in own} - {None}
    if not ad.phone_number:
        ad.phone_number = own[0]
    for field in ("phone_number", "whatsapp_number"):
        value = getattr(ad, field)
        if value and _phone_key(value, kenyan) not in own_keys:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Your own promo must use your support number ("
                    + own[0]
                    + "). To advertise another business, choose \"An ad I sold\"."
                ),
            )


# ---------------------------------------------------------------------------
# Review status and history
# ---------------------------------------------------------------------------

async def was_taken_down(db: AsyncSession, ad_id: int) -> bool:
    if ad_id is None:
        return False
    found = (await db.execute(
        select(AdReviewEvent.id).where(
            AdReviewEvent.ad_id == ad_id, AdReviewEvent.action == ACTION_TAKEDOWN,
        ).limit(1)
    )).first()
    return found is not None


async def decide_status(db: AsyncSession, ad, user: User) -> str:
    """Status for a reseller's new or changed ad: approved at once, unless
    Bitwave took it down, which only an admin can undo."""
    if await was_taken_down(db, ad.id):
        return "rejected"
    return "approved"


def record_event(db: AsyncSession, ad, action: str, actor_id: Optional[int], note: Optional[str] = None) -> None:
    db.add(AdReviewEvent(
        ad_id=ad.id, owner_user_id=ad.owner_user_id, slot=ad.slot or "platform",
        action=action, actor_user_id=actor_id, note=(note or None) and note[:300],
    ))


async def run_submit_checks(db: AsyncSession, ad, user: User) -> None:
    """Automatic checks on every reseller submit (create or content edit).
    The house lock runs first so a locked name/phone is what gets checked."""
    if ad.slot == "house":
        await apply_house_lock(db, ad, user)
    check_ad_phones(ad, user)
    await check_blocked_words(db, ad)
