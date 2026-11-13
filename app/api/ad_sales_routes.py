"""Selling ads through Bitwave: the reseller sells an ad to a local business,
the business pays Bitwave by M-Pesa, Bitwave keeps 20% and the reseller's 80%
joins their payout. Money rules live in app/services/ad_sales.py, the automatic
checks in app/services/ad_review.py. Nobody reviews a sold ad first: it goes live
when the shop's payment is confirmed.

Reseller (and "Captive portal" staff):
  POST /api/ad-sales                      create "An ad I sold" and prompt the shop
  GET  /api/ad-sales/access               may this reseller sell yet?
  GET  /api/ad-sales/quote                total, Bitwave fee, what the reseller gets
  GET  /api/ad-sales                      their sold ads with payment status (admin: all)
  GET  /api/ads/{ad_id}/sale              one sold ad: status, prompts, link (poll this)
  POST /api/ads/{ad_id}/sale              put an older sold ad up for payment
  POST /api/ads/{ad_id}/sale/prompt       send the M-Pesa prompt (again)
  POST /api/ads/{ad_id}/sale/renew        renewal prompt

Bitwave admin:
  POST /api/ads/{ad_id}/takedown          take any ad off every portal now
  POST /api/ad-sales/payments/{id}/refund record a refund made by hand
  GET/PUT /api/ad-review/rules            blocked words, selling switch and pilot list

Public:
  POST /api/mpesa/ad-sales/callback       Safaricom STK callback
  GET  /api/public/promo/{token}          the business's read-only report
  POST /api/public/promo/{token}/pay      prompt to the business's saved number
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import ads_routes as ar
from app.db.database import get_db
from app.db.models import Ad, AdSale, AdSalePayment, User, UserRole
from app.services import ad_review, ad_sales
from app.services.ad_serving import invalidate_ad_cache
from app.services.auth import get_current_user, verify_token
from app.services.subscription import enforce_active_subscription

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ad-sales"])


class SaleTerms(BaseModel):
    business_name: str
    business_phone: str
    weeks: int
    price_per_week: int


class SoldAdCreateRequest(ar.AdCreateRequest, SaleTerms):
    pass


class PromptRequest(BaseModel):
    phone: Optional[str] = None
    weeks: Optional[int] = None
    price_per_week: Optional[int] = None
    # The reseller told the shop a renewal's new price before this prompt.
    confirm_new_price: bool = False


class TakedownRequest(BaseModel):
    note: str


class RefundRequest(BaseModel):
    note: Optional[str] = None


class ReviewRulesRequest(BaseModel):
    blocked_words: Optional[list[str]] = None
    selling_mode: Optional[str] = None
    selling_allowlist: Optional[list[int]] = None


_SALE_FIELDS = {"business_name", "business_phone", "weeks", "price_per_week"}


def _require_kenyan_reseller(user) -> None:
    if ar._is_admin(user):
        raise HTTPException(status_code=400, detail="Bitwave's own ads use the platform slot")
    if not ad_review.is_kenyan(user):
        raise HTTPException(
            status_code=400,
            detail="Selling ads through Bitwave works with M-Pesa, so it is only open to Kenyan networks for now.",
        )


COMING_SOON_MESSAGE = (
    "Selling ads through Bitwave is coming soon. It's being tested with a few "
    "networks first. Your own promos work as usual."
)


async def _require_selling_open(db: AsyncSession, reseller_id: int, message: str = COMING_SOON_MESSAGE) -> None:
    """The kill switch and pilot list. No new sold ad, and no new prompt."""
    if not await ad_sales.selling_allowed(db, reseller_id):
        raise HTTPException(status_code=403, detail=message)


ADS_OFF_MESSAGE = (
    "Ads are switched off on your portal, so this ad wouldn't show. Turn on "
    "Show Ads in Portal customization, then send the prompt."
)


async def _require_portal_ads_on(db: AsyncSession, reseller_id: int, message: str = ADS_OFF_MESSAGE) -> None:
    """Never ask a shop to pay for an ad the reseller's portals won't show."""
    if not await ad_review.portal_shows_ads(db, reseller_id):
        raise HTTPException(status_code=400, detail=message)


async def _sale_payload(db: AsyncSession, ad: Optional[Ad], sale: AdSale, prompt=None) -> dict:
    payments = await ad_sales._payments(db, sale.id)
    taken = await ad_review.was_taken_down(db, sale.ad_id)
    out = ad_sales.summarize(ad, sale, payments, taken, with_payments=True)
    out["ad_id"] = sale.ad_id
    if prompt is not None:
        out["prompt_result"] = {"sent": prompt.sent, "message": prompt.message}
    return out


async def _owned_sale(db: AsyncSession, user, ad_id: int) -> tuple[Ad, AdSale]:
    ad = await ar._load_owned_ad(db, user, ad_id)
    sale = await ad_sales.get_sale_for_ad(db, ad.id)
    if sale is None:
        raise HTTPException(status_code=404, detail="This ad has no sale")
    return ad, sale


# ---------------------------------------------------------------------------
# Reseller: sell, prompt, renew
# ---------------------------------------------------------------------------

@router.get("/api/ad-sales/access")
async def selling_access(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Whether this reseller may sell yet. The dashboard shows "coming soon"
    in place of the selling form when not."""
    user = await get_current_user(token, db)
    allowed = (
        not ar._is_admin(user)
        and ad_review.is_kenyan(user)
        and await ad_sales.selling_allowed(db, user.id)
    )
    return {"allowed": allowed}


@router.get("/api/ad-sales/quote")
async def quote(weeks: int, price_per_week: int):
    return ad_sales.quote(weeks, price_per_week)


@router.post("/api/ad-sales")
async def create_sold_ad(
    request: SoldAdCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Create "An ad I sold" and send the M-Pesa prompt to the business."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    _require_kenyan_reseller(user)
    await _require_selling_open(db, user.id)
    await _require_portal_ads_on(db, user.id)
    ad_sales.validate_terms(request.weeks, request.price_per_week)

    ad = Ad(owner_user_id=user.id, slot="reseller", status="pending", is_active=True, priority=0)
    data = request.model_dump(exclude=_SALE_FIELDS | {
        "advertiser_id", "slot", "router_ids", "priority", "starts_at", "expires_at",
    })
    ar._apply_fields(ad, data)
    ar._check_media_complete(ad)
    ad.router_ids = await ar._check_router_scope(db, user, request.router_ids)
    await ad_review.run_submit_checks(db, ad, user)
    db.add(ad)
    await db.flush()
    if await ad_review.decide_status(db, ad, user) == "approved":
        ad.status = "approved"
        ad.reviewed_at = datetime.utcnow()
        ad.review_note = "Approved automatically"
        ad_review.record_event(db, ad, ad_review.ACTION_AUTO_APPROVE, None)
    sale, payment = await ad_sales.create_sale(
        db, ad, user, business_name=request.business_name, business_phone=request.business_phone,
        weeks=request.weeks, price_per_week=request.price_per_week, requested_by=user.id,
    )
    ad_id, sale_id, payment_id = ad.id, sale.id, payment.id
    await db.commit()  # nothing held across the STK call
    logger.info("Sold ad #%s created by reseller %s (%s)", ad_id, user.id, ad.status)

    prompt = await ad_sales.send_prompt(payment_id)
    db.expire_all()  # send_prompt wrote through its own session
    ad = await db.get(Ad, ad_id)
    sale = await db.get(AdSale, sale_id)
    totals = await ar._event_totals(db, [ad_id])
    names = await ar._owner_names(db, [ad.owner_user_id])
    return {
        "ad": ar._serialize_manage(ad, totals.get(ad_id), names.get(ad.owner_user_id)),
        "sale": await _sale_payload(db, ad, sale, prompt),
    }


@router.get("/api/ads/{ad_id}/sale")
async def get_sale(
    ad_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """The sold ad's payment status. The dashboard polls this while a prompt is out."""
    user = await get_current_user(token, db)
    ad, sale = await _owned_sale(db, user, ad_id)
    return await _sale_payload(db, ad, sale)


@router.post("/api/ads/{ad_id}/sale")
async def attach_sale(
    ad_id: int,
    request: SaleTerms,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Put a sold ad made before payments existed up for payment."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    _require_kenyan_reseller(user)
    ad = await ar._load_owned_ad(db, user, ad_id)
    if ad.slot != "reseller":
        raise HTTPException(status_code=400, detail="Only an ad you sold is paid for")
    await _require_selling_open(db, ad.owner_user_id)
    await _require_portal_ads_on(db, ad.owner_user_id)
    if await ad_sales.get_sale_for_ad(db, ad.id) is not None:
        raise HTTPException(status_code=400, detail="This ad already has a sale; send the prompt again instead")
    ad.starts_at = None
    ad.expires_at = None
    sale, payment = await ad_sales.create_sale(
        db, ad, user, business_name=request.business_name, business_phone=request.business_phone,
        weeks=request.weeks, price_per_week=request.price_per_week, requested_by=user.id,
    )
    sale_id, payment_id = sale.id, payment.id
    await db.commit()
    await invalidate_ad_cache()
    prompt = await ad_sales.send_prompt(payment_id)
    db.expire_all()  # send_prompt wrote through its own session
    return await _sale_payload(db, await db.get(Ad, ad_id), await db.get(AdSale, sale_id), prompt)


async def _prompt(db, user, ad_id: int, body: PromptRequest, renew: bool) -> dict:
    enforce_active_subscription(user)
    # A plain value: db.expire_all() below also expires `user`, and reading an
    # expired attribute on an AsyncSession raises MissingGreenlet (a 500).
    user_id = user.id
    ad, sale = await _owned_sale(db, user, ad_id)
    if ad.status == "rejected":
        raise HTTPException(status_code=400, detail="This ad was rejected; fix it and resubmit before asking for payment")
    await _require_selling_open(db, sale.reseller_user_id)
    await _require_portal_ads_on(db, sale.reseller_user_id)
    sale_id = sale.id
    await db.commit()  # release before asking Safaricom about an earlier prompt

    if await ad_sales.settle_in_flight(sale_id) == "paid":
        db.expire_all()
        sale = await db.get(AdSale, sale_id)
        out = await _sale_payload(db, await db.get(Ad, ad_id), sale)
        out["prompt_result"] = {"sent": False, "message": "The shop has already paid this"}
        return out

    db.expire_all()
    ad = await db.get(Ad, ad_id)
    sale = await db.get(AdSale, sale_id)
    if renew:
        payment = await ad_sales.prepare_renewal(
            db, sale, ad, weeks=body.weeks, price_per_week=body.price_per_week,
            phone=body.phone, requested_by=user_id, confirm_new_price=body.confirm_new_price,
        )
    else:
        payment = await ad_sales.prepare_resend(
            db, sale, phone=body.phone, weeks=body.weeks, price_per_week=body.price_per_week,
            requested_by=user_id, confirm_new_price=body.confirm_new_price,
        )
    payment_id = payment.id
    await db.commit()
    prompt = await ad_sales.send_prompt(payment_id)
    db.expire_all()
    return await _sale_payload(db, await db.get(Ad, ad_id), await db.get(AdSale, sale_id), prompt)


@router.post("/api/ads/{ad_id}/sale/prompt")
async def send_payment_prompt(
    ad_id: int,
    request: PromptRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Send the M-Pesa prompt for whatever is due (first payment or renewal).
    The reseller can confirm or change the phone, weeks and weekly price."""
    user = await get_current_user(token, db)
    return await _prompt(db, user, ad_id, request, renew=False)


@router.post("/api/ads/{ad_id}/sale/renew")
async def renew_sold_ad(
    ad_id: int,
    request: PromptRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Renewal prompt to the shop (same price and length unless changed)."""
    user = await get_current_user(token, db)
    return await _prompt(db, user, ad_id, request, renew=True)


@router.get("/api/ad-sales")
async def list_sales(
    state: Optional[str] = None,
    payout_status: Optional[str] = None,
    owner_user_id: Optional[int] = None,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Sold ads with payment status, amount, Bitwave's 20% and payout status.
    Admins see every reseller's (?payout_status=refund_due is the refund
    queue); a reseller sees their own."""
    user = await get_current_user(token, db)
    admin = ar._is_admin(user)
    q = select(AdSale).order_by(AdSale.created_at.desc(), AdSale.id.desc()).limit(1000)
    if not admin:
        q = q.where(AdSale.reseller_user_id == user.id)
    elif owner_user_id is not None:
        q = q.where(AdSale.reseller_user_id == owner_user_id)
    sales = list((await db.execute(q)).scalars().all())
    ads = {a.id: a for a in (await db.execute(
        select(Ad).where(Ad.id.in_([s.ad_id for s in sales]))
    )).scalars().all()} if sales else {}
    by_sale: dict = {}
    if sales:
        for p in (await db.execute(
            select(AdSalePayment).where(AdSalePayment.sale_id.in_([s.id for s in sales]))
            .order_by(AdSalePayment.created_at, AdSalePayment.id)
        )).scalars().all():
            by_sale.setdefault(p.sale_id, []).append(p)
    from app.db.models import AdReviewEvent
    taken = set((await db.execute(
        select(AdReviewEvent.ad_id).where(
            AdReviewEvent.ad_id.in_([s.ad_id for s in sales] or [0]),
            AdReviewEvent.action == ad_review.ACTION_TAKEDOWN,
        )
    )).scalars().all())
    names = await ar._owner_names(db, [s.reseller_user_id for s in sales])
    now = datetime.utcnow()
    items = []
    for s in sales:
        ad = ads.get(s.ad_id)
        summary = ad_sales.summarize(ad, s, by_sale.get(s.id, []), s.ad_id in taken, now)
        if state and summary["state"] != state:
            continue
        if payout_status and summary["payout_status"] != payout_status:
            continue
        summary.update({
            "ad_id": s.ad_id,
            "title": ad.title if ad else None,
            "owner_user_id": s.reseller_user_id,
            "owner_name": names.get(s.reseller_user_id),
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
        items.append(summary)
    totals = {
        key: sum(i[key] for i in items)
        for key in (
            "paid_total", "bitwave_fee_total", "reseller_share_total", "credited_total", "refund_due_total",
            "refunded_total", "reseller_recovered_total", "bitwave_refund_part_total",
            "shop_net_total", "bitwave_fee_net_total", "reseller_share_net_total",
        )
    }
    page, per_page = max(page, 1), min(max(per_page, 1), 100)
    return {
        "sales": items[(page - 1) * per_page: page * per_page],
        "totals": totals,
        "pagination": {
            "page": page, "per_page": per_page, "total": len(items),
            "total_pages": (len(items) + per_page - 1) // per_page,
        },
        "fee_percent": ad_sales.FEE_PERCENT,
        "min_price_per_week": ad_sales.MIN_PRICE_PER_WEEK,
        "max_weeks": ad_sales.MAX_WEEKS,
    }


# ---------------------------------------------------------------------------
# Admin: takedown, refunds, review rules
# ---------------------------------------------------------------------------

@router.post("/api/ads/{ad_id}/takedown")
async def take_down_ad(
    ad_id: int,
    request: TakedownRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Take any ad off every portal at once. Paid weeks that never started are
    flagged for a full refund. Whole days not used yet are flagged for refund and
    the reseller's part of them is recorded as a debit. Sends no money, and a
    repeat adds nothing."""
    user = await get_current_user(token, db)
    ar._require_admin(user)
    ad = await ar._load_owned_ad(db, user, ad_id)
    note = (request.note or "").strip()[:250]
    if not note:
        raise HTTPException(status_code=400, detail="Say why the ad was taken down")
    await ad_sales.lock_sale_for_ad(db, ad)
    ad.status = "rejected"
    ad.review_note = f"Taken down by Bitwave: {note}"
    ad.reviewed_at = datetime.utcnow()
    ad.reviewed_by = user.id
    ad_review.record_event(db, ad, ad_review.ACTION_TAKEDOWN, user.id, note)
    flagged = await ad_sales.on_rejected(db, ad, note, actor_id=user.id, takedown=True)
    await db.commit()
    await invalidate_ad_cache()
    logger.info("Ad #%s taken down by admin %s (%s refunds flagged)", ad_id, user.id, flagged)
    await db.refresh(ad)
    return await ar._manage_view(db, ad)


@router.post("/api/ad-sales/payments/{payment_id}/refund")
async def mark_refunded(
    payment_id: int,
    request: RefundRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Record that a due refund was paid back by hand. Moves no money."""
    user = await get_current_user(token, db)
    ar._require_admin(user)
    payment = await db.get(AdSalePayment, payment_id)
    if payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    if payment.refund_status != ad_sales.REFUND_DUE:
        raise HTTPException(status_code=400, detail="No refund is due on this payment")
    payment.refund_status = ad_sales.REFUNDED
    payment.refunded_at = datetime.utcnow()
    payment.refunded_by = user.id
    if request.note:
        payment.refund_reason = f"{payment.refund_reason or ''} | {request.note.strip()}"[:300]
    await db.commit()
    return ad_sales._payment_dict(payment)


async def _rules_payload(db: AsyncSession) -> dict:
    mode, ids = await ad_sales.selling_settings(db)
    names = await ar._owner_names(db, ids)
    return {
        "blocked_words": await ad_review.get_blocked_words(db),
        "default_blocked_words": list(ad_review.DEFAULT_BLOCKED_WORDS),
        "fee_percent": ad_sales.FEE_PERCENT,
        "min_price_per_week": ad_sales.MIN_PRICE_PER_WEEK,
        "max_weeks": ad_sales.MAX_WEEKS,
        "selling_mode": mode,
        "selling_modes": list(ad_sales.SELLING_MODES),
        "selling_allowlist": [{"id": i, "name": names.get(i)} for i in ids],
    }


@router.get("/api/ad-review/rules")
async def get_review_rules(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    ar._require_admin(user)
    return await _rules_payload(db)


@router.put("/api/ad-review/rules")
async def put_review_rules(
    request: ReviewRulesRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    ar._require_admin(user)
    from app.services.app_settings import set_setting
    if request.selling_mode is not None and request.selling_mode not in ad_sales.SELLING_MODES:
        raise HTTPException(status_code=400, detail="selling_mode must be off, allowlist or everyone")
    allowlist = None
    if request.selling_allowlist is not None:
        allowlist = list(dict.fromkeys(request.selling_allowlist))
        found = set()
        if allowlist:
            found = set((await db.execute(
                select(User.id).where(User.id.in_(allowlist), User.role == UserRole.RESELLER)
            )).scalars().all())
        unknown = [i for i in allowlist if i not in found]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"Not a reseller account: {', '.join(map(str, unknown))}",
            )
        allowlist = ",".join(map(str, allowlist))
    blocked = None
    if request.blocked_words is not None:
        blocked = ad_review.serialize_blocked_words(request.blocked_words)
    # Everything is checked above, so a bad value can't leave half a change saved.
    if blocked is not None:
        await set_setting(db, ad_review.BLOCKED_WORDS_KEY, blocked)
    if allowlist is not None:
        await set_setting(db, ad_sales.SELLING_ALLOWLIST_KEY, allowlist)
    if request.selling_mode is not None:
        await set_setting(db, ad_sales.SELLING_MODE_KEY, request.selling_mode)
        logger.info("Ad selling mode set to %s by admin %s", request.selling_mode, user.id)
    return await _rules_payload(db)


# ---------------------------------------------------------------------------
# Public: Safaricom callback, the business's link
# ---------------------------------------------------------------------------

@router.post("/api/mpesa/ad-sales/callback")
async def ad_sales_mpesa_callback(request: Request, db: AsyncSession = Depends(get_db)):
    """Always answers ResultCode 0: anything else makes Safaricom retry, and a
    retry is handled idempotently anyway."""
    try:
        body = await request.json()
        outcome = await ad_sales.handle_callback(db, body)
        logger.info("Ad sale M-Pesa callback: %s", outcome)
    except Exception:
        logger.exception("Ad sale M-Pesa callback error")
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


@router.get("/api/public/promo/{token}")
async def public_report(token: str, db: AsyncSession = Depends(get_db)):
    report = await ad_sales.report_for_token(db, token)
    if report is None:
        raise HTTPException(status_code=404, detail="Link not found")
    return report


@router.post("/api/public/promo/{token}/pay")
async def public_pay(token: str, db: AsyncSession = Depends(get_db)):
    """The business asks for the prompt for what is due. It only ever goes to
    the number saved on the sale: anyone holding this link must not be able to
    send a prompt to another phone, so the request takes no number at all.
    Same in-flight guard and rate limit as the reseller's button."""
    if not token or len(token) > 48:
        raise HTTPException(status_code=404, detail="Link not found")
    sale = (await db.execute(select(AdSale).where(AdSale.share_token == token))).scalar_one_or_none()
    if sale is None:
        raise HTTPException(status_code=404, detail="Link not found")
    ad = await db.get(Ad, sale.ad_id)
    if ad is None or ad.status == "rejected":
        raise HTTPException(status_code=400, detail="This ad can't be paid for")
    await _require_selling_open(
        db, sale.reseller_user_id,
        "Paying for ads here isn't open yet. Please ask the WiFi owner.",
    )
    await _require_portal_ads_on(
        db, sale.reseller_user_id,
        "This WiFi network has ads switched off right now. Ask the owner to turn them on, then pay.",
    )
    sale_id = sale.id
    await db.commit()
    if await ad_sales.settle_in_flight(sale_id) == "paid":
        return {"sent": False, "message": "Already paid. Thank you!"}
    db.expire_all()
    sale = await db.get(AdSale, sale_id)
    payment = await ad_sales.prepare_resend(db, sale, phone=sale.business_phone, requested_by=None)
    payment_id = payment.id
    await db.commit()
    prompt = await ad_sales.send_prompt(payment_id)
    return {"sent": prompt.sent, "message": prompt.message}
