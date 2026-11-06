"""Ads a reseller sells to local businesses, paid through Bitwave (Dennis, 4 Nov 2026).

Money
-----
* The reseller charges whatever they want (Dennis, 6 Nov 2026): the weekly price
  only has to be a whole number of shillings, KES 1 or more, for a number of
  whole weeks (MIN_WEEKS..MAX_WEEKS). The total has to fit in one M-Pesa payment
  (MAX_TOTAL). The business pays the total
  by M-Pesa STK push to BITWAVE's own paybill (the system shortcode), even
  when the reseller settles hotspot money directly to their own till: that is
  what lets Bitwave take its cut.
* Split, in whole KES: ``bitwave_fee = floor(amount * 20 / 100)`` and
  ``reseller_share = amount - bitwave_fee``. Any odd shilling from the
  rounding goes to the reseller (KES 1,005 -> Bitwave 201, reseller 804). There
  is no minimum fee: on KES 1 to 4 Bitwave's part rounds down to 0 and the
  reseller gets all of it.
* The reseller's 80% is credited when the paid weeks start running (go-live,
  or an extension of a live ad). Nobody reviews an ad first, so that is the
  moment the payment is confirmed. An old ad rejected before it ran was never
  credited, and the whole payment waits in the admin refund queue. Credited shares are summed by ad_credit_total(),
  which the payout balance (mpesa_b2b.get_unpaid_balance) adds as its own
  term, so ad money is paid out by the normal B2B payout and is never mixed
  into hotspot revenue (customer_payments). Bitwave's 20% is reported as the
  "ad_commission" stream in platform_earnings.
* The split is on the gross amount the shop pays. Safaricom's collection fee on
  that payment comes out of Bitwave's 20%; nothing here takes it from the
  reseller. Their normal payout transfer fee still applies when money is sent
  (mpesa_b2b.compute_fee_breakdown).
* A new price applies from the next renewal only. Each payment row keeps the
  price it was paid at, and AdSale.price_per_week moves when a renewal at a new price is actually paid.
  A reseller has to confirm they told the shop before a renewal at a new price
  goes out, and the shop's link shows the old and the new price.

Stopping an ad that has run
---------------------------
* Takedown, or rejection of an ad that has run: the unused whole days are owed
  back to the shop, and the ad's paid period ends now. A day already started
  counts as used.
* Unused days come off the newest paid weeks first, payment by payment. For one
  payment, ``refund = floor(amount * unused_days / paid_days)``. What is kept is
  split by the same 80/20 rule, and the reseller's part of the refund is
  ``reseller_share - share_of_kept``, Bitwave's ``bitwave_fee - fee_of_kept``.
  So the two parts add up to the refund and the kept split still follows the
  rule, to the shilling.
* The reseller's part is recorded as a ResellerTransactionCharge (reference
  "ad-refund:<payment id>"), which the payout balance subtracts like any other
  charge. It can take the balance below zero: nothing is paid out until later
  earnings cover it. No money moves here.
* A payment that never ran gets a full refund, and was never credited, so there
  is nothing to recover. Each row is flagged once, under the sale lock, and a
  stopped ad has no days left, so repeating a takedown or rejection adds nothing.

Timing
------
* The paid period starts when the payment is confirmed: a sold ad goes live by
  itself at that point, even one still marked pending from before review was
  removed (Dennis, 5 Nov 2026). Weeks are banked on the sale (weeks_banked) only
  for rows that can't go live by themselves: paid and marked pending before this
  rule, or pending after a takedown. Those start when an admin approves the ad.
  A renewal paid while the ad is live extends its end date; paid after it ended,
  it starts a new period now.
* The ad stops by itself at expires_at: ad_serving refuses a sold ad without
  a paid period (expires_at NULL), and the live-ads query drops anything past
  expires_at.
* Time off doesn't use up paid time. While a running ad is paused or Show Ads is
  off, AdSale.off_since holds when it stopped showing, and paid_until() gives
  the real end. When it shows again expires_at moves out by the time it was off.
  The several reasons overlap safely: there is one clock, stopped while any
  reason holds. Every path calls sync_off_state(), which is idempotent.

Payments
--------
* Each prompt is an AdSalePayment row. Prompts for the same order (the first
  sale, or one renewal) share order_key. Resending a prompt adds a row on the
  same key; the first paid row is the payment and any later paid row on that
  key is a duplicate flagged for refund, never credited.
* The callback, the STK-query reconciler and the "pay" link can all report
  the same payment. Applying a payment locks the sale row (SELECT ... FOR
  UPDATE) and moves the payment row only out of a non-paid state, and the
  M-Pesa receipt is unique, so a payment is applied and credited once.
* A failed or timed-out prompt leaves the ad unpaid; the reseller (or the
  business, from its link) can send a new prompt. A success callback that
  arrives after a timeout still counts: the money is real.
* No refund is ever sent automatically. A refund that is due (rejected after
  payment, ad deleted, duplicate payment, unused days of an ad stopped early) is
  listed for an admin, who refunds by hand and marks it done.

Who can sell
------------
A Bitwave admin controls this in app_settings: ads_selling_mode is off,
allowlist or everyone, and ads_selling_allowlist holds the reseller ids. With
nothing saved the mode is allowlist with DEFAULT_SELLING_ALLOWLIST only, so
selling stays a pilot until an admin opens it. An unrecognised mode counts as
off. The switch stops new sold ads and new prompts only: a callback for a
prompt already sent is still applied, because that money is real.

Database Session Discipline: the STK push and the STK query run with no
session open; reads and writes around them are short sessions.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from fastapi import HTTPException
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import database as db_module
from app.db.models import Ad, AdEvent, AdSale, AdSalePayment, ResellerTransactionCharge, User

logger = logging.getLogger(__name__)

FEE_PERCENT = 20
# An STK push takes whole shillings and nothing below 1. There is no other limit
# on the weekly price: the reseller decides it.
MIN_PRICE_PER_WEEK = 1
MIN_WEEKS = 1
MAX_WEEKS = 12
# Safaricom's limit on one M-Pesa transaction, PayBill included: KES 250,000
# (safaricom.co.ke/personal/m-pesa/mpesa-charges, and its September 2023 press
# release on the CBK approval). One order is one STK push, so price x weeks has
# to fit.
MAX_TOTAL = 250_000
WEEK = timedelta(days=7)
DAY = timedelta(days=1)
DAYS_PER_WEEK = 7
RENEWAL_WINDOW = timedelta(days=2)
# A prompt younger than this is on the shop's phone right now: no second one.
IN_FLIGHT_WINDOW = timedelta(seconds=90)
# Safaricom drops an unanswered prompt after about a minute; past this age an
# unconfirmed prompt is treated as dead once the STK query can't confirm it.
STALE_PROMPT = timedelta(minutes=3)
# Never more than this many prompts to one shop for one ad in PROMPT_WINDOW.
MAX_PROMPTS_PER_WINDOW = 3
PROMPT_WINDOW = timedelta(minutes=10)
QUERY_MIN_AGE = timedelta(minutes=2)
PAYMENT_TIMEOUT = timedelta(minutes=30)
NO_CHECKOUT_TIMEOUT = timedelta(minutes=5)

KIND_INITIAL = "initial"
KIND_RENEWAL = "renewal"
INITIAL_ORDER = "initial"

AWAITING = "awaiting_payment"
PAID = "paid"
FAILED = "failed"
CANCELLED = "cancelled"
TIMED_OUT = "timed_out"
UNPAID_STATES = (AWAITING, FAILED, CANCELLED, TIMED_OUT)

# STK ResultCodes that mean the person on the phone did not pay.
_CANCELLED_CODES = {1032}            # cancelled by the user
_TIMEOUT_CODES = {1037, 1019}        # phone unreachable / prompt expired


def status_for_result_code(code: Optional[int]) -> str:
    if code in _CANCELLED_CODES:
        return CANCELLED
    if code in _TIMEOUT_CODES:
        return TIMED_OUT
    return FAILED

REFUND_DUE = "due"
REFUNDED = "refunded"
# reseller_transaction_charges.reference of the debit behind a refund. Metrics
# use it to keep these out of what they report as recovered costs.
RECOVERY_REFERENCE_PREFIX = "ad-refund:"

SELLING_MODE_KEY = "ads_selling_mode"
SELLING_ALLOWLIST_KEY = "ads_selling_allowlist"
MODE_OFF = "off"
MODE_ALLOWLIST = "allowlist"
MODE_EVERYONE = "everyone"
SELLING_MODES = (MODE_OFF, MODE_ALLOWLIST, MODE_EVERYONE)
DEFAULT_SELLING_MODE = MODE_ALLOWLIST
# Dennis's test reseller (Acme Internet Service) until the end-to-end test passes.
DEFAULT_SELLING_ALLOWLIST = (20,)

# Shown to the business on its M-Pesa prompt (Safaricom allows 12 characters).
ACCOUNT_REFERENCE = "Bitwave Ad"


# ---------------------------------------------------------------------------
# Who can sell: the kill switch and the pilot list
# ---------------------------------------------------------------------------

def parse_allowlist(raw: Optional[str]) -> list[int]:
    """Reseller ids from the saved setting. None (never saved) is the default
    list; an empty string is a list an admin emptied."""
    if raw is None:
        return list(DEFAULT_SELLING_ALLOWLIST)
    ids: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit() and int(part) not in ids:
            ids.append(int(part))
    return ids


async def selling_settings(db: AsyncSession) -> tuple[str, list[int]]:
    from app.services.app_settings import get_setting
    mode = await get_setting(db, SELLING_MODE_KEY)
    if mode is None:
        mode = DEFAULT_SELLING_MODE
    elif mode not in SELLING_MODES:
        logger.warning("Unrecognised %s value %r: treating selling as off", SELLING_MODE_KEY, mode)
        mode = MODE_OFF
    return mode, parse_allowlist(await get_setting(db, SELLING_ALLOWLIST_KEY))


async def selling_allowed(db: AsyncSession, reseller_id: int) -> bool:
    mode, ids = await selling_settings(db)
    if mode == MODE_EVERYONE:
        return True
    return mode == MODE_ALLOWLIST and reseller_id in ids


# ---------------------------------------------------------------------------
# Terms and the split
# ---------------------------------------------------------------------------

def split_amount(amount: int) -> tuple[int, int]:
    """(bitwave_fee, reseller_share) in whole KES.

    Bitwave's 20% is rounded DOWN and the reseller gets the remainder, so the
    two always add up to the amount paid and any rounding favours the reseller.
    """
    amount = int(amount)
    if amount < 0:
        raise ValueError("amount must not be negative")
    fee = (amount * FEE_PERCENT) // 100
    return fee, amount - fee


def validate_terms(weeks, price_per_week) -> tuple[int, int, int]:
    """(weeks, price_per_week, total) or a 400 saying what is wrong."""
    try:
        weeks_i = int(weeks)
        price_i = int(price_per_week)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Weeks and price per week must be whole numbers")
    if weeks_i != weeks or price_i != price_per_week:
        raise HTTPException(status_code=400, detail="Weeks and price per week must be whole numbers")
    if not MIN_WEEKS <= weeks_i <= MAX_WEEKS:
        raise HTTPException(status_code=400, detail=f"An ad runs for {MIN_WEEKS} to {MAX_WEEKS} weeks")
    if price_i < MIN_PRICE_PER_WEEK:
        raise HTTPException(status_code=400, detail=f"The price must be at least KES {MIN_PRICE_PER_WEEK} a week")
    total = weeks_i * price_i
    if total > MAX_TOTAL:
        raise HTTPException(
            status_code=400,
            detail=(
                f"M-Pesa takes at most KES {MAX_TOTAL:,} in one payment and this comes to KES {total:,}. "
                "Lower the price or the weeks."
            ),
        )
    return weeks_i, price_i, total


def quote(weeks: int, price_per_week: int) -> dict:
    weeks, price, total = validate_terms(weeks, price_per_week)
    fee, share = split_amount(total)
    return {
        "weeks": weeks, "price_per_week": price, "amount": total,
        "bitwave_fee": fee, "reseller_share": share, "fee_percent": FEE_PERCENT,
    }


def normalize_business_phone(raw: Optional[str]) -> str:
    from app.services.ad_review import normalize_ke_phone
    phone = normalize_ke_phone(raw)
    if phone is None:
        raise HTTPException(
            status_code=400,
            detail="Enter the business's M-Pesa number, e.g. 0712 345 678",
        )
    return phone


def share_url(sale: AdSale) -> str:
    return f"{settings.FRONTEND_BASE_URL.rstrip('/')}/promo/{sale.share_token}"


def callback_url() -> str:
    base = settings.MPESA_CALLBACK_URL.rstrip("/")
    if "/api/mpesa/callback" in base:
        return base.replace("/api/mpesa/callback", "/api/mpesa/ad-sales/callback")
    return base + "/api/mpesa/ad-sales/callback"


# ---------------------------------------------------------------------------
# Creating a sale and its payment rows
# ---------------------------------------------------------------------------

def _new_payment(sale: AdSale, *, kind: str, order_key: str, weeks: int,
                 price_per_week: int, phone: str, requested_by: Optional[int]) -> AdSalePayment:
    amount = weeks * price_per_week
    fee, share = split_amount(amount)
    return AdSalePayment(
        sale_id=sale.id, ad_id=sale.ad_id, reseller_user_id=sale.reseller_user_id,
        kind=kind, order_key=order_key, weeks=weeks, price_per_week=price_per_week,
        amount=amount, bitwave_fee=fee, reseller_share=share, phone=phone,
        status=AWAITING, requested_by=requested_by,
    )


async def create_sale(db: AsyncSession, ad: Ad, reseller: User, *, business_name: str,
                      business_phone: str, weeks: int, price_per_week: int,
                      requested_by: Optional[int]) -> tuple[AdSale, AdSalePayment]:
    """Sale + first payment row for an ad that has an id (flushed). Not committed."""
    weeks, price, _total = validate_terms(weeks, price_per_week)
    name = (business_name or "").strip()[:150]
    if not name:
        raise HTTPException(status_code=400, detail="Enter the business's name")
    phone = normalize_business_phone(business_phone)
    sale = AdSale(
        ad_id=ad.id, reseller_user_id=reseller.id, business_name=name,
        business_phone=phone, price_per_week=price, weeks=weeks, weeks_banked=0,
        share_token=secrets.token_urlsafe(18),
    )
    db.add(sale)
    await db.flush()
    payment = _new_payment(sale, kind=KIND_INITIAL, order_key=INITIAL_ORDER, weeks=weeks,
                           price_per_week=price, phone=phone, requested_by=requested_by)
    db.add(payment)
    await db.flush()
    return sale, payment


async def get_sale_for_ad(db: AsyncSession, ad_id: int) -> Optional[AdSale]:
    return (await db.execute(select(AdSale).where(AdSale.ad_id == ad_id))).scalar_one_or_none()


async def _payments(db: AsyncSession, sale_id: int) -> list[AdSalePayment]:
    return list((await db.execute(
        select(AdSalePayment).where(AdSalePayment.sale_id == sale_id)
        .order_by(AdSalePayment.created_at, AdSalePayment.id)
    )).scalars().all())


def _paid_orders(payments: Iterable[AdSalePayment]) -> set:
    return {p.order_key for p in payments if p.status == PAID and not p.is_duplicate}


def open_order(payments: list[AdSalePayment]) -> Optional[AdSalePayment]:
    """The latest prompt of the newest order nobody has paid yet, or None."""
    paid = _paid_orders(payments)
    for p in reversed(payments):
        if p.order_key not in paid:
            return p
        # The newest order is paid: anything older is settled or superseded.
        return None
    return None


def check_prompt_limits(payments: list[AdSalePayment], now: datetime) -> None:
    """No second prompt while one is on the shop's phone, and at most
    MAX_PROMPTS_PER_WINDOW prompts per ad in PROMPT_WINDOW."""
    for p in payments:
        if p.status == AWAITING and p.created_at and now - p.created_at < STALE_PROMPT:
            raise HTTPException(
                status_code=409,
                detail="A payment prompt is on the shop's phone now. Wait for them to enter their PIN.",
            )
    recent = [p for p in payments if p.created_at and now - p.created_at < PROMPT_WINDOW]
    if len(recent) >= MAX_PROMPTS_PER_WINDOW:
        raise HTTPException(
            status_code=429,
            detail=(
                f"{MAX_PROMPTS_PER_WINDOW} prompts were sent to this shop in the last "
                f"{int(PROMPT_WINDOW.total_seconds() // 60)} minutes. Try again a little later."
            ),
        )


def _require_price_told(new_price: int, sale: AdSale, confirmed: bool) -> None:
    """A renewal at a new price goes out only once the reseller confirms they
    told the shop. The prompt and the shop's link show the amount too."""
    if new_price != sale.price_per_week and not confirmed:
        raise HTTPException(
            status_code=409,
            detail=(
                f"This changes the price from KES {sale.price_per_week:,} to KES {new_price:,} a week. "
                "Tell the shop the new price first, then confirm you have."
            ),
        )


async def prepare_resend(db: AsyncSession, sale: AdSale, *, phone: Optional[str],
                         requested_by: Optional[int], now: Optional[datetime] = None,
                         weeks: Optional[int] = None,
                         price_per_week: Optional[int] = None,
                         confirm_new_price: bool = False) -> AdSalePayment:
    """A new prompt for the order still waiting to be paid. Not committed.

    The reseller may confirm or change the phone, weeks and weekly price while
    the order is unpaid. Only a first order that nobody has paid updates the
    sale's terms: a renewal's price becomes the sale's price when it is paid.
    Callers run settle_in_flight() first, which asks Safaricom about a prompt
    still marked waiting before another is allowed."""
    now = now or datetime.utcnow()
    payments = await _payments(db, sale.id)
    last = open_order(payments)
    if last is None:
        raise HTTPException(status_code=400, detail="Nothing is waiting to be paid for this ad")
    check_prompt_limits(payments, now)
    target = normalize_business_phone(phone) if phone else last.phone
    new_weeks, new_price, _ = validate_terms(
        weeks if weeks is not None else last.weeks,
        price_per_week if price_per_week is not None else last.price_per_week,
    )
    if last.kind == KIND_INITIAL:
        sale.weeks = new_weeks
        sale.price_per_week = new_price
    elif new_price != last.price_per_week:
        _require_price_told(new_price, sale, confirm_new_price)
    sale.business_phone = target
    payment = _new_payment(sale, kind=last.kind, order_key=last.order_key, weeks=new_weeks,
                           price_per_week=new_price, phone=target, requested_by=requested_by)
    db.add(payment)
    await db.flush()
    return payment


def can_renew(ad: Optional[Ad]) -> bool:
    return bool(ad and ad.status == "approved" and ad.expires_at is not None)


def renewal_due(ad: Optional[Ad], now: Optional[datetime] = None, sale: Optional[AdSale] = None) -> bool:
    now = now or datetime.utcnow()
    return can_renew(ad) and paid_until(ad, sale, now) - now <= RENEWAL_WINDOW


async def prepare_renewal(db: AsyncSession, sale: AdSale, ad: Optional[Ad], *,
                          weeks: Optional[int], requested_by: Optional[int],
                          now: Optional[datetime] = None, phone: Optional[str] = None,
                          price_per_week: Optional[int] = None,
                          confirm_new_price: bool = False) -> AdSalePayment:
    """A renewal prompt, by default at the same weekly price and length. Not
    committed. The period already paid keeps its price: a new price is on the
    new payment row only, and reaches the sale when that renewal is paid.

    Only for an approved ad that has run; an unpaid renewal already waiting is
    resent instead of starting a second one."""
    now = now or datetime.utcnow()
    if not can_renew(ad):
        raise HTTPException(status_code=400, detail="Only an approved ad that has run can be renewed")
    payments = await _payments(db, sale.id)
    pending = open_order(payments)
    if pending is not None:
        if pending.kind != KIND_RENEWAL:
            raise HTTPException(status_code=400, detail="The first payment for this ad is still due")
        return await prepare_resend(db, sale, phone=phone, requested_by=requested_by, now=now,
                                    weeks=weeks, price_per_week=price_per_week,
                                    confirm_new_price=confirm_new_price)
    check_prompt_limits(payments, now)
    weeks_i, price, _ = validate_terms(
        weeks if weeks is not None else sale.weeks,
        price_per_week if price_per_week is not None else sale.price_per_week,
    )
    target = normalize_business_phone(phone) if phone else sale.business_phone
    _require_price_told(price, sale, confirm_new_price)
    sale.business_phone = target
    payment = _new_payment(sale, kind=KIND_RENEWAL, order_key=f"renewal-{uuid.uuid4().hex[:12]}",
                           weeks=weeks_i, price_per_week=price, phone=target,
                           requested_by=requested_by)
    db.add(payment)
    await db.flush()
    return payment


# ---------------------------------------------------------------------------
# Sending a prompt (no session held across the STK call)
# ---------------------------------------------------------------------------

@dataclass
class PromptResult:
    payment_id: int
    sent: bool
    message: str


async def send_prompt(payment_id: int) -> PromptResult:
    """Raise the STK push for a committed payment row and record the outcome."""
    from app.services.mpesa import initiate_stk_push_direct

    async with db_module.async_session() as db:
        payment = await db.get(AdSalePayment, payment_id)
        if payment is None or payment.status != AWAITING or payment.checkout_request_id:
            await db.commit()
            return PromptResult(payment_id, False, "This prompt was already handled")
        phone, amount, sale_id = payment.phone, payment.amount, payment.sale_id
        await db.commit()

    error = None
    stk = None
    try:
        stk = await initiate_stk_push_direct(
            phone_number=phone, amount=amount, reference=f"AD-{sale_id}",
            callback_url=callback_url(), account_reference=ACCOUNT_REFERENCE,
        )
        if stk is None:
            error = "M-Pesa returned no response"
    except Exception as e:  # StkPushRejected, HTTPException, network
        error = getattr(e, "detail", None) or str(e) or type(e).__name__

    async with db_module.async_session() as db:
        payment = await db.get(AdSalePayment, payment_id)
        if payment is None:
            await db.commit()
            return PromptResult(payment_id, False, "Payment not found")
        if error:
            if payment.status == AWAITING:
                payment.status = FAILED
                payment.result_desc = str(error)[:255]
            await db.commit()
            logger.warning("Ad sale prompt %s failed: %s", payment_id, error)
            return PromptResult(payment_id, False, _friendly_stk_error(str(error)))
        payment.checkout_request_id = stk.checkout_request_id
        payment.merchant_request_id = stk.merchant_request_id
        await db.commit()
    logger.info("Ad sale prompt %s sent (KES %s, checkout %s)", payment_id, amount, stk.checkout_request_id)
    return PromptResult(payment_id, True, "Payment prompt sent to the business's phone")


def _friendly_stk_error(error: str) -> str:
    if "Invalid PhoneNumber" in error or "invalid phone" in error.lower():
        return "M-Pesa rejected this phone number. Check the business's Safaricom number."
    return "M-Pesa didn't send the prompt. Try again in a minute."


# ---------------------------------------------------------------------------
# Applying a payment (callback, reconciler) - idempotent
# ---------------------------------------------------------------------------

async def _lock_sale(db: AsyncSession, sale_id: int) -> Optional[AdSale]:
    return (await db.execute(
        select(AdSale).where(AdSale.id == sale_id).with_for_update()
        .execution_options(populate_existing=True)
    )).scalar_one_or_none()


async def lock_sale_for_ad(db: AsyncSession, ad: Ad) -> Optional[AdSale]:
    """Lock the sold ad's sale row and re-read its paid period. None for any other
    ad. Routes call this BEFORE changing the ad: payments take the sale lock and
    then write the ad, so the same order here can't deadlock with them, and a
    renewal paid a moment ago can't be overwritten."""
    if ad.slot != "reseller":
        return None
    found = (await db.execute(select(AdSale.id).where(AdSale.ad_id == ad.id))).scalar_one_or_none()
    if found is None:
        return None
    sale = await _lock_sale(db, found)
    await db.refresh(ad, attribute_names=["starts_at", "expires_at"])
    return sale


# ---------------------------------------------------------------------------
# Time off: a paid period's clock stops while the ad isn't showing
# ---------------------------------------------------------------------------

def paid_until(ad: Optional[Ad], sale: Optional[AdSale], now: datetime) -> Optional[datetime]:
    """The real end of the paid period: expires_at plus the time off so far."""
    if ad is None or ad.expires_at is None:
        return None
    if sale is not None and sale.off_since is not None and now > sale.off_since:
        return ad.expires_at + (now - sale.off_since)
    return ad.expires_at


def off_reason(ad: Optional[Ad], sale: AdSale) -> Optional[str]:
    """Why the clock is stopped: paused | not_approved | show_ads_off, or None."""
    if ad is None or sale.off_since is None:
        return None
    if not ad.is_active:
        return "paused"
    if ad.status != "approved":
        return "not_approved"
    return "show_ads_off"


def apply_off_state(sale: AdSale, ad: Ad, show_ads: bool, now: datetime) -> bool:
    """Stop or restart the clock to match the ad. Idempotent. Not committed.

    Returns True when something changed. An ad not inside a paid period has
    nothing to protect, so it stays as it is."""
    showing = bool(show_ads) and bool(ad.is_active) and ad.status == "approved"
    if showing:
        if sale.off_since is None:
            return False
        off_for = max(now - sale.off_since, timedelta(0))
        if ad.expires_at is not None:
            ad.expires_at = ad.expires_at + off_for
        sale.off_seconds_total = (sale.off_seconds_total or 0) + int(off_for.total_seconds())
        sale.off_since = None
        logger.info("Ad #%s back on: end date moved out by %s", ad.id, off_for)
        return True
    if sale.off_since is None and ad.starts_at is not None and ad.expires_at is not None and ad.expires_at > now:
        sale.off_since = now
        logger.info("Ad #%s off: paid time stopped", ad.id)
        return True
    return False


async def sync_off_state(db: AsyncSession, sale: AdSale, ad: Ad, now: Optional[datetime] = None) -> bool:
    """apply_off_state with the reseller's Show Ads switch read for you. Call it
    with the sale row locked (lock_sale_for_ad). Not committed."""
    from app.services.ad_review import portal_shows_ads
    return apply_off_state(sale, ad, await portal_shows_ads(db, sale.reseller_user_id), now or datetime.utcnow())


async def on_show_ads_changed(db: AsyncSession, reseller_id: int, show_ads: bool,
                              now: Optional[datetime] = None) -> int:
    """The reseller's Show Ads switch moved: stop or restart the clock on all
    their sold ads. Idempotent. Not committed. Returns how many changed."""
    now = now or datetime.utcnow()
    sales = list((await db.execute(
        select(AdSale).where(AdSale.reseller_user_id == reseller_id)
        .order_by(AdSale.id).with_for_update().execution_options(populate_existing=True)
    )).scalars().all())
    if not sales:
        return 0
    ads = {a.id: a for a in (await db.execute(
        select(Ad).where(Ad.id.in_([s.ad_id for s in sales])).execution_options(populate_existing=True)
    )).scalars().all()}
    changed = 0
    for sale in sales:
        ad = ads.get(sale.ad_id)
        if ad is not None and apply_off_state(sale, ad, show_ads, now):
            changed += 1
    return changed


async def _credit_paid_weeks(db: AsyncSession, sale: AdSale, now: datetime) -> int:
    await db.flush()  # the payment just marked paid must be visible to the UPDATE
    result = await db.execute(
        update(AdSalePayment)
        .where(
            AdSalePayment.sale_id == sale.id,
            AdSalePayment.status == PAID,
            AdSalePayment.is_duplicate == False,  # noqa: E712
            AdSalePayment.credited_at.is_(None),
            AdSalePayment.refund_status.is_(None),
        )
        .values(credited_at=now)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount or 0


async def activate_banked(db: AsyncSession, sale: AdSale, ad: Optional[Ad], now: datetime) -> bool:
    """Start (or extend) the ad's paid period with the banked weeks, if it is
    approved, and credit the payments behind them. Not committed."""
    if ad is None or sale.weeks_banked <= 0 or ad.status != "approved":
        return False
    span = WEEK * sale.weeks_banked
    end = paid_until(ad, sale, now)
    if ad.starts_at is not None and end is not None and end > now:
        ad.expires_at = ad.expires_at + span
    else:
        ad.starts_at = now
        ad.expires_at = now + span
        sale.off_since = None
    sale.weeks_banked = 0
    await _credit_paid_weeks(db, sale, now)
    # Paid while paused or with Show Ads off: the new weeks wait too.
    await sync_off_state(db, sale, ad, now)
    logger.info("Ad #%s paid period runs %s -> %s", ad.id, ad.starts_at, ad.expires_at)
    return True


async def _flag_refund(payment: AdSalePayment, reason: str) -> None:
    payment.refund_status = REFUND_DUE
    payment.refund_reason = reason[:300]


def refund_amount_of(payment: AdSalePayment) -> int:
    """What the shop gets back on a flagged payment. NULL means all of it."""
    return payment.refund_amount if payment.refund_amount is not None else payment.amount


def refund_for_unused_days(amount: int, paid_days: int, unused_days: int) -> tuple[int, int, int]:
    """(refund, reseller_part, bitwave_part) in whole KES for one payment.

    The refund rounds down to a whole shilling. What is kept is split by the
    same 80/20 rule as any payment, so the parts always add up to the refund."""
    unused_days = min(unused_days, paid_days)
    if paid_days <= 0 or unused_days <= 0:
        return 0, 0, 0
    refund = (amount * unused_days) // paid_days
    fee, share = split_amount(amount)
    kept_fee, kept_share = split_amount(amount - refund)
    return refund, share - kept_share, fee - kept_fee


def unused_whole_days(ad: Optional[Ad], sale: Optional[AdSale], now: datetime) -> int:
    """Whole days left in the paid period. A day already started counts as used."""
    end = paid_until(ad, sale, now)
    if ad is None or ad.starts_at is None or end is None or end <= now:
        return 0
    return (end - now) // DAY


async def _go_live_on_payment(db: AsyncSession, ad: Ad, now: datetime) -> None:
    """A paid ad needs nobody's approval. Only an ad Bitwave took down waits."""
    from app.services import ad_review
    if ad.status != "pending" or await ad_review.was_taken_down(db, ad.id):
        return
    ad.status = "approved"
    ad.review_note = "Approved automatically"
    ad.reviewed_at = now
    ad.reviewed_by = None
    ad_review.record_event(db, ad, ad_review.ACTION_AUTO_APPROVE, None)


async def confirm_payment(db: AsyncSession, payment_id: int, *, receipt: Optional[str],
                          now: Optional[datetime] = None) -> str:
    """Record a successful payment exactly once. Commits. Returns what happened:
    applied | already_paid | duplicate | refund_due | unknown."""
    now = now or datetime.utcnow()
    receipt = (receipt or "").strip()[:64] or None
    payment = await db.get(AdSalePayment, payment_id)
    if payment is None:
        await db.commit()
        return "unknown"
    sale = await _lock_sale(db, payment.sale_id)
    payment = (await db.execute(
        select(AdSalePayment).where(AdSalePayment.id == payment_id)
        .execution_options(populate_existing=True)
    )).scalar_one()
    if payment.status == PAID:
        if receipt and not payment.mpesa_receipt:
            payment.mpesa_receipt = receipt
        await db.commit()
        return "already_paid"
    if receipt:
        used = (await db.execute(
            select(AdSalePayment.id).where(
                AdSalePayment.mpesa_receipt == receipt, AdSalePayment.id != payment.id,
            )
        )).first()
        if used:
            await db.commit()
            logger.warning("Ad sale receipt %s already recorded on another payment", receipt)
            return "already_paid"

    payment.status = PAID
    payment.paid_at = now
    payment.mpesa_receipt = receipt
    result = "applied"

    order_paid = (await db.execute(
        select(AdSalePayment.id).where(
            AdSalePayment.sale_id == payment.sale_id,
            AdSalePayment.order_key == payment.order_key,
            AdSalePayment.status == PAID,
            AdSalePayment.is_duplicate == False,  # noqa: E712
            AdSalePayment.id != payment.id,
        )
    )).first()
    ad = await db.get(Ad, sale.ad_id) if sale else None
    if order_paid:
        payment.is_duplicate = True
        await _flag_refund(payment, "Paid twice for the same order (the prompt was sent more than once)")
        result = "duplicate"
    elif sale is None or ad is None:
        await _flag_refund(payment, "The ad was deleted before it ran")
        result = "refund_due"
    elif ad.status == "rejected":
        await _flag_refund(payment, "The ad was rejected before it ran")
        result = "refund_due"
    else:
        sale.weeks_banked = (sale.weeks_banked or 0) + payment.weeks
        sale.price_per_week = payment.price_per_week
        await _go_live_on_payment(db, ad, now)
        await activate_banked(db, sale, ad, now)
    await db.commit()
    if result == "applied":
        from app.services.ad_serving import invalidate_ad_cache
        await invalidate_ad_cache()
    logger.info("Ad sale payment %s (KES %s, receipt %s): %s", payment.id, payment.amount, receipt, result)
    return result


async def fail_payment(db: AsyncSession, payment_id: int, *, status: str, desc: Optional[str]) -> bool:
    """awaiting_payment -> failed/timed_out. Never touches a paid row. Commits."""
    result = await db.execute(
        update(AdSalePayment)
        .where(AdSalePayment.id == payment_id, AdSalePayment.status == AWAITING)
        .values(status=status, result_desc=(desc or "")[:255] or None, updated_at=datetime.utcnow())
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return bool(result.rowcount)


def _callback_items(cb: dict) -> dict:
    return {
        item.get("Name"): item.get("Value")
        for item in (cb.get("CallbackMetadata") or {}).get("Item", []) or []
        if isinstance(item, dict)
    }


async def handle_callback(db: AsyncSession, body: dict) -> str:
    cb = (body or {}).get("Body", {}).get("stkCallback", {}) or {}
    checkout_id = cb.get("CheckoutRequestID")
    if not checkout_id:
        return "ignored"
    payment = (await db.execute(
        select(AdSalePayment).where(AdSalePayment.checkout_request_id == checkout_id)
    )).scalar_one_or_none()
    if payment is None:
        await db.commit()
        logger.warning("Ad sale callback for unknown checkout %s", checkout_id)
        return "unknown"
    try:
        result_code = int(cb.get("ResultCode"))
    except (TypeError, ValueError):
        result_code = -1
    if result_code == 0:
        items = _callback_items(cb)
        paid_amount = items.get("Amount")
        if paid_amount is not None and int(float(paid_amount)) != payment.amount:
            logger.warning("Ad sale payment %s: paid %s, expected %s", payment.id, paid_amount, payment.amount)
        return await confirm_payment(db, payment.id, receipt=items.get("MpesaReceiptNumber"))
    status = status_for_result_code(result_code)
    await fail_payment(db, payment.id, status=status, desc=cb.get("ResultDesc"))
    return status


# ---------------------------------------------------------------------------
# Review hooks (called from ads_routes)
# ---------------------------------------------------------------------------

async def on_approved(db: AsyncSession, ad: Ad, now: Optional[datetime] = None) -> None:
    """After an ad is approved (by an admin or automatically). Not committed.

    A sold ad goes live with any banked weeks and credits them, exactly once: a
    second call finds no banked weeks and no uncredited payment. One that was never paid gets no
    period at all (start/end cleared), so approving it can't make it run free."""
    if ad.slot != "reseller":
        return
    now = now or datetime.utcnow()
    sale = await lock_sale_for_ad(db, ad)
    if sale is not None:
        await activate_banked(db, sale, ad, now)
        await sync_off_state(db, sale, ad, now)
    credited = sale is not None and (await db.execute(
        select(AdSalePayment.id).where(
            AdSalePayment.sale_id == sale.id, AdSalePayment.credited_at.is_not(None),
        ).limit(1)
    )).first() is not None
    if not credited:
        ad.starts_at = None
        ad.expires_at = None


async def on_rejected(db: AsyncSession, ad: Ad, reason: str, *, actor_id: int,
                      takedown: bool = False, now: Optional[datetime] = None) -> int:
    """After a rejection or takedown. Not committed. Moves no money.

    Paid weeks that never started: full refund due. Paid days not used yet: that
    part refunded, the reseller's part of it recorded as a debit, and the paid
    period ends now. Safe to repeat: a flagged payment is never flagged again,
    and a stopped ad has no days left. Returns how many payments were flagged."""
    sale = await lock_sale_for_ad(db, ad)
    if sale is None:
        return 0
    now = now or datetime.utcnow()
    word = "Taken down" if takedown else "Rejected"
    unused = unused_whole_days(ad, sale, now)
    still_running = (paid_until(ad, sale, now) or now) > now
    flagged = 0
    credited = []
    for p in await _payments(db, sale.id):
        if p.status != PAID or p.is_duplicate or p.refund_status is not None:
            continue
        if p.credited_at is not None:
            credited.append(p)
            continue
        await _flag_refund(p, f"{word} before it ran: {reason}" if reason else f"{word} before it ran")
        flagged += 1
    sale.weeks_banked = 0

    # The newest paid weeks are the ones not used yet.
    credited.sort(key=lambda p: (p.paid_at or p.created_at, p.id), reverse=True)
    for p in credited:
        if unused <= 0:
            break
        paid_days = p.weeks * DAYS_PER_WEEK
        days = min(unused, paid_days)
        unused -= days
        refund, reseller_part, bitwave_part = refund_for_unused_days(p.amount, paid_days, days)
        if refund <= 0:
            continue
        note = f"{word} with {days} of {paid_days} paid days unused"
        await _flag_refund(p, f"{note}: {reason}" if reason else note)
        p.refund_amount = refund
        p.refund_unused_days = days
        p.reseller_recovery = reseller_part
        p.bitwave_refund_part = bitwave_part
        if reseller_part > 0:
            charge = ResellerTransactionCharge(
                reseller_id=p.reseller_user_id, amount=reseller_part,
                description=f"Ad refund: {sale.business_name}, {note.lower()}"[:255],
                reference=f"{RECOVERY_REFERENCE_PREFIX}{p.id}", created_by=actor_id,
            )
            db.add(charge)
            await db.flush()
            p.recovery_charge_id = charge.id
        flagged += 1

    if still_running:
        ad.expires_at = now
    sale.off_since = None
    return flagged


async def assert_deletable(db: AsyncSession, ad: Ad, now: Optional[datetime] = None) -> None:
    """A sold ad can't be deleted while money is in flight or owed: a prompt
    still waiting, paid weeks not yet run, or still inside its paid period."""
    if ad.slot != "reseller":
        return
    now = now or datetime.utcnow()
    sale = await get_sale_for_ad(db, ad.id)
    if sale is None:
        return
    payments = await _payments(db, sale.id)
    if any(p.status == AWAITING and not _prompt_expired(p, now) for p in payments):
        raise HTTPException(status_code=409, detail="A payment prompt is still waiting. Try again in a few minutes.")
    if sale.weeks_banked:
        raise HTTPException(status_code=409, detail="This ad is paid and waiting to run. Ask Bitwave to cancel it.")
    end = paid_until(ad, sale, now)
    if end is not None and end > now and ad.status != "rejected":
        raise HTTPException(status_code=409, detail="This ad is paid and running until its end date. Pause it instead.")


def _prompt_expired(p: AdSalePayment, now: datetime) -> bool:
    return bool(p.created_at and now - p.created_at > PAYMENT_TIMEOUT)


# ---------------------------------------------------------------------------
# Reading: per-ad summary, lists, totals
# ---------------------------------------------------------------------------

def sale_state(ad: Optional[Ad], sale: AdSale, payments: list[AdSalePayment],
               taken_down: bool, now: datetime) -> str:
    """One word for the dashboard: awaiting_payment, payment_failed, in_review,
    live, paused, ended, rejected, taken_down, deleted."""
    if ad is None:
        return "deleted"
    if ad.status == "rejected":
        return "taken_down" if taken_down else "rejected"
    ran = ad.starts_at is not None and ad.expires_at is not None
    if ran and paid_until(ad, sale, now) > now:
        if ad.status != "approved":
            return "in_review"
        return "live" if ad.is_active and sale.off_since is None else "paused"
    if sale.weeks_banked:
        return "in_review"
    pending = open_order(payments)
    if pending is not None and (not ran or pending.kind == KIND_RENEWAL):
        if pending.status == AWAITING and not _prompt_expired(pending, now):
            return "awaiting_payment" if not ran else "ended"
        if not ran:
            return "payment_failed"
    return "ended" if ran else "awaiting_payment"


def _payment_dict(p: AdSalePayment) -> dict:
    return {
        "id": p.id, "kind": p.kind, "weeks": p.weeks, "price_per_week": p.price_per_week,
        "amount": p.amount, "bitwave_fee": p.bitwave_fee, "reseller_share": p.reseller_share,
        "phone": p.phone, "status": p.status, "mpesa_receipt": p.mpesa_receipt,
        "result_desc": p.result_desc, "is_duplicate": bool(p.is_duplicate),
        "paid_at": p.paid_at.isoformat() if p.paid_at else None,
        "credited_at": p.credited_at.isoformat() if p.credited_at else None,
        "refund_status": p.refund_status, "refund_reason": p.refund_reason,
        "refund_amount": refund_amount_of(p) if p.refund_status else None,
        "refund_unused_days": p.refund_unused_days,
        "reseller_recovery": p.reseller_recovery,
        "bitwave_refund_part": p.bitwave_refund_part,
        "refunded_at": p.refunded_at.isoformat() if p.refunded_at else None,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def payout_status(payments: list[AdSalePayment]) -> str:
    """credited | waiting_to_run | refund_due | refunded | none."""
    real = [p for p in payments if p.status == PAID]
    if any(p.refund_status == REFUND_DUE for p in real):
        return "refund_due"
    if any(not p.is_duplicate and p.credited_at is None and p.refund_status is None for p in real):
        return "waiting_to_run"
    if any(p.credited_at is not None for p in real):
        return "credited"
    if any(p.refund_status == REFUNDED for p in real):
        return "refunded"
    return "none"


def prompt_status(p: Optional[AdSalePayment], now: datetime) -> Optional[dict]:
    """The newest prompt, in the words the button shows: sending,
    waiting_for_pin, paid, cancelled, failed, timed_out (with M-Pesa's reason)."""
    if p is None:
        return None
    if p.status == AWAITING:
        label = "waiting_for_pin" if p.checkout_request_id else "sending"
    else:
        label = p.status
    retry_at = None
    if p.created_at:
        retry_at = (p.created_at + STALE_PROMPT).isoformat() if p.status == AWAITING else None
    return {
        "payment_id": p.id, "status": label, "amount": p.amount, "phone": p.phone,
        "kind": p.kind, "reason": p.result_desc if p.status != AWAITING else None,
        "sent_at": p.created_at.isoformat() if p.created_at else None,
        "retry_after": retry_at,
    }


def summarize(ad: Optional[Ad], sale: AdSale, payments: list[AdSalePayment], taken_down: bool,
              now: Optional[datetime] = None, *, with_payments: bool = False) -> dict:
    now = now or datetime.utcnow()
    state = sale_state(ad, sale, payments, taken_down, now)
    pending = open_order(payments)
    good = [p for p in payments if p.status == PAID and not p.is_duplicate]
    credited = [p for p in good if p.credited_at is not None]
    refunded = [p for p in payments if p.refund_status == REFUNDED]
    # What each side keeps once refunds are taken off. Equal to the gross totals
    # when nothing was refunded.
    kept_share = kept_fee = 0
    for p in good:
        if p.refund_status is None:
            kept_share += p.reseller_share
            kept_fee += p.bitwave_fee
        elif p.credited_at is not None:
            kept_share += p.reseller_share - (p.reseller_recovery or 0)
            kept_fee += p.bitwave_fee - (p.bitwave_refund_part or 0)
    refunds_on_good = sum(refund_amount_of(p) for p in good if p.refund_status)
    try:
        check_prompt_limits(payments, now)
        limits_ok = True
    except HTTPException:
        limits_ok = False
    latest = payments[-1] if payments else None
    out = {
        "sale_id": sale.id,
        "business_name": sale.business_name,
        "business_phone": sale.business_phone,
        "price_per_week": sale.price_per_week,
        "weeks": sale.weeks,
        "fee_percent": FEE_PERCENT,
        "state": state,
        "amount_due": pending.amount if pending else None,
        "due_kind": pending.kind if pending else None,
        "due_weeks": pending.weeks if pending else None,
        "due_price_per_week": pending.price_per_week if pending else None,
        # The price the shop is moving from, when a renewal changes it.
        "price_changed_from": (
            sale.price_per_week
            if pending and pending.kind == KIND_RENEWAL and pending.price_per_week != sale.price_per_week
            else None
        ),
        "payment_status": pending.status if pending else (PAID if good else None),
        "last_payment_error": pending.result_desc if pending and pending.status != AWAITING else None,
        "can_resend": bool(pending is not None and limits_ok and state not in ("rejected", "taken_down", "deleted")),
        "prompt": prompt_status(latest, now),
        "paid_total": sum(p.amount for p in good),
        "bitwave_fee_total": sum(p.bitwave_fee for p in good),
        "reseller_share_total": sum(p.reseller_share for p in good),
        "credited_total": sum(p.reseller_share for p in credited),
        "refund_due_total": sum(refund_amount_of(p) for p in payments if p.refund_status == REFUND_DUE),
        "refunded_total": sum(refund_amount_of(p) for p in refunded),
        "reseller_recovered_total": sum(p.reseller_recovery or 0 for p in good),
        "bitwave_refund_part_total": sum(p.bitwave_refund_part or 0 for p in good),
        "shop_net_total": sum(p.amount for p in good) - refunds_on_good,
        "bitwave_fee_net_total": kept_fee,
        "reseller_share_net_total": kept_share,
        "clock_stopped": sale.off_since is not None,
        "off_reason": off_reason(ad, sale),
        "off_seconds_total": sale.off_seconds_total or 0,
        "payout_status": payout_status(payments),
        "weeks_banked": sale.weeks_banked or 0,
        "live_from": ad.starts_at.isoformat() if ad and ad.starts_at else None,
        "live_until": paid_until(ad, sale, now).isoformat() if ad and ad.expires_at else None,
        "renewal_due": bool(renewal_due(ad, now, sale) and not (pending and pending.kind == KIND_RENEWAL and pending.status == AWAITING)),
        "can_renew": can_renew(ad) and state not in ("rejected", "taken_down"),
        "share_url": share_url(sale),
    }
    if with_payments:
        out["payments"] = [_payment_dict(p) for p in reversed(payments)]
    return out


async def summaries_for_ads(db: AsyncSession, ads: list[Ad], now: Optional[datetime] = None) -> dict:
    """{ad_id: summary} for the sold ads among `ads`, in three queries."""
    from app.db.models import AdReviewEvent
    ids = [a.id for a in ads if a.slot == "reseller"]
    if not ids:
        return {}
    sales = (await db.execute(select(AdSale).where(AdSale.ad_id.in_(ids)))).scalars().all()
    if not sales:
        return {}
    by_sale: dict = {}
    for p in (await db.execute(
        select(AdSalePayment).where(AdSalePayment.sale_id.in_([s.id for s in sales]))
        .order_by(AdSalePayment.created_at, AdSalePayment.id)
    )).scalars().all():
        by_sale.setdefault(p.sale_id, []).append(p)
    taken = set((await db.execute(
        select(AdReviewEvent.ad_id).where(AdReviewEvent.ad_id.in_(ids), AdReviewEvent.action == "takedown")
    )).scalars().all())
    ads_by_id = {a.id: a for a in ads}
    return {
        s.ad_id: summarize(ads_by_id.get(s.ad_id), s, by_sale.get(s.id, []), s.ad_id in taken, now)
        for s in sales
    }


async def ad_credit_total(db: AsyncSession, reseller_id: int, *,
                          start: Optional[datetime] = None, end: Optional[datetime] = None) -> float:
    """The reseller's credited ad money (their 80%), optionally by credit date.

    This is a term of the payout balance (mpesa_b2b.get_unpaid_balance)."""
    q = select(func.coalesce(func.sum(AdSalePayment.reseller_share), 0)).where(
        AdSalePayment.reseller_user_id == reseller_id,
        AdSalePayment.credited_at.is_not(None),
        AdSalePayment.is_duplicate == False,  # noqa: E712
    )
    if start is not None:
        q = q.where(AdSalePayment.credited_at >= start)
    if end is not None:
        q = q.where(AdSalePayment.credited_at < end)
    return float((await db.execute(q)).scalar() or 0)


async def all_ad_credits_total(db: AsyncSession) -> float:
    return float((await db.execute(
        select(func.coalesce(func.sum(AdSalePayment.reseller_share), 0)).where(
            AdSalePayment.credited_at.is_not(None),
            AdSalePayment.is_duplicate == False,  # noqa: E712
        )
    )).scalar() or 0)


async def ad_credit_entries(db: AsyncSession, reseller_id: int, *,
                            start: Optional[datetime] = None, end: Optional[datetime] = None) -> list[dict]:
    """Account-statement lines: one per credited ad payment."""
    q = (
        select(AdSalePayment, AdSale.business_name)
        .join(AdSale, AdSale.id == AdSalePayment.sale_id)
        .where(
            AdSalePayment.reseller_user_id == reseller_id,
            AdSalePayment.credited_at.is_not(None),
            AdSalePayment.is_duplicate == False,  # noqa: E712
        )
    )
    if start is not None:
        q = q.where(AdSalePayment.credited_at >= start)
    if end is not None:
        q = q.where(AdSalePayment.credited_at < end)
    rows = (await db.execute(q)).all()
    return [
        {
            "type": "ad_revenue",
            "id": p.id,
            "amount": float(p.reseller_share),
            "description": f"Ad sold to {name}: {p.weeks} week(s), your {100 - FEE_PERCENT}% of KES {p.amount:,}",
            "reference": p.mpesa_receipt,
            "notes": f"Bitwave fee KES {p.bitwave_fee:,}",
            "date": p.credited_at.isoformat(),
        }
        for p, name in rows
    ]


async def ad_commission_totals(db: AsyncSession, start: datetime, end: datetime,
                               prev_start: datetime, prev_end: datetime) -> tuple[float, float, int]:
    """Bitwave's 20% on ads that started running in each window, and how many
    payments were credited in the current one."""
    credited = AdSalePayment.credited_at
    def in_window(s, e):
        return and_(credited >= s, credited < e)
    from sqlalchemy import case
    # Refunded days aren't earnings: they come off the window the fee was in.
    kept = AdSalePayment.bitwave_fee - func.coalesce(AdSalePayment.bitwave_refund_part, 0)
    row = (await db.execute(
        select(
            func.coalesce(func.sum(case((in_window(start, end), kept), else_=0)), 0),
            func.coalesce(func.sum(case((in_window(prev_start, prev_end), kept), else_=0)), 0),
            func.count(case((in_window(start, end), AdSalePayment.id))),
        ).where(
            credited.is_not(None),
            AdSalePayment.is_duplicate == False,  # noqa: E712
            credited >= prev_start, credited < end,
        )
    )).one()
    return float(row[0] or 0), float(row[1] or 0), int(row[2] or 0)


async def ad_money_not_earned(db: AsyncSession) -> dict:
    """Money Bitwave holds for ads that has not become anyone's revenue yet."""
    held = (await db.execute(
        select(func.coalesce(func.sum(AdSalePayment.amount), 0)).where(
            AdSalePayment.status == PAID, AdSalePayment.credited_at.is_(None),
            AdSalePayment.refund_status.is_(None), AdSalePayment.is_duplicate == False,  # noqa: E712
        )
    )).scalar() or 0
    refunds = (await db.execute(
        select(func.coalesce(func.sum(func.coalesce(AdSalePayment.refund_amount, AdSalePayment.amount)), 0)).where(
            AdSalePayment.refund_status == REFUND_DUE,
        )
    )).scalar() or 0
    return {"ads_paid_not_yet_running": float(held), "ad_refunds_due": float(refunds)}


async def report_for_token(db: AsyncSession, token: str, now: Optional[datetime] = None) -> Optional[dict]:
    """What the business sees on its link: no reseller-private data."""
    from app.db.models import AdReviewEvent
    from app.services.ad_media import public_media_url
    from app.services.ad_review import network_name
    now = now or datetime.utcnow()
    if not token or len(token) > 48:
        return None
    sale = (await db.execute(select(AdSale).where(AdSale.share_token == token))).scalar_one_or_none()
    if sale is None:
        return None
    ad = await db.get(Ad, sale.ad_id)
    payments = await _payments(db, sale.id)
    taken = (await db.execute(
        select(AdReviewEvent.id).where(AdReviewEvent.ad_id == sale.ad_id, AdReviewEvent.action == "takedown").limit(1)
    )).first() is not None
    reseller = await db.get(User, sale.reseller_user_id)
    state = sale_state(ad, sale, payments, taken, now)
    pending = open_order(payments)
    daily: dict = {}
    if ad is not None:
        for day, event_type, n in (await db.execute(
            select(AdEvent.day, AdEvent.event_type, func.count())
            .where(AdEvent.ad_id == ad.id)
            .group_by(AdEvent.day, AdEvent.event_type).order_by(AdEvent.day)
        )).all():
            row = daily.setdefault(day, {"day": day, "views": 0, "taps": 0})
            row["views" if event_type == "impression" else "taps"] += n
    payable = (
        pending is not None
        and state not in ("rejected", "taken_down", "deleted")
        and await selling_allowed(db, sale.reseller_user_id)
    )
    return {
        "title": ad.title if ad else None,
        "business_name": sale.business_name,
        "network_name": network_name(reseller) if reseller else None,
        "image_url": public_media_url((ad.poster_url or ad.image_url) if ad else None),
        "state": state,
        "live_from": ad.starts_at.isoformat() if ad and ad.starts_at else None,
        "live_until": paid_until(ad, sale, now).isoformat() if ad and ad.expires_at else None,
        "views": sum(d["views"] for d in daily.values()),
        "taps": sum(d["taps"] for d in daily.values()),
        "daily": list(daily.values()),
        "payment_due": (
            {"amount": pending.amount, "weeks": pending.weeks, "price_per_week": pending.price_per_week,
             "kind": pending.kind, "status": pending.status,
             # The old weekly price, so the shop sees a new price before it pays.
             "previous_price_per_week": (
                 sale.price_per_week
                 if pending.kind == KIND_RENEWAL and pending.price_per_week != sale.price_per_week
                 else None
             )}
            if payable else None
        ),
    }


async def settle_in_flight(sale_id: int, now: Optional[datetime] = None) -> Optional[str]:
    """Before another prompt: ask Safaricom about one still marked waiting.

    Returns "paid" when the earlier prompt turns out to be paid (no new prompt
    must go out), None when nothing is in flight any more. A prompt that is
    still on the phone is left alone; check_prompt_limits then refuses the new
    one. No session is held during the query."""
    from app.services.mpesa import query_stk_push_status

    now = now or datetime.utcnow()
    async with db_module.async_session() as db:
        rows = (await db.execute(
            select(AdSalePayment.id, AdSalePayment.checkout_request_id, AdSalePayment.created_at)
            .where(AdSalePayment.sale_id == sale_id, AdSalePayment.status == AWAITING)
        )).all()
        await db.commit()
    outcome = None
    for pid, checkout_id, created in rows:
        if created and now - created < IN_FLIGHT_WINDOW:
            continue  # on the phone right now: check_prompt_limits refuses
        verdict = None
        if checkout_id:
            try:
                verdict = await query_stk_push_status(checkout_id)
            except Exception as e:
                logger.debug("Ad sale in-flight query %s not final: %s", checkout_id, e)
        async with db_module.async_session() as db:
            code = verdict.get("result_code") if verdict else None
            if code == 0:
                if await confirm_payment(db, pid, receipt=None, now=now) in ("applied", "already_paid"):
                    outcome = "paid"
            elif code not in (None, -1):
                await fail_payment(db, pid, status=status_for_result_code(code), desc=verdict.get("result_desc"))
            elif not checkout_id or (created and now - created >= STALE_PROMPT):
                await fail_payment(db, pid, status=TIMED_OUT, desc="No answer from the phone")
            else:
                await db.commit()
    return outcome


# ---------------------------------------------------------------------------
# Reconciler: STK query for prompts whose callback never came
# ---------------------------------------------------------------------------

_reconcile_running = False


async def reconcile_ad_sale_payments_background() -> None:
    global _reconcile_running
    if _reconcile_running:
        return
    _reconcile_running = True
    try:
        await reconcile_ad_sale_payments()
    except Exception:
        logger.exception("Ad sale payment reconciliation failed")
    finally:
        _reconcile_running = False


async def reconcile_ad_sale_payments(now: Optional[datetime] = None) -> dict:
    from app.services.mpesa import get_access_token, query_stk_push_status

    now = now or datetime.utcnow()
    counts = {"paid": 0, "failed": 0, "timed_out": 0}
    async with db_module.async_session() as db:
        rows = (await db.execute(
            select(AdSalePayment.id, AdSalePayment.checkout_request_id, AdSalePayment.created_at)
            .where(AdSalePayment.status == AWAITING, AdSalePayment.created_at < now - QUERY_MIN_AGE)
            .order_by(AdSalePayment.created_at).limit(20)
        )).all()
        await db.commit()
    if not rows:
        return counts

    # A prompt that never got a checkout id can never be confirmed.
    to_query = []
    for pid, checkout_id, created in rows:
        if not checkout_id:
            if now - created > NO_CHECKOUT_TIMEOUT:
                async with db_module.async_session() as db:
                    if await fail_payment(db, pid, status=FAILED, desc="The prompt was never sent"):
                        counts["failed"] += 1
            continue
        to_query.append((pid, checkout_id, created))
    if not to_query:
        return counts

    try:
        token = await get_access_token()
    except Exception as e:
        logger.warning("Ad sale reconcile: no Safaricom token: %s", e)
        token = None

    for pid, checkout_id, created in to_query:
        verdict = None
        if token is not None:
            try:
                verdict = await query_stk_push_status(checkout_id, access_token=token)
            except Exception as e:  # still processing comes back as an HTTP error
                logger.debug("Ad sale reconcile: query %s not final: %s", checkout_id, e)
        async with db_module.async_session() as db:
            if verdict is not None and verdict.get("result_code") == 0:
                if await confirm_payment(db, pid, receipt=None, now=now) == "applied":
                    counts["paid"] += 1
            elif verdict is not None and verdict.get("result_code") not in (None, -1):
                status = status_for_result_code(verdict.get("result_code"))
                if await fail_payment(db, pid, status=status, desc=verdict.get("result_desc")):
                    counts["timed_out" if status == TIMED_OUT else "failed"] += 1
            elif now - created > PAYMENT_TIMEOUT:
                if await fail_payment(db, pid, status=TIMED_OUT, desc="No answer from M-Pesa"):
                    counts["timed_out"] += 1
            else:
                await db.commit()
    return counts
