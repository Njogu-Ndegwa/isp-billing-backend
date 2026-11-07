"""Zambia market (ZM, ZMW) and the portal currency.

A Zambian reseller sells vouchers priced in Kwacha. His dashboard money comes
from his market (``users.market_code``); the captive portal reads the currency
from the router payload, so both portal endpoints must carry the owner's
market currency. Kenyan routers keep KES.
"""

import pytest  # noqa: F401  (pytest.ini asyncio_mode=auto)

from app.api.public_routes import get_portal_data
from app.api.router_management import get_router_by_identity
from app.services import customer_sms_templates as sms_templates
from app.services.markets import (
    MARKETS,
    PAY_CARD,
    get_market,
    kes_per_unit,
    kes_rates,
    market_summary,
    to_kes,
)
from app.services.plan_cache import invalidate_plan_cache
from tests.factories import make_reseller, make_router


def test_zambia_market_is_registered_in_kwacha():
    zm = get_market("zm")
    assert zm.code == "ZM"
    assert zm.currency == "ZMW"
    assert zm.timezone == "Africa/Lusaka"
    assert zm.phone_prefix == "260"
    # Bitwave bills Zambia like the other international markets: USD by card.
    assert zm.pricing.currency == "USD"
    assert zm.subscription_payment_methods == (PAY_CARD,)
    assert zm.fx_rate_to("USD") == zm.usd_rate > 0


def test_kenya_is_unchanged():
    ke = MARKETS["KE"]
    assert ke.currency == "KES"
    assert ke.pricing.currency == "KES"
    assert get_market(None).code == "KE"


def test_platform_totals_convert_kwacha_to_kes_instead_of_adding_it_raw():
    # ZMW 100 is worth far more than KES 100; totals must convert it.
    expected = MARKETS["KE"].usd_rate / MARKETS["ZM"].usd_rate
    assert kes_per_unit("ZMW") == pytest.approx(expected)
    assert to_kes(100, "ZMW") == pytest.approx(round(100 * expected, 2))
    assert "ZMW" in kes_rates()


def test_customer_sms_amount_uses_kwacha():
    assert sms_templates.format_amount(150, "ZMW") == "ZMW 150"


async def test_zambian_reseller_summary_reports_zmw(db):
    reseller = await make_reseller(db, market_code="ZM")
    summary = market_summary(reseller)
    assert summary["currency"] == "ZMW"
    assert summary["subscription_currency"] == "USD"


async def test_portal_payload_carries_the_owner_currency(db):
    zambian = await make_reseller(db, market_code="ZM", business_name="Fairview")
    zm_router = await make_router(db, zambian, identity="Router-ZM-1", payment_methods=["voucher"])
    kenyan = await make_reseller(db, business_name="Nairobi Spot")
    ke_router = await make_router(db, kenyan, identity="Router-KE-1")

    await invalidate_plan_cache()
    zm_payload = await get_portal_data(identity=zm_router.identity, db=db)
    ke_payload = await get_portal_data(identity=ke_router.identity, db=db)

    assert zm_payload["router"]["currency"] == "ZMW"
    assert zm_payload["router"]["payment_methods"] == ["voucher"]
    assert ke_payload["router"]["currency"] == "KES"
    assert ke_payload["router"]["payment_provider"] == "mpesa"


async def test_router_lookup_fallback_carries_the_owner_currency(db):
    zambian = await make_reseller(db, market_code="ZM")
    zm_router = await make_router(db, zambian, identity="Router-ZM-2")
    kenyan = await make_reseller(db)
    ke_router = await make_router(db, kenyan, identity="Router-KE-2")

    assert (await get_router_by_identity(zm_router.identity, db=db))["currency"] == "ZMW"
    assert (await get_router_by_identity(ke_router.identity, db=db))["currency"] == "KES"
