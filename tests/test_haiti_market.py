"""Haiti market (HT, HTG) and the portal currency.

A Haitian reseller sells vouchers priced in gourdes, like the Zambian ones.
Bitwave bills him in USD by card. His dashboard defaults to French, and the
captive portal reads the currency from the router payload.
"""

from datetime import datetime

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
    reseller_language,
    to_kes,
)
from app.services.plan_cache import invalidate_plan_cache
from app.services.subscription_reminders import render_reminder_inbox, to_local
from tests.factories import make_reseller, make_router


def test_haiti_market_is_registered_in_gourdes():
    ht = get_market("ht")
    assert ht.code == "HT"
    assert ht.name == "Haiti"
    assert ht.currency == "HTG"
    assert ht.timezone == "America/Port-au-Prince"
    assert ht.phone_prefix == "509"
    assert ht.default_language == "fr"
    assert ht.languages == ("fr", "en")
    # Billed like the other international markets: USD 10 minimum, by card.
    assert ht.pricing.currency == "USD"
    assert ht.pricing.minimum == 10.0
    assert ht.subscription_payment_methods == (PAY_CARD,)
    assert ht.fx_rate_to("USD") == ht.usd_rate > 0


def test_platform_totals_convert_gourdes_to_kes_instead_of_adding_them_raw():
    expected = MARKETS["KE"].usd_rate / MARKETS["HT"].usd_rate
    assert kes_per_unit("HTG") == pytest.approx(expected)
    assert to_kes(1000, "HTG") == pytest.approx(round(1000 * expected, 2))
    assert "HTG" in kes_rates()


def test_customer_sms_amount_uses_gourdes():
    assert sms_templates.format_amount(300, "HTG") == "HTG 300"


async def test_haitian_reseller_summary_reports_htg_in_french(db):
    reseller = await make_reseller(db, market_code="HT")
    summary = market_summary(reseller)
    assert summary["currency"] == "HTG"
    assert summary["language"] == "fr"
    assert summary["languages"] == ["fr", "en"]
    assert summary["timezone"] == "America/Port-au-Prince"
    assert summary["subscription_currency"] == "USD"
    assert summary["subscription_payment_methods"] == [PAY_CARD]


async def test_haitian_reseller_can_choose_english(db):
    reseller = await make_reseller(db, market_code="HT", preferred_language="en")
    assert reseller_language(reseller) == "en"
    # Swahili is not a Haitian language; he gets the market default.
    reseller.preferred_language = "sw"
    assert reseller_language(reseller) == "fr"


async def test_portal_payload_carries_htg(db):
    haitian = await make_reseller(db, market_code="HT", business_name="Bigner Net")
    router = await make_router(db, haitian, identity="Router-HT-1", payment_methods=["voucher"])

    await invalidate_plan_cache()
    payload = await get_portal_data(identity=router.identity, db=db)

    assert payload["router"]["currency"] == "HTG"
    assert payload["router"]["payment_methods"] == ["voucher"]
    assert (await get_router_by_identity(router.identity, db=db))["currency"] == "HTG"


def test_haiti_reminders_follow_daylight_saving():
    # Haiti is UTC-5 (EST) in winter and UTC-4 (EDT) from March to November.
    winter = datetime(2026, 12, 14, 15, 0)
    summer = datetime(2026, 7, 14, 15, 0)
    assert to_local(winter, "America/Port-au-Prince").hour == 10
    assert to_local(summer, "America/Port-au-Prince").hour == 11

    _, body = render_reminder_inbox(winter, winter, 10.0, "USD", tz_name="America/Port-au-Prince")
    assert "10:00AM EST" in body
    _, body = render_reminder_inbox(summer, summer, 10.0, "USD", tz_name="America/Port-au-Prince")
    assert "11:00AM EDT" in body
