"""Markets: per-country settings for resellers outside (and inside) Kenya.

Every reseller belongs to one market (``users.market_code``, default ``KE``).
The market is the single source of truth for:

* the reseller's operating currency: plan prices, customer payments and
  hotspot revenue are all in this currency;
* how the platform bills the reseller (the subscription pricing rule) and in
  which currency, plus the fixed exchange rate used when the invoice currency
  differs from the operating currency;
* which methods the reseller can use to pay that subscription;
* defaults for language and timezone.

Adding a country is one entry in ``MARKETS``. A reseller-specific price goes in
``users.subscription_price_override`` rather than a new market.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace

PRICING_USAGE = "usage"
PRICING_FLAT = "flat"

PAY_MPESA = "mpesa"
PAY_CARD = "card"

DEFAULT_MARKET = "KE"


@dataclass(frozen=True)
class PricingRule:
    kind: str                   # PRICING_USAGE | PRICING_FLAT
    currency: str               # currency the invoice is issued in
    hotspot_rate: float = 0.0   # usage: share of hotspot revenue
    per_pppoe_user: float = 0.0 # usage: per active PPPoE user per month
    minimum: float = 0.0        # usage: minimum monthly charge
    flat_amount: float = 0.0    # flat: fixed monthly charge

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Market:
    code: str
    name: str
    currency: str
    default_language: str
    languages: tuple[str, ...]
    timezone: str
    phone_prefix: str
    pricing: PricingRule
    subscription_payment_methods: tuple[str, ...]
    # Units of the operating currency per 1 USD. Fixed on purpose (no live
    # feed billing depends on); update by hand when rates drift. Each invoice
    # stores the rate it used.
    usd_rate: float | None = None

    def fx_rate_to(self, invoice_currency: str) -> float:
        """Local units per 1 unit of the invoice currency."""
        if invoice_currency == self.currency:
            return 1.0
        if invoice_currency == "USD" and self.usd_rate:
            return self.usd_rate
        raise ValueError(
            f"No exchange rate from {self.currency} to {invoice_currency} for market {self.code}"
        )


# Everyone pays the same shape of formula: 3% of hotspot revenue plus a
# per-PPPoE-user fee, with a monthly minimum. Kenya pays it in KES over
# M-Pesa. International resellers pay it in USD by card: their local-currency
# revenue is converted at the market's fixed usd_rate, so the $10 minimum
# applies until 3% of revenue passes about $333.
_KENYA_PRICING = PricingRule(
    kind=PRICING_USAGE, currency="KES",
    hotspot_rate=0.03, per_pppoe_user=25.0, minimum=500.0,
)
_INTERNATIONAL_PRICING = PricingRule(
    kind=PRICING_USAGE, currency="USD",
    hotspot_rate=0.03, per_pppoe_user=0.20, minimum=10.0,
)

MARKETS: dict[str, Market] = {
    # usd_rate values: open.er-api.com mid-market rates on 2026-09-19.
    "KE": Market("KE", "Kenya", "KES", "en", ("en", "sw"), "Africa/Nairobi", "254",
                 _KENYA_PRICING, (PAY_MPESA,), usd_rate=129.5),
    "CM": Market("CM", "Cameroon", "XAF", "fr", ("fr", "en"), "Africa/Douala", "237",
                 _INTERNATIONAL_PRICING, (PAY_CARD,), usd_rate=571.0),
    "UG": Market("UG", "Uganda", "UGX", "en", ("en",), "Africa/Kampala", "256",
                 _INTERNATIONAL_PRICING, (PAY_CARD,), usd_rate=3818.0),
    "TZ": Market("TZ", "Tanzania", "TZS", "sw", ("sw", "en"), "Africa/Dar_es_Salaam", "255",
                 _INTERNATIONAL_PRICING, (PAY_CARD,), usd_rate=2649.0),
}


def get_market(code: str | None) -> Market:
    return MARKETS.get((code or DEFAULT_MARKET).upper(), MARKETS[DEFAULT_MARKET])


def reseller_market(user) -> Market:
    return get_market(getattr(user, "market_code", None))


def reseller_pricing(user) -> PricingRule:
    """The market's pricing rule with the reseller's price override applied.

    For flat pricing the override replaces the monthly fee; for usage pricing
    it replaces the minimum charge.
    """
    rule = reseller_market(user).pricing
    override = getattr(user, "subscription_price_override", None)
    if override is None or override <= 0:
        return rule
    if rule.kind == PRICING_FLAT:
        return replace(rule, flat_amount=float(override))
    return replace(rule, minimum=float(override))


def reseller_language(user) -> str:
    market = reseller_market(user)
    preferred = getattr(user, "preferred_language", None)
    return preferred if preferred in market.languages else market.default_language


def market_summary(user) -> dict:
    """What the frontend needs to render money, language and payment options."""
    market = reseller_market(user)
    pricing = reseller_pricing(user)
    return {
        "code": market.code,
        "name": market.name,
        "currency": market.currency,
        "language": reseller_language(user),
        "languages": list(market.languages),
        "timezone": market.timezone,
        "subscription_currency": pricing.currency,
        "subscription_pricing": pricing.as_dict(),
        "fx_rate": market.fx_rate_to(pricing.currency),
        "subscription_payment_methods": list(market.subscription_payment_methods),
    }


# ---------------------------------------------------------------------------
# Converting to KES for platform-wide totals
# ---------------------------------------------------------------------------
# Admin dashboards add up money across resellers. Each reseller's customer
# revenue is in their market currency and subscription payments carry their
# own currency, so totals convert everything to KES with the same fixed rates
# used for invoicing.

REPORTING_CURRENCY = "KES"


def kes_per_unit(currency: str | None) -> float:
    """KES value of 1 unit of ``currency`` at the fixed market rates."""
    code = (currency or REPORTING_CURRENCY).upper()
    kes_per_usd = MARKETS[DEFAULT_MARKET].usd_rate
    if code == REPORTING_CURRENCY:
        return 1.0
    if code == "USD":
        return kes_per_usd
    for market in MARKETS.values():
        if market.currency == code and market.usd_rate:
            return kes_per_usd / market.usd_rate
    raise ValueError(f"No KES rate for {code}")


def to_kes(amount: float | None, currency: str | None) -> float:
    return round(float(amount or 0) * kes_per_unit(currency), 2)


def sql_kes_by_currency(amount_col, currency_col):
    """SQL: ``amount_col`` in KES, reading the currency from ``currency_col``.

    For tables that store a currency (subscription_invoices,
    subscription_payments). Unknown/NULL currencies count as KES.
    """
    from sqlalchemy import case

    currencies = {"USD"} | {m.currency for m in MARKETS.values()}
    whens = [
        (currency_col == code, amount_col * kes_per_unit(code))
        for code in sorted(currencies) if code != REPORTING_CURRENCY
    ]
    return case(*whens, else_=amount_col)


def sql_kes_by_market(amount_col, market_code_col):
    """SQL: ``amount_col`` in KES for money in a reseller's market currency.

    For customer payments / plan prices, whose currency is the owning
    reseller's market (join users and pass ``User.market_code``).
    """
    from sqlalchemy import case

    whens = [
        (market_code_col == m.code, amount_col * kes_per_unit(m.currency))
        for m in MARKETS.values() if m.currency != REPORTING_CURRENCY
    ]
    return case(*whens, else_=amount_col)
