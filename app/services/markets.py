"""Markets: per-country settings for resellers outside (and inside) Kenya.

Every reseller belongs to one market (``users.market_code``, default ``KE``).
The market is the single source of truth for:

* the reseller's operating currency: plan prices, customer payments and
  hotspot revenue are all in this currency;
* how the platform bills the reseller (the subscription pricing rule) and in
  which currency;
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


# Kenya keeps the long-standing usage formula paid over M-Pesa. Other markets
# pay a flat USD fee by card: their hotspot revenue is in another currency, so
# a KES percentage/minimum means nothing there.
_KENYA_PRICING = PricingRule(
    kind=PRICING_USAGE, currency="KES",
    hotspot_rate=0.03, per_pppoe_user=25.0, minimum=500.0,
)
_INTERNATIONAL_PRICING = PricingRule(kind=PRICING_FLAT, currency="USD", flat_amount=10.0)

MARKETS: dict[str, Market] = {
    "KE": Market("KE", "Kenya", "KES", "en", ("en", "sw"), "Africa/Nairobi", "254",
                 _KENYA_PRICING, (PAY_MPESA,)),
    "CM": Market("CM", "Cameroon", "XAF", "fr", ("fr", "en"), "Africa/Douala", "237",
                 _INTERNATIONAL_PRICING, (PAY_CARD,)),
    "UG": Market("UG", "Uganda", "UGX", "en", ("en",), "Africa/Kampala", "256",
                 _INTERNATIONAL_PRICING, (PAY_CARD,)),
    "TZ": Market("TZ", "Tanzania", "TZS", "sw", ("sw", "en"), "Africa/Dar_es_Salaam", "255",
                 _INTERNATIONAL_PRICING, (PAY_CARD,)),
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
        "subscription_payment_methods": list(market.subscription_payment_methods),
    }
