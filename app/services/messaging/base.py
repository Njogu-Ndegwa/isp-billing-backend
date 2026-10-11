"""Provider-agnostic messaging interface and provider self-description.

A provider module contributes three things:

    class FooProvider(MessagingProvider):  # the transport
        name = "foo"
        def __init__(self, api_key: str, base_url: str): ...
        async def send_bulk(...) -> list[SendResult]: ...

    SPEC = ProviderSpec(                    # how to configure it
        name="foo",
        label="Foo SMS",
        fields=[ProviderField("api_key", "API key", secret=True), ...],
        factory=FooProvider,
    )

`ProviderSpec.fields` is the single source of truth for a provider's
credentials: it drives config validation, what the admin UI renders, which
values are encrypted at rest, and which are masked on read. Adding a provider
therefore means adding one module — no edits to the factory, the config
object, the API layer, or the database schema.

Field keys must match the provider constructor's keyword arguments; the
registry builds instances with `factory(**config)`.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class SendResult:
    recipient: str
    success: bool
    provider_message_id: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    cost: Optional[str] = None


@dataclass
class BalanceResult:
    """What a gateway reports about its own account balance.

    `ok` False with `error` set means the gateway answered but refused (bad
    credentials, unknown account) or could not be reached. `balance` is the
    number the vendor reports, in the vendor's own unit: `unit` names it when
    the vendor says (e.g. "KES") and is None when it doesn't.
    """

    ok: bool
    balance: Optional[float] = None
    unit: Optional[str] = None
    raw: Optional[str] = None
    error: Optional[str] = None


class MessagingProvider(ABC):
    name: str = "base"
    # Providers that can report their account balance set this and override
    # get_balance(). The rest keep the default and the UI says "not available".
    supports_balance: bool = False

    @abstractmethod
    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        """Send one body to many recipients; return one result per recipient."""
        raise NotImplementedError

    async def get_balance(self) -> BalanceResult:
        """Ask the gateway for its remaining balance. Read-only; sends nothing."""
        raise NotImplementedError(f"{self.name} does not report a balance")


def parse_amount(value) -> tuple[Optional[float], Optional[str]]:
    """Pull a number, and a currency/unit prefix if any, out of a vendor value.

    Vendors return balances as 800, "800.00", "1,234.5", "KES 1785.50" or
    "$9,999". Returns (None, None) when there is no number in it.
    """
    if value is None or isinstance(value, bool):
        return None, None
    if isinstance(value, (int, float)):
        return float(value), None
    text = str(value).strip()
    start = next((i for i, ch in enumerate(text) if ch.isdigit()), None)
    if start is None:
        return None, None
    if start > 0 and text[start - 1] == "-":
        start -= 1
    number = "".join(ch for ch in text[start:].split()[0] if ch.isdigit() or ch in ".-")
    try:
        amount = float(number)
    except ValueError:
        return None, None
    unit = text[:start].strip() or None
    return amount, unit


@dataclass(frozen=True)
class ProviderField:
    """One configurable value a provider needs.

    key:      constructor kwarg name, and the key used in the stored config JSON
    label:    human label for the admin UI
    secret:   encrypted at rest and masked on read (passwords, tokens, keys)
    required: a config missing this key is rejected before it can be saved
    default:  used when the key is absent; also shown as the UI placeholder
    help:     one-line hint for the admin UI
    """

    key: str
    label: str
    secret: bool = False
    required: bool = True
    default: str = ""
    help: str = ""


@dataclass(frozen=True)
class ProviderSpec:
    """Everything the platform needs to know about a provider it never imports."""

    name: str
    label: str
    fields: list[ProviderField]
    factory: Callable[..., MessagingProvider]
    # Shown in the admin UI so an operator knows what a valid sender ID looks
    # like for this provider; never used as an implicit fallback.
    sender_id_hint: str = ""
    docs_url: str = ""
    # Country hints are advisory only — they help an operator pick, they do not
    # restrict where a provider may be used.
    countries: list[str] = field(default_factory=list)

    def field_map(self) -> dict[str, ProviderField]:
        return {f.key: f for f in self.fields}

    def secret_keys(self) -> set[str]:
        return {f.key for f in self.fields if f.secret}

    def apply_defaults(self, config: dict) -> dict:
        """Return config with declared defaults filled in and unknown keys dropped."""
        out: dict[str, str] = {}
        for f in self.fields:
            value = config.get(f.key)
            if value is None or value == "":
                value = f.default
            out[f.key] = value
        return out

    def validate(self, config: dict) -> list[str]:
        """Return a list of human-readable problems; empty means valid."""
        resolved = self.apply_defaults(config)
        return [
            f"{f.label} is required"
            for f in self.fields
            if f.required and not str(resolved.get(f.key) or "").strip()
        ]

    def build(self, config: dict) -> MessagingProvider:
        return self.factory(**self.apply_defaults(config))
