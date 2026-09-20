"""Discovery of messaging providers.

Every module in `app.services.messaging` that defines a module-level `SPEC`
of type `ProviderSpec` is a provider. Nothing else registers them: dropping
`app/services/messaging/<vendor>.py` into the package is the whole
installation step.

Discovery is lazy and cached. It must stay lazy — `app.services.messaging`
imports this module, so scanning at import time would recurse.
"""

import importlib
import logging
import pkgutil
from typing import Optional

from app.services.messaging.base import MessagingProvider, ProviderSpec

logger = logging.getLogger(__name__)

_specs: Optional[dict[str, ProviderSpec]] = None

# Infrastructure modules of this package. They carry no SPEC and would be
# skipped anyway; naming them keeps discovery from importing the heavier ones
# (accounts pulls in the ORM and the crypto helpers) just to look for an
# attribute that isn't there.
_NOT_PROVIDERS = {"accounts", "base", "registry", "segments"}


def _discover() -> dict[str, ProviderSpec]:
    import app.services.messaging as package

    found: dict[str, ProviderSpec] = {}
    for module_info in pkgutil.iter_modules(package.__path__):
        if module_info.ispkg or module_info.name.startswith("_"):
            continue
        if module_info.name in _NOT_PROVIDERS:
            continue
        module_name = f"{package.__name__}.{module_info.name}"
        try:
            module = importlib.import_module(module_name)
        except Exception:
            # One broken vendor module must not take the whole SMS layer down.
            logger.exception("Skipping messaging module %s: import failed", module_name)
            continue
        spec = getattr(module, "SPEC", None)
        if not isinstance(spec, ProviderSpec):
            continue
        if spec.name in found:
            logger.error(
                "Duplicate messaging provider name %r (%s); keeping the first",
                spec.name, module_name,
            )
            continue
        found[spec.name] = spec
    return found


def all_specs() -> dict[str, ProviderSpec]:
    """All installed providers, keyed by name. Cached after the first call."""
    global _specs
    if _specs is None:
        _specs = _discover()
        logger.info("Messaging providers discovered: %s", sorted(_specs))
    return _specs


def reset_cache() -> None:
    """Drop the discovery cache. For tests that install a fake provider."""
    global _specs
    _specs = None


def get_spec(name: str) -> ProviderSpec:
    spec = all_specs().get((name or "").strip().lower())
    if spec is None:
        raise ValueError(f"Unsupported SMS provider: {name!r}")
    return spec


def provider_names() -> list[str]:
    return sorted(all_specs())


def build(name: str, config: dict) -> MessagingProvider:
    """Instantiate a provider from a plaintext config dict."""
    return get_spec(name).build(config)


def validate(name: str, config: dict) -> list[str]:
    return get_spec(name).validate(config)


def describe() -> list[dict]:
    """Provider catalogue for the admin UI — field specs, never any values."""
    return [
        {
            "name": spec.name,
            "label": spec.label,
            "sender_id_hint": spec.sender_id_hint,
            "docs_url": spec.docs_url,
            "countries": spec.countries,
            "fields": [
                {
                    "key": f.key,
                    "label": f.label,
                    "secret": f.secret,
                    "required": f.required,
                    "default": f.default,
                    "help": f.help,
                }
                for f in spec.fields
            ],
        }
        for spec in sorted(all_specs().values(), key=lambda s: s.label.lower())
    ]
