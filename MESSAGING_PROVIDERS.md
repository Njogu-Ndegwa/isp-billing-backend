# SMS Gateway Providers

How the platform sends SMS through more than one vendor, and how a reseller
gets put on their own gateway.

## The problem this solves

Resellers increasingly arrive with their own SMS contract — a different
vendor, their own sender ID, their own balance. Before this, the gateway was
a single process-wide environment variable (`SMS_PROVIDER`), so every message
the platform sent went through one vendor account.

Two things are now separate:

* **which vendors the code can talk to** — a registry of provider modules
* **which vendor a given send actually uses** — a per-tenant account row

## Adding a provider

One file. Drop `app/services/messaging/<vendor>.py` into the package with a
transport class and a module-level `SPEC`:

```python
from app.services.messaging.base import (
    MessagingProvider, ProviderField, ProviderSpec, SendResult,
)

class AcmeProvider(MessagingProvider):
    name = "acme"

    def __init__(self, api_key: str, base_url: str = "https://api.acme.example"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    async def send_bulk(self, recipients, body, sender_id) -> list[SendResult]:
        ...  # one SendResult per recipient, always

SPEC = ProviderSpec(
    name="acme",
    label="Acme SMS",
    factory=AcmeProvider,
    countries=["KE"],
    fields=[
        ProviderField("api_key", "API key", secret=True),
        ProviderField("base_url", "API base URL",
                      default="https://api.acme.example"),
    ],
)
```

That is the whole installation step. There is no factory to edit, no enum to
extend, no settings field to add, no database migration, and no admin form to
build — `app/services/messaging/registry.py` discovers any module in the
package that exports a `ProviderSpec`, and the admin UI renders the form from
`SPEC.fields`.

Two rules the registry relies on:

* **Field keys are constructor kwargs.** The registry builds providers with
  `factory(**config)`, so `ProviderField("api_key", ...)` requires an
  `api_key=` parameter.
* **`send_bulk` returns one result per recipient.** Credit refunds and
  per-message status both depend on it. A vendor that only reports one
  outcome per batch must fan it back out — see `hostpinnacle.py`.

Mark every credential `secret=True`. That single flag is what makes a value
encrypted at rest and masked in API responses.

## Who sends a given message

`app.services.messaging.accounts.resolve(db, user_id)` decides, in order:

1. the reseller's own default active account
2. any other active account that reseller owns
3. the platform default account (`user_id IS NULL`)
4. the environment fallback (`SMS_PROVIDER` + its env credentials)

Step 4 means **a deployment with no accounts configured behaves exactly as it
did before this existed**. The feature ships dark; resellers move onto their
own gateway one row at a time.

A broken reseller account (uninstalled provider, credentials that will not
decrypt) falls through to the platform account rather than black-holing that
reseller's messages. It is logged at ERROR and surfaced as
`config_problems` in the admin API.

### Sender IDs

The sender ID is resolved at *queue* time by
`accounts.resolve_sender_id_for(db, user_id, fallback)` so that the ID stamped
on the row is the one the gateway that actually sends will accept. A reseller
on HostPinnacle with `DUKESTOP` must not get the platform's TalkSASA ID
stamped on their campaign — HostPinnacle would reject it.

`SMS_SENDER_ID` remains an operational override for platform gateway
migrations, but it only applies on the environment path. An account carries
its own sender ID and is never overridden by it.

## Configuring a reseller's gateway

All admin-only, under `/api/admin/messaging`:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/providers` | installed providers + the fields each needs |
| GET | `/provider-accounts?user_id=&scope=` | list accounts |
| POST | `/provider-accounts` | create |
| PUT | `/provider-accounts/{id}` | update |
| DELETE | `/provider-accounts/{id}` | deactivate (rows are never hard-deleted) |
| POST | `/provider-accounts/{id}/test` | send one real SMS and record the result |

Put a reseller on HostPinnacle:

```http
POST /api/admin/messaging/provider-accounts
{
  "provider": "hostpinnacle",
  "user_id": 42,
  "label": "Dukestop HostPinnacle",
  "sender_id": "DUKESTOP",
  "credentials": {
    "userid": "dukestop",
    "password": "<portal password>"
  }
}
```

Then verify before any customer traffic touches it:

```http
POST /api/admin/messaging/provider-accounts/7/test
{ "phone": "254712345678" }
```

The test send spends one message of the *gateway's* balance and charges no
portal credits. Its outcome is stored on the row (`last_test_ok`,
`last_test_error`) so the admin list shows which accounts are known good.

Omit `user_id` to configure the platform-wide account instead. Exactly one
account per owner can be the default, enforced by two partial unique indexes.

### Credentials

Values on fields marked `secret=True` are Fernet-encrypted with a key derived
from `SECRET_KEY` — the same helpers the payment layer uses, deliberately, so
there is one credential-encryption path in the app. They are never returned
in plaintext: reads give a last-4 mask.

An update may omit a secret, send it empty, or echo back the mask it was
given; all three keep the stored value. Only a genuinely new value replaces
it. This is what lets the admin UI render masks and `PUT` the form unchanged.

Rotating `SECRET_KEY` invalidates every stored credential — payment methods
and SMS accounts alike. Resolution fails loudly rather than sending with a
garbage credential.

## Installed providers

| Name | Vendor | Auth |
| --- | --- | --- |
| `talksasa` | TalkSASA | bearer token |
| `africastalking` | Africa's Talking | username + API key header |
| `hostpinnacle` | HostPinnacle Kenya | portal username + password in the form body |

### A note on HostPinnacle

HostPinnacle white-labels the SMSGatewayCenter platform. Its own API reference
sits behind a portal login, and two details differ between deployments of that
platform, so both are config fields rather than hardcoded:

* `send_path` — `/SMSApi/send` (HostPinnacle) vs `/SMSApi/rest/send` (upstream)
* `send_method` — `quick` (HostPinnacle) vs `simpleMsg` (upstream)

The defaults match HostPinnacle's own documented samples. If a tenant's portal
turns out to use the other variant, change the account, not the code. Use the
test-send endpoint to confirm against the live account.

HostPinnacle reports one transaction per request plus an `invalidMobile` list
rather than a per-recipient result, so the provider fans that back out to one
`SendResult` per recipient.

## Schema

`messaging_provider_accounts` — one row per gateway account.

* `user_id` NULL = the platform account
* `credentials` JSON, keyed by the provider's declared field keys

Credentials live in JSON rather than one column per vendor **on purpose**:
it is what lets a new provider ship as a single module with no migration.
(`reseller_payment_methods` took the column-per-vendor route and now carries
a column set per gateway — the cost of that choice is visible there.)

`sms_messages.provider_account_id` records which account carried each message,
so a billing dispute can be traced to one set of credentials even after a
reseller switches vendors.

## Not built yet

* Reseller self-service. Today an admin configures a reseller's gateway for
  them, which keeps credential handling on one path. Reseller-facing CRUD
  would reuse `accounts.py` unchanged.
* Delivery-report webhooks per provider. `SmsMessageStatus.DELIVERED` exists
  but nothing sets it; a `ProviderSpec` hook for inbound DLRs is the natural
  place.
* Per-provider balance checks in the admin dashboard.
