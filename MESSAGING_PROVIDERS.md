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

Two ways in: an admin sets it up for a reseller, or the reseller sets it up
themselves from their own portal. Self-service is **off by default** — see
[Who may add a gateway](#who-may-add-a-gateway).

### Admin — any account, including the platform's own

Under `/api/admin/messaging`:

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

### Reseller — their own accounts only

Under `/api/messaging`, same shapes minus `user_id` (the caller is always the
owner):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/providers` | providers they can choose from + whether self-service is on |
| GET | `/provider-accounts` | their own gateways, and which one their sends use now |
| POST | `/provider-accounts` | add one |
| PUT | `/provider-accounts/{id}` | update one |
| DELETE | `/provider-accounts/{id}` | deactivate one |
| POST | `/provider-accounts/{id}/test` | test send |

`GET /provider-accounts` also returns an `effective` block — the gateway,
sender ID and source their messages actually go out on right now. A reseller
who has configured nothing sees `source: "platform"` or `"env"`, which is how
the portal can say "you are on the platform gateway" without guessing.

Every reseller handler pins `user_id` to the caller and refuses any row it
does not own. A request for another tenant's account id returns **404, not
403**, so account ids cannot be probed. The platform account is invisible and
uneditable from this path.

Reads work even with self-service off, so a reseller can always see the
gateway an admin configured for them. Only writes are gated.

Deactivating their own gateway is safe: the next send falls back to the
platform gateway, so a reseller can never lock themselves out of sending.

### Who may add a gateway

`MessagingSettings.allow_reseller_gateways` (admin settings endpoint,
`allow_reseller_gateways`) controls reseller self-service. It defaults to
**false**, and writes return 403 until an admin turns it on.

It defaults off because of an open commercial question, not a technical one:

> **A reseller sending on their own gateway is still charged portal SMS
> credits.** Credits are reserved at queue time regardless of which gateway
> carries the message. So a reseller who brings their own vendor currently
> pays twice — their vendor, and the platform.

That may be exactly right (the platform's margin is on the software, not the
SMS) or exactly wrong (the credit price is priced as resale of platform SMS).
It is a pricing decision, so this change does not touch billing. Whichever way
it goes, the lever is in `app/api/messaging_routes.py` where `try_deduct`
reserves credits — resolution already knows whether the sending account is the
reseller's own (`resolved.source == "reseller"`).

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

* A decision on whether own-gateway sends should still cost portal credits —
  see [Who may add a gateway](#who-may-add-a-gateway).
* Delivery-report webhooks per provider. `SmsMessageStatus.DELIVERED` exists
  but nothing sets it; a `ProviderSpec` hook for inbound DLRs is the natural
  place.
* Per-provider balance checks in the admin dashboard.
