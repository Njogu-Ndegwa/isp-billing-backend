# Signup Attribution — Frontend Contract

Records which channel a reseller account came from, so paid campaigns on TikTok
and Google Search can be judged on customers rather than clicks.

GA4 counts *sessions* by channel. It can say "47 sessions from TikTok, 3
converted"; it cannot say "the reseller paying us KES 8,000/month came from
TikTok". Because billing is a share of the reseller's revenue, the number that
decides where budget goes is **cost per shilling of recurring revenue by
channel** — and that join needs the source stored on the account.

---

## Sending it

`POST /api/users/register` accepts an optional `attribution` object. No auth;
same endpoint as before, everything else unchanged.

```jsonc
{
  "email": "...",
  "password": "...",
  "role": "reseller",
  "organization_name": "...",
  "support_phone": "+2547...",

  "attribution": {                    // all fields optional
    "utm_source": "tiktok",
    "utm_medium": "cpc",
    "utm_campaign": "test_sep",
    "utm_content": "setup_video",     // which creative
    "utm_term": "",
    "gclid": "",                      // Google click id
    "ttclid": "",                     // TikTok click id
    "referrer": "tiktok.com",
    "landing_path": "/pricing",
    "seen_at": "2026-09-10T18:22:04.113Z",   // ISO 8601, first touch
    "last_utm_source": "google"       // only when last touch differs from first
  }
}
```

Omit the field entirely for an untagged visitor rather than sending `{}`.

**Unknown keys are kept, not rejected.** A new platform's click id can ship from
the frontend alone, with no coordinated backend release.

**Attribution can never fail a signup.** A malformed, oversized, or wrongly
typed value is sanitized away and the registration proceeds. It feeds a report;
it must not be able to stop someone becoming a customer.

The response echoes `acquisition_source`, which is the cheapest way to confirm
the round trip worked in production.

---

## What is stored

On the `users` row:

| Column | Type | Contents |
|---|---|---|
| `acquisition_source` | `varchar(120)`, indexed | `utm_source`, **lowercased** so `TikTok`/`tiktok` group as one row |
| `acquisition_campaign` | `varchar(190)`, indexed | `utm_campaign`, original case (it is read back in Ads Manager) |
| `acquisition_details` | `json` | the whole sanitized payload, including click ids |

NULL on every account created before this shipped and on admin-created
accounts. The click ids are the part that matters beyond reporting: they are
what allows uploading offline conversions back to Google and TikTok, so those
platforms can optimise toward resellers who actually pay rather than toward
signups.

Sanitising (`app/services/attribution.py`): values are coerced to strings,
capped at 200 characters, stripped of control characters, and the object is
capped at 24 keys. Known keys always win a place over unknown ones.

---

## Effect on the lead pipeline

A tagged signup is filed under the channel it came from instead of the generic
"Website":

- `utm_source=tiktok&utm_medium=cpc` → lead source **"TikTok Ads"**
- `utm_source=tiktok&utm_medium=social` → lead source **"TikTok"**
- untagged → **"Website"**, exactly as before

Paid and organic stay separate on purpose: while money is running, "did this
reseller come from the ad or from an organic post?" is the whole question, and
one shared "TikTok" row cannot answer it. A medium of `cpc`/`ppc`/`paid`/`cpm`,
or the presence of a `gclid`/`ttclid`, counts as paid.

A channel that starts sending real signups gets its own `lead_sources` row added
automatically rather than being flattened into "Other".

**An existing lead's source is never overwritten.** If somebody already spoke to
this person and recorded where they came from, that is the true source; the ad
click is appended to the auto-logged activity instead. The only exception is a
lead whose source was never set at all.

Because the pipeline already advances a lead to `paying` when the subscription
activates, filing signups by channel here is what makes **signup → paying, by
channel** answerable without building a new screen.

---

## Migration

`run_signup_attribution_migrations()` in `main.py` — `ADD COLUMN IF NOT EXISTS`
for the three columns plus `CREATE INDEX IF NOT EXISTS` on source and campaign.
Idempotent, non-fatal, runs on every boot.

Tests: `tests/test_signup_attribution.py`.
