# Messaging System — Design

**Date:** 2026-06-14
**Branch:** `worktree-messaging-system`
**Status:** Approved design, pending spec review → implementation plan

## Overview

Add a messaging system to the ISP billing platform with three capabilities:

1. **Resellers → their customers** — manual/bulk SMS (compose, pick recipients,
   send now), with saved templates.
2. **Us (admin) → resellers** — an in-app message inbox in the reseller
   dashboard, with an optional SMS for urgent messages.
3. **Selling SMS credits to resellers** — we own the messaging provider account
   (buy in bulk), admin sets a price per SMS, and resellers **self-purchase**
   credits via the same M-Pesa paybill flow already used for subscriptions.

The SMS provider is **pluggable**: an Africa's Talking implementation ships
first, behind an interface so another provider can be swapped in via config.

## Goals & Non-Goals

**Goals (v1)**
- Pluggable provider abstraction; Africa's Talking as the first implementation.
- Integer SMS-credit balance per reseller, backed by an auditable ledger.
- Reseller self-purchase of credits via M-Pesa STK push on the platform paybill.
- Admin-configurable price per SMS (+ optional preset bundles) and manual credit
  grants/corrections.
- Reseller bulk send with recipient filters, live segment/credit estimation,
  saved templates, and per-campaign history.
- Admin → reseller in-app inbox + optional SMS.
- Frontend (reseller + admin) in `isp-billing-admin`.
- Auto-migration on deploy following the existing startup-migration pattern.

**Non-Goals (v1) / deferred**
- Automated/triggered SMS (expiry reminders, payment confirmations) — fast-follow.
- Per-reseller registered sender IDs — single shared platform sender ID for v1.
- Two-way SMS / inbound replies.
- Reseller-owned provider accounts/credentials (account is centrally owned).

## Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Admin → reseller channel | In-app inbox (+ optional SMS for urgent) |
| Credit sourcing | Self-purchase via existing M-Pesa paybill; admin sets price |
| Credit denomination | Integer SMS credits (1 credit = 1 SMS segment) |
| v1 message features | Manual/bulk send + saved templates |
| Architecture | A — ledger + background dispatch |
| Sender ID | Single shared platform sender ID (env) |
| Per-recipient logs | Per-recipient rows + auto-retention (lean indexes) |

## v1 Stated Assumptions (correct before implementing if wrong)

- Credits are whole SMS **segments**; a long message consumes multiple credits
  per recipient.
- A credit purchase grants credits **only on full payment** (no partial grants).
- Admin → reseller SMS is billed to the **platform**, not deducted from reseller
  credits.
- AT delivery-report webhook is **optional/stretch**; v1 records send-accepted
  status returned by the provider on submit.
- Resellers do **not** get their own sender ID in v1.

---

## Architecture

```
Reseller UI ─┐
             ├─> messaging_routes (FastAPI)
Admin UI ────┘        │
                      ├─ sms_credits service  (balance/ledger: grant, deduct, refund)
                      ├─ sms_dispatch service (campaign fan-out, DB-discipline)
                      ├─ messaging provider    (get_provider() → AfricasTalkingProvider)
                      └─ mpesa.initiate_stk_push_direct (existing, platform paybill)
```

Mirrors the existing `payment_gateway.py` dispatch pattern: a thin interface, a
concrete provider, and a factory keyed on config. The provider account is owned
by us; resellers never see provider credentials.

### Provider abstraction

New package `app/services/messaging/`:

- `base.py`
  - `SendResult` dataclass: `recipient`, `success`, `provider_message_id`,
    `status`, `error`, `cost` (optional).
  - `MessagingProvider` ABC: `async send_bulk(recipients: list[str], body: str,
    sender_id: str) -> list[SendResult]`.
- `africas_talking.py` — `AfricasTalkingProvider`, `httpx` POST to the AT bulk
  SMS endpoint; reads `AT_USERNAME` / `AT_API_KEY` / `AT_BASE_URL` from settings;
  maps the AT per-recipient response into `SendResult`s.
- `segments.py` — `count_segments(body) -> int` (GSM‑7: 160 single / 153 per part;
  UCS‑2: 70 single / 67 per part) and GSM-7 charset detection.
- `__init__.py` — `get_provider() -> MessagingProvider`, keyed on
  `settings.SMS_PROVIDER` (default `africastalking`).

### Config / env additions (`app/config.py`)

| Setting | Default | Purpose |
|---|---|---|
| `SMS_PROVIDER` | `africastalking` | Provider selector for the factory |
| `AT_USERNAME` | — | Africa's Talking username |
| `AT_API_KEY` | — | Africa's Talking API key (env/secret only) |
| `AT_SENDER_ID` | — | Default shared sender ID (fallback if settings row unset) |
| `AT_BASE_URL` | live URL | Sandbox/live switch |
| `SMS_DISPATCH_CHUNK_SIZE` | 100 | Recipients per provider call / per short DB session |
| `SMS_DISPATCH_ENABLED` | `true` | Master kill-switch for outgoing SMS |

Credentials live only in server env files / GitHub secrets (per AGENTS.md).

---

## Data Model (8 new tables)

All follow existing conventions: integer PKs, FKs to `users`/`customers`, enums
declared as `(str, enum.Enum)`, `created_at`/`updated_at` timestamps.

### 1. `messaging_settings` (global singleton, `id = 1`)
- `price_per_sms_kes` DECIMAL(6,2) — admin-set price per SMS segment.
- `min_purchase_credits` INTEGER (default 10).
- `sender_id` VARCHAR(20) NULL — overrides `AT_SENDER_ID` when set.
- `provider` VARCHAR(50) (default `africastalking`).
- `enabled` BOOLEAN (default true).
- `message_retention_days` INTEGER (default 60) — prune window for sent/delivered rows.
- `bundles` JSON NULL — optional quick-buy presets `[{ "credits": int, "label": str }]`.
- `created_at`, `updated_at`.

### 2. `sms_credit_accounts`
- `user_id` INTEGER UNIQUE FK→users.
- `balance` INTEGER NOT NULL DEFAULT 0, **CHECK (balance >= 0)**.
- `total_purchased` INTEGER DEFAULT 0, `total_spent` INTEGER DEFAULT 0.
- `updated_at`.
- Index: unique on `user_id`.

### 3. `sms_credit_transactions` (ledger)
- `user_id` INTEGER FK→users.
- `change` INTEGER NOT NULL (signed).
- `balance_after` INTEGER NOT NULL.
- `kind` ENUM `smscredittxnkind` (`purchase`, `send_debit`, `refund`, `admin_adjustment`).
- `reference` VARCHAR(64) NULL (order id / campaign id).
- `note` VARCHAR(255) NULL.
- `created_at`.
- Index: `(user_id, created_at)`.

### 4. `sms_credit_orders` (self-purchase via M-Pesa — mirrors `SubscriptionPayment`)
- `user_id` INTEGER FK→users.
- `quantity` INTEGER NOT NULL.
- `unit_price` DECIMAL(6,2) NOT NULL (snapshot).
- `amount` INTEGER NOT NULL (whole KES = `ceil(quantity * unit_price)`).
- `phone_number` VARCHAR(20) NOT NULL.
- `status` ENUM `smscreditorderstatus` (`pending`, `completed`, `failed`, `expired`).
- `mpesa_checkout_request_id` VARCHAR(128) NULL, `mpesa_merchant_request_id` VARCHAR(128) NULL.
- `payment_reference` VARCHAR(128) NULL (M-Pesa receipt).
- `created_at`, `updated_at`.
- Index: `mpesa_checkout_request_id`, `(user_id, created_at)`.

### 5. `message_templates`
- `user_id` INTEGER FK→users (owner; admin templates use admin's id).
- `name` VARCHAR(120) NOT NULL.
- `body` VARCHAR(1000) NOT NULL.
- `created_at`, `updated_at`.
- Index: `(user_id)`.

### 6. `sms_campaigns`
- `user_id` INTEGER FK→users (reseller).
- `body` VARCHAR(1000) NOT NULL.
- `recipient_count` INTEGER NOT NULL.
- `segments_per_message` INTEGER NOT NULL.
- `total_credits` INTEGER NOT NULL (reserved up front).
- `sent_count` INTEGER DEFAULT 0, `failed_count` INTEGER DEFAULT 0.
- `refunded_credits` INTEGER DEFAULT 0.
- `sender_id` VARCHAR(20) NULL (snapshot).
- `status` ENUM `smscampaignstatus` (`queued`, `sending`, `completed`, `partial`, `failed`, `canceled`).
- `created_at`, `updated_at`.
- Index: `(user_id, created_at)`.
- **Permanent aggregate of a send** — survives retention pruning of its rows.

### 7. `sms_messages` (per-recipient log — the only high-growth table)
- `campaign_id` INTEGER FK→sms_campaigns NULL (null for single/admin sends).
- `user_id` INTEGER FK→users (sender).
- `customer_id` INTEGER FK→customers NULL.
- `recipient_phone` VARCHAR(20) NOT NULL.
- `body` VARCHAR(1000) NOT NULL.
- `segments` INTEGER NOT NULL, `credits_charged` INTEGER NOT NULL.
- `kind` ENUM `smsmessagekind` (`reseller_to_customer`, `admin_to_reseller`).
- `provider` VARCHAR(50) NULL, `provider_message_id` VARCHAR(128) NULL.
- `status` ENUM `smsmessagestatus` (`queued`, `sent`, `delivered`, `failed`).
- `error` VARCHAR(255) NULL.
- `created_at`, `updated_at`.
- **Lean indexes only**: `campaign_id`; partial index on `status` for `failed`
  rows (troubleshooting). No wide multi-column indexes.
- **Retention**: a job prunes `sent`/`delivered` rows older than
  `message_retention_days` in chunked deletes; `failed` rows kept longer.
  Aggregates live on `sms_campaigns`, so history totals are never lost.

### 8. `reseller_inbox_messages` (admin → reseller in-app)
- `recipient_user_id` INTEGER FK→users (reseller).
- `sender_user_id` INTEGER FK→users (admin).
- `subject` VARCHAR(200) NULL.
- `body` VARCHAR(2000) NOT NULL.
- `is_read` BOOLEAN DEFAULT false, `read_at` DATETIME NULL.
- `sent_sms` BOOLEAN DEFAULT false.
- `broadcast_id` VARCHAR(64) NULL (groups one admin broadcast to all resellers).
- `created_at`.
- Index: `(recipient_user_id, is_read)`.

### Enums
`smscredittxnkind`, `smscreditorderstatus`, `smscampaignstatus`,
`smsmessagestatus`, `smsmessagekind`.

---

## Flows

### A. Credit purchase (reseller self-service)

1. `GET /api/messaging/credits` → balance, recent ledger, current price + bundles.
2. `POST /api/messaging/credits/purchase { quantity | bundle_id, phone }`:
   - Validate `quantity >= min_purchase_credits`; compute `amount = ceil(quantity * price)`.
   - Create `SmsCreditOrder(pending)`, `flush`.
   - `initiate_stk_push_direct(phone, amount, reference="SMS-{order.id}",
     callback_url=/api/messaging/credits/mpesa/callback,
     account_reference="SMS Credits")` — **system/platform M-Pesa credentials**,
     identical to `subscription/pay`.
   - Persist `checkout_request_id`, commit. (Follows the proven subscription
     pattern: single fast STK call; the strict no-I/O-with-session rule is most
     critical on the bulk fan-out path below.)
3. `POST /api/messaging/credits/mpesa/callback` — idempotent (skip if order not
   `pending`); on `ResultCode == 0`: mark `completed`, store receipt, **grant**
   credits (`balance += quantity`, `total_purchased += quantity`, ledger
   `purchase` row). Otherwise mark `failed`.

### B. Reseller → customer send

1. `GET /api/messaging/recipients?filter=...` — resolve customer phones scoped to
   the reseller (`all` / `by_plan` / `expiring` / `status` / explicit `customer_ids`),
   returning de-duplicated phones + count.
2. `POST /api/messaging/send { body, filter | customer_ids | template_id }`:
   - **Short txn**: resolve recipients; `segments = count_segments(body)`;
     `total = segments * recipient_count`. If `balance < total` → 400 with the
     shortfall. Else deduct (`balance -= total`, ledger `send_debit`), create
     `SmsCampaign(queued)` + queued `sms_messages` rows. **Commit.**
   - **Background dispatch** (FastAPI `BackgroundTasks` for v1; can graduate to
     the scheduler): mark campaign `sending`; for each chunk of
     `SMS_DISPATCH_CHUNK_SIZE`, call `provider.send_bulk(...)` **with no DB
     session open**, then open a short session to update those `sms_messages`
     rows + campaign counters. **Refund** credits for failed recipients (ledger
     `refund`, `balance += refunded`, `campaign.refunded_credits += ...`).
     Finalize campaign `completed` / `partial` / `failed`.
   - **Load-shed**: if DB pool pressure is warning/critical, defer/slow dispatch;
     chunk + time-budget; back off the provider on errors.
3. Templates CRUD: `GET/POST/PUT/DELETE /api/messaging/templates`.
4. History: `GET /api/messaging/campaigns`, `GET /api/messaging/campaigns/{id}`
   (per-recipient statuses, subject to retention).

### C. Admin → reseller inbox

- `POST /api/admin/messaging/inbox { recipient: reseller_id | "all", subject,
  body, also_sms }` → create `ResellerInboxMessage` per recipient (shared
  `broadcast_id` when `"all"`); if `also_sms`, send to reseller `support_phone`
  via the provider (platform cost, **no reseller credit deduction**), same DB
  discipline.
- Reseller: `GET /api/messaging/inbox` (+ unread count), `POST
  /api/messaging/inbox/{id}/read`.

### D. Retention job

- Periodic (daily) chunked delete of `sms_messages` where
  `status IN (sent, delivered)` AND `created_at < now - message_retention_days`.
- Runs only when DB pool pressure is healthy; deletes in bounded batches;
  campaign aggregates are untouched.

---

## API Surface (summary)

**Reseller**
- `GET  /api/messaging/credits`
- `POST /api/messaging/credits/purchase`
- `POST /api/messaging/credits/mpesa/callback` (M-Pesa → server)
- `GET  /api/messaging/recipients`
- `POST /api/messaging/send`
- `GET/POST/PUT/DELETE /api/messaging/templates[/{id}]`
- `GET  /api/messaging/campaigns[/{id}]`
- `GET  /api/messaging/inbox`, `POST /api/messaging/inbox/{id}/read`

**Admin**
- `GET/PUT /api/admin/messaging/settings`
- `GET  /api/admin/messaging/credits/orders`
- `POST /api/admin/messaging/resellers/{id}/credits/adjust`
- `POST /api/admin/messaging/inbox`

Role gating mirrors existing routes (`get_current_user` + role check; admin via
`_require_admin`).

---

## Frontend (`isp-billing-admin`)

**Reseller** — new nav item "Messaging" → `app/messaging/page.tsx`, tabs:
- **Send**: compose with live segment + credit counter, recipient selector
  (all / by plan / expiring / individual), template pick/save, balance display.
- **Credits**: balance, buy (bundle or custom qty) → STK prompt + status poll
  (reuse subscription-pay polling), purchase history.
- **History**: campaigns list → per-recipient drill-in.
- **Templates**: CRUD.
- **Inbox**: bell icon + unread badge in nav; list + mark-read.

**Admin** — `app/admin/messaging/page.tsx`, tabs:
- **Settings**: price per SMS, min purchase, bundles, sender ID, enable toggle,
  retention days.
- **Credit sales**: orders list + revenue; per-reseller manual credit adjust.
- **Message resellers**: compose to one/all resellers + optional SMS.

`app/lib/api.ts` + `types.ts` get the new client methods and types. Follow
existing page/component conventions.

---

## Auto-Migration (deploy-safety)

The app has no Alembic; schema changes are applied by idempotent
`run_*_migrations()` functions in `main.py`'s `startup_event`, each wrapped in its
own try/except (non-fatal) and safe to run repeatedly.

1. Add the 8 models to `app/db/models.py`.
2. `migrations/create_messaging_tables.py` — standalone idempotent script
   mirroring `create_mtn_momo_tables.py`: create enums via
   `DO $$ ... EXCEPTION WHEN duplicate_object THEN NULL; END $$`, `CREATE TABLE`
   guarded by `information_schema` existence checks, create indexes, seed the
   `messaging_settings` `id = 1` row with defaults. Supports `--rollback`.
3. `run_messaging_migrations()` added to `main.py` and called in `startup_event`
   inside its own try/except — **deploys auto-migrate without crashing**, exactly
   like every other migration here. Idempotent: existence-checked column/table/
   enum adds, seed only if absent.

---

## Reliability / DB Session Discipline (per AGENTS.md)

- **Never hold a DB session across provider HTTP.** Send path: reserve credits in
  a short txn → commit → `send_bulk` outside any session → record results in a
  fresh short session per chunk.
- **Refunds** run in their own short transaction.
- **Fan-out** is chunked (`SMS_DISPATCH_CHUNK_SIZE`) and time-budgeted; no single
  session spans per-recipient provider calls.
- **Load-shed**: dispatch and the retention job skip/slow when DB pool pressure
  is warning/critical (`db_pool_snapshot`).
- New endpoints keep transactions short; no new connection-pool pressure.

---

## Testing

Focused tests (Python, `pytest`):
- `tests/test_messaging_provider.py` — segment counting (GSM‑7/UCS‑2 boundaries),
  AT payload construction, `get_provider()` factory, mocked `send_bulk`.
- `tests/test_sms_credits.py` — grant on purchase, deduct on send, refund on
  failure, non-negative balance CHECK, ledger correctness.
- `tests/test_messaging_send.py` — recipient resolution scoped to reseller,
  up-front reservation, dispatch with mocked provider, partial-failure refund,
  and **assert no DB session is held across the provider call**.
- `tests/test_messaging_routes.py` — role gating, purchase flow with mocked STK +
  idempotent callback grant.

Frontend: `npm run build` in `isp-billing-admin`; optional vitest on the
messaging page. Any test that can't run due to missing deps will be called out
explicitly in the handoff.

---

## Open Questions

None blocking. Future work: automated triggers, per-reseller sender IDs,
delivery-report webhook, inbound/two-way SMS.
