# Reseller Welcome Message on Signup — Design

Date: 2026-06-24
Status: Approved (spec-review gate waived by user)
Repos: `isp-billing` (backend), `isp-billing-admin` (frontend)

## Overview

When a reseller registers, automatically send them a welcome message over **two
channels** — the in-app inbox (always) and **SMS** (when a phone is on file) —
reusing the existing admin→reseller messaging plumbing. The message welcomes the
reseller and offers **free router-onboarding help with a support phone number**.

Admins see these messages in the existing admin SMS history, tagged as `welcome`.
The whole behavior is globally toggleable and the message text + support phone are
editable from admin Messaging settings, **pre-filled with sensible defaults** on
first load.

## Decisions (from brainstorming)

- Channels: **in-app inbox + SMS**.
- Content source: **admin Messaging settings (DB)**, pre-filled with code defaults.
- Admin visibility: **tag in the existing SMS history** (filterable).
- Trigger: **auto-send on every reseller signup, with a master on/off toggle**.
- Single shared, concise body for both inbox + SMS (keeps SMS ~1–2 segments).
- Welcome SMS is **free** to the reseller (matches existing admin→reseller sends).

## Data Model (idempotent startup migrations in `main.py` — AGENTS.md First Rule)

Wire all of the following into the existing messaging migration block in `main.py`
(around the `messaging_settings` / `sms_messages` statements) **and** update
`app/db/models.py`.

`messaging_settings` — new columns:

- `welcome_enabled BOOLEAN NOT NULL DEFAULT true`
- `welcome_subject VARCHAR(200) NULL`
- `welcome_message_body VARCHAR(2000) NULL`
- `welcome_support_phone VARCHAR(20) NULL`

`sms_messages` — new column:

- `category VARCHAR(40) NULL`  — welcome SMS sets `category='reseller_welcome'`;
  all other rows stay `NULL`.

No new `SmsMessageKind` enum value. Welcome SMS keeps `kind=ADMIN_TO_RESELLER`
(so it already appears in `list_admin_sms`) and is distinguished by `category`.
This avoids a finicky Postgres enum migration.

The `welcome_*` text columns are nullable; the **effective** value is resolved at
read time (DB value if set, else code default constant). This is what makes the
frontend form pre-fill with defaults yet remain editable, and makes "reset to
default" equivalent to clearing the field.

## Backend Service — new `app/services/reseller_welcome.py`

Constants:

- `DEFAULT_WELCOME_SUBJECT` — e.g. `"Welcome aboard"`.
- `DEFAULT_WELCOME_BODY` — concise welcome that mentions free router-onboarding
  help and includes the `{support_phone}` placeholder. Example:
  `"Hi {org}, welcome aboard! Your reseller account is ready. Need help adding "`
  `"your first router? We'll set it up for you for FREE — just call "`
  `"{support_phone}. Log in any time to get started."`
- `DEFAULT_WELCOME_SUPPORT_PHONE` — `None` (admin fills it in). If unset, the
  `{support_phone}` placeholder renders to a neutral fallback like
  `"our support line"` so the message never shows a literal `{support_phone}`.

Helpers:

- `effective_welcome_settings(settings_row) -> dict` — returns resolved
  `enabled`, `subject`, `body`, `support_phone` applying defaults for null fields.
- `render_welcome_body(body_template, *, org, support_phone) -> str` — safe
  `{org}` / `{support_phone}` substitution that tolerates missing/extra braces
  (no `KeyError`/`IndexError`; unknown placeholders left intact).

Main entry:

- `async def queue_reseller_welcome(db, reseller) -> list[int]`
  1. Load `MessagingSettings(1)`. Resolve effective welcome settings.
  2. If welcome disabled → return `[]` (no rows).
  3. Resolve inbox sender id: `reseller.created_by` if it references an ADMIN,
     else the lowest-id ADMIN user. If no admin exists → skip the inbox row.
  4. Always add a `ResellerInboxMessage(recipient_user_id=reseller.id,
     sender_user_id=<admin>, subject, body, sent_sms=<phone present?>)` when an
     admin sender was resolved.
  5. If `reseller.support_phone` is present **and** `messaging.enabled` is true →
     add `SmsMessage(user_id=reseller.id, recipient_phone=phone, body,
     segments=count_segments(body), credits_charged=segments,
     kind=ADMIN_TO_RESELLER, category='reseller_welcome',
     status=QUEUED)`. **No credit deduction** (onboarding is free).
  6. `await db.flush()`; return the list of created `SmsMessage` ids.

  This function does **DB work only** — no network/provider I/O. It does **not**
  commit; the caller owns the transaction boundary. (Database Session Discipline.)

## Backend — Registration Hook (`app/api/auth_routes.py`)

- Add `background: BackgroundTasks` parameter to `register_user_api`.
- In the existing `role_enum == UserRole.RESELLER` branch, after `create_user`
  (which has already committed), add a **non-fatal** block (mirrors the existing
  lead-link try/except):
  - `ids = await queue_reseller_welcome(db, user)`
  - resolve `sender_id` via `resolve_sender_id(settings_row.sender_id)`
  - `await db.commit()`
  - if `ids`: `background.add_task(sms_dispatch.dispatch_admin_sms_messages,
    ids, sender_id)`
- Any exception in this block is logged and rolled back; it must **never** fail
  registration. Provider I/O happens only later inside
  `dispatch_admin_sms_messages`, with no DB session held — satisfies Database
  Session Discipline.

## Backend — Admin API (`app/api/admin_messaging_routes.py`)

- Extend `SettingsIn` with `welcome_enabled`, `welcome_subject`,
  `welcome_message_body`, `welcome_support_phone` (all optional).
- `GET /api/admin/messaging/settings` returns the new fields using the
  **effective** resolver (never null for subject/body), so the frontend pre-fills
  with defaults. Also return `welcome_support_phone` (may be null) and
  `welcome_enabled`.
- `PUT /api/admin/messaging/settings` persists the new fields. Empty string for a
  text field is stored as `NULL` (→ falls back to default = "reset to default").
- `GET /api/admin/messaging/sms`: include `category` in each message dict and
  accept an optional `category` query param to filter (e.g.
  `?category=reseller_welcome`). Welcome rows already match the existing
  `kind=ADMIN_TO_RESELLER` filter.

## Frontend (`isp-billing-admin`, separate worktree)

Files: `app/messaging/MessagingIsland.tsx`, `app/messaging/page.tsx`,
`app/lib/api.ts` (+ types).

- **Messaging settings form**: add controls for the welcome toggle, subject,
  body (textarea), and support phone. Pre-fill all fields from the GET settings
  response (defaults appear on first load). Show a small hint listing the
  `{org}` and `{support_phone}` placeholders. Save via the existing PUT.
- **SMS history**: render a "Welcome" badge when
  `category === 'reseller_welcome'`, and add a filter (chip / dropdown) to show
  only welcome messages.

Coordination risk: an in-progress "messaging-rebuild" exists in sibling
worktrees. Target the **canonical** (non-worktree) files in the admin repo and
note a possible rebase.

## Edge Cases

- Welcome disabled → no rows, no-op.
- No phone on file → inbox only; SMS skipped (logged). **Known gap**: such a
  reseller has no row in the *SMS* history (the chosen admin surface); the inbox
  message still records the welcome.
- Messaging globally disabled (`MessagingSettings.enabled == false`) → SMS row
  not created (so nothing is stuck queued); inbox still sent.
- `SMS_DISPATCH_ENABLED == false` → SMS rows left QUEUED by the dispatcher (its
  existing behavior); inbox unaffected.
- No admin user to use as sender → skip inbox row; SMS still sent if eligible.
- Sent once per signup (registration happens once per email; no extra dedup).

## Testing

Backend — new `tests/test_reseller_welcome.py`:

- enabled + phone → both `ResellerInboxMessage` and `SmsMessage` rows created;
  SMS has `kind=ADMIN_TO_RESELLER`, `category='reseller_welcome'`, `status=QUEUED`.
- disabled → no rows.
- no phone → inbox row only, no SMS row.
- `render_welcome_body` substitutes `{org}` / `{support_phone}` and tolerates a
  missing support phone (neutral fallback, no literal placeholder leak).
- `effective_welcome_settings` returns defaults when columns are null.
- registration endpoint: reseller signup creates welcome rows and schedules the
  dispatch background task; a forced messaging error does **not** fail signup.

Also extend `tests/test_admin_messaging_routes.py` for the new settings fields and
the `category` field/filter in `list_admin_sms`.

Frontend — `npm run build` in `isp-billing-admin`; optionally extend the messaging
e2e to assert the welcome badge + settings fields.

## Database Session Discipline Summary

All welcome DB work runs in short DB sections; the provider send happens only in
the existing background dispatcher with no DB session held. The registration
handler commits welcome rows before scheduling the background dispatch.

## Worktrees (standing user rule)

- Backend changes in `isp-billing` worktree `worktree-reseller-welcome-message`.
- Frontend changes in a **separate** `isp-billing-admin` worktree — never shared.
