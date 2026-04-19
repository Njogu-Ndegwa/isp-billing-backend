# Lead Backfill API — Frontend Contract

Classify every existing reseller user as a lead in the pipeline. Safe to call repeatedly — users already linked to a lead are skipped (no duplicates).

**Base URL:** Your API root (e.g. `https://yourdomain.com`)

---

## Authentication

All endpoints require an admin JWT:

```
Authorization: Bearer <admin_token>
```

Non-admin callers receive `403 Admin access required`.

---

## 1. Preview Backfill (Dry Run)

Returns the full classification plan without writing anything. Use this to show the user what will happen before they confirm.

### Request

```
POST /api/leads/backfill
Content-Type: application/json
```

**Body:**

```json
{
  "since": null,
  "dry_run": true
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `since` | string \| null | No | `null` | `"YYYY-MM-DD"` cutoff. Only include users created on/after this date. Pass `null` or `"all"` for no cutoff. |
| `dry_run` | bool | No | `false` | `true` = preview only, no writes. |

An empty body `{}` is valid — defaults apply.

### Response `200`

```json
{
  "since": null,
  "dry_run": true,
  "admin_owner_id": 1,
  "admin_owner_email": "admin@example.com",
  "source_id": 7,
  "source_name": "Website",
  "candidates": 23,
  "leads_created": 0,
  "stage_counts": {
    "paying": 12,
    "churned": 2,
    "installation_help": 3,
    "signed_up": 6
  },
  "items": [
    {
      "user_id": 15,
      "email": "john@example.com",
      "name": "John's ISP",
      "stage": "paying",
      "reason": "subscription.status=active, has completed payments",
      "signup_date": "2026-02-14",
      "lead_id": null
    }
  ],
  "message": "Dry run — 23 reseller(s) would be backfilled."
}
```

---

## 2. Run Backfill (Write)

Identical endpoint, `dry_run: false` (or omitted).

### Request

```
POST /api/leads/backfill
Content-Type: application/json
```

**Body:**

```json
{
  "since": "2026-01-01",
  "dry_run": false
}
```

Same fields as section 1.

### Response `200`

```json
{
  "since": "2026-01-01",
  "dry_run": false,
  "admin_owner_id": 1,
  "admin_owner_email": "admin@example.com",
  "source_id": 7,
  "source_name": "Website",
  "candidates": 23,
  "leads_created": 23,
  "stage_counts": {
    "paying": 12,
    "churned": 2,
    "installation_help": 3,
    "signed_up": 6
  },
  "items": [
    {
      "user_id": 15,
      "email": "john@example.com",
      "name": "John's ISP",
      "stage": "paying",
      "reason": "subscription.status=active, has completed payments",
      "signup_date": "2026-02-14",
      "lead_id": 42
    }
  ],
  "message": "Backfill complete — 23 lead(s) created."
}
```

---

## 3. Response Field Reference

### Top-level

| Field | Type | Description |
|-------|------|-------------|
| `since` | string \| null | Echoed `since` value from the request (`"YYYY-MM-DD"` or `null`). |
| `dry_run` | bool | Echoed `dry_run` value. |
| `admin_owner_id` | int \| null | ID of the admin that owns the created leads. `null` if no admin exists. |
| `admin_owner_email` | string \| null | Email of the admin owner. `null` if no admin exists. |
| `source_id` | int \| null | Lead source ID used (`"Website"` preferred). `null` if no source available. |
| `source_name` | string \| null | Lead source name used. |
| `candidates` | int | Number of resellers eligible for backfill (not yet linked to a lead). |
| `leads_created` | int | Number of leads actually written. `0` when `dry_run` is `true`. Equals `candidates` on a successful write. |
| `stage_counts` | object | Map of stage value → count of users landing in it. Keys present only for stages that appear. |
| `items` | array | Per-user classification details. See `items[]` below. |
| `message` | string | Human-readable summary of the outcome. |

### `items[]`

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | int | ID of the reseller user. |
| `email` | string \| null | User email (may be `null`). |
| `name` | string | Display name. Falls back to organization name, then email local part, then `user-{id}`. |
| `stage` | string | Assigned stage (see section 4). |
| `reason` | string | Why that stage was chosen. |
| `signup_date` | string \| null | `"YYYY-MM-DD"` date the user registered. |
| `lead_id` | int \| null | New lead's ID. `null` when `dry_run` is `true`. |

---

## 4. Stage Classification Rules

Stages are assigned in priority order (first match wins):

| Stage Value | Condition |
|-------------|-----------|
| `churned` | Subscription status is `suspended` or `inactive` **and** user has ≥1 completed payment ever. |
| `paying` | Subscription status is `active`, **or** user has ≥1 completed payment and is not suspended/inactive. |
| `installation_help` | User has ≥1 router or ≥1 customer record, with no paying signal. |
| `signed_up` | Registered, none of the above. |

These values match the stage values documented in `LEAD_PIPELINE_API.md` section "Pipeline Stages".

---

## 5. Deduplication Guarantee

A user is considered "already in the pipeline" if any `Lead` row has `converted_user_id == user.id`. Such users are excluded from every backfill run. Consequences:

- Calling the endpoint N times is equivalent to calling it once.
- A user manually converted via `POST /api/leads/{lead_id}/convert` (section 6.1 of `LEAD_PIPELINE_API.md`) is also skipped.
- A user whose lead was auto-created via self-signup (section 7.1 of `LEAD_PIPELINE_API.md`) is also skipped.

`candidates: 0` means every reseller is already represented in the pipeline.

---

## 6. Errors

| Status | Body | When |
|--------|------|------|
| `400` | `{"detail": "`since` must be in YYYY-MM-DD format, or 'all' / null for no cutoff"}` | `since` is a non-empty string that does not parse as `YYYY-MM-DD` and is not `"all"`. |
| `401` | `{"detail": "..."}` | Missing/invalid/expired token. |
| `403` | `{"detail": "Admin access required"}` | Caller is not an admin. |
| `500` | `{"detail": "Backfill failed: <error>"}` | Unexpected server error. The transaction is rolled back; no partial writes. Safe to retry. |

A `200` response with `"admin_owner_id": null` and `"candidates": 0` is returned when no admin user exists in the system. No leads are created in that case and `message` will read: `"No admin user found; cannot backfill (lead owner required)."`

---

## 7. Request/Response Cheatsheet

| Goal | Request Body |
|------|--------------|
| Preview everything | `{"dry_run": true}` |
| Preview users signed up since a date | `{"since": "2026-01-01", "dry_run": true}` |
| Run for all historical users | `{}` |
| Run for users signed up since a date | `{"since": "2026-01-01"}` |

---

## 8. Endpoint Quick Reference

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 1 | `POST` | `/api/leads/backfill` | Classify all un-tracked resellers as leads (supports `dry_run`). |

---

## 9. Related Endpoints

After a backfill run, the standard lead pipeline endpoints work as-is on the newly created leads. See `LEAD_PIPELINE_API.md`:

| Purpose | Endpoint |
|---------|----------|
| List leads filtered by stage | `GET /api/leads?stage={stage}` |
| Stage counts for Kanban | `GET /api/leads/pipeline/summary` |
| Full analytics + advice | `GET /api/leads/pipeline/stats` |
| Lead detail + timeline | `GET /api/leads/{lead_id}` |
| Change stage | `PATCH /api/leads/{lead_id}/stage` |
| Log activity | `POST /api/leads/{lead_id}/activities` |
| Schedule follow-up | `POST /api/leads/{lead_id}/followups` |
