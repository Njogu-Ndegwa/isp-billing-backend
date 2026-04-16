# Lead Pipeline / CRM API

Track potential reseller customers from first social media contact through to paying member. Admin-only feature.

## Authentication

All endpoints require admin JWT in the `Authorization: Bearer <token>` header.

## Pipeline Stages

| Stage | Value | Description |
|-------|-------|-------------|
| New Lead | `new_lead` | Just captured (DM, comment, referral) |
| Contacted | `contacted` | You reached out or replied |
| Talking | `talking` | Active conversation happening |
| Installation Help | `installation_help` | Helping them set up |
| Signed Up | `signed_up` | Registered but not yet paying |
| Paying | `paying` | Active paying reseller |
| Churned | `churned` | Was paying, stopped |
| Lost | `lost` | Dropped off before becoming a customer |

## Activity Types

`note`, `call`, `dm`, `email`, `meeting`, `stage_change`, `followup_completed`, `other`

---

## Lead Sources

Managed list of channels where leads come from. Pre-seeded with: Instagram, TikTok, WhatsApp, Referral, Phone Call, Walk-in, Website, Facebook, Other.

### GET `/api/leads/sources`

List all lead sources (for populating dropdowns).

**Query Parameters:**
- `active_only` (bool, default `true`) — only return active sources

**Response:**
```json
[
  {
    "id": 1,
    "name": "Instagram",
    "description": "Leads from Instagram DMs and comments",
    "is_active": true,
    "created_at": "2026-04-15T12:00:00"
  }
]
```

### POST `/api/leads/sources`

Add a new lead source.

**Request Body:**
```json
{
  "name": "YouTube",
  "description": "Leads from YouTube video comments"
}
```

### PUT `/api/leads/sources/{source_id}`

Update a source name or description.

**Request Body:**
```json
{
  "name": "Instagram DMs",
  "description": "Updated description",
  "is_active": true
}
```

### DELETE `/api/leads/sources/{source_id}`

Soft-delete (deactivate) a source. Existing leads keep their source reference.

---

## Leads

### POST `/api/leads`

Create a new lead.

**Request Body:**
```json
{
  "name": "John Doe",
  "phone": "0712345678",
  "email": "john@example.com",
  "social_platform": "tiktok",
  "social_handle": "@johndoe_isp",
  "source_id": 2,
  "source_detail": "Commented on router setup video",
  "stage": "new_lead",
  "notes": "Interested in becoming a reseller in Nairobi",
  "next_followup_at": "2026-04-18T10:00:00"
}
```

**Required fields:** `name`

**Response:** Full lead object (see GET detail below).

### GET `/api/leads`

List leads with filtering, search, and pagination.

**Query Parameters:**
- `stage` (string) — filter by pipeline stage (e.g., `talking`, `new_lead`)
- `source_id` (int) — filter by lead source
- `search` (string) — search in name, phone, email, social handle
- `page` (int, default 1) — page number
- `per_page` (int, default 50, max 200) — results per page

**Response:**
```json
{
  "total": 42,
  "page": 1,
  "per_page": 50,
  "leads": [
    {
      "id": 1,
      "name": "John Doe",
      "phone": "0712345678",
      "email": "john@example.com",
      "social_platform": "tiktok",
      "social_handle": "@johndoe_isp",
      "source": "TikTok",
      "source_id": 2,
      "stage": "talking",
      "stage_changed_at": "2026-04-15T14:30:00",
      "next_followup_at": "2026-04-18T10:00:00",
      "created_at": "2026-04-14T09:00:00",
      "updated_at": "2026-04-15T14:30:00"
    }
  ]
}
```

### GET `/api/leads/{lead_id}`

Get full lead detail including activities timeline and follow-ups.

**Response:**
```json
{
  "id": 1,
  "name": "John Doe",
  "phone": "0712345678",
  "email": "john@example.com",
  "social_platform": "tiktok",
  "social_handle": "@johndoe_isp",
  "source": "TikTok",
  "source_id": 2,
  "source_detail": "Commented on router setup video",
  "stage": "talking",
  "stage_changed_at": "2026-04-15T14:30:00",
  "next_followup_at": "2026-04-18T10:00:00",
  "notes": "Interested in becoming a reseller in Nairobi",
  "converted_user_id": null,
  "lost_reason": null,
  "created_at": "2026-04-14T09:00:00",
  "updated_at": "2026-04-15T14:30:00",
  "activities": [
    {
      "id": 2,
      "activity_type": "stage_change",
      "description": "Had first call, very interested",
      "old_stage": "contacted",
      "new_stage": "talking",
      "created_at": "2026-04-15T14:30:00"
    },
    {
      "id": 1,
      "activity_type": "stage_change",
      "description": "Lead created",
      "old_stage": null,
      "new_stage": "new_lead",
      "created_at": "2026-04-14T09:00:00"
    }
  ],
  "follow_ups": [
    {
      "id": 1,
      "title": "Call back about router installation",
      "due_at": "2026-04-18T10:00:00",
      "is_completed": false,
      "completed_at": null,
      "created_at": "2026-04-15T14:35:00"
    }
  ]
}
```

### PUT `/api/leads/{lead_id}`

Update lead information (not the stage — use PATCH stage endpoint for that).

**Request Body:** Same fields as create, all optional.

### PATCH `/api/leads/{lead_id}/stage`

Move a lead to a new pipeline stage. Automatically logs a stage_change activity.

**Request Body:**
```json
{
  "stage": "talking",
  "note": "Had first call, very interested",
  "lost_reason": null
}
```

- `stage` (required) — one of the pipeline stage values
- `note` (optional) — description logged in the activity timeline
- `lost_reason` (optional) — reason for loss/churn (only used when stage is `lost` or `churned`)

### DELETE `/api/leads/{lead_id}`

Permanently delete a lead and all its activities/follow-ups.

---

## Pipeline Views

### GET `/api/leads/pipeline/summary`

Counts per stage — use this for Kanban board columns.

**Response:**
```json
{
  "stages": {
    "new_lead": 5,
    "contacted": 3,
    "talking": 8,
    "installation_help": 2,
    "signed_up": 4,
    "paying": 12,
    "churned": 1,
    "lost": 6
  },
  "total": 41
}
```

### GET `/api/leads/pipeline/stats`

Comprehensive analytics: conversion funnel with drop-off percentages, source performance, stale lead detection, and actionable advice.

**Response:**
```json
{
  "total_leads": 41,
  "active_pipeline": 18,
  "conversion_rate": 39.0,
  "loss_rate": 17.1,
  "by_stage": {
    "new_lead": 5,
    "contacted": 3,
    "talking": 8,
    "installation_help": 2,
    "signed_up": 4,
    "paying": 12,
    "churned": 1,
    "lost": 6
  },
  "by_source": {
    "TikTok": {"total": 12, "converted": 5, "conversion_rate": 41.7},
    "Instagram": {"total": 15, "converted": 4, "conversion_rate": 26.7},
    "Referral": {"total": 8, "converted": 6, "conversion_rate": 75.0},
    "WhatsApp": {"total": 6, "converted": 1, "conversion_rate": 16.7}
  },
  "funnel": [
    {"stage": "new_lead", "reached": 41, "percent_of_total": 100.0, "dropped_off": 0, "drop_off_percent": 0},
    {"stage": "contacted", "reached": 36, "percent_of_total": 87.8, "dropped_off": 5, "drop_off_percent": 12.2},
    {"stage": "talking", "reached": 30, "percent_of_total": 73.2, "dropped_off": 6, "drop_off_percent": 16.7},
    {"stage": "installation_help", "reached": 22, "percent_of_total": 53.7, "dropped_off": 8, "drop_off_percent": 26.7},
    {"stage": "signed_up", "reached": 17, "percent_of_total": 41.5, "dropped_off": 5, "drop_off_percent": 22.7},
    {"stage": "paying", "reached": 13, "percent_of_total": 31.7, "dropped_off": 4, "drop_off_percent": 23.5}
  ],
  "avg_days_in_stage": {
    "new_lead": 2.3,
    "contacted": 4.1,
    "talking": 8.5,
    "installation_help": 3.2,
    "signed_up": 6.0
  },
  "health": {
    "stale_leads": 4,
    "no_followup_scheduled": 7,
    "overdue_followups": 2,
    "stale_lead_previews": [
      {"id": 12, "name": "Jane Doe", "stage": "talking", "days_since_update": 14, "phone": "0712345678"}
    ]
  },
  "advice": [
    {
      "priority": "high",
      "category": "follow_up",
      "title": "4 lead(s) have gone cold",
      "detail": "You have 4 leads in active stages with no update for 7+ days..."
    },
    {
      "priority": "high",
      "category": "funnel",
      "title": "Biggest drop-off: 26.7% lost before \"Installation Help\"",
      "detail": "26.7% of leads in conversation don't move to installation..."
    },
    {
      "priority": "medium",
      "category": "source",
      "title": "Best source: Referral (75.0% conversion)",
      "detail": "\"Referral\" converts at 75.0% (6 of 8 leads)..."
    }
  ]
}
```

**Key sections explained:**

| Section | What it tells you |
|---------|-------------------|
| `funnel` | How many leads reached each stage, with drop-off between stages |
| `by_source` | Which channels produce the most leads AND which actually convert to paying |
| `avg_days_in_stage` | How long leads sit in each stage (helps spot bottlenecks) |
| `health` | Stale leads, missing follow-ups, overdue reminders |
| `advice` | Prioritized, actionable tips based on your actual data |

**Advice priorities:** `high` (act today), `medium` (address this week), `low` (good to know)

**Advice categories:** `follow_up`, `funnel`, `speed`, `source`, `action`, `general`

---

## Activities (Timeline)

### POST `/api/leads/{lead_id}/activities`

Log an interaction with a lead.

**Request Body:**
```json
{
  "activity_type": "call",
  "description": "Called to discuss pricing, agreed on Silver plan"
}
```

Valid `activity_type` values: `note`, `call`, `dm`, `email`, `meeting`, `other`

(Stage changes and follow-up completions are logged automatically.)

### GET `/api/leads/{lead_id}/activities`

List all activities for a lead, newest first.

---

## Follow-ups

### POST `/api/leads/{lead_id}/followups`

Schedule a follow-up reminder.

**Request Body:**
```json
{
  "title": "Call back about router installation",
  "due_at": "2026-04-18T10:00:00"
}
```

### GET `/api/leads/followups/upcoming`

Get all upcoming (incomplete) follow-ups across all leads.

**Query Parameters:**
- `days` (int, default 7, max 90) — look-ahead window

**Response:**
```json
{
  "followups": [
    {
      "id": 1,
      "title": "Call back about router installation",
      "due_at": "2026-04-18T10:00:00",
      "is_overdue": false,
      "lead_id": 1,
      "lead_name": "John Doe",
      "lead_stage": "talking",
      "created_at": "2026-04-15T14:35:00"
    }
  ],
  "total": 1
}
```

### PATCH `/api/leads/followups/{followup_id}/complete`

Mark a follow-up as done. Automatically logs a `followup_completed` activity and updates the lead's `next_followup_at` to the next pending follow-up (if any).

---

## Conversion

### POST `/api/leads/{lead_id}/convert`

Convert a lead into a reseller account. Creates a new User with `role=reseller`, links it to the lead, and moves the stage to `signed_up`.

**Request Body:**
```json
{
  "email": "john@example.com",
  "organization_name": "John's ISP",
  "password": "securepassword123",
  "business_name": "John Internet Services",
  "support_phone": "0712345678"
}
```

**Required:** `email`, `organization_name`, `password`

**Response:**
```json
{
  "detail": "Lead converted to reseller",
  "lead_id": 1,
  "new_user_id": 15,
  "new_user_email": "john@example.com",
  "new_stage": "signed_up"
}
```

---

## Automatic Stage Progression

Once a lead is linked to a reseller account (either via the `/convert` endpoint or auto-linking on registration), the lead stage advances automatically based on real system events:

```
Lead created ──(manual)──> ... ──(manual/auto)──> signed_up
                                                      │
                                  Subscription activated (payment)
                                                      │
                                                      ▼
                                                   paying
                                                      │
                                  Subscription suspended/deactivated
                                                      │
                                                      ▼
                                                   churned
                                                      │
                                  Subscription reactivated (new payment)
                                                      │
                                                      ▼
                                                   paying (again)
```

### Auto-linking on registration

When a new reseller signs up via `POST /api/users/register`, the system checks if their email or phone matches an existing lead. If found:
- The lead's `converted_user_id` is set to the new user ID
- The lead stage moves to `signed_up`
- A `stage_change` activity is logged automatically

This means: if you add a lead with their email, and that person later signs up on their own, the link happens automatically.

### Auto-advance to paying

When `activate_subscription()` is called (reseller pays), the system checks if the user has a linked lead and moves it to `paying`. This is logged in the activity timeline.

### Auto-regress to churned

When `deactivate_subscription()` is called (subscription suspended due to non-payment), the system checks for a linked lead and moves it to `churned`.

### What stays manual

The early pipeline stages (new_lead → contacted → talking → installation_help) are always manual — these represent your personal conversations and outreach that only you know about.

---

## Frontend Integration Notes

### Kanban Board
1. Call `GET /api/leads/pipeline/summary` to get column counts
2. Call `GET /api/leads?stage=<stage>` to load leads per column
3. On drag-drop between columns, call `PATCH /api/leads/{id}/stage`

### Lead Detail Page
1. Call `GET /api/leads/{id}` — returns activities + follow-ups in one call
2. Show timeline from `activities` array (newest first)
3. Show pending follow-ups from `follow_ups` array

### Dashboard Widget
1. Call `GET /api/leads/followups/upcoming?days=7` for the follow-up reminder list
2. Call `GET /api/leads/pipeline/stats` for the analytics card (conversion rate, leads by source chart)

### Source Dropdown
1. Call `GET /api/leads/sources` on form load to populate the "Where did this lead come from?" dropdown
