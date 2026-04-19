# Lead Pipeline / CRM API

Track potential reseller customers from first social media contact through to paying member. Admin-only feature.

**Base URL:** Your API root (e.g. `https://yourdomain.com`)

## Authentication

All endpoints require admin JWT in the `Authorization` header:

```
Authorization: Bearer <admin_token>
```

Non-admin users receive `403 Admin access required`.

---

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

| Value | Description |
|-------|-------------|
| `note` | General note |
| `call` | Phone call |
| `dm` | Direct message (social media) |
| `email` | Email sent/received |
| `meeting` | In-person or virtual meeting |
| `stage_change` | Auto-logged when stage changes |
| `followup_completed` | Auto-logged when a follow-up is marked done |
| `other` | Anything else |

---

## 1. Lead Sources

Managed list of channels where leads come from. Pre-seeded defaults: Instagram, TikTok, WhatsApp, Referral, Phone Call, Walk-in, Website, Facebook, Other.

---

### 1.1 List Sources

```
GET /api/leads/sources?active_only=true
```

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `active_only` | bool | `true` | Only return active sources |

**Response `200`:**

```json
[
  {
    "id": 1,
    "name": "Instagram",
    "description": "Leads from Instagram DMs and comments",
    "is_active": true,
    "created_at": "2026-04-15T12:00:00"
  },
  {
    "id": 2,
    "name": "TikTok",
    "description": "Leads from TikTok videos and comments",
    "is_active": true,
    "created_at": "2026-04-15T12:00:00"
  }
]
```

---

### 1.2 Create Source

```
POST /api/leads/sources
```

**Request Body:**

```json
{
  "name": "YouTube",
  "description": "Leads from YouTube video comments"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique source name |
| `description` | string | No | What this source means |

**Response `201`:**

```json
{
  "id": 10,
  "name": "YouTube",
  "description": "Leads from YouTube video comments",
  "is_active": true,
  "created_at": "2026-04-15T16:00:00"
}
```

**Error `409`:** `"A source with this name already exists"`

---

### 1.3 Update Source

```
PUT /api/leads/sources/{source_id}
```

**Request Body (all fields optional):**

```json
{
  "name": "Instagram DMs",
  "description": "Updated description",
  "is_active": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | New name (checked for uniqueness) |
| `description` | string | No | New description |
| `is_active` | bool | No | Enable/disable this source |

**Response `200`:**

```json
{
  "id": 1,
  "name": "Instagram DMs",
  "description": "Updated description",
  "is_active": true,
  "created_at": "2026-04-15T12:00:00"
}
```

**Error `404`:** `"Source not found"`
**Error `409`:** `"A source with this name already exists"`

---

### 1.4 Delete Source (soft-delete)

```
DELETE /api/leads/sources/{source_id}
```

Sets `is_active = false`. Existing leads keep their source reference.

**Response `200`:**

```json
{
  "detail": "Source deactivated",
  "id": 1
}
```

**Error `404`:** `"Source not found"`

---

## 2. Leads — CRUD

---

### 2.1 Create Lead

```
POST /api/leads
```

**Request Body:**

```json
{
  "name": "John Doe",
  "phone": "+254712345678",
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

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Lead's name or business name |
| `phone` | string | No | Phone number |
| `email` | string | No | Email address |
| `social_platform` | string | No | e.g. `tiktok`, `instagram`, `facebook` |
| `social_handle` | string | No | e.g. `@johndoe_isp` |
| `source_id` | int | No | ID from lead sources list |
| `source_detail` | string | No | Extra context (e.g. which post they commented on) |
| `stage` | string | No | Starting stage (default: `new_lead`) |
| `notes` | string | No | Free-form notes |
| `next_followup_at` | datetime | No | When to follow up next |

**Response `201`:**

```json
{
  "id": 1,
  "name": "John Doe",
  "phone": "+254712345678",
  "email": "john@example.com",
  "social_platform": "tiktok",
  "social_handle": "@johndoe_isp",
  "source": "TikTok",
  "source_id": 2,
  "source_detail": "Commented on router setup video",
  "stage": "new_lead",
  "stage_changed_at": "2026-04-15T16:00:00",
  "next_followup_at": "2026-04-18T10:00:00",
  "notes": "Interested in becoming a reseller in Nairobi",
  "converted_user_id": null,
  "lost_reason": null,
  "created_at": "2026-04-15T16:00:00",
  "updated_at": "2026-04-15T16:00:00"
}
```

**Error `400`:** `"Invalid stage: xyz"` or `"Invalid source_id"`

---

### 2.2 List Leads

```
GET /api/leads?stage=talking&source_id=2&search=john&page=1&per_page=50
```

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `stage` | string | — | Filter by stage value |
| `source_id` | int | — | Filter by lead source |
| `search` | string | — | Search in name, phone, email, social handle |
| `page` | int | `1` | Page number (min 1) |
| `per_page` | int | `50` | Results per page (1–200) |

**Response `200`:**

```json
{
  "total": 42,
  "page": 1,
  "per_page": 50,
  "leads": [
    {
      "id": 1,
      "name": "John Doe",
      "phone": "+254712345678",
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

---

### 2.3 Get Lead Detail

```
GET /api/leads/{lead_id}
```

Returns full lead info including activities timeline and follow-ups.

**Response `200`:**

```json
{
  "id": 1,
  "name": "John Doe",
  "phone": "+254712345678",
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
      "id": 3,
      "activity_type": "call",
      "description": "Called to discuss pricing, agreed on Silver plan",
      "old_stage": null,
      "new_stage": null,
      "created_at": "2026-04-15T15:00:00"
    },
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

**Error `404`:** `"Lead not found"`

---

### 2.4 Update Lead

```
PUT /api/leads/{lead_id}
```

Update lead info. **Send a field as `null` to clear it. Omit a field to leave it unchanged.** Do NOT use this to change stages — use the stage endpoint (2.5) instead.

**Request Body (all fields optional):**

```json
{
  "name": "John Doe Updated",
  "phone": "+254700111222",
  "email": "newemail@example.com",
  "social_platform": "instagram",
  "social_handle": "@johndoe_new",
  "source_id": 1,
  "source_detail": "Switched from TikTok to Instagram",
  "notes": "Updated notes here",
  "next_followup_at": "2026-04-20T10:00:00"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Updated name |
| `phone` | string | No | Updated phone (send `null` to clear) |
| `email` | string | No | Updated email (send `null` to clear) |
| `social_platform` | string | No | Updated platform (send `null` to clear) |
| `social_handle` | string | No | Updated handle (send `null` to clear) |
| `source_id` | int | No | Updated source (send `null` to clear) |
| `source_detail` | string | No | Updated source detail (send `null` to clear) |
| `notes` | string | No | Updated notes (send `null` to clear) |
| `next_followup_at` | datetime | No | Updated follow-up date (send `null` to clear) |

**Response `200`:** Full lead object (same shape as 2.3, without `activities` and `follow_ups`).

**Error `404`:** `"Lead not found"`
**Error `400`:** `"Invalid source_id"`

---

### 2.5 Change Lead Stage

```
PATCH /api/leads/{lead_id}/stage
```

Move a lead to a new pipeline stage. Automatically logs a `stage_change` activity.

**Request Body:**

```json
{
  "stage": "talking",
  "note": "Had first call, very interested",
  "lost_reason": null
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `stage` | string | **Yes** | Target stage value |
| `note` | string | No | Description logged in activity timeline |
| `lost_reason` | string | No | Why the lead was lost/churned (only for `lost` or `churned`) |

**Response `200`:** Full lead object (same shape as 2.3, without `activities` and `follow_ups`).

**Error `400`:** `"Invalid stage: xyz"` or `"Lead is already in this stage"`
**Error `404`:** `"Lead not found"`

---

### 2.6 Delete Lead

```
DELETE /api/leads/{lead_id}
```

Permanently deletes a lead and all its activities and follow-ups (cascade).

**Response `200`:**

```json
{
  "detail": "Lead deleted",
  "id": 1
}
```

**Error `404`:** `"Lead not found"`

---

## 3. Pipeline & Analytics

---

### 3.1 Pipeline Summary

```
GET /api/leads/pipeline/summary
```

Counts per stage. Use this for Kanban board column headers.

**Response `200`:**

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

---

### 3.2 Pipeline Stats (Full Analytics)

```
GET /api/leads/pipeline/stats
```

Comprehensive analytics: conversion funnel, source performance, stale leads, and actionable advice.

**Response `200`:**

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
    "TikTok": {
      "total": 12,
      "converted": 5,
      "conversion_rate": 41.7
    },
    "Instagram": {
      "total": 15,
      "converted": 4,
      "conversion_rate": 26.7
    },
    "Referral": {
      "total": 8,
      "converted": 6,
      "conversion_rate": 75.0
    },
    "WhatsApp": {
      "total": 6,
      "converted": 1,
      "conversion_rate": 16.7
    }
  },
  "funnel": [
    {
      "stage": "new_lead",
      "reached": 41,
      "percent_of_total": 100.0,
      "still_in_stage": 5,
      "dropped_off": 0,
      "drop_off_percent": 0
    },
    {
      "stage": "contacted",
      "reached": 35,
      "percent_of_total": 85.4,
      "still_in_stage": 4,
      "dropped_off": 1,
      "drop_off_percent": 2.4
    },
    {
      "stage": "talking",
      "reached": 30,
      "percent_of_total": 73.2,
      "still_in_stage": 6,
      "dropped_off": 1,
      "drop_off_percent": 2.9
    },
    {
      "stage": "installation_help",
      "reached": 22,
      "percent_of_total": 53.7,
      "still_in_stage": 3,
      "dropped_off": 2,
      "drop_off_percent": 6.7
    },
    {
      "stage": "signed_up",
      "reached": 17,
      "percent_of_total": 41.5,
      "still_in_stage": 4,
      "dropped_off": 2,
      "drop_off_percent": 9.1
    },
    {
      "stage": "paying",
      "reached": 13,
      "percent_of_total": 31.7,
      "still_in_stage": 13,
      "dropped_off": 1,
      "drop_off_percent": 5.9
    }
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
      {
        "id": 12,
        "name": "Jane Doe",
        "stage": "talking",
        "days_since_update": 14,
        "phone": "+254712345678"
      },
      {
        "id": 8,
        "name": "Mike Reseller",
        "stage": "new_lead",
        "days_since_update": 10,
        "phone": "+254700111222"
      }
    ]
  },
  "advice": [
    {
      "priority": "high",
      "category": "follow_up",
      "title": "4 lead(s) have gone cold",
      "detail": "You have 4 leads in active stages with no update for 7+ days. These are at high risk of being lost. Reach out today."
    },
    {
      "priority": "high",
      "category": "funnel",
      "title": "Biggest drop-off: 29.6% lost before \"Installation Help\"",
      "detail": "29.6% of leads in conversation don't move to installation. They may be unsure about the technical side. Create a simple guide or short video showing how easy setup is."
    },
    {
      "priority": "medium",
      "category": "follow_up",
      "title": "7 active lead(s) with no follow-up scheduled",
      "detail": "Every active lead should have a next step. Schedule follow-ups so nothing slips through the cracks."
    },
    {
      "priority": "low",
      "category": "source",
      "title": "Best source: Referral (75.0% conversion)",
      "detail": "\"Referral\" converts at 75.0% (6 of 8 leads). Consider doubling down on this channel."
    }
  ]
}
```

**Field reference:**

| Field | Description |
|-------|-------------|
| `total_leads` | Total leads in system |
| `active_pipeline` | Leads in stages: new_lead + contacted + talking + installation_help |
| `conversion_rate` | % of leads that reached signed_up or paying |
| `loss_rate` | % of leads that are lost or churned |
| `by_stage` | Count of leads in each stage |
| `by_source` | Per-source total leads, conversions, and conversion rate |
| `funnel` | Per-stage view of how many leads have actually been recorded at each stage, plus in-progress counts and real drop-off between stages |
| `funnel[].reached` | Distinct leads with this stage in their recorded history — i.e. it appears as the `old_stage` or `new_stage` of a `stage_change` activity, OR it is their current stage. **No progression is inferred:** a backfilled lead inserted directly at `paying` will count toward `paying` only, not toward earlier stages it never visited in this system. `churned` leads count toward `paying`. |
| `funnel[].still_in_stage` | Leads currently sitting in this stage. These are **in-progress**, not drop-offs. |
| `funnel[].dropped_off` | Leads that have been marked `lost` whose furthest recorded stage is the *previous* funnel stage — they reached it and then abandoned the pipeline. |
| `funnel[].drop_off_percent` | `dropped_off / reached[previous] * 100` — genuine loss rate between stages. Will be `0` when no leads have been marked `lost`. |
| `avg_days_in_stage` | Average days leads sit in each active stage |
| `health.stale_leads` | Leads in active stages with no update for 7+ days |
| `health.no_followup_scheduled` | Active leads with no next follow-up |
| `health.overdue_followups` | Follow-ups past their due date |
| `health.stale_lead_previews` | Top 20 stale leads with preview info |
| `advice` | Prioritized actionable tips based on your data |

**Advice priorities:** `high` (act today), `medium` (this week), `low` (good to know)

**Advice categories:** `follow_up`, `funnel`, `speed`, `source`, `action`, `general`

---

## 4. Activities (Timeline)

---

### 4.1 Log Activity

```
POST /api/leads/{lead_id}/activities
```

Log an interaction with a lead.

**Request Body:**

```json
{
  "activity_type": "call",
  "description": "Called to discuss pricing, agreed on Silver plan"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `activity_type` | string | **Yes** | One of: `note`, `call`, `dm`, `email`, `meeting`, `other` |
| `description` | string | No | What happened |

Note: `stage_change` and `followup_completed` are logged automatically by the system.

**Response `201`:**

```json
{
  "id": 5,
  "lead_id": 1,
  "activity_type": "call",
  "description": "Called to discuss pricing, agreed on Silver plan",
  "old_stage": null,
  "new_stage": null,
  "created_at": "2026-04-15T16:30:00"
}
```

**Error `400`:** `"Invalid activity_type: xyz"`
**Error `404`:** `"Lead not found"`

---

### 4.2 List Activities

```
GET /api/leads/{lead_id}/activities
```

List all activities for a lead, newest first.

**Response `200`:**

```json
{
  "activities": [
    {
      "id": 5,
      "activity_type": "call",
      "description": "Called to discuss pricing, agreed on Silver plan",
      "old_stage": null,
      "new_stage": null,
      "created_at": "2026-04-15T16:30:00"
    },
    {
      "id": 4,
      "activity_type": "followup_completed",
      "description": "Completed follow-up: Call back about pricing",
      "old_stage": null,
      "new_stage": null,
      "created_at": "2026-04-15T16:29:00"
    },
    {
      "id": 3,
      "activity_type": "stage_change",
      "description": "Had first call, very interested",
      "old_stage": "contacted",
      "new_stage": "talking",
      "created_at": "2026-04-15T14:30:00"
    },
    {
      "id": 2,
      "activity_type": "dm",
      "description": "Sent intro DM on TikTok",
      "old_stage": null,
      "new_stage": null,
      "created_at": "2026-04-14T12:00:00"
    },
    {
      "id": 1,
      "activity_type": "stage_change",
      "description": "Lead created",
      "old_stage": null,
      "new_stage": "new_lead",
      "created_at": "2026-04-14T09:00:00"
    }
  ]
}
```

**Error `404`:** `"Lead not found"`

---

## 5. Follow-ups (Reminders)

---

### 5.1 Schedule Follow-up

```
POST /api/leads/{lead_id}/followups
```

**Request Body:**

```json
{
  "title": "Call back about router installation",
  "due_at": "2026-04-18T10:00:00"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | string | **Yes** | What to do |
| `due_at` | datetime | **Yes** | When it's due (ISO 8601) |

Automatically updates the lead's `next_followup_at` if this is the earliest pending follow-up.

**Response `201`:**

```json
{
  "id": 3,
  "lead_id": 1,
  "title": "Call back about router installation",
  "due_at": "2026-04-18T10:00:00",
  "is_completed": false,
  "created_at": "2026-04-15T16:35:00"
}
```

**Error `404`:** `"Lead not found"`

---

### 5.2 List Upcoming Follow-ups

```
GET /api/leads/followups/upcoming?days=7
```

Lists all incomplete follow-ups across all your leads within the given time window, including overdue ones.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `days` | int | `7` | Look-ahead window (1–90) |

**Response `200`:**

```json
{
  "followups": [
    {
      "id": 2,
      "title": "Send pricing sheet",
      "due_at": "2026-04-14T09:00:00",
      "is_overdue": true,
      "lead_id": 5,
      "lead_name": "Mike Reseller",
      "lead_stage": "talking",
      "created_at": "2026-04-13T11:00:00"
    },
    {
      "id": 3,
      "title": "Call back about router installation",
      "due_at": "2026-04-18T10:00:00",
      "is_overdue": false,
      "lead_id": 1,
      "lead_name": "John Doe",
      "lead_stage": "talking",
      "created_at": "2026-04-15T16:35:00"
    }
  ],
  "total": 2
}
```

---

### 5.3 Complete Follow-up

```
PATCH /api/leads/followups/{followup_id}/complete
```

Marks a follow-up as done. Automatically:
- Logs a `followup_completed` activity on the lead
- Updates the lead's `next_followup_at` to the next pending follow-up (or `null` if none left)

**Request Body:** None required.

**Response `200`:**

```json
{
  "detail": "Follow-up completed",
  "id": 3
}
```

**Error `404`:** `"Follow-up not found"`

---

## 6. Conversion (Lead → Reseller Account)

---

### 6.1 Convert Lead

```
POST /api/leads/{lead_id}/convert
```

Creates a reseller user account directly from a lead, links it, and moves the stage to `signed_up`.

**Request Body:**

```json
{
  "email": "john@example.com",
  "organization_name": "John's ISP",
  "password": "securepassword123",
  "business_name": "John Internet Services",
  "support_phone": "+254712345678"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | **Yes** | Login email for the new reseller account |
| `organization_name` | string | **Yes** | Organization/company name |
| `password` | string | **Yes** | Account password |
| `business_name` | string | No | Display business name |
| `support_phone` | string | No | Support phone number |

**Response `200`:**

```json
{
  "detail": "Lead converted to reseller",
  "lead_id": 1,
  "new_user_id": 15,
  "new_user_email": "john@example.com",
  "new_stage": "signed_up"
}
```

**Error `400`:** `"Lead has already been converted"`
**Error `404`:** `"Lead not found"`
**Error `409`:** `"A user with this email already exists"`

---

## 7. Automatic Stage Progression

These happen without any frontend calls. They are documented here so you can explain the behavior to users or show appropriate UI indicators.

### 7.1 Self-signup auto-tracking

When a reseller registers via `POST /api/users/register`:

1. System checks if their email or phone matches an existing lead
2. **If a match is found:** lead is linked to the new user, stage moves to `signed_up`
3. **If no match is found:** a new lead is auto-created at `signed_up` stage with source "Website" and detail "Self-signup (no prior lead record)"

This means every reseller who signs up — from ads, website, referral link — automatically appears in your pipeline.

### 7.2 Auto-advance to paying

When a reseller's subscription is activated (they pay), the linked lead automatically moves to `paying`.

### 7.3 Auto-regress to churned

When a reseller's subscription is suspended or deactivated, the linked lead automatically moves to `churned`.

### 7.4 Auto-recover to paying

If a churned reseller reactivates their subscription, the lead moves back to `paying`.

```
Lead created ──(manual)──> ... ──(manual/convert)──> signed_up
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

---

## 8. Endpoint Quick Reference

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 1 | `GET` | `/api/leads/sources` | List lead sources |
| 2 | `POST` | `/api/leads/sources` | Create lead source |
| 3 | `PUT` | `/api/leads/sources/{source_id}` | Update lead source |
| 4 | `DELETE` | `/api/leads/sources/{source_id}` | Deactivate lead source |
| 5 | `POST` | `/api/leads` | Create lead |
| 6 | `GET` | `/api/leads` | List leads (filtered, paginated) |
| 7 | `GET` | `/api/leads/{lead_id}` | Get lead detail + activities + follow-ups |
| 8 | `PUT` | `/api/leads/{lead_id}` | Update lead info |
| 9 | `PATCH` | `/api/leads/{lead_id}/stage` | Change lead stage |
| 10 | `DELETE` | `/api/leads/{lead_id}` | Delete lead |
| 11 | `GET` | `/api/leads/pipeline/summary` | Stage counts for Kanban board |
| 12 | `GET` | `/api/leads/pipeline/stats` | Full analytics + advice |
| 13 | `POST` | `/api/leads/{lead_id}/activities` | Log activity on lead |
| 14 | `GET` | `/api/leads/{lead_id}/activities` | List lead activities |
| 15 | `POST` | `/api/leads/{lead_id}/followups` | Schedule follow-up |
| 16 | `GET` | `/api/leads/followups/upcoming` | List upcoming follow-ups |
| 17 | `PATCH` | `/api/leads/followups/{followup_id}/complete` | Complete follow-up |
| 18 | `POST` | `/api/leads/{lead_id}/convert` | Convert lead to reseller account |

---

## 9. Frontend Page Mapping

| Page | Endpoints Used |
|------|---------------|
| **Kanban Board** | 6 (list by stage), 9 (drag between columns), 11 (column counts) |
| **Lead Detail** | 7 (full detail), 8 (edit info), 9 (change stage), 13 (log activity), 14 (timeline), 15 (add follow-up), 17 (complete follow-up) |
| **Add/Edit Lead Form** | 1 (source dropdown), 5 (create), 8 (update) |
| **Dashboard / Analytics** | 12 (stats + advice), 16 (upcoming follow-ups widget) |
| **Settings > Lead Sources** | 1 (list), 2 (create), 3 (update), 4 (delete) |
| **Convert Lead Modal** | 18 (convert to reseller) |
