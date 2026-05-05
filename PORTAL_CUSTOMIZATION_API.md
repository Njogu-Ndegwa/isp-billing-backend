# Portal Customization — Reseller Dashboard API Reference

This document covers the three admin endpoints that let a reseller configure how their public captive portal looks and behaves. All endpoints require a JWT bearer token.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Get Settings](#2-get-settings)
3. [Update Settings](#3-update-settings)
4. [Reset to Defaults](#4-reset-to-defaults)
5. [Field Reference](#5-field-reference)
6. [Enum Values](#6-enum-values)
7. [Suggested Dashboard UI](#7-suggested-dashboard-ui)

---

## 1. Overview

Each reseller has one settings row. The row is created automatically with defaults the first time `GET /api/portal/settings` is called — no manual setup needed. Changes take effect the next time a customer loads the captive portal.

```
Base URL: https://your-api-domain.com
Auth:     Authorization: Bearer <token>
```

---

## 2. Get Settings

```
GET /api/portal/settings
```

Returns the reseller's current settings, plus lists of all valid values for each enum field.

**Response**

```json
{
  "settings": {
    "id": 5,
    "user_id": 12,
    "color_theme": "ocean_blue",
    "header_style": "standard",
    "show_ads": true,
    "show_welcome_banner": true,
    "welcome_title": "Welcome to FastNet WiFi",
    "welcome_subtitle": "Affordable internet for everyone",
    "company_logo_url": "https://example.com/logo.png",
    "header_bg_image_url": null,
    "footer_text": "© 2026 FastNet. All rights reserved.",
    "portal_support_phone": "+254700000000",
    "portal_support_whatsapp": "+254700000000",
    "show_ratings": true,
    "show_reconnect_button": true,
    "show_social_links": false,
    "facebook_url": null,
    "whatsapp_group_url": null,
    "instagram_url": null,
    "show_announcement": false,
    "announcement_type": "info",
    "announcement_text": null,
    "portal_language": "en",
    "plans_section_title": null,
    "featured_plan_ids": null,
    "created_at": "2026-05-05T17:00:00",
    "updated_at": "2026-05-05T17:00:00"
  },
  "available_themes": ["emerald_green", "midnight_purple", "ocean_blue", "rose_gold", "slate_gray", "sunset_orange"],
  "available_header_styles": ["compact", "hero", "minimal", "standard"],
  "available_languages": ["en", "fr", "sw"],
  "available_announcement_types": ["info", "success", "warning"]
}
```

---

## 3. Update Settings

```
PUT /api/portal/settings
Content-Type: application/json
```

Partial update — only the fields you include are changed. You can send a single field or all of them at once.

**Request body (all fields optional)**

```json
{
  "color_theme": "emerald_green",
  "header_style": "hero",
  "show_ads": false,
  "show_welcome_banner": true,
  "welcome_title": "Welcome to FastNet WiFi",
  "welcome_subtitle": "Affordable, fast internet for everyone",
  "company_logo_url": "https://example.com/logo.png",
  "header_bg_image_url": "https://example.com/hero-bg.jpg",
  "footer_text": "© 2026 FastNet. All rights reserved.",
  "portal_support_phone": "+254700000000",
  "portal_support_whatsapp": "+254700000000",
  "show_ratings": true,
  "show_reconnect_button": true,
  "show_social_links": true,
  "facebook_url": "https://facebook.com/fastnet",
  "whatsapp_group_url": "https://chat.whatsapp.com/xyz",
  "instagram_url": "https://instagram.com/fastnet",
  "show_announcement": true,
  "announcement_type": "warning",
  "announcement_text": "Network maintenance tonight 11 PM – 1 AM.",
  "portal_language": "en",
  "plans_section_title": "Choose Your Plan",
  "featured_plan_ids": "3,7"
}
```

**Response**

```json
{
  "message": "Portal settings updated successfully",
  "updated_fields": ["color_theme", "show_ads", "show_announcement", "announcement_text"],
  "settings": { ... }
}
```

**Validation errors (422)**

Sending an invalid enum value returns:

```json
{
  "detail": [
    {
      "loc": ["body", "color_theme"],
      "msg": "Value error, color_theme must be one of: emerald_green, midnight_purple, ocean_blue, rose_gold, slate_gray, sunset_orange",
      "type": "value_error"
    }
  ]
}
```

---

## 4. Reset to Defaults

```
POST /api/portal/settings/reset
```

Wipes all customizations and recreates the row with system defaults. Useful as an "Undo all changes" action.

**Response**

```json
{
  "message": "Portal settings reset to defaults",
  "settings": { ... }
}
```

---

## 5. Field Reference

| Field | Type | Default | Description |
|---|---|---|---|
| `color_theme` | string | `ocean_blue` | Portal colour theme. See [themes](#color-themes). |
| `header_style` | string | `standard` | Layout of the header section. See [header styles](#header-styles). |
| `show_ads` | bool | `true` | Show or hide the marketplace ads strip entirely. |
| `show_welcome_banner` | bool | `true` | Show the welcome title/subtitle at the top of the portal. |
| `welcome_title` | string | null | Defaults to the reseller's `business_name`. |
| `welcome_subtitle` | string | null | Short tagline shown under the title. |
| `company_logo_url` | string | null | URL of the ISP logo image. Shown in the header. |
| `header_bg_image_url` | string | null | Background image for the `hero` header style only. |
| `footer_text` | string | null | Text shown at the bottom of the portal. |
| `portal_support_phone` | string | null | Overrides the user-level `support_phone` on the portal. |
| `portal_support_whatsapp` | string | null | WhatsApp number for the support button. |
| `show_ratings` | bool | `true` | Show or hide the customer ratings / feedback section. |
| `show_reconnect_button` | bool | `true` | Show or hide the "Already paid? Reconnect" section. |
| `show_social_links` | bool | `false` | Show or hide the social media links row. |
| `facebook_url` | string | null | Facebook page URL. |
| `whatsapp_group_url` | string | null | WhatsApp community / group link. |
| `instagram_url` | string | null | Instagram profile URL. |
| `show_announcement` | bool | `false` | Show or hide the announcement banner. |
| `announcement_type` | string | `info` | Banner colour: `info` (blue), `warning` (orange), `success` (green). |
| `announcement_text` | string | null | The message displayed in the announcement banner. |
| `portal_language` | string | `en` | Portal language: `en`, `sw` (Swahili), `fr`. |
| `plans_section_title` | string | null | Heading above the plans grid. Defaults to "Choose Your Plan". |
| `featured_plan_ids` | string | null | Comma-separated plan IDs to pin at the top, e.g. `"3,7"`. |

---

## 6. Enum Values

### Color Themes

| Value | Description |
|---|---|
| `ocean_blue` | Deep blue / cyan — cool, professional |
| `emerald_green` | Green — fresh, modern |
| `sunset_orange` | Orange / warm — energetic |
| `midnight_purple` | Dark purple — bold, premium |
| `rose_gold` | Pink / rose — friendly, approachable |
| `slate_gray` | Neutral gray — minimal, clean |

### Header Styles

| Value | Description |
|---|---|
| `standard` | Logo left + welcome text. Default layout. |
| `minimal` | Network name only. Very clean, maximises plan visibility. |
| `hero` | Full-width banner with optional `header_bg_image_url`. Best for branded experiences. |
| `compact` | Slim single-line header. Pushes plans higher on small screens. |

### Announcement Types

| Value | Banner colour |
|---|---|
| `info` | Blue |
| `warning` | Orange / amber |
| `success` | Green |

---

## 7. Suggested Dashboard UI

### Settings page layout

```
┌─────────────────────────────────────────────────────┐
│  Portal Appearance                       [Save] [Reset] │
├─────────────────────────────────────────────────────┤
│                                                     │
│  THEME                                              │
│  ○ Ocean Blue  ○ Emerald Green  ○ Sunset Orange     │
│  ○ Midnight Purple  ○ Rose Gold  ○ Slate Gray       │
│                                                     │
│  HEADER LAYOUT                                      │
│  ○ Standard  ○ Minimal  ○ Hero  ○ Compact           │
│                                                     │
│  BRANDING                                           │
│  Logo URL  [_______________________________]        │
│  Welcome title  [____________________________]      │
│  Welcome subtitle  [_________________________]      │
│                                                     │
│  TOGGLES                          ON/OFF            │
│  Show ads                         [●]               │
│  Show ratings                     [●]               │
│  Show reconnect button            [●]               │
│  Show social links                [ ]               │
│                                                     │
│  ANNOUNCEMENT BANNER              [ ] Enable        │
│  Type   ○ Info  ○ Warning  ○ Success                │
│  Message  [___________________________________]     │
│                                                     │
│  SUPPORT CONTACTS                                   │
│  Phone  [______________]                            │
│  WhatsApp  [___________]                            │
│                                                     │
│  LANGUAGE   ○ English  ○ Swahili  ○ French          │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Save pattern

Send only the changed fields — no need to re-send the entire object on every save:

```js
// Example: user toggled show_ads off
await fetch('/api/portal/settings', {
  method: 'PUT',
  headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ show_ads: false })
});
```

### Preview link

After saving, link to the live portal with their router's identity so they can preview changes immediately:

```
https://portal.yourdomain.com/?router=<identity>
```
