# Subscription System — Frontend Integration Guide

This document describes every backend API change related to the reseller subscription system and exactly how the frontend should consume them. All endpoints use JWT Bearer auth unless noted otherwise.

---

## Table of Contents

1. [Login Response Changes](#1-login-response-changes)
2. [Dashboard Response Changes](#2-dashboard-response-changes)
3. [403 Subscription Enforcement](#3-403-subscription-enforcement)
4. [Reseller Section — New Pages](#4-reseller-section--new-pages)
   - 4.1 Subscription Overview
   - 4.2 Current Invoice Banner
   - 4.3 Invoice List
   - 4.4 Invoice Detail
   - 4.5 Pay Invoice (M-Pesa)
   - 4.6 Payment History
5. [Admin Section — New Pages](#5-admin-section--new-pages)
   - 5.1 Subscription List (Reseller Table Changes)
   - 5.2 Subscription Revenue Dashboard
   - 5.3 Expiring Soon List
   - 5.4 Reseller Subscription Detail
   - 5.5 Edit Subscription (Status / Expiry / Adjust Days)
   - 5.6 Activate / Deactivate / Waive Actions
   - 5.7 Generate Invoices (Manual Trigger)
6. [Admin Dashboard Widget Changes](#6-admin-dashboard-widget-changes)
7. [Suggested UI Components](#7-suggested-ui-components)

---

## 1. Login Response Changes

The `POST /api/auth/login` response now includes subscription fields.

### New fields in `response.user`

```json
{
  "access_token": "...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "email": "reseller@example.com",
    "role": "reseller",
    "organization_name": "MyISP",
    "business_name": "MyISP Networks",
    "support_phone": "0712345678",
    "mpesa_shortcode": "123456",
    "subscription_status": "trial",
    "subscription_expires_at": "2026-04-14T12:00:00"
  },
  "subscription_alert": {
    "status": "trial",
    "message": "Your free trial ends in 3 days.",
    "current_invoice": null
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `user.subscription_status` | `string` | One of: `active`, `trial`, `suspended`, `inactive` |
| `user.subscription_expires_at` | `string\|null` | ISO datetime or null |
| `subscription_alert` | `object\|undefined` | Only present when an alert is needed |
| `subscription_alert.status` | `string` | Same as subscription_status |
| `subscription_alert.message` | `string` | Human-readable alert text |
| `subscription_alert.current_invoice` | `object\|null` | Enriched invoice object if an invoice is due |

### What the frontend should do

- **Store** `subscription_status` in your auth/user state (localStorage, context, store)
- **On login**, if `subscription_alert` exists, display it as a banner/toast
- **If `subscription_status` is `suspended` or `inactive`**, redirect to a subscription page or show a blocking modal — most API calls will return 403

---

## 2. Dashboard Response Changes

`GET /api/dashboard/overview` now includes a `subscription_alert` field for reseller users.

```json
{
  "total_customers": 45,
  "subscription_alert": {
    "status": "trial",
    "message": "Your free trial ends in 2 days.",
    "current_invoice": null
  }
}
```

### What the frontend should do

- On the reseller dashboard, if `subscription_alert` is not null, render a prominent alert banner at the top
- The `message` field is ready to display as-is
- If `current_invoice` is present, link it to the invoice detail page or show a "Pay Now" button

---

## 3. 403 Subscription Enforcement

When a reseller's subscription is `suspended` or `inactive`, the following existing endpoints now return **HTTP 403**:

| Endpoint | Action blocked |
|----------|---------------|
| `POST /api/customers` | Creating new customers |
| `PUT /api/customers/{id}` | Editing customers |
| `POST /api/mpesa/payment` | Initiating customer payments |
| `POST /api/hotspot/register-and-pay` | Hotspot registration + payment |
| `POST /api/routers` | Adding new routers |
| `POST /api/radius/register-and-pay` | RADIUS hotspot payment (returns 503) |

### 403 Response body

```json
{
  "detail": "Your subscription is inactive. Please renew your subscription to continue using the service."
}
```

### What the frontend should do

- Add a **global response interceptor** (axios interceptor or fetch wrapper) that catches 403
- When the error `detail` contains "subscription", show a renewal prompt instead of a generic error
- Provide a link/button to the subscription page from the error UI
- Example:

```javascript
// Axios interceptor example
api.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 403 &&
        error.response?.data?.detail?.includes('subscription')) {
      // Show subscription renewal modal or redirect
      store.dispatch('showSubscriptionBlockedModal');
    }
    return Promise.reject(error);
  }
);
```

---

## 4. Reseller Section — New Pages

### 4.1 Subscription Overview

**Endpoint:** `GET /api/subscription`

**Response:**
```json
{
  "status": "trial",
  "expires_at": "2026-04-14T12:00:00",
  "trial_ends_at": null,
  "current_period_start": null,
  "current_period_end": null,
  "total_paid": 0.0,
  "invoice_count": 0,
  "pending_invoice": null
}
```

After a payment:
```json
{
  "status": "active",
  "expires_at": "2026-05-07T12:00:00",
  "trial_ends_at": null,
  "current_period_start": "2026-04-07T12:00:00",
  "current_period_end": "2026-05-07T12:00:00",
  "total_paid": 500.0,
  "invoice_count": 1,
  "pending_invoice": null
}
```

With a pending invoice:
```json
{
  "status": "active",
  "expires_at": "2026-05-07T12:00:00",
  "current_period_start": "2026-04-07T12:00:00",
  "current_period_end": "2026-05-07T12:00:00",
  "total_paid": 500.0,
  "invoice_count": 2,
  "pending_invoice": {
    "id": 3,
    "period_label": "April 2026",
    "final_charge": 750.0,
    "status": "pending",
    "due_date": "2026-05-06T00:00:00",
    "days_until_due": 4,
    "is_overdue": false,
    "is_due_soon": true,
    "human_message": "Due in 4 days"
  }
}
```

### Suggested UI

Build a **Subscription** page/section with:

- **Status badge** — color-coded (`active` = green, `trial` = blue, `suspended` = red, `inactive` = gray)
- **Expiry countdown** — "Expires in X days" calculated from `expires_at`
- **Billing summary** — total paid, invoice count
- **Pending invoice card** — if `pending_invoice` is not null, show the charge and a "Pay Now" button
- **Trial progress bar** — during trial, show days remaining out of 7

---

### 4.2 Current Invoice Banner

**Endpoint:** `GET /api/subscription/current-invoice`

**Response:**
```json
{
  "current_invoice": {
    "id": 3,
    "user_id": 1,
    "period_start": "2026-04-01T00:00:00",
    "period_end": "2026-04-30T23:59:59",
    "period_label": "April 2026",
    "hotspot_revenue": 15000.0,
    "hotspot_charge": 450.0,
    "pppoe_user_count": 8,
    "pppoe_charge": 200.0,
    "gross_charge": 650.0,
    "final_charge": 650.0,
    "status": "pending",
    "due_date": "2026-05-06T00:00:00",
    "paid_at": null,
    "days_until_due": 4,
    "is_overdue": false,
    "is_due_soon": true,
    "human_message": "Due in 4 days",
    "created_at": "2026-05-01T00:30:00"
  }
}
```

Returns `{"current_invoice": null}` if nothing is due.

### Suggested UI

- Use this to render a **banner or notification bar** at the top of the reseller dashboard
- Show `human_message` directly — it is display-ready
- Color the banner: yellow for `is_due_soon`, red for `is_overdue`, none for normal
- Include a "View Details" link → invoice detail and a "Pay Now" button → pay flow

---

### 4.3 Invoice List

**Endpoint:** `GET /api/subscription/invoices?page=1&per_page=20&status=pending`

| Param | Type | Default | Options |
|-------|------|---------|---------|
| `page` | int | 1 | >= 1 |
| `per_page` | int | 20 | 1–100 |
| `status` | string | (all) | `pending`, `paid`, `overdue`, `waived` |

**Response:**
```json
{
  "page": 1,
  "per_page": 20,
  "total": 5,
  "total_pages": 1,
  "invoices": [
    {
      "id": 3,
      "user_id": 1,
      "period_start": "2026-04-01T00:00:00",
      "period_end": "2026-04-30T23:59:59",
      "period_label": "April 2026",
      "hotspot_revenue": 15000.0,
      "hotspot_charge": 450.0,
      "pppoe_user_count": 8,
      "pppoe_charge": 200.0,
      "gross_charge": 650.0,
      "final_charge": 650.0,
      "status": "pending",
      "due_date": "2026-05-06T00:00:00",
      "paid_at": null,
      "days_until_due": 4,
      "is_overdue": false,
      "is_due_soon": true,
      "human_message": "Due in 4 days",
      "created_at": "2026-05-01T00:30:00"
    }
  ]
}
```

### Suggested UI

- **Table** with columns: Period, Amount (final_charge), Status (badge), Due Date, Message, Actions
- **Status filter tabs** at the top: All | Pending | Paid | Overdue | Waived
- **Pagination** using `page`, `total_pages`
- Row click → invoice detail page

---

### 4.4 Invoice Detail

**Endpoint:** `GET /api/subscription/invoices/{invoice_id}`

Returns the same enriched invoice object plus a `payments` array:

```json
{
  "id": 3,
  "period_label": "April 2026",
  "hotspot_revenue": 15000.0,
  "hotspot_charge": 450.0,
  "pppoe_user_count": 8,
  "pppoe_charge": 200.0,
  "gross_charge": 650.0,
  "final_charge": 650.0,
  "status": "paid",
  "due_date": "2026-05-06T00:00:00",
  "paid_at": "2026-05-04T10:23:00",
  "human_message": "Paid",
  "payments": [
    {
      "id": 7,
      "amount": 650.0,
      "payment_method": "mpesa",
      "payment_reference": "SHK12345ABC",
      "phone_number": "254712345678",
      "status": "completed",
      "created_at": "2026-05-04T10:22:00"
    }
  ]
}
```

### Suggested UI

- **Charge breakdown card**: show hotspot revenue → 3% charge, PPPoE users × KES 25, gross vs final (min 500)
- **Status + timeline**: status badge, due date, paid date
- **Payment history table**: linked payments with M-Pesa receipt references
- **Pay Now button** if status is `pending` or `overdue`

---

### 4.5 Pay Invoice (M-Pesa STK Push)

**Endpoint:** `POST /api/subscription/pay`

**Request:**
```json
{
  "invoice_id": 3,
  "phone_number": "0712345678"
}
```

**Response (success):**
```json
{
  "message": "STK push sent. Check your phone to complete payment.",
  "payment_id": 7,
  "checkout_request_id": "ws_CO_123456789",
  "amount": 650.0,
  "phone_number": "254712345678"
}
```

**Error responses:**
- `404` — Invoice not found
- `400` — Invoice already paid/waived
- `502` — M-Pesa STK push failed

### Suggested UI flow

1. Show a **Pay modal/drawer** with:
   - Invoice summary (period, amount)
   - Phone number input (pre-fill from user profile)
   - "Pay KES X" button
2. On submit, call the endpoint
3. Show a **"Check your phone"** screen with a spinner
4. Poll `GET /api/subscription/invoices/{id}` every 5 seconds for up to 60 seconds
5. When invoice status flips to `paid`, show success and refresh subscription data
6. If timeout, show "Payment is being processed. It may take a moment." with a manual refresh button

---

### 4.6 Payment History

**Endpoint:** `GET /api/subscription/payments?page=1&per_page=20`

**Response:**
```json
{
  "page": 1,
  "per_page": 20,
  "total": 3,
  "total_pages": 1,
  "payments": [
    {
      "id": 7,
      "invoice_id": 3,
      "amount": 650.0,
      "payment_method": "mpesa",
      "payment_reference": "SHK12345ABC",
      "phone_number": "254712345678",
      "status": "completed",
      "created_at": "2026-05-04T10:22:00"
    }
  ]
}
```

### Suggested UI

- **Table** with columns: Date, Amount, Method, Reference, Status, Invoice #
- Invoice # links to invoice detail
- Status badges: `completed` = green, `pending` = yellow, `failed` = red

---

## 5. Admin Section — New Pages

### 5.1 Subscription List

**Endpoint:** `GET /api/admin/subscriptions`

| Param | Type | Default | Options |
|-------|------|---------|---------|
| `status` | string | (all) | `active`, `trial`, `suspended`, `inactive` |
| `sort_by` | string | — | `expires_at`, `revenue`, `created_at` |
| `sort_order` | string | `desc` | `asc`, `desc` |
| `search` | string | — | Searches email and organization name |

**Response:**
```json
{
  "total": 12,
  "subscriptions": [
    {
      "id": 5,
      "email": "reseller@example.com",
      "organization_name": "MyISP",
      "business_name": "MyISP Networks",
      "subscription_status": "active",
      "subscription_expires_at": "2026-05-07T12:00:00",
      "total_paid": 1500.0,
      "outstanding": 650.0,
      "pending_invoice": { "...enriched invoice object..." },
      "created_at": "2026-01-15T08:00:00",
      "last_login_at": "2026-04-06T14:30:00"
    }
  ]
}
```

### Suggested UI

- **Dedicated "Subscriptions" page** in admin, or add a tab to the existing resellers page
- **Filter tabs**: All | Active | Trial | Suspended | Inactive
- **Search bar** for email/organization
- **Table columns**: Reseller, Status (badge), Expires, Total Paid, Outstanding, Last Login, Actions
- **Row actions**: View Detail, Activate, Suspend, Edit Expiry
- Click row → reseller subscription detail

---

### 5.2 Subscription Revenue Dashboard

**Endpoint:** `GET /api/admin/subscriptions/revenue`

**Response:**
```json
{
  "total_collected": 45000.0,
  "this_month_collected": 8500.0,
  "total_outstanding": 3200.0,
  "total_invoices": 36,
  "overdue_invoices": 4,
  "resellers": {
    "active": 8,
    "trial": 3,
    "suspended": 2
  }
}
```

### Suggested UI

- **Stat cards**: Total Collected, This Month, Outstanding, Overdue Count
- **Reseller breakdown**: Pie or donut chart — active vs trial vs suspended
- Place this as a section on the admin dashboard or a dedicated subscriptions overview page

---

### 5.3 Expiring Soon

**Endpoint:** `GET /api/admin/subscriptions/expiring-soon?days=7`

**Response:**
```json
{
  "days_threshold": 7,
  "total": 3,
  "resellers": [
    {
      "id": 5,
      "email": "reseller@example.com",
      "organization_name": "MyISP",
      "subscription_status": "active",
      "subscription_expires_at": "2026-04-12T12:00:00",
      "days_until_expiry": 5
    }
  ]
}
```

### Suggested UI

- **Warning card/widget** on the admin dashboard: "3 subscriptions expiring in the next 7 days"
- Clicking it opens a list/modal showing the resellers
- Each row has quick actions: Extend, View Detail

---

### 5.4 Reseller Subscription Detail (Admin)

**Endpoint:** `GET /api/admin/subscriptions/{reseller_id}`

**Response:**
```json
{
  "reseller": {
    "id": 5,
    "email": "reseller@example.com",
    "organization_name": "MyISP",
    "business_name": "MyISP Networks"
  },
  "subscription": {
    "status": "active",
    "expires_at": "2026-05-07T12:00:00",
    "trial_ends_at": null,
    "current_period_start": "2026-04-07T12:00:00",
    "current_period_end": "2026-05-07T12:00:00",
    "total_paid": 1500.0,
    "invoice_count": 3,
    "pending_invoice": null
  },
  "invoices": [ "...array of enriched invoice objects..." ],
  "payments": [
    {
      "id": 7,
      "invoice_id": 3,
      "amount": 650.0,
      "payment_method": "mpesa",
      "payment_reference": "SHK12345ABC",
      "phone_number": "254712345678",
      "status": "completed",
      "created_at": "2026-05-04T10:22:00"
    }
  ]
}
```

### Suggested UI

- **Reseller header**: name, email, status badge
- **Subscription card**: status, expiry, period dates, total paid
- **Invoices tab/table**: all invoices with status badges and waive action
- **Payments tab/table**: payment history
- **Action buttons**: Activate, Suspend, Edit Expiry

---

### 5.5 Edit Subscription (Status / Expiry / Adjust Days)

**Endpoint:** `PATCH /api/admin/subscriptions/{reseller_id}`

**Request body** (all fields optional, send any combination):

```json
{
  "subscription_status": "active",
  "subscription_expires_at": "2026-06-07T12:00:00",
  "adjust_days": 5
}
```

| Field | Type | Description |
|-------|------|-------------|
| `subscription_status` | string | Set to: `active`, `inactive`, `trial`, `suspended` |
| `subscription_expires_at` | string | Set an absolute expiry date (ISO format) |
| `adjust_days` | integer | Add (positive) or subtract (negative) days from current expiry |

**Response:**
```json
{
  "message": "Subscription updated",
  "reseller_id": 5,
  "subscription_status": "active",
  "subscription_expires_at": "2026-06-12T12:00:00",
  "days_remaining": 66
}
```

### Suggested UI

Build an **Edit Subscription modal/drawer** with:

- **Status dropdown**: active, trial, suspended, inactive
- **Expiry date picker**: for setting an absolute date
- **Quick adjust buttons**: "+1 day", "+7 days", "+30 days", "-1 day", "-7 days" (these send `adjust_days`)
- After save, show the returned `days_remaining` as confirmation
- The quick-adjust buttons are especially useful for testing — e.g. click "-6 days" to make a 7-day trial expire tomorrow

---

### 5.6 Admin Actions

#### Activate

**Endpoint:** `POST /api/admin/subscriptions/{reseller_id}/activate?months=1`

| Param | Type | Default | Range |
|-------|------|---------|-------|
| `months` | int | 1 | 1–12 |

**Response:**
```json
{
  "message": "Subscription activated for 1 month(s)",
  "reseller_id": 5,
  "subscription_status": "active",
  "subscription_expires_at": "2026-05-07T12:00:00"
}
```

#### Deactivate / Suspend

**Endpoint:** `POST /api/admin/subscriptions/{reseller_id}/deactivate`

**Response:**
```json
{
  "message": "Subscription suspended",
  "reseller_id": 5,
  "subscription_status": "suspended"
}
```

#### Waive Invoice

**Endpoint:** `POST /api/admin/subscriptions/{reseller_id}/waive/{invoice_id}`

**Response:**
```json
{
  "message": "Invoice waived",
  "invoice_id": 3,
  "reseller_id": 5
}
```

Error: `400` if invoice is already paid.

### Suggested UI

- **Activate**: Confirm dialog with month selector (1–12), then call the endpoint
- **Suspend**: Confirm dialog ("Are you sure? This will block the reseller from using the system.")
- **Waive**: On invoice rows, show a "Waive" button (disabled if status is `paid`). Confirm dialog before calling.

---

### 5.7 Generate Invoices (Manual Trigger)

**Endpoint:** `POST /api/admin/subscriptions/generate-invoices`

**Response:**
```json
{
  "message": "Invoice generation complete",
  "generated": 8,
  "skipped": 2,
  "errors": []
}
```

### Suggested UI

- A button on the subscription revenue page: "Generate Monthly Invoices"
- Confirm dialog: "This will generate invoices for all eligible resellers for last month."
- Show results: "8 invoices generated, 2 skipped"
- Note: This runs automatically on the 1st of each month, but the button is useful for testing or catch-up

---

## 6. Admin Dashboard Widget Changes

The existing `GET /api/admin/dashboard` response now includes subscription counts.

### New fields in the `resellers` object

```json
{
  "resellers": {
    "total": 12,
    "active_last_30_days": 8,
    "subscription_active": 5,
    "subscription_trial": 3,
    "subscription_suspended": 2,
    "subscription_inactive": 2
  }
}
```

### Also available in the resellers list

`GET /api/admin/resellers` now includes on each reseller row:

```json
{
  "subscription_status": "active",
  "subscription_expires_at": "2026-05-07T12:00:00"
}
```

And supports new filters:
- `?filter=sub_active`
- `?filter=sub_trial`
- `?filter=sub_suspended`
- `?filter=sub_inactive`

And sorting: `?sort_by=subscription_expires_at`

### Suggested UI changes

- Add **subscription stat cards** to the admin dashboard: Active (green), Trial (blue), Suspended (red), Inactive (gray)
- Add a **subscription status column** to the existing resellers table with color-coded badges
- Add **subscription filter buttons/tabs** to the resellers table toolbar

---

## 7. Suggested UI Components

### Reusable components to build

| Component | Used in |
|-----------|---------|
| `SubscriptionStatusBadge` | Everywhere — renders colored badge for active/trial/suspended/inactive |
| `InvoiceStatusBadge` | Invoice tables — renders badge for pending/paid/overdue/waived |
| `SubscriptionAlertBanner` | Dashboard + top nav — renders `subscription_alert.message` with appropriate color |
| `PayInvoiceModal` | Invoice detail + subscription overview — phone input + STK push flow |
| `InvoiceChargeBreakdown` | Invoice detail — shows hotspot revenue × 3%, PPPoE users × 25, minimum 500 |
| `EditSubscriptionModal` | Admin — status dropdown, date picker, adjust days buttons |
| `ConfirmActionDialog` | Admin — activate/suspend/waive confirm dialogs |

### Suggested route structure

```
/reseller/subscription           → Subscription Overview (4.1)
/reseller/subscription/invoices  → Invoice List (4.3)
/reseller/subscription/invoices/:id → Invoice Detail (4.4)
/reseller/subscription/payments  → Payment History (4.6)

/admin/subscriptions             → Subscription List (5.1)
/admin/subscriptions/revenue     → Revenue Dashboard (5.2)
/admin/subscriptions/:id         → Reseller Subscription Detail (5.4)
```

### Badge color mapping

| Status | Color | Hex suggestion |
|--------|-------|----------------|
| `active` | Green | `#22c55e` |
| `trial` | Blue | `#3b82f6` |
| `suspended` | Red | `#ef4444` |
| `inactive` | Gray | `#6b7280` |
| `pending` (invoice) | Yellow | `#eab308` |
| `paid` (invoice) | Green | `#22c55e` |
| `overdue` (invoice) | Red | `#ef4444` |
| `waived` (invoice) | Gray | `#6b7280` |
