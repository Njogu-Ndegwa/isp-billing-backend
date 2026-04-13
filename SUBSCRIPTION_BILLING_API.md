# Subscription Billing API

All endpoints require `Authorization: Bearer <token>` header.

---

## Reseller Endpoints

### GET `/api/subscription`

Get the current reseller's subscription status and summary.

**Response:**

```json
{
  "status": "active",
  "expires_at": "2026-05-13T08:00:00",
  "trial_ends_at": "2026-04-20T08:00:00",
  "current_period_start": "2026-04-13T08:00:00",
  "current_period_end": "2026-05-13T08:00:00",
  "total_paid": 1500.0,
  "invoice_count": 3,
  "pending_invoice": {
    "id": 12,
    "user_id": 5,
    "period_start": "2026-04-01T00:00:00",
    "period_end": "2026-05-13T08:00:00",
    "period_label": "April 2026",
    "hotspot_revenue": 45000.0,
    "hotspot_charge": 1350.0,
    "pppoe_user_count": 8,
    "pppoe_charge": 200.0,
    "gross_charge": 1550.0,
    "final_charge": 1550.0,
    "amount_paid": 0.0,
    "balance_remaining": 1550.0,
    "status": "pending",
    "due_date": "2026-05-13T08:00:00",
    "paid_at": null,
    "days_until_due": 30,
    "is_overdue": false,
    "is_due_soon": false,
    "human_message": "Due in 30 days",
    "created_at": "2026-04-08T08:00:00"
  }
}
```

`pending_invoice` is `null` when there is no unpaid invoice.

---

### GET `/api/subscription/current-invoice`

Get the latest unpaid invoice. Returns `null` if none exists.

**Response:**

```json
{
  "current_invoice": {
    "id": 12,
    "user_id": 5,
    "period_start": "2026-04-01T00:00:00",
    "period_end": "2026-05-13T08:00:00",
    "period_label": "April 2026",
    "hotspot_revenue": 45000.0,
    "hotspot_charge": 1350.0,
    "pppoe_user_count": 8,
    "pppoe_charge": 200.0,
    "gross_charge": 1550.0,
    "final_charge": 1550.0,
    "amount_paid": 500.0,
    "balance_remaining": 1050.0,
    "status": "pending",
    "due_date": "2026-05-13T08:00:00",
    "paid_at": null,
    "days_until_due": 4,
    "is_overdue": false,
    "is_due_soon": true,
    "human_message": "Due in 4 days",
    "created_at": "2026-04-08T08:00:00"
  }
}
```

---

### GET `/api/subscription/invoices`

List all invoices for the current reseller (paginated).

**Query params:** `page` (default 1), `per_page` (default 20), `status` (optional: `pending`, `paid`, `overdue`, `waived`)

**Response:**

```json
{
  "page": 1,
  "per_page": 20,
  "total": 3,
  "total_pages": 1,
  "invoices": [
    {
      "id": 12,
      "user_id": 5,
      "period_start": "2026-04-01T00:00:00",
      "period_end": "2026-05-13T08:00:00",
      "period_label": "April 2026",
      "hotspot_revenue": 45000.0,
      "hotspot_charge": 1350.0,
      "pppoe_user_count": 8,
      "pppoe_charge": 200.0,
      "gross_charge": 1550.0,
      "final_charge": 1550.0,
      "amount_paid": 0.0,
      "balance_remaining": 1550.0,
      "status": "pending",
      "due_date": "2026-05-13T08:00:00",
      "paid_at": null,
      "days_until_due": 30,
      "is_overdue": false,
      "is_due_soon": false,
      "human_message": "Due in 30 days",
      "created_at": "2026-04-08T08:00:00"
    }
  ]
}
```

---

### GET `/api/subscription/invoices/{invoice_id}`

Get detailed invoice breakdown with payment history.

**Response:**

```json
{
  "id": 12,
  "user_id": 5,
  "period_start": "2026-04-01T00:00:00",
  "period_end": "2026-05-13T08:00:00",
  "period_label": "April 2026",
  "hotspot_revenue": 45000.0,
  "hotspot_charge": 1350.0,
  "pppoe_user_count": 8,
  "pppoe_charge": 200.0,
  "gross_charge": 1550.0,
  "final_charge": 1550.0,
  "amount_paid": 500.0,
  "balance_remaining": 1050.0,
  "status": "pending",
  "due_date": "2026-05-13T08:00:00",
  "paid_at": null,
  "days_until_due": 4,
  "is_overdue": false,
  "is_due_soon": true,
  "human_message": "Due in 4 days",
  "created_at": "2026-04-08T08:00:00",
  "payments": [
    {
      "id": 7,
      "amount": 500.0,
      "payment_method": "mpesa",
      "payment_reference": "SHK4839FJD",
      "phone_number": "254712345678",
      "status": "completed",
      "created_at": "2026-04-10T14:23:00"
    }
  ]
}
```

---

### POST `/api/subscription/request-invoice`

Generate an invoice on demand. Returns existing pending invoice if one already exists. No request body needed.

**Response:**

```json
{
  "current_invoice": {
    "id": 12,
    "user_id": 5,
    "period_start": "2026-04-01T00:00:00",
    "period_end": "2026-05-13T08:00:00",
    "period_label": "April 2026",
    "hotspot_revenue": 45000.0,
    "hotspot_charge": 1350.0,
    "pppoe_user_count": 8,
    "pppoe_charge": 200.0,
    "gross_charge": 1550.0,
    "final_charge": 1550.0,
    "amount_paid": 0.0,
    "balance_remaining": 1550.0,
    "status": "pending",
    "due_date": "2026-05-13T08:00:00",
    "paid_at": null,
    "days_until_due": 30,
    "is_overdue": false,
    "is_due_soon": false,
    "human_message": "Due in 30 days",
    "created_at": "2026-04-13T08:00:00"
  },
  "generated": true
}
```

`generated` is `true` when a new invoice was created, `false` when returning an existing one.

---

### POST `/api/subscription/pay`

Initiate M-Pesa STK push to pay a subscription invoice. Supports partial payments.

**Request body:**

```json
{
  "invoice_id": 12,
  "phone_number": "0712345678",
  "amount": 1550.0
}
```

`amount` is optional. Omit to pay the full remaining balance. Phone accepts `0712...`, `254712...`, or `+254712...` formats.

**Response:**

```json
{
  "message": "STK push sent. Check your phone to complete payment.",
  "payment_id": 7,
  "checkout_request_id": "ws_CO_13042026...",
  "amount": 1550.0,
  "invoice_total": 1550.0,
  "already_paid": 0.0,
  "balance_after_this": 0.0,
  "phone_number": "254712345678"
}
```

---

### GET `/api/subscription/payments`

List all subscription payments for the current reseller (paginated).

**Query params:** `page` (default 1), `per_page` (default 20)

**Response:**

```json
{
  "page": 1,
  "per_page": 20,
  "total": 2,
  "total_pages": 1,
  "payments": [
    {
      "id": 7,
      "invoice_id": 12,
      "amount": 500.0,
      "payment_method": "mpesa",
      "payment_reference": "SHK4839FJD",
      "phone_number": "254712345678",
      "status": "completed",
      "created_at": "2026-04-10T14:23:00"
    }
  ]
}
```

`status` values: `pending`, `completed`, `failed`

---

## Admin Endpoints

### GET `/api/admin/subscriptions`

List all reseller subscriptions with financials.

**Query params:** `status` (optional: `active`, `trial`, `suspended`, `inactive`), `sort_by` (optional: `expires_at`, `revenue`, `created_at`), `sort_order` (default `desc`), `search` (optional, matches email or org name)

**Response:**

```json
{
  "total": 15,
  "subscriptions": [
    {
      "id": 5,
      "email": "reseller@example.com",
      "organization_name": "Speedy ISP",
      "business_name": "Speedy Networks Ltd",
      "subscription_status": "active",
      "subscription_expires_at": "2026-05-13T08:00:00",
      "total_paid": 1500.0,
      "outstanding": 1550.0,
      "pending_invoice": {
        "id": 12,
        "final_charge": 1550.0,
        "status": "pending",
        "due_date": "2026-05-13T08:00:00",
        "human_message": "Due in 30 days"
      },
      "created_at": "2026-01-15T10:00:00",
      "last_login_at": "2026-04-13T07:30:00"
    }
  ]
}
```

`pending_invoice` is `null` when the reseller has no unpaid invoice. The `pending_invoice` object contains the full enriched invoice shape (same as in GET `/api/subscription/current-invoice`).

---

### GET `/api/admin/subscriptions/revenue`

Subscription revenue dashboard.

**Response:**

```json
{
  "total_collected": 45000.0,
  "this_month_collected": 8500.0,
  "total_outstanding": 12300.0,
  "total_invoices": 45,
  "overdue_invoices": 3,
  "resellers": {
    "active": 10,
    "trial": 4,
    "suspended": 1
  }
}
```

---

### GET `/api/admin/subscriptions/expiring-soon`

List resellers whose subscriptions expire within N days.

**Query params:** `days` (default 7, range 1-90)

**Response:**

```json
{
  "days_threshold": 7,
  "total": 3,
  "resellers": [
    {
      "id": 5,
      "email": "reseller@example.com",
      "organization_name": "Speedy ISP",
      "subscription_status": "active",
      "subscription_expires_at": "2026-04-18T08:00:00",
      "days_until_expiry": 5
    }
  ]
}
```

---

### GET `/api/admin/subscriptions/{reseller_id}`

Full subscription detail for a specific reseller including all invoices and payments.

**Response:**

```json
{
  "reseller": {
    "id": 5,
    "email": "reseller@example.com",
    "organization_name": "Speedy ISP",
    "business_name": "Speedy Networks Ltd"
  },
  "subscription": {
    "status": "active",
    "expires_at": "2026-05-13T08:00:00",
    "trial_ends_at": null,
    "current_period_start": "2026-04-13T08:00:00",
    "current_period_end": "2026-05-13T08:00:00",
    "total_paid": 1500.0,
    "invoice_count": 3,
    "pending_invoice": null
  },
  "invoices": [
    {
      "id": 12,
      "period_label": "April 2026",
      "final_charge": 1550.0,
      "status": "pending",
      "due_date": "2026-05-13T08:00:00",
      "human_message": "Due in 30 days"
    }
  ],
  "payments": [
    {
      "id": 7,
      "invoice_id": 11,
      "amount": 500.0,
      "payment_method": "mpesa",
      "payment_reference": "SHK4839FJD",
      "phone_number": "254712345678",
      "status": "completed",
      "created_at": "2026-03-10T14:23:00"
    }
  ]
}
```

`invoices` array contains the full enriched invoice shape. `payments` array contains all subscription payments.

---

### PATCH `/api/admin/subscriptions/{reseller_id}`

Edit a reseller's subscription status or expiry date.

**Request body (all fields optional):**

```json
{
  "subscription_status": "active",
  "subscription_expires_at": "2026-06-13T08:00:00",
  "adjust_days": 30
}
```

`subscription_status`: `active`, `inactive`, `trial`, `suspended`. `subscription_expires_at`: ISO datetime string. `adjust_days`: add/subtract days from current expiry (positive or negative integer).

**Response:**

```json
{
  "message": "Subscription updated",
  "reseller_id": 5,
  "subscription_status": "active",
  "subscription_expires_at": "2026-06-13T08:00:00",
  "days_remaining": 61
}
```

---

### POST `/api/admin/subscriptions/{reseller_id}/activate`

Manually activate a reseller's subscription.

**Query params:** `months` (default 1, range 1-12)

**Response:**

```json
{
  "message": "Subscription activated for 1 month(s)",
  "reseller_id": 5,
  "subscription_status": "active",
  "subscription_expires_at": "2026-05-13T08:00:00"
}
```

---

### POST `/api/admin/subscriptions/{reseller_id}/deactivate`

Suspend a reseller's subscription.

**Response:**

```json
{
  "message": "Subscription suspended",
  "reseller_id": 5,
  "subscription_status": "suspended"
}
```

---

### POST `/api/admin/subscriptions/{reseller_id}/waive/{invoice_id}`

Waive a specific invoice for a reseller.

**Response:**

```json
{
  "message": "Invoice waived",
  "invoice_id": 12,
  "reseller_id": 5
}
```

---

### POST `/api/admin/subscriptions/generate-invoices`

Manually trigger monthly invoice generation for the previous month.

**Response:**

```json
{
  "message": "Invoice generation complete",
  "created": 8,
  "skipped": 2,
  "errors": []
}
```

---

### POST `/api/admin/subscriptions/generate-pre-expiry-invoices`

Manually trigger pre-expiry invoice generation for resellers expiring within 5 days.

**Response:**

```json
{
  "message": "Pre-expiry invoice generation complete",
  "created": 3,
  "skipped": 1,
  "errors": []
}
```

---

## Billing Formula Reference

```
hotspot_charge  = hotspot_revenue * 3%
pppoe_charge    = active_pppoe_users * KES 25
gross_charge    = hotspot_charge + pppoe_charge
final_charge    = max(gross_charge, KES 500)
```

## Invoice Status Values

`pending`, `paid`, `overdue`, `waived`

## Subscription Status Values

`active`, `inactive`, `trial`, `suspended`

## Automated Jobs

| Job | Schedule | Description |
|-----|----------|-------------|
| Monthly invoice generation | 1st of month, 00:30 | Bills all active/trial resellers for the previous month |
| Pre-expiry invoice generation | Daily, 08:00 | Creates invoices for resellers expiring within 5 days |
| Overdue check | Daily, 06:00 | Marks overdue invoices and suspends non-payers |
