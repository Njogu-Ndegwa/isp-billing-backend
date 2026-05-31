# Shop API — Frontend Reference

Base URL: your deployment root (e.g. `https://api.yourdomain.com`)

---

## Authentication

Admin-only endpoints require a JWT bearer token obtained from your existing login flow.

```
Authorization: Bearer <token>
```

Public endpoints (product listing, placing orders, tracking) require **no token**.

---

## Enums

| Field | Allowed values |
|---|---|
| `status` (order) | `pending` `confirmed` `processing` `shipped` `delivered` `cancelled` |
| `payment_status` | `unpaid` `paid` `refunded` |

---

## Table of Contents

**Admin**
1. [Create Product](#1-create-product)
2. [List Admin Products](#2-list-admin-products)
3. [Update Product](#3-update-product)
4. [Delete Product](#4-delete-product)
5. [List Admin Orders](#5-list-admin-orders)
6. [Get Admin Order Detail](#6-get-admin-order-detail)
7. [Update Order Status](#7-update-order-status)
8. [Add Tracking Event](#8-add-tracking-event)
9. [Shop Dashboard](#9-shop-dashboard)
10. [Shop Analytics](#10-shop-analytics)

**Public / Customer**
11. [List Products](#11-list-products)
12. [Get Single Product](#12-get-single-product)
13. [Place Order](#13-place-order)
14. [Initiate Payment (M-Pesa STK)](#14-initiate-payment-m-pesa-stk)
15. [Check Payment Status](#15-check-payment-status)
16. [Track Order](#16-track-order)

**Webhook**
17. [M-Pesa Callback](#17-m-pesa-callback)

**Unified Dashboard**
18. [Shop block in /api/dashboard/overview](#18-shop-block-in-apidashboardoverview)

---

## Admin Endpoints

### 1. Create Product

`POST /api/shop/products` — **Auth required**

#### Request body

```json
{
  "name": "Mikrotik hAP ac²",
  "description": "Dual-band home access point",
  "price": 4500.00,
  "stock_quantity": 20,
  "image_url": "https://cdn.example.com/hapac2.jpg",
  "category": "Routers",
  "is_active": true
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | Yes | Product title |
| `description` | string | No | Long description |
| `price` | number | Yes | KES, 2 decimal places |
| `stock_quantity` | integer | No | Defaults to `0` |
| `image_url` | string | No | Absolute URL |
| `category` | string | No | e.g. `"Routers"`, `"Cables"` |
| `is_active` | boolean | No | Defaults to `true`. Set `false` to hide from store |

#### Response `200`

```json
{
  "id": 1,
  "name": "Mikrotik hAP ac²",
  "description": "Dual-band home access point",
  "price": 4500.0,
  "stock_quantity": 20,
  "image_url": "https://cdn.example.com/hapac2.jpg",
  "category": "Routers",
  "is_active": true,
  "created_at": "2026-04-30T13:00:00"
}
```

---

### 2. List Admin Products

`GET /api/shop/admin/products` — **Auth required**

Returns **all** products for the authenticated admin (including inactive/soft-deleted ones), newest first.

No query parameters.

#### Response `200`

```json
[
  {
    "id": 1,
    "name": "Mikrotik hAP ac²",
    "description": "Dual-band home access point",
    "price": 4500.0,
    "stock_quantity": 20,
    "image_url": "https://cdn.example.com/hapac2.jpg",
    "category": "Routers",
    "is_active": true,
    "created_at": "2026-04-30T13:00:00"
  }
]
```

---

### 3. Update Product

`PUT /api/shop/products/{product_id}` — **Auth required**

All fields are optional — send only what you want to change.

#### Request body

```json
{
  "price": 4200.00,
  "stock_quantity": 15,
  "is_active": true
}
```

| Field | Type | Notes |
|---|---|---|
| `name` | string | |
| `description` | string | |
| `price` | number | |
| `stock_quantity` | integer | |
| `image_url` | string | |
| `category` | string | |
| `is_active` | boolean | Use `false` to hide product |

#### Response `200` — updated product object (same shape as Create Product response)

#### Errors

| Code | Meaning |
|---|---|
| `404` | Product not found or does not belong to your account |

---

### 4. Delete Product

`DELETE /api/shop/products/{product_id}` — **Auth required**

Performs a **soft delete** — sets `is_active=false` and `stock_quantity=0`. The product disappears from the public listing but historical order data is preserved.

#### Response `200`

```json
{ "message": "Product removed from shop" }
```

#### Errors

| Code | Meaning |
|---|---|
| `404` | Product not found |

---

### 5. List Admin Orders

`GET /api/shop/admin/orders` — **Auth required**

#### Query parameters

| Param | Type | Notes |
|---|---|---|
| `status` | string | Filter by order status enum value |
| `payment_status` | string | Filter by payment status enum value |

Example: `GET /api/shop/admin/orders?status=confirmed&payment_status=paid`

#### Response `200`

Array of order objects (same shape as [Get Admin Order Detail](#6-get-admin-order-detail)).

#### Errors

| Code | Meaning |
|---|---|
| `400` | Invalid `status` or `payment_status` value — response includes list of valid options |

---

### 6. Get Admin Order Detail

`GET /api/shop/admin/orders/{order_id}` — **Auth required**

#### Response `200`

```json
{
  "id": 42,
  "order_number": "ORD3A9F1C2B",
  "buyer_name": "Jane Doe",
  "buyer_phone": "0712345678",
  "buyer_email": "jane@example.com",
  "delivery_address": "123 Ngong Road, Nairobi",
  "total_amount": 9000.0,
  "status": "confirmed",
  "payment_status": "paid",
  "mpesa_receipt_number": "QJK3X1Y2Z4",
  "notes": "Please call before delivery",
  "created_at": "2026-04-30T14:22:00",
  "items": [
    {
      "id": 10,
      "product_id": 1,
      "product_name": "Mikrotik hAP ac²",
      "product_price": 4500.0,
      "quantity": 2,
      "subtotal": 9000.0
    }
  ],
  "tracking_history": [
    {
      "id": 1,
      "status_label": "Payment confirmed",
      "note": "M-Pesa receipt: QJK3X1Y2Z4",
      "created_at": "2026-04-30T14:22:05"
    }
  ]
}
```

#### Errors

| Code | Meaning |
|---|---|
| `404` | Order not found |

---

### 7. Update Order Status

`PUT /api/shop/admin/orders/{order_id}/status` — **Auth required**

Use this to move the order through its lifecycle.

#### Request body

```json
{ "status": "shipped" }
```

Valid values: `pending` `confirmed` `processing` `shipped` `delivered` `cancelled`

#### Response `200`

```json
{ "message": "Status updated", "status": "shipped" }
```

#### Errors

| Code | Meaning |
|---|---|
| `400` | Invalid status value |
| `404` | Order not found |

---

### 8. Add Tracking Event

`POST /api/shop/admin/orders/{order_id}/tracking` — **Auth required**

Appends a timestamped tracking milestone visible to the customer.

#### Request body

```json
{
  "status_label": "Dispatched from warehouse",
  "note": "Will arrive within 2 business days"
}
```

| Field | Type | Required |
|---|---|---|
| `status_label` | string | Yes |
| `note` | string | No |

#### Response `200`

```json
{
  "id": 5,
  "status_label": "Dispatched from warehouse",
  "note": "Will arrive within 2 business days",
  "created_at": "2026-04-30T15:00:00"
}
```

#### Errors

| Code | Meaning |
|---|---|
| `404` | Order not found |

---

### 9. Shop Dashboard

`GET /api/shop/dashboard` — **Auth required**

Returns KPI summary cards, order counts, top products, and recent paid orders.

#### Response `200`

```json
{
  "revenue": {
    "today": 13500.0,
    "this_week": 67200.0,
    "this_month": 241000.0,
    "all_time": 1850000.0
  },
  "orders": {
    "total": 312,
    "by_status": {
      "pending": 4,
      "confirmed": 8,
      "processing": 3,
      "shipped": 12,
      "delivered": 280,
      "cancelled": 5
    },
    "by_payment": {
      "unpaid": 6,
      "paid": 302,
      "refunded": 4
    },
    "pending_payment": 6,
    "needs_fulfillment": 11
  },
  "top_products": [
    {
      "product_id": 1,
      "product_name": "Mikrotik hAP ac²",
      "units_sold": 95,
      "revenue": 427500.0
    }
  ],
  "recent_orders": [
    {
      "id": 42,
      "order_number": "ORD3A9F1C2B",
      "buyer_name": "Jane Doe",
      "buyer_phone": "0712345678",
      "buyer_email": "jane@example.com",
      "delivery_address": "123 Ngong Road, Nairobi",
      "total_amount": 9000.0,
      "status": "confirmed",
      "payment_status": "paid",
      "mpesa_receipt_number": "QJK3X1Y2Z4",
      "notes": null,
      "created_at": "2026-04-30T14:22:00"
    }
  ],
  "generated_at": "2026-04-30T13:45:00"
}
```

> `needs_fulfillment` = `confirmed` + `processing` orders — use this as an action badge.
> `recent_orders` objects do **not** include `items` or `tracking_history`.

---

### 10. Shop Analytics

`GET /api/shop/analytics` — **Auth required**

Time-series data for charting revenue and order trends.

#### Query parameters

| Param | Type | Notes |
|---|---|---|
| `preset` | string | See presets table below. Default: `this_month` |
| `start_date` | string | `YYYY-MM-DD`. Overrides preset when supplied |
| `end_date` | string | `YYYY-MM-DD`. Overrides preset when supplied |

**Preset values**

| Preset | Window |
|---|---|
| `today` | Midnight → now |
| `yesterday` | Previous day |
| `this_week` | Monday → now |
| `this_month` | 1st of month → now |
| `last_30_days` | 30-day rolling |
| `last_90_days` | 90-day rolling |
| `this_year` | Jan 1 → now |
| `all_time` | Since 2020 |

Examples:
- `GET /api/shop/analytics?preset=last_30_days`
- `GET /api/shop/analytics?start_date=2026-04-01&end_date=2026-04-30`

#### Response `200`

```json
{
  "period": {
    "label": "Last 30 Days",
    "start": "2026-03-31",
    "end": "2026-04-30"
  },
  "summary": {
    "total_revenue": 241000.0,
    "total_orders": 58,
    "unique_buyers": 42,
    "avg_order_value": 4155.17
  },
  "daily_trend": [
    { "date": "2026-03-31", "label": "Mar 31", "orders": 2, "revenue": 9000.0 },
    { "date": "2026-04-01", "label": "Apr 01", "orders": 0, "revenue": 0.0 }
  ],
  "hourly_pattern": [
    { "hour": 0,  "label": "00:00", "orders": 1, "revenue": 4500.0 },
    { "hour": 1,  "label": "01:00", "orders": 0, "revenue": 0.0 },
    { "hour": 14, "label": "14:00", "orders": 12, "revenue": 54000.0 }
  ],
  "top_products": [
    {
      "product_id": 1,
      "product_name": "Mikrotik hAP ac²",
      "units_sold": 22,
      "revenue": 99000.0
    }
  ],
  "revenue_by_status": [
    { "status": "delivered", "orders": 48, "revenue": 216000.0 },
    { "status": "confirmed", "orders": 8,  "revenue": 36000.0 },
    { "status": "cancelled", "orders": 2,  "revenue": 9000.0 }
  ],
  "generated_at": "2026-04-30T13:45:00"
}
```

> `daily_trend` always has one entry per calendar day — no gaps — so you can feed it directly to a chart without pre-processing.
> `hourly_pattern` always has 24 entries (hours 0–23).
> `revenue_by_status` covers **all** order statuses, not just paid ones — useful for funnel analysis.

---

## Public / Customer Endpoints

No authentication needed for any endpoint in this section.

---

### 11. List Products

`GET /api/shop/products`

Returns only active, in-stock-capable products ordered by newest first.

#### Query parameters

| Param | Type | Notes |
|---|---|---|
| `category` | string | Filter by category name (exact match) |

Example: `GET /api/shop/products?category=Routers`

#### Response `200`

```json
[
  {
    "id": 1,
    "name": "Mikrotik hAP ac²",
    "description": "Dual-band home access point",
    "price": 4500.0,
    "stock_quantity": 18,
    "image_url": "https://cdn.example.com/hapac2.jpg",
    "category": "Routers",
    "is_active": true,
    "created_at": "2026-04-30T13:00:00"
  }
]
```

---

### 12. Get Single Product

`GET /api/shop/products/{product_id}`

#### Response `200` — single product object (same shape as list item above)

#### Errors

| Code | Meaning |
|---|---|
| `404` | Product not found or inactive |

---

### 13. Place Order

`POST /api/shop/orders`

Creates an order and reserves stock. The order starts with `status=pending` and `payment_status=unpaid`. Call [Initiate Payment](#14-initiate-payment-m-pesa-stk) next to prompt the customer for M-Pesa PIN.

#### Request body

```json
{
  "buyer_name": "Jane Doe",
  "buyer_phone": "0712345678",
  "buyer_email": "jane@example.com",
  "delivery_address": "123 Ngong Road, Nairobi",
  "notes": "Please call before delivery",
  "items": [
    { "product_id": 1, "quantity": 2 }
  ]
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `buyer_name` | string | Yes | |
| `buyer_phone` | string | Yes | `07XXXXXXXX` or `254XXXXXXXXX` |
| `buyer_email` | string | No | |
| `delivery_address` | string | No | |
| `notes` | string | No | Special instructions |
| `items` | array | Yes | At least one item |
| `items[].product_id` | integer | Yes | |
| `items[].quantity` | integer | Yes | Must be ≥ 1 |

#### Response `200`

```json
{
  "order_id": 42,
  "order_number": "ORD3A9F1C2B",
  "total_amount": 9000.0,
  "status": "pending",
  "payment_status": "unpaid"
}
```

> Save `order_id` and `order_number`. You'll need `order_id` to initiate payment and `order_number` + phone for public tracking.

#### Errors

| Code | Meaning |
|---|---|
| `400` | Empty items list, quantity < 1, or insufficient stock — message includes the product name and available quantity |
| `404` | One of the `product_id` values does not exist or is inactive |

---

### 14. Initiate Payment (M-Pesa STK)

`POST /api/shop/orders/{order_id}/pay`

Sends an STK push to the given phone number. The customer sees a PIN prompt on their phone. Payment confirmation is handled automatically via the M-Pesa callback — poll [Check Payment Status](#15-check-payment-status) to know when it goes through.

#### Request body

```json
{ "phone": "0712345678" }
```

| Field | Notes |
|---|---|
| `phone` | Accepts `07XXXXXXXX`, `01XXXXXXXX`, `2547XXXXXXXX`, or `+2547XXXXXXXX` |

#### Response `200`

```json
{
  "message": "STK push sent. Enter M-Pesa PIN on your phone.",
  "checkout_request_id": "ws_CO_30042026_123456789",
  "order_number": "ORD3A9F1C2B"
}
```

#### Errors

| Code | Meaning |
|---|---|
| `400` | Order already paid |
| `404` | Order not found |
| `502` | M-Pesa gateway error — display a friendly retry message |

---

### 15. Check Payment Status

`GET /api/shop/orders/{order_id}/payment-status`

Poll this endpoint after STK push (e.g. every 3 seconds for up to 60 seconds) to detect when the customer completes or cancels payment.

#### Response `200`

```json
{
  "payment_status": "paid",
  "status": "confirmed",
  "mpesa_receipt_number": "QJK3X1Y2Z4"
}
```

| `payment_status` | What it means |
|---|---|
| `unpaid` | Awaiting payment |
| `paid` | Payment received — show success screen |
| `refunded` | Refunded by admin |

> When `payment_status` becomes `paid` the order `status` will also have advanced to `confirmed` automatically.

#### Errors

| Code | Meaning |
|---|---|
| `404` | Order not found |

---

### 16. Track Order

`GET /api/shop/orders/track/{order_number}?phone=07XXXXXXXX`

Public order tracking — no token required. The `phone` parameter must match the phone used when placing the order (used as a basic ownership check).

#### Path / query parameters

| Param | Where | Notes |
|---|---|---|
| `order_number` | Path | e.g. `ORD3A9F1C2B` — case-insensitive |
| `phone` | Query | `07XXXXXXXX` or `254XXXXXXXXX` |

Example: `GET /api/shop/orders/track/ORD3A9F1C2B?phone=0712345678`

#### Response `200`

```json
{
  "id": 42,
  "order_number": "ORD3A9F1C2B",
  "buyer_name": "Jane Doe",
  "buyer_phone": "0712345678",
  "buyer_email": "jane@example.com",
  "delivery_address": "123 Ngong Road, Nairobi",
  "total_amount": 9000.0,
  "status": "shipped",
  "payment_status": "paid",
  "mpesa_receipt_number": "QJK3X1Y2Z4",
  "notes": "Please call before delivery",
  "created_at": "2026-04-30T14:22:00",
  "items": [
    {
      "id": 10,
      "product_id": 1,
      "product_name": "Mikrotik hAP ac²",
      "product_price": 4500.0,
      "quantity": 2,
      "subtotal": 9000.0
    }
  ],
  "tracking_history": [
    {
      "id": 1,
      "status_label": "Payment confirmed",
      "note": "M-Pesa receipt: QJK3X1Y2Z4",
      "created_at": "2026-04-30T14:22:05"
    },
    {
      "id": 2,
      "status_label": "Dispatched from warehouse",
      "note": "Will arrive within 2 business days",
      "created_at": "2026-04-30T16:00:00"
    }
  ]
}
```

#### Errors

| Code | Meaning |
|---|---|
| `403` | Phone number does not match the order |
| `404` | Order number not found |

---

## Webhook

### 17. M-Pesa Callback

`POST /api/shop/mpesa/callback`

**This endpoint is called by Safaricom — do not call it from your frontend.**

When a customer completes payment the Daraja API posts to this URL. The server automatically:
- Sets `payment_status = paid`
- Sets `status = confirmed`
- Saves the M-Pesa receipt number
- Appends a `"Payment confirmed"` tracking event

Always returns `{"ResultCode": 0, "ResultDesc": "Accepted"}` to acknowledge Safaricom.

---

## Unified Dashboard

### 18. Shop block in `/api/dashboard/overview`

`GET /api/dashboard/overview` — **Auth required** (existing endpoint, unchanged)

The response now includes a `shop` key alongside the existing billing data.

```json
{
  "...existing billing fields...": "...",
  "shop": {
    "revenue": {
      "today": 13500.0,
      "this_week": 67200.0,
      "this_month": 241000.0,
      "all_time": 1850000.0
    },
    "pending_payment_orders": 6,
    "needs_fulfillment": 11
  },
  "generated_at": "2026-04-30T13:45:00"
}
```

> `shop` will be `null` if there is a temporary issue fetching shop data — the rest of the billing dashboard will still work normally.

---

## Typical Customer Flow

```
1. GET  /api/shop/products              → display product grid
2. POST /api/shop/orders                → place order → save order_id + order_number
3. POST /api/shop/orders/{id}/pay       → send STK push
4. GET  /api/shop/orders/{id}/payment-status   (poll every 3s until paid / timeout)
5. GET  /api/shop/orders/track/{number}?phone= → show tracking page
```

## Typical Admin Flow

```
1. POST /api/shop/products                          → add products
2. GET  /api/shop/dashboard                         → overview KPIs
3. GET  /api/shop/admin/orders?payment_status=paid  → view paid orders
4. PUT  /api/shop/admin/orders/{id}/status          → move to processing/shipped
5. POST /api/shop/admin/orders/{id}/tracking        → add delivery milestone
6. GET  /api/shop/analytics?preset=this_month       → revenue charts
```
