# ISP Billing Admin Dashboard API Documentation

**Base URL:** `https://isp.bitwavetechnologies.com/api`

---

## 📊 Dashboard Overview

### GET `/dashboard/overview`

Get complete business metrics for dashboard homepage.

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `user_id` | int | No | 1 | Reseller/owner ID |

**Example Request:**
```
GET https://isp.bitwavetechnologies.com/api/dashboard/overview?user_id=1
```

**Example Response:**
```json
{
  "revenue": {
    "today": 0.0,
    "this_week": 10.0,
    "this_month": 10.0,
    "all_time": 730.0
  },
  "customers": {
    "total": 10,
    "active": 0,
    "inactive": 10
  },
  "revenue_by_router": [
    {
      "router_id": 2,
      "router_name": "Guest Hotspot Router",
      "transaction_count": 52,
      "revenue": 730.0
    }
  ],
  "revenue_by_plan": [
    {
      "plan_id": 1,
      "plan_name": "1 Hour Plan",
      "plan_price": 50,
      "sales_count": 5,
      "revenue": 250.0
    },
    {
      "plan_id": 2,
      "plan_name": "5 Minutes Test Plan",
      "plan_price": 10,
      "sales_count": 46,
      "revenue": 460.0
    }
  ],
  "recent_transactions": [
    {
      "payment_id": 52,
      "amount": 10.0,
      "customer_name": "Guest 5364",
      "customer_phone": "254795635364",
      "plan_name": "5 Minutes Test Plan",
      "payment_date": "2026-01-06T17:52:35.259434",
      "payment_method": "mobile_money"
    }
  ],
  "expiring_soon": [],
  "generated_at": "2026-01-10T15:33:29.555889"
}
```

---

## 👥 Customers

### GET `/customers`

Get all customers.

**Query Parameters:**
| Parameter | Type | Required | Default |
|-----------|------|----------|---------|
| `user_id` | int | No | 1 |

**Example Response:**
```json
[
  {
    "id": 1,
    "name": "Guest 5364",
    "phone": "254795635364",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "status": "active",
    "expiry": "2026-01-10T18:00:00",
    "plan": {
      "id": 2,
      "name": "5 Minutes Test Plan",
      "price": 10
    },
    "router": {
      "id": 2,
      "name": "Guest Hotspot Router"
    }
  }
]
```

### GET `/customers/active`

Get currently active customers only.

**Query Parameters:**
| Parameter | Type | Required | Default |
|-----------|------|----------|---------|
| `user_id` | int | No | 1 |

**Example Response:**
```json
[
  {
    "id": 1,
    "name": "Guest 5364",
    "phone": "254795635364",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "status": "active",
    "expiry": "2026-01-10T18:00:00",
    "hours_remaining": 2.5,
    "plan": {
      "id": 2,
      "name": "5 Minutes Test Plan",
      "price": 10
    },
    "router": {
      "id": 2,
      "name": "Guest Hotspot Router"
    }
  }
]
```

---

## 📋 Plans

### GET `/plans`

Get all available plans.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | int | No | Filter by owner |
| `connection_type` | string | No | Filter by type |

**Example Response:**
```json
[
  {
    "id": 1,
    "name": "1 Hour Plan",
    "price": 50,
    "duration_value": 1,
    "duration_unit": "hours",
    "download_speed": "5M",
    "upload_speed": "2M"
  }
]
```

### POST `/plans/create`

Create a new internet plan.

**Request Body:**
```json
{
  "name": "1 Hour Plan",
  "speed": "5M/2M",
  "price": 50,
  "duration_value": 1,
  "duration_unit": "HOURS",
  "connection_type": "hotspot",
  "router_profile": "default",
  "user_id": 1
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Plan name |
| `speed` | string | Yes | Speed (e.g. "5M/2M") |
| `price` | int | Yes | Price in local currency |
| `duration_value` | int | Yes | Duration amount (min 1) |
| `duration_unit` | string | Yes | `HOURS`, `DAYS`, or `MINUTES` |
| `connection_type` | string | Yes | `hotspot` or `pppoe` |
| `router_profile` | string | No | MikroTik profile name |
| `user_id` | int | No | Owner ID (default: 1) |

**Example Response:**
```json
{
  "id": 5,
  "name": "1 Hour Plan",
  "speed": "5M/2M",
  "price": 50,
  "duration_value": 1,
  "duration_unit": "HOURS",
  "connection_type": "hotspot",
  "router_profile": "default",
  "user_id": 1,
  "created_at": "2026-01-10T16:00:00.000000"
}
```

### DELETE `/plans/{plan_id}`

Delete a plan (only if no active customers using it).

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `plan_id` | int | Plan ID to delete |

**Query Parameters:**
| Parameter | Type | Required | Default |
|-----------|------|----------|---------|
| `user_id` | int | No | 1 |

**Example Response:**
```json
{
  "success": true,
  "message": "Plan '1 Hour Plan' deleted successfully"
}
```

**Error (active customers exist):**
```json
{
  "detail": "Cannot delete plan. 3 active customer(s) are using this plan"
}
```

### GET `/plans/performance`

Get performance metrics for each plan.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | int | No | Reseller ID |
| `start_date` | string | No | ISO format (YYYY-MM-DD) |
| `end_date` | string | No | ISO format (YYYY-MM-DD) |

**Example Response:**
```json
{
  "plans": [
    {
      "plan_id": 1,
      "plan_name": "1 Hour Plan",
      "plan_price": 50,
      "duration": "1 hours",
      "total_customers": 5,
      "total_sales": 10,
      "total_revenue": 500.0,
      "average_revenue_per_sale": 50.0,
      "active_customers": 2
    }
  ],
  "period": {
    "start_date": "2026-01-01",
    "end_date": "2026-01-10"
  }
}
```

---

## 💰 M-Pesa Transactions

### GET `/mpesa/transactions`

Get M-Pesa transactions with filters.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | int | No | Reseller ID (default: 1) |
| `router_id` | int | No | Filter by router |
| `start_date` | string | No | ISO format |
| `end_date` | string | No | ISO format |
| `status` | string | No | pending, completed, failed, expired |

**Example Response:**
```json
[
  {
    "transaction_id": 52,
    "checkout_request_id": "ws_CO_123...",
    "phone_number": "254795635364",
    "amount": 10.0,
    "reference": "REF123",
    "lipay_tx_no": "LIPAY123",
    "status": "completed",
    "mpesa_receipt_number": "QJK1234ABC",
    "transaction_date": "2026-01-06T17:52:35",
    "created_at": "2026-01-06T17:52:30",
    "customer": {
      "id": 1,
      "name": "Guest 5364",
      "phone": "254795635364",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "status": "active"
    },
    "router": {
      "id": 2,
      "name": "Guest Hotspot Router",
      "ip_address": "192.168.1.1"
    },
    "plan": {
      "id": 2,
      "name": "5 Minutes Test Plan",
      "price": 10,
      "duration_value": 5,
      "duration_unit": "minutes"
    }
  }
]
```

### GET `/mpesa/transactions/summary`

Get transaction summary with statistics.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | int | No | Reseller ID |
| `router_id` | int | No | Filter by router |
| `start_date` | string | No | ISO format |
| `end_date` | string | No | ISO format |

**Example Response:**
```json
{
  "total_transactions": 52,
  "total_amount": 730.0,
  "status_breakdown": {
    "completed": { "count": 50, "amount": 710.0 },
    "pending": { "count": 1, "amount": 10.0 },
    "failed": { "count": 1, "amount": 10.0 }
  },
  "router_breakdown": {
    "Guest Hotspot Router": {
      "count": 52,
      "amount": 730.0,
      "router_id": 2
    }
  },
  "period": {
    "start_date": "2026-01-01",
    "end_date": "2026-01-10"
  }
}
```

---

## 🌐 Routers

### GET `/routers`

Get all routers for authenticated user.

**Headers:**
```
Authorization: Bearer <token>
```

**Example Response:**
```json
[
  {
    "id": 2,
    "name": "Guest Hotspot Router",
    "ip_address": "192.168.1.1",
    "port": 8728
  }
]
```

### GET `/routers/{router_id}/users`

Get all hotspot users for a specific router.

**Headers:**
```
Authorization: Bearer <token>
```

**Example Response:**
```json
{
  "router_id": 2,
  "router_name": "Guest Hotspot Router",
  "users": [
    {
      "username": "AABBCCDDEEFF",
      "profile": "default",
      "disabled": false,
      "comment": "Guest 5364",
      "uptime_limit": "1h",
      "active": true,
      "session": {
        "address": "192.168.88.100",
        "login_time": "jan/10/2026 15:30:00",
        "uptime": "00:30:00",
        "bytes_in": "1048576",
        "bytes_out": "2097152"
      }
    }
  ],
  "total_users": 10,
  "active_sessions": 3
}
```

---

## 🔐 Authentication

### POST `/auth/login`

Login to get JWT token.

**Request Body:**
```json
{
  "username": "admin",
  "password": "password123"
}
```

**Example Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

---

## Notes

- All timestamps are in ISO 8601 format (UTC)
- Status values: `active`, `inactive`, `expired`
- Payment methods: `mobile_money`, `cash`
- Transaction statuses: `pending`, `completed`, `failed`, `expired`

