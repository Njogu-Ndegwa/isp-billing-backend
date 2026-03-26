# Reseller Account Statement & Transaction Charges API Reference

All endpoints require `Authorization: Bearer <token>`.

Base URL: your server (e.g. `https://api.yourisp.com`)

---

## Overview

This feature adds:

1. **Admin endpoints** to add and view transaction charges (deductions) against a reseller's balance
2. **Reseller endpoint** to see a full account statement: payouts received, charges deducted, and net balance
3. **Updated balance formula** everywhere: `unpaid_balance = mpesa_revenue - payouts - transaction_charges`

---

## PART 1 — Admin Endpoints

These require the logged-in user to have `role: "admin"`.

---

### 1. Add Transaction Charge

Deduct a fee from the reseller's balance (bank fees, M-Pesa withdrawal charges, etc.). The charge is immediately visible to the reseller on their account statement.

**POST** `/api/admin/resellers/{reseller_id}/transaction-charges`

#### Request Body

```json
{
  "amount": 150.00,
  "description": "M-Pesa withdrawal fee",
  "reference": "TXN-FEE-2026-0042"
}
```

| Field         | Type   | Required | Notes                                      |
|---------------|--------|----------|--------------------------------------------|
| `amount`      | float  | Yes      | Must be > 0                                |
| `description` | string | Yes      | What the charge is for (shown to reseller) |
| `reference`   | string | No       | Optional external reference number         |

#### Response `200 OK`

```json
{
  "charge": {
    "id": 7,
    "reseller_id": 3,
    "amount": 150.0,
    "description": "M-Pesa withdrawal fee",
    "reference": "TXN-FEE-2026-0042",
    "created_by": 1,
    "created_at": "2026-03-27T10:30:00"
  },
  "unpaid_balance": 4350.0
}
```

| Field                  | Type   | Notes                                                        |
|------------------------|--------|--------------------------------------------------------------|
| `charge`               | object | The newly created charge record                              |
| `charge.id`            | int    | Unique ID of this charge                                     |
| `charge.reseller_id`   | int    | Which reseller was charged                                   |
| `charge.amount`        | float  | The deduction amount                                         |
| `charge.description`   | string | Reason for the charge                                        |
| `charge.reference`     | string | External reference (or null)                                 |
| `charge.created_by`    | int    | Admin user ID who recorded the charge                        |
| `charge.created_at`    | string | ISO 8601 timestamp                                          |
| `unpaid_balance`       | float  | Updated balance after applying this charge                   |

#### Error Responses

| Status | Detail                     |
|--------|----------------------------|
| 400    | "Amount must be positive"  |
| 400    | "Description is required"  |
| 403    | "Admin access required"    |
| 404    | "Reseller not found"       |

---

### 2. List Transaction Charges

Get paginated list of all transaction charges for a reseller.

**GET** `/api/admin/resellers/{reseller_id}/transaction-charges`

#### Query Parameters

| Param        | Type   | Default | Notes                          |
|--------------|--------|---------|--------------------------------|
| `page`       | int    | 1       | Page number (min 1)            |
| `per_page`   | int    | 50      | Items per page (1–200)         |
| `start_date` | string | —       | Filter from date (YYYY-MM-DD)  |
| `end_date`   | string | —       | Filter to date (YYYY-MM-DD)    |

#### Example Request

```
GET /api/admin/resellers/3/transaction-charges?page=1&per_page=20
```

#### Response `200 OK`

```json
{
  "reseller_id": 3,
  "page": 1,
  "per_page": 20,
  "total_count": 4,
  "total_pages": 1,
  "summary": {
    "total_charges": 4,
    "total_amount": 580.0
  },
  "charges": [
    {
      "id": 7,
      "amount": 150.0,
      "description": "M-Pesa withdrawal fee",
      "reference": "TXN-FEE-2026-0042",
      "created_by": 1,
      "created_at": "2026-03-27T10:30:00"
    },
    {
      "id": 5,
      "amount": 200.0,
      "description": "Bank transfer charge - March payout",
      "reference": "BANK-FEE-003",
      "created_by": 1,
      "created_at": "2026-03-20T14:15:00"
    },
    {
      "id": 3,
      "amount": 80.0,
      "description": "M-Pesa transaction fee",
      "reference": null,
      "created_by": 1,
      "created_at": "2026-03-15T09:00:00"
    },
    {
      "id": 1,
      "amount": 150.0,
      "description": "M-Pesa withdrawal fee - February",
      "reference": "TXN-FEE-2026-0021",
      "created_by": 1,
      "created_at": "2026-02-28T16:45:00"
    }
  ]
}
```

| Field                      | Type   | Notes                               |
|----------------------------|--------|-------------------------------------|
| `reseller_id`              | int    | The reseller these charges belong to|
| `page`                     | int    | Current page                        |
| `per_page`                 | int    | Items per page                      |
| `total_count`              | int    | Total charge records matching       |
| `total_pages`              | int    | Total pages available               |
| `summary.total_charges`    | int    | Count of charges in range           |
| `summary.total_amount`     | float  | Sum of all charges in range         |
| `charges[].id`             | int    | Charge ID                           |
| `charges[].amount`         | float  | Deduction amount                    |
| `charges[].description`    | string | What the charge was for             |
| `charges[].reference`      | string | External reference (or null)        |
| `charges[].created_by`     | int    | Admin user ID who added it          |
| `charges[].created_at`     | string | ISO 8601 timestamp                  |

---

### Updated Fields in Existing Admin Endpoints

These existing endpoints now include transaction charge data:

#### GET `/api/admin/resellers` (List Resellers)

Each reseller object now includes:

```json
{
  "id": 3,
  "email": "reseller@example.com",
  "total_revenue": 25000.0,
  "mpesa_revenue": 18000.0,
  "unpaid_balance": 4350.0,
  "total_transaction_charges": 580.0,
  "...other fields..."
}
```

**New field:** `total_transaction_charges` — sum of all charges applied to this reseller.  
**Updated field:** `unpaid_balance` now subtracts charges: `mpesa_revenue - payouts - charges`.

---

#### GET `/api/admin/resellers/{reseller_id}` (Reseller Detail)

The `payouts` object now includes charges, and there's a new `recent_transaction_charges` array:

```json
{
  "id": 3,
  "email": "reseller@example.com",
  "payouts": {
    "total_paid": 13070.0,
    "total_transaction_charges": 580.0,
    "last_payout_date": "2026-03-25T12:00:00",
    "unpaid_balance": 4350.0
  },
  "recent_transaction_charges": [
    {
      "id": 7,
      "amount": 150.0,
      "description": "M-Pesa withdrawal fee",
      "reference": "TXN-FEE-2026-0042",
      "created_at": "2026-03-27T10:30:00"
    }
  ],
  "...other fields..."
}
```

**New field:** `payouts.total_transaction_charges` — total deductions.  
**New field:** `recent_transaction_charges` — latest 5 charges (quick preview).  
**Updated field:** `payouts.unpaid_balance` now subtracts charges.

---

#### GET `/api/admin/dashboard`

The `payouts` section now includes:

```json
{
  "payouts": {
    "total_paid": 45000.0,
    "total_transaction_charges": 3200.0,
    "total_unpaid": 12800.0
  },
  "...other fields..."
}
```

**New field:** `total_transaction_charges` — platform-wide total charges across all resellers.  
**Updated field:** `total_unpaid` now subtracts charges.

---

## PART 2 — Reseller Endpoint

This endpoint is for the reseller themselves (any authenticated user, uses their own `user.id`).

---

### 3. Account Statement

Shows the reseller their full financial picture: how much was collected on their behalf, what they've been paid, what charges were deducted, and their current balance.

**GET** `/api/reseller/account-statement`

#### Query Parameters

| Param        | Type   | Default | Notes                                          |
|--------------|--------|---------|-------------------------------------------------|
| `page`       | int    | 1       | Page number for entries list                    |
| `per_page`   | int    | 50      | Entries per page                                |
| `start_date` | string | —       | Filter entries from date (YYYY-MM-DD)           |
| `end_date`   | string | —       | Filter entries to date (YYYY-MM-DD)             |

**Note:** The `balance` section always shows all-time totals regardless of date filters. Only the `entries` list and `period_summary` are filtered by date.

#### Example Request

```
GET /api/reseller/account-statement?page=1&per_page=20
```

#### Response `200 OK`

```json
{
  "balance": {
    "total_system_collected": 18000.0,
    "total_paid_to_you": 13070.0,
    "total_transaction_charges": 580.0,
    "unpaid_balance": 4350.0
  },
  "period_summary": {
    "total_payouts": 13070.0,
    "total_charges": 580.0,
    "net": 12490.0
  },
  "page": 1,
  "per_page": 20,
  "total_entries": 6,
  "total_pages": 1,
  "entries": [
    {
      "type": "charge",
      "id": 7,
      "amount": 150.0,
      "description": "M-Pesa withdrawal fee",
      "reference": "TXN-FEE-2026-0042",
      "notes": null,
      "date": "2026-03-27T10:30:00"
    },
    {
      "type": "payout",
      "id": 12,
      "amount": 5000.0,
      "description": "Payout via M-Pesa",
      "reference": "PAYOUT-2026-012",
      "notes": "March second payout",
      "date": "2026-03-25T12:00:00"
    },
    {
      "type": "charge",
      "id": 5,
      "amount": 200.0,
      "description": "Bank transfer charge - March payout",
      "reference": "BANK-FEE-003",
      "notes": null,
      "date": "2026-03-20T14:15:00"
    },
    {
      "type": "payout",
      "id": 9,
      "amount": 4500.0,
      "description": "Payout via Bank Transfer",
      "reference": "PAYOUT-2026-009",
      "notes": "March first payout",
      "date": "2026-03-10T09:30:00"
    },
    {
      "type": "charge",
      "id": 3,
      "amount": 80.0,
      "description": "M-Pesa transaction fee",
      "reference": null,
      "notes": null,
      "date": "2026-03-05T09:00:00"
    },
    {
      "type": "payout",
      "id": 5,
      "amount": 3570.0,
      "description": "Payout via M-Pesa",
      "reference": "PAYOUT-2026-005",
      "notes": "February payout",
      "date": "2026-02-28T16:00:00"
    }
  ]
}
```

#### Response Field Reference

**`balance` (all-time, always unfiltered)**

| Field                       | Type  | Notes                                                                |
|-----------------------------|-------|----------------------------------------------------------------------|
| `total_system_collected`    | float | Total M-Pesa revenue the system collected on behalf of this reseller |
| `total_paid_to_you`         | float | Sum of all payouts sent to the reseller                              |
| `total_transaction_charges` | float | Sum of all deductions (fees, charges)                                |
| `unpaid_balance`            | float | `collected - paid - charges` = what the admin still owes             |

**`period_summary` (filtered by start_date/end_date)**

| Field           | Type  | Notes                                      |
|-----------------|-------|--------------------------------------------|
| `total_payouts` | float | Payouts in the selected period             |
| `total_charges` | float | Charges in the selected period             |
| `net`           | float | `payouts - charges` for the period         |

**`entries[]` (merged feed, newest first)**

| Field         | Type   | Notes                                                         |
|---------------|--------|---------------------------------------------------------------|
| `type`        | string | `"payout"` or `"charge"`                                     |
| `id`          | int    | ID of the payout or charge record                             |
| `amount`      | float  | The amount (always positive; context from `type`)             |
| `description` | string | For payouts: `"Payout via {method}"`. For charges: admin text |
| `reference`   | string | External reference number (or null)                           |
| `notes`       | string | Payout notes from admin (null for charges)                    |
| `date`        | string | ISO 8601 timestamp                                           |

---

## TypeScript Interfaces (for frontend)

```typescript
// POST /api/admin/resellers/:id/transaction-charges
interface TransactionChargeRequest {
  amount: number;
  description: string;
  reference?: string;
}

interface TransactionChargeResponse {
  charge: {
    id: number;
    reseller_id: number;
    amount: number;
    description: string;
    reference: string | null;
    created_by: number;
    created_at: string;
  };
  unpaid_balance: number;
}

// GET /api/admin/resellers/:id/transaction-charges
interface TransactionChargeListResponse {
  reseller_id: number;
  page: number;
  per_page: number;
  total_count: number;
  total_pages: number;
  summary: {
    total_charges: number;
    total_amount: number;
  };
  charges: Array<{
    id: number;
    amount: number;
    description: string;
    reference: string | null;
    created_by: number;
    created_at: string;
  }>;
}

// GET /api/reseller/account-statement
interface AccountStatementResponse {
  balance: {
    total_system_collected: number;
    total_paid_to_you: number;
    total_transaction_charges: number;
    unpaid_balance: number;
  };
  period_summary: {
    total_payouts: number;
    total_charges: number;
    net: number;
  };
  page: number;
  per_page: number;
  total_entries: number;
  total_pages: number;
  entries: Array<AccountStatementEntry>;
}

interface AccountStatementEntry {
  type: "payout" | "charge";
  id: number;
  amount: number;
  description: string;
  reference: string | null;
  notes: string | null;
  date: string;
}
```

---

## Quick Reference

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/admin/resellers/{id}/transaction-charges` | POST | Admin | Add a transaction charge |
| `/api/admin/resellers/{id}/transaction-charges` | GET | Admin | List charges (paginated) |
| `/api/reseller/account-statement` | GET | Reseller | View account statement |
