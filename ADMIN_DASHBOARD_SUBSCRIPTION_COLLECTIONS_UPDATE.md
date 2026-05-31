# Admin Dashboard Subscription Collections Update Plan

This document is for the future **admin dashboard** update. These screens and actions are for the system owner/admin only and must never be shown in the reseller dashboard.

All endpoints require:

```http
Authorization: Bearer <admin-token>
```

---

## Goal

Update the admin dashboard so the owner can:

- See individual reseller subscription payments instead of only cumulative totals.
- See which completed subscription collections have already been sent to the owner bank account.
- See the cumulative amount not yet sent.
- Configure an owner bank/paybill destination.
- Trigger a B2B transfer of available subscription collections to that destination.

This is separate from reseller payouts. It is money paid by resellers to the platform for their subscriptions.

---

## Important Product Rule

Do not expose these collection/send-to-bank controls to resellers.

Resellers may continue to see their own subscription invoices and payment history through existing reseller subscription endpoints, but they should not see:

- Platform-wide subscription collections.
- Other resellers' subscription payments.
- Owner bank destinations.
- Send-to-bank actions.
- `send_status`, `sent_amount`, `pending_send_amount`, or `unsent_amount` for platform owner transfers.

---

## Recommended Admin Navigation

Add a new admin section:

```text
/admin/subscription-collections
```

Suggested tabs:

- `Overview`
- `Transactions`
- `Bank Destination`
- `Transfer History`

If the current admin dashboard already has a subscriptions page, this can be added as a `Collections` tab under that area.

---

## Overview Tab

Endpoint:

```http
GET /api/admin/subscriptions/collections
```

Response:

```json
{
  "total_collected": 45000.0,
  "completed_sent": 25000.0,
  "pending_send": 5000.0,
  "completed_bank_net": 24800.0,
  "completed_fees": 200.0,
  "available_to_send": 15000.0,
  "fee_preview": {
    "safaricom_fee": 108,
    "kadogo_surcharge": 0,
    "total_fee": 108,
    "net_payout": 14892
  }
}
```

UI requirements:

- Stat cards:
  - `Total subscription collected`
  - `Already sent`
  - `Pending send`
  - `Available to send`
  - `Completed transfer fees`
- Transfer preview card:
  - Gross available amount.
  - Safaricom fee.
  - Kadogo surcharge if any.
  - Net amount expected in the bank/paybill.
- Primary action button: `Send available balance`.
- Disable the send button when `available_to_send <= 0`.

Suggested warning text near the action:

```text
Pending transfers are reserved and already excluded from available balance.
```

---

## Transactions Tab

Endpoint:

```http
GET /api/admin/subscriptions/payments?page=1&per_page=50
```

Supported query parameters:

| Param | Type | Notes |
|-------|------|-------|
| `page` | number | Minimum `1` |
| `per_page` | number | `1` to `200` |
| `reseller_id` | number | Optional reseller filter |
| `status` | string | `pending`, `completed`, `failed` |
| `send_status` | string | `sent`, `partially_sent`, `pending_send`, `unsent`, `not_applicable` |
| `start_date` | string | `YYYY-MM-DD` |
| `end_date` | string | `YYYY-MM-DD` |

Response:

```json
{
  "page": 1,
  "per_page": 50,
  "total": 2,
  "total_pages": 1,
  "summary": {
    "total_collected": 45000.0,
    "completed_sent": 25000.0,
    "pending_send": 5000.0,
    "available_to_send": 15000.0
  },
  "payments": [
    {
      "id": 41,
      "invoice_id": 22,
      "reseller_id": 12,
      "reseller_email": "reseller@example.com",
      "reseller_name": "Example ISP",
      "amount": 650.0,
      "payment_method": "mpesa",
      "payment_reference": "SHK12345ABC",
      "mpesa_checkout_request_id": "ws_CO_...",
      "phone_number": "254712345678",
      "status": "completed",
      "send_status": "unsent",
      "sent_amount": 0.0,
      "pending_send_amount": 0.0,
      "unsent_amount": 650.0,
      "created_at": "2026-06-20T10:21:00"
    }
  ]
}
```

UI requirements:

- Table columns:
  - Date
  - Reseller
  - Invoice ID
  - Amount
  - Payment reference
  - Payment status
  - Bank send status
  - Sent amount
  - Pending amount
  - Unsent amount
- Filters:
  - Payment status.
  - Send status.
  - Date range.
  - Search/filter by reseller if the frontend has reseller lookup available.
- Row click can open a payment detail drawer.

Send status badge mapping:

| Status | Meaning | UI |
|--------|---------|----|
| `unsent` | Completed payment not yet included in owner bank transfer | Warning |
| `pending_send` | Reserved by a pending B2B transfer | Info |
| `partially_sent` | Part of the payment is covered by sent/pending transfers | Mixed/warning |
| `sent` | Covered by completed owner bank transfer | Success |
| `not_applicable` | Payment is pending or failed, so it is not transferable | Muted |

---

## Bank Destination Tab

List endpoint:

```http
GET /api/admin/subscriptions/bank-destinations
```

Create endpoint:

```http
POST /api/admin/subscriptions/bank-destinations
```

Create bank account request:

```json
{
  "method_type": "bank_account",
  "label": "Equity Settlement Account",
  "bank_paybill_number": "247247",
  "bank_account_number": "1234567890"
}
```

Create M-Pesa paybill request:

```json
{
  "method_type": "mpesa_paybill",
  "label": "Owner Paybill",
  "mpesa_paybill_number": "123456"
}
```

List response:

```json
{
  "destinations": [
    {
      "id": 3,
      "user_id": 1,
      "method_type": "bank_account",
      "label": "Equity Settlement Account",
      "is_active": true,
      "bank_paybill_number": "247247",
      "bank_account_number": "1234567890",
      "created_at": "2026-06-20T10:21:00",
      "updated_at": "2026-06-20T10:21:00"
    }
  ]
}
```

UI requirements:

- Show active admin-owned destinations only by default.
- Form fields:
  - Type selector: `Bank account` or `M-Pesa paybill`.
  - Label.
  - Bank paybill number and bank account number for bank accounts.
  - Paybill number for M-Pesa paybill.
- Use the selected destination when sending money, or omit `payment_method_id` to let the backend use the first active eligible destination.

---

## Send To Bank Action

Endpoint:

```http
POST /api/admin/subscriptions/send-to-bank
```

Request:

```json
{
  "payment_method_id": 3
}
```

`payment_method_id` is optional. If omitted, the backend uses the first active eligible admin destination.

Success response:

```json
{
  "message": "Subscription collection transfer initiated",
  "balance_before": 15000.0,
  "destination": {
    "id": 3,
    "method_type": "bank_account",
    "label": "Equity Settlement Account"
  },
  "transaction": {
    "id": 9,
    "amount": 15000.0,
    "fee": 108.0,
    "net_amount": 14892.0,
    "party_a": "123456",
    "party_b": "247247",
    "account_reference": "1234567890",
    "status": "pending",
    "conversation_id": "AG_...",
    "created_at": "2026-06-20T10:21:00"
  }
}
```

UI flow:

1. Fetch `GET /api/admin/subscriptions/collections`.
2. Fetch `GET /api/admin/subscriptions/bank-destinations`.
3. If no destination exists, show setup form before allowing transfer.
4. Show confirmation modal:
   - Gross amount.
   - Fees.
   - Net payout.
   - Destination label and account/paybill.
5. Submit `POST /api/admin/subscriptions/send-to-bank`.
6. On success, refresh:
   - Collections overview.
   - Transactions table.
   - Transfer history.

Error handling:

| Status | Meaning | UI |
|--------|---------|----|
| `400` | No available balance, no destination, invalid destination, or amount too small after fees | Show backend `detail` |
| `403` | User is not admin | Redirect or show admin-only message |
| `500` | B2B initiation failed | Show retry option and inspect backend logs |

---

## Transfer History Tab

The existing B2B transaction history endpoint can be reused.

Endpoint:

```http
GET /api/admin/b2b-transactions?reseller_id={admin_user_id}
```

Important filtering rule:

- Only show transfers where `triggered_by` is `subscription_owner` if the backend exposes that field in the response.
- If the current response does not expose `triggered_by`, add a small backend enhancement later to return it or add a dedicated endpoint for subscription-owner transfer history.

Current response shape includes:

```json
{
  "transactions": [
    {
      "id": 9,
      "reseller_id": 1,
      "amount": 15000.0,
      "fee": 108.0,
      "net_amount": 14892.0,
      "party_a": "123456",
      "party_b": "247247",
      "account_reference": "1234567890",
      "status": "completed",
      "result_code": "0",
      "result_desc": "The service request is processed successfully.",
      "transaction_id": "SHK...",
      "created_at": "2026-06-20T10:21:00",
      "completed_at": "2026-06-20T10:22:00"
    }
  ]
}
```

UI requirements:

- Show amount, fee, net amount, destination, status, result description, M-Pesa transaction id, created date, completed date.
- Status badge mapping:
  - `pending`: info/warning
  - `completed`: success
  - `failed`: danger
  - `timeout`: warning

---

## Existing Admin Subscription Context

These existing admin endpoints remain useful for subscription management:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/admin/subscriptions` | List reseller subscription statuses and cumulative totals |
| `GET /api/admin/subscriptions/revenue` | Subscription revenue dashboard |
| `GET /api/admin/subscriptions/{reseller_id}` | Full reseller subscription detail |
| `POST /api/admin/subscriptions/{reseller_id}/verify-payments` | Verify pending payments for one reseller |

The new collections UI should complement these pages. It should not replace reseller subscription management.

---

## TypeScript Shapes

```typescript
type SubscriptionPaymentStatus = "pending" | "completed" | "failed";
type BankSendStatus =
  | "sent"
  | "partially_sent"
  | "pending_send"
  | "unsent"
  | "not_applicable";

interface AdminSubscriptionCollectionsSummary {
  total_collected: number;
  completed_sent: number;
  pending_send: number;
  completed_bank_net: number;
  completed_fees: number;
  available_to_send: number;
  fee_preview: {
    safaricom_fee: number;
    kadogo_surcharge: number;
    total_fee: number;
    net_payout: number;
  };
}

interface AdminSubscriptionPaymentRow {
  id: number;
  invoice_id: number | null;
  reseller_id: number;
  reseller_email: string;
  reseller_name: string | null;
  amount: number;
  payment_method: string;
  payment_reference: string | null;
  mpesa_checkout_request_id: string | null;
  phone_number: string | null;
  status: SubscriptionPaymentStatus;
  send_status: BankSendStatus;
  sent_amount: number;
  pending_send_amount: number;
  unsent_amount: number;
  created_at: string | null;
}

interface OwnerBankDestination {
  id: number;
  user_id: number;
  method_type: "bank_account" | "mpesa_paybill";
  label: string;
  is_active: boolean;
  bank_paybill_number?: string;
  bank_account_number?: string;
  mpesa_paybill_number?: string;
  created_at: string | null;
  updated_at: string | null;
}
```

---

## Implementation Checklist

- Add admin-only route/page for subscription collections.
- Add overview stat cards from `GET /api/admin/subscriptions/collections`.
- Add transaction table from `GET /api/admin/subscriptions/payments`.
- Add filters for payment status, send status, date range, and reseller.
- Add bank destination list and create form.
- Add send-to-bank confirmation modal.
- Refresh overview and transaction list after a successful transfer.
- Add transfer history tab, using B2B history or a future dedicated endpoint.
- Hide all collection transfer UI for reseller users.
- Add frontend route guards so only `role === "admin"` can access this section.

