# C2B Paybill — Frontend Integration Guide

Backend is live. This doc covers every API surface the frontend needs to integrate for C2B Paybill auto-activation (PPPoE customers).

## What changed for the frontend

Two new fields on every customer object, six new endpoints, and a new "Unmatched Payments" workflow.

### New fields on existing customer responses

These fields are now present in `GET /api/customers`, `GET /api/customers/{id}`, and `POST /api/customers/register`:

| Field | Type | Description |
|---|---|---|
| `account_number` | `string` (8 digits) | Luhn-validated number the customer types into M-Pesa Paybill to pay. Display prominently on customer profile. |
| `wallet_credit_kes` | `integer` | Overpayment credit in KES. Auto-applied on next renewal. Display as "KES X credit" badge on profile. |

### New endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/c2b/unmatched` | Reseller / Admin | List payments that couldn't auto-apply |
| `POST` | `/api/c2b/unmatched/{id}/attribute` | Reseller / Admin | Manually credit a payment to a customer |
| `POST` | `/api/admin/c2b/register-platform-paybill` | Admin only | Register platform paybill URLs with Safaricom |
| `POST` | `/api/payment-methods/{id}/register-c2b` | Reseller | Register reseller's own paybill with Safaricom |
| `POST` | `/api/c2b/validation` | None (Safaricom webhook) | No frontend work needed |
| `POST` | `/api/c2b/confirmation` | None (Safaricom webhook) | No frontend work needed |

---

## UI changes needed

### 1. Customer profile — account number card

Display on every customer detail page:

```
┌──────────────────────────────────────────────┐
│  Paybill Payment Instructions                │
│                                              │
│  Paybill Number:   600980        [Copy]      │
│  Account Number:   41234567      [Copy]      │
│  Amount:           KES 500                   │
│                                              │
│  Wallet Credit:    KES 150                   │
└──────────────────────────────────────────────┘
```

- **Paybill Number**: Use the platform shortcode (from app config) for resellers without their own paybill. For resellers with `MPESA_PAYBILL_WITH_KEYS`, use their `mpesa_shortcode` from `GET /api/payment-methods`.
- **Account Number**: From `customer.account_number`. Add a copy-to-clipboard button — this is what the reseller gives the customer.
- **Amount**: From `customer.plan.price`.
- **Wallet Credit**: From `customer.wallet_credit_kes`. Only show if > 0.

### 2. Customer list — account number column

Add `account_number` as a searchable/filterable column in the customer table.

### 3. Customer registration — show account number in response

After `POST /api/customers/register` succeeds, display the generated `account_number` prominently so the reseller can immediately share it with the customer.

### 4. Unmatched payments page (new)

New page accessible from the reseller dashboard sidebar. Lists payments Safaricom confirmed but the system couldn't auto-apply.

**Fetch:** `GET /api/c2b/unmatched?resolved=false&limit=100`

**Table columns:**

| Column | Source |
|---|---|
| Trans ID | `transaction.trans_id` |
| Amount | `transaction.trans_amount` |
| Account Typed | `transaction.bill_ref_number` |
| Phone | `transaction.msisdn` |
| Reason | `reason` (see reason labels below) |
| Received | `transaction.received_at` |
| Action | "Attribute" button |

**Reason labels for display:**

| API value | Display label |
|---|---|
| `unknown_account` | Unknown account number |
| `amount_too_low` | Amount below plan price |
| `wrong_reseller` | Wrong paybill used |
| `invalid_luhn` | Invalid account number (typo) |

**"Attribute" button flow:**
1. Open a modal with a customer search/picker
2. On select, call `POST /api/c2b/unmatched/{id}/attribute` with `{ "customer_id": X, "notes": "optional" }`
3. On success, remove the row from the list (or move to "Resolved" tab)
4. Show `new_wallet_credit_kes` in a success toast

**Resolved tab:** Call `GET /api/c2b/unmatched?resolved=true` to show historically resolved payments.

### 5. Payment methods page — C2B registration button

For payment methods with `method_type = "mpesa_paybill_with_keys"`, add a **"Register for C2B"** button.

**On click:**
1. Prompt for confirmation URL and validation URL (pre-fill with defaults based on the app's base URL)
2. Call `POST /api/payment-methods/{id}/register-c2b` with:
   ```json
   {
     "confirmation_url": "https://yourdomain.com/api/c2b/confirmation",
     "validation_url": "https://yourdomain.com/api/c2b/validation",
     "response_type": "Completed"
   }
   ```
3. On success, show Safaricom's response and update the UI to show "C2B Registered" with the `c2b_registered_at` timestamp

**Already registered indicator:** If `c2b_registered_at` is not null on a payment method, show a green badge "C2B Active" instead of the register button.

### 6. Admin page — platform paybill registration

Admin-only section. Similar to #5 but calls `POST /api/admin/c2b/register-platform-paybill`. This registers the platform's shared paybill that resellers without API keys use.

---

## API reference

### GET /api/customers

Returns an array. Each object now includes:

```json
{
  "id": 1,
  "name": "John Doe",
  "phone": "254712345678",
  "mac_address": "00:1A:2B:3C:4D:5E",
  "pppoe_username": "pppoe_254712345678",
  "pppoe_password": "aB3cD4eF5gH6",
  "static_ip": null,
  "status": "active",
  "expiry": "2026-06-23T10:30:45",
  "created_at": "2026-05-24T10:30:45",
  "plan_id": 5,
  "router_id": 2,
  "account_number": "41234567",
  "wallet_credit_kes": 150,
  "plan": {
    "id": 5,
    "name": "Premium 10Mbps",
    "price": 500,
    "connection_type": "pppoe"
  },
  "router": {
    "id": 2,
    "name": "Main Router"
  }
}
```

**New fields:** `account_number`, `wallet_credit_kes`

**Query params:** `?router_id=N` (optional, filters by router)

---

### GET /api/customers/{customer_id}

Same shape as above, single object.

---

### POST /api/customers/register

**Request:**

```json
{
  "name": "Jane Doe",
  "phone": "254712345678",
  "plan_id": 5,
  "router_id": 2,
  "mac_address": "00:1A:2B:3C:4D:5E",
  "pppoe_username": null,
  "pppoe_password": null,
  "static_ip": null
}
```

**Response** (note `account_number` is now included):

```json
{
  "id": 42,
  "name": "Jane Doe",
  "phone": "254712345678",
  "mac_address": "00:1A:2B:3C:4D:5E",
  "pppoe_username": "pppoe_254712345678",
  "static_ip": null,
  "status": "inactive",
  "plan_id": 5,
  "router_id": 2,
  "user_id": 10,
  "account_number": "41234567",
  "expiry": null,
  "created_at": "2026-05-24T10:30:45"
}
```

---

### GET /api/c2b/unmatched

**Query params:**
- `resolved` (bool, default `false`) — include resolved payments
- `limit` (int, default `100`, max `500`)

**Response:**

```json
[
  {
    "id": 1,
    "reason": "unknown_account",
    "resolved_at": null,
    "resolved_by_user_id": null,
    "resolution_customer_id": null,
    "notes": null,
    "assigned_reseller_id": 10,
    "transaction": {
      "id": 42,
      "trans_id": "RJ7T8K9MNP",
      "bill_ref_number": "99999999",
      "trans_amount": 500.0,
      "msisdn": "254712345678",
      "business_shortcode": "600980",
      "received_at": "2026-05-24T10:30:45"
    }
  }
]
```

**Scoping:** Resellers see only payments assigned to them. Admins see all.

---

### POST /api/c2b/unmatched/{id}/attribute

**Request:**

```json
{
  "customer_id": 42,
  "notes": "Customer typed wrong account number"
}
```

**Response (success):**

```json
{
  "ok": true,
  "customer_id": 42,
  "new_wallet_credit_kes": 0,
  "c2b_transaction_id": 15
}
```

**Error responses:**
- `404` — unmatched payment or customer not found
- `403` — not your payment / not your customer
- `409` — already resolved
- `400` — amount + wallet still below plan price

---

### POST /api/admin/c2b/register-platform-paybill

**Auth:** Admin only

**Request:**

```json
{
  "confirmation_url": "https://api.yourdomain.com/api/c2b/confirmation",
  "validation_url": "https://api.yourdomain.com/api/c2b/validation",
  "response_type": "Completed"
}
```

**Response:** Safaricom's raw response:

```json
{
  "ResponseCode": "0",
  "ResponseDescription": "success"
}
```

---

### POST /api/payment-methods/{id}/register-c2b

**Auth:** Reseller (must own the payment method)

**Prerequisite:** Payment method must be `method_type = "mpesa_paybill_with_keys"` with shortcode + consumer credentials configured.

**Request:**

```json
{
  "confirmation_url": "https://api.yourdomain.com/api/c2b/confirmation",
  "validation_url": "https://api.yourdomain.com/api/c2b/validation",
  "response_type": "Completed"
}
```

**Response:** Same as platform registration (Safaricom's raw response).

**Side effect:** Updates the payment method's `c2b_registered_at` timestamp.

---

## Account number format

- **Length:** exactly 8 characters
- **Characters:** digits only (0-9)
- **Validation:** Luhn algorithm (same as credit card check digits)
- **First 7 digits:** random base
- **8th digit:** Luhn check digit
- **Example:** `41234567` where `7` is the computed check digit
- **Uniqueness:** globally unique across all customers
- **Auto-generated:** assigned at customer registration, no user input needed

**Frontend validation (optional but recommended):**

```javascript
function isValidAccountNumber(value) {
  if (!/^\d{8}$/.test(value)) return false;
  const digits = value.split('').map(Number);
  let sum = 0;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i];
    if ((digits.length - 1 - i) % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}
```

## Wallet credit behavior

- **Type:** integer (KES, no fractions)
- **Range:** 0 or positive (never negative)
- **How it fills:** when a customer overpays via Paybill, the excess is stored
- **How it drains:** on next Paybill payment, wallet is applied first before checking if the amount covers the plan price
- **Display:** show on customer profile as "Wallet Credit: KES X" when > 0
- **Example flow:**
  1. Plan costs KES 500
  2. Customer pays KES 700 → activated, wallet = KES 200
  3. Next month, customer pays KES 400 → effective = 400 + 200 = 600 ≥ 500 → activated, wallet = KES 100
  4. Next month, customer pays KES 300 → effective = 300 + 100 = 400 < 500 → NOT activated, payment goes to unmatched queue

## Status values

| Value | Meaning |
|---|---|
| `active` | Customer has been paid for and provisioned |
| `inactive` | Expired or not yet paid |
| `pending` | Just registered, awaiting first payment |

## Connection types

| Value | Meaning | C2B supported? |
|---|---|---|
| `pppoe` | PPPoE broadband | Yes — auto-activates on Paybill payment |
| `hotspot` | WiFi hotspot | Not yet — uses STK Push via captive portal |
| `static_ip` | Static IP assignment | Not yet |
