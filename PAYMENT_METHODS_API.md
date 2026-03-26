# Payment Methods API Reference

All endpoints require `Authorization: Bearer <token>` unless noted otherwise.

Base URL: your server (e.g. `https://api.yourisp.com`)

---

## PART 1 — Reseller Dashboard Endpoints

These are for the **reseller settings page** where resellers create/manage their payment methods and assign them to routers.

---

### 1. Create Payment Method

`POST /api/payment-methods`

**Auth**: Bearer token required

---

#### 1A. Create Bank Account Method

**Request:**

```json
POST /api/payment-methods
Content-Type: application/json
Authorization: Bearer <token>

{
  "method_type": "bank_account",
  "label": "My KCB Account",
  "bank_paybill_number": "522522",
  "bank_account_number": "1234567890"
}
```

**Response `200 OK`:**

```json
{
  "id": 1,
  "user_id": 5,
  "method_type": "bank_account",
  "label": "My KCB Account",
  "is_active": true,
  "bank_paybill_number": "522522",
  "bank_account_number": "1234567890",
  "created_at": "2026-03-26T10:30:00",
  "updated_at": "2026-03-26T10:30:00"
}
```

---

#### 1B. Create M-Pesa Paybill (No Keys — System Collects)

System collects money using its own M-Pesa credentials. Admin manually pays the reseller later.

**Request:**

```json
POST /api/payment-methods
Content-Type: application/json
Authorization: Bearer <token>

{
  "method_type": "mpesa_paybill",
  "label": "My Paybill (System Collects)",
  "mpesa_paybill_number": "174379"
}
```

**Response `200 OK`:**

```json
{
  "id": 2,
  "user_id": 5,
  "method_type": "mpesa_paybill",
  "label": "My Paybill (System Collects)",
  "is_active": true,
  "mpesa_paybill_number": "174379",
  "created_at": "2026-03-26T10:35:00",
  "updated_at": "2026-03-26T10:35:00"
}
```

---

#### 1C. Create M-Pesa Paybill/Till WITH API Keys (Direct Collection)

Money goes directly into the reseller's M-Pesa account. Reseller provides all 4 credentials.

**Request:**

```json
POST /api/payment-methods
Content-Type: application/json
Authorization: Bearer <token>

{
  "method_type": "mpesa_paybill_with_keys",
  "label": "My Direct M-Pesa",
  "mpesa_shortcode": "174379",
  "mpesa_passkey": "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919",
  "mpesa_consumer_key": "GjVxc8sOT7gfRYz4aIKdH9l5JLlZnKbc",
  "mpesa_consumer_secret": "T8bw4F3xkP9qL2mN"
}
```

**Response `200 OK`:**

```json
{
  "id": 3,
  "user_id": 5,
  "method_type": "mpesa_paybill_with_keys",
  "label": "My Direct M-Pesa",
  "is_active": true,
  "mpesa_shortcode": "174379",
  "mpesa_passkey": "****************************c919",
  "mpesa_consumer_key": "****************************Knbc",
  "mpesa_consumer_secret": "**************2mN",
  "created_at": "2026-03-26T10:40:00",
  "updated_at": "2026-03-26T10:40:00"
}
```

> Secrets are always masked in responses. Only the last 4 characters are visible.

---

#### 1D. Create ZenoPay Method (Tanzania)

For Tanzanian mobile money (M-Pesa TZ, Airtel, Tigo Pesa, Halopesa).

**Request:**

```json
POST /api/payment-methods
Content-Type: application/json
Authorization: Bearer <token>

{
  "method_type": "zenopay",
  "label": "My ZenoPay TZ",
  "zenopay_api_key": "zp_live_abc123def456ghi789"
}
```

**Response `200 OK`:**

```json
{
  "id": 4,
  "user_id": 5,
  "method_type": "zenopay",
  "label": "My ZenoPay TZ",
  "is_active": true,
  "zenopay_api_key": "*****************i789",
  "created_at": "2026-03-26T10:45:00",
  "updated_at": "2026-03-26T10:45:00"
}
```

---

#### Create — Error Responses

**`400` — Invalid method_type:**

```json
{
  "detail": "Invalid method_type. Must be one of: bank_account, mpesa_paybill, mpesa_paybill_with_keys, zenopay"
}
```

**`400` — Missing required fields:**

```json
{
  "detail": "Missing required fields for M-Pesa with keys: mpesa_passkey, mpesa_consumer_secret"
}
```

```json
{
  "detail": "bank_paybill_number and bank_account_number are required for Bank Account"
}
```

```json
{
  "detail": "mpesa_paybill_number is required for M-Pesa Paybill (no keys)"
}
```

```json
{
  "detail": "zenopay_api_key is required for ZenoPay"
}
```

#### Required Fields Per Type

| method_type | Required Fields |
|---|---|
| `bank_account` | `label`, `bank_paybill_number`, `bank_account_number` |
| `mpesa_paybill` | `label`, `mpesa_paybill_number` |
| `mpesa_paybill_with_keys` | `label`, `mpesa_shortcode`, `mpesa_passkey`, `mpesa_consumer_key`, `mpesa_consumer_secret` |
| `zenopay` | `label`, `zenopay_api_key` |

---

### 2. List Payment Methods

`GET /api/payment-methods`

**Auth**: Bearer token required

**Query Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `include_inactive` | boolean | `false` | Set `true` to also show deactivated methods |

**Request:**

```
GET /api/payment-methods
Authorization: Bearer <token>
```

Or with inactive:

```
GET /api/payment-methods?include_inactive=true
Authorization: Bearer <token>
```

**Response `200 OK`:**

```json
[
  {
    "id": 1,
    "user_id": 5,
    "method_type": "bank_account",
    "label": "My KCB Account",
    "is_active": true,
    "bank_paybill_number": "522522",
    "bank_account_number": "1234567890",
    "created_at": "2026-03-26T10:30:00",
    "updated_at": "2026-03-26T10:30:00"
  },
  {
    "id": 2,
    "user_id": 5,
    "method_type": "mpesa_paybill",
    "label": "My Paybill (System Collects)",
    "is_active": true,
    "mpesa_paybill_number": "174379",
    "created_at": "2026-03-26T10:35:00",
    "updated_at": "2026-03-26T10:35:00"
  },
  {
    "id": 3,
    "user_id": 5,
    "method_type": "mpesa_paybill_with_keys",
    "label": "My Direct M-Pesa",
    "is_active": true,
    "mpesa_shortcode": "174379",
    "mpesa_passkey": "****************************c919",
    "mpesa_consumer_key": "****************************Knbc",
    "mpesa_consumer_secret": "**************2mN",
    "created_at": "2026-03-26T10:40:00",
    "updated_at": "2026-03-26T10:40:00"
  },
  {
    "id": 4,
    "user_id": 5,
    "method_type": "zenopay",
    "label": "My ZenoPay TZ",
    "is_active": true,
    "zenopay_api_key": "*****************i789",
    "created_at": "2026-03-26T10:45:00",
    "updated_at": "2026-03-26T10:45:00"
  }
]
```

> Each item only includes fields relevant to its `method_type`. Empty array `[]` if no methods configured.

---

### 3. Get Single Payment Method

`GET /api/payment-methods/{method_id}`

**Auth**: Bearer token required

**Request:**

```
GET /api/payment-methods/3
Authorization: Bearer <token>
```

**Response `200 OK`:**

```json
{
  "id": 3,
  "user_id": 5,
  "method_type": "mpesa_paybill_with_keys",
  "label": "My Direct M-Pesa",
  "is_active": true,
  "mpesa_shortcode": "174379",
  "mpesa_passkey": "****************************c919",
  "mpesa_consumer_key": "****************************Knbc",
  "mpesa_consumer_secret": "**************2mN",
  "created_at": "2026-03-26T10:40:00",
  "updated_at": "2026-03-26T10:40:00"
}
```

**Response `404 Not Found`:**

```json
{
  "detail": "Payment method not found"
}
```

---

### 4. Update Payment Method

`PUT /api/payment-methods/{method_id}`

**Auth**: Bearer token required

Only include the fields you want to change. Omitted fields stay unchanged. You can update any combination of fields.

**Request — Update label only:**

```json
PUT /api/payment-methods/3
Content-Type: application/json
Authorization: Bearer <token>

{
  "label": "My Updated M-Pesa"
}
```

**Request — Update credentials:**

```json
PUT /api/payment-methods/3
Content-Type: application/json
Authorization: Bearer <token>

{
  "mpesa_shortcode": "654321",
  "mpesa_consumer_key": "new-consumer-key-here",
  "mpesa_consumer_secret": "new-consumer-secret-here"
}
```

**Request — Deactivate (disable) via update:**

```json
PUT /api/payment-methods/3
Content-Type: application/json
Authorization: Bearer <token>

{
  "is_active": false
}
```

**Response `200 OK`:**

Returns the full updated payment method:

```json
{
  "id": 3,
  "user_id": 5,
  "method_type": "mpesa_paybill_with_keys",
  "label": "My Updated M-Pesa",
  "is_active": true,
  "mpesa_shortcode": "654321",
  "mpesa_passkey": "****************************c919",
  "mpesa_consumer_key": "****************************here",
  "mpesa_consumer_secret": "****************************here",
  "created_at": "2026-03-26T10:40:00",
  "updated_at": "2026-03-26T12:15:00"
}
```

#### All Updatable Fields

| Field | Type | Description |
|---|---|---|
| `label` | string | Display name |
| `is_active` | boolean | Enable/disable the method |
| `bank_paybill_number` | string | Bank paybill |
| `bank_account_number` | string | Bank account |
| `mpesa_paybill_number` | string | Paybill number (no keys) |
| `mpesa_shortcode` | string | M-Pesa shortcode (with keys) |
| `mpesa_passkey` | string | M-Pesa passkey — re-encrypted on update |
| `mpesa_consumer_key` | string | M-Pesa consumer key — re-encrypted on update |
| `mpesa_consumer_secret` | string | M-Pesa consumer secret — re-encrypted on update |
| `zenopay_api_key` | string | ZenoPay API key — re-encrypted on update |

---

### 5. Delete (Deactivate) Payment Method

`DELETE /api/payment-methods/{method_id}`

**Auth**: Bearer token required

Deactivates the method and **unassigns it from all routers**. Those routers revert to the legacy (system default) payment flow.

**Request:**

```
DELETE /api/payment-methods/3
Authorization: Bearer <token>
```

**Response `200 OK`:**

```json
{
  "message": "Payment method deactivated",
  "id": 3
}
```

**Response `404 Not Found`:**

```json
{
  "detail": "Payment method not found"
}
```

---

### 6. Test Payment Method Credentials

`POST /api/payment-methods/{method_id}/test`

**Auth**: Bearer token required

Validates stored credentials against the external service.

**Request:**

```
POST /api/payment-methods/3/test
Authorization: Bearer <token>
```

No request body needed.

#### Response — M-Pesa with Keys (success)

```json
{
  "status": "success",
  "message": "M-Pesa credentials are valid"
}
```

#### Response — M-Pesa with Keys (failed)

```json
{
  "status": "failed",
  "message": "M-Pesa credential test failed: Failed to get M-Pesa access token: 401 Unauthorized"
}
```

#### Response — ZenoPay (success)

```json
{
  "status": "success",
  "message": "ZenoPay API key accepted (order not found is expected)"
}
```

#### Response — ZenoPay (failed)

```json
{
  "status": "failed",
  "message": "ZenoPay API key is invalid"
}
```

#### Response — Bank Account / Paybill without keys

```json
{
  "status": "success",
  "message": "No credentials to test for this method type. Configuration saved."
}
```

---

### 7. Assign Payment Method to Router

`PUT /api/routers/{router_id}/payment-method`

**Auth**: Bearer token required

Assigns a payment method to a specific router. When customers pay on this router, the assigned payment method is used instead of the system default.

#### Request — Assign a payment method

```json
PUT /api/routers/12/payment-method
Content-Type: application/json
Authorization: Bearer <token>

{
  "payment_method_id": 3
}
```

#### Response `200 OK` (assigned)

```json
{
  "router_id": 12,
  "payment_method_id": 3,
  "message": "Payment method assigned"
}
```

#### Request — Revert to system default (unassign)

```json
PUT /api/routers/12/payment-method
Content-Type: application/json
Authorization: Bearer <token>

{
  "payment_method_id": null
}
```

#### Response `200 OK` (reverted)

```json
{
  "router_id": 12,
  "payment_method_id": null,
  "message": "Reverted to legacy (system default) payment"
}
```

#### Error Responses

**`404` — Router not found:**

```json
{
  "detail": "Router not found"
}
```

**`404` — Payment method not found or inactive:**

```json
{
  "detail": "Payment method not found or inactive"
}
```

---

## PART 2 — Customer-Facing Endpoints (Captive Portal / App)

These endpoints are called by the **customer-facing frontend** (captive portal, mobile app) when a customer wants to pay for internet.

The request bodies are **unchanged**. The only difference is the **response** may now include a `gateway` field that tells the frontend which polling endpoint to use.

---

### 8. Hotspot Register and Pay

`POST /api/hotspot/register-and-pay`

**No auth needed** — called from captive portal.

**Request (unchanged):**

```json
POST /api/hotspot/register-and-pay
Content-Type: application/json

{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "phone": "254712345678",
  "plan_id": 3,
  "router_id": 1,
  "name": "John Doe",
  "payment_method": "mobile_money"
}
```

#### Response — Legacy router (no payment method assigned, NO CHANGE)

Router has no `payment_method_id` → uses system M-Pesa as before:

```json
{
  "id": 42,
  "name": "John Doe",
  "phone": "254712345678",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "status": "pending",
  "plan_id": 3,
  "router_id": 1,
  "message": "STK Push sent to phone"
}
```

Frontend polls: `GET /api/hotspot/payment-status/42` (existing flow, no change).

#### Response — Router with M-Pesa method assigned (bank_account, mpesa_paybill, or mpesa_paybill_with_keys)

Same response shape. The backend uses the reseller's M-Pesa credentials (or system credentials for bank_account/mpesa_paybill), but the response to the frontend is identical:

```json
{
  "id": 42,
  "name": "John Doe",
  "phone": "254712345678",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "status": "pending",
  "plan_id": 3,
  "router_id": 1,
  "message": "STK Push sent to phone"
}
```

Frontend polls: `GET /api/hotspot/payment-status/42` (same as legacy).

#### Response — Router with ZenoPay method assigned

Same response shape. The payment is initiated via ZenoPay instead of M-Pesa:

```json
{
  "id": 42,
  "name": "John Doe",
  "phone": "254712345678",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "status": "pending",
  "plan_id": 3,
  "router_id": 1,
  "message": "STK Push sent to phone"
}
```

Frontend polls: `GET /api/hotspot/payment-status/42` (same endpoint works — ZenoPay webhook updates the customer status just like M-Pesa callback does).

> **Note:** The register-and-pay endpoint returns the same shape regardless of which gateway was used. The frontend doesn't need to know or care which gateway is behind it — it just polls payment-status as usual.

---

### 9. Initiate M-Pesa Payment (for existing customers)

`POST /api/mpesa/initiate-payment`

**Auth**: Bearer token required

**Request (unchanged):**

```json
POST /api/mpesa/initiate-payment
Content-Type: application/json
Authorization: Bearer <token>

{
  "customer_id": 42,
  "amount": 500,
  "phone": "254712345678"
}
```

#### Response — Legacy router (no payment method assigned, NO CHANGE)

```json
{
  "message": "Mobile money payment initiated successfully. Please check your phone to complete payment.",
  "checkout_request_id": "ws_CO_26032026103000174379123456",
  "customer_id": 42,
  "status": "PENDING"
}
```

#### Response — Router with M-Pesa method (bank_account, mpesa_paybill, or mpesa_paybill_with_keys)

```json
{
  "message": "Payment initiated successfully. Please check your phone to complete payment.",
  "customer_id": 42,
  "status": "PENDING",
  "gateway": "mpesa",
  "checkout_request_id": "ws_CO_26032026103000174379123456"
}
```

New field: `gateway` = `"mpesa"`. Frontend still polls `GET /api/hotspot/payment-status/42`.

#### Response — Router with ZenoPay method

```json
{
  "message": "Payment initiated successfully. Please check your phone to complete payment.",
  "customer_id": 42,
  "status": "PENDING",
  "gateway": "zenopay",
  "order_id": "3rer407fe-3ee8-4525-456f-ccb95de38250"
}
```

New fields: `gateway` = `"zenopay"`, `order_id`. Frontend should poll `GET /api/zenopay/order-status/{order_id}`.

---

### 10. RADIUS Hotspot Register and Pay

`POST /api/radius/hotspot/register-and-pay`

**No auth needed** — called from captive portal for RADIUS routers.

**Request (unchanged):**

```json
POST /api/radius/hotspot/register-and-pay
Content-Type: application/json

{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "phone": "254712345678",
  "plan_id": 3,
  "router_id": 1,
  "name": "John Doe",
  "payment_method": "mobile_money"
}
```

#### Response — Legacy RADIUS router (no payment method assigned)

```json
{
  "id": 42,
  "name": "John Doe",
  "phone": "254712345678",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "status": "pending",
  "plan_id": 3,
  "router_id": 1,
  "auth_method": "RADIUS",
  "message": "STK Push sent to phone"
}
```

Frontend polls: `GET /api/radius/hotspot/payment-status/42`.

#### Response — RADIUS router with payment method assigned

Same response shape (the gateway resolves internally):

```json
{
  "id": 42,
  "name": "John Doe",
  "phone": "254712345678",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "status": "pending",
  "plan_id": 3,
  "router_id": 1,
  "auth_method": "RADIUS",
  "message": "STK Push sent to phone"
}
```

#### Response — Already active subscription found

```json
{
  "id": 42,
  "name": "John Doe",
  "phone": "254712345678",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "status": "active",
  "plan_id": 3,
  "router_id": 1,
  "auth_method": "RADIUS",
  "radius_username": "AABBCCDDEEFF",
  "radius_password": "x7k2m9p1",
  "message": "Active subscription found. Use credentials to login."
}
```

---

### 11. Payment Status Polling (existing, unchanged)

`GET /api/hotspot/payment-status/{customerId}`

**No auth needed.**

```
GET /api/hotspot/payment-status/42
```

**Response (unchanged):**

```json
{
  "customer_id": 42,
  "status": "active",
  "plan_name": "Daily 5Mbps",
  "expiry": "2026-03-27T10:30:00",
  "message": "Payment confirmed"
}
```

Or when still pending:

```json
{
  "customer_id": 42,
  "status": "pending",
  "plan_name": "Daily 5Mbps",
  "expiry": null,
  "message": "Payment pending"
}
```

---

### 12. ZenoPay Order Status Polling

`GET /api/zenopay/order-status/{order_id}`

**No auth needed** — used only when `gateway` = `"zenopay"` was returned from initiate-payment.

```
GET /api/zenopay/order-status/3rer407fe-3ee8-4525-456f-ccb95de38250
```

#### Response — Pending

```json
{
  "order_id": "3rer407fe-3ee8-4525-456f-ccb95de38250",
  "status": "pending",
  "amount": 1000.00,
  "reference": null,
  "channel": null,
  "customer_id": 42,
  "customer_status": "pending",
  "plan_name": "Daily 5Mbps",
  "expiry": null,
  "created_at": "2026-03-26T12:00:00"
}
```

#### Response — Completed

```json
{
  "order_id": "3rer407fe-3ee8-4525-456f-ccb95de38250",
  "status": "completed",
  "amount": 1000.00,
  "reference": "0936183435",
  "channel": "MPESA-TZ",
  "customer_id": 42,
  "customer_status": "active",
  "plan_name": "Daily 5Mbps",
  "expiry": "2026-03-27T12:00:00",
  "created_at": "2026-03-26T12:00:00"
}
```

#### Response — Failed

```json
{
  "order_id": "3rer407fe-3ee8-4525-456f-ccb95de38250",
  "status": "failed",
  "amount": 1000.00,
  "reference": null,
  "channel": null,
  "customer_id": 42,
  "customer_status": "inactive",
  "plan_name": "Daily 5Mbps",
  "expiry": null,
  "created_at": "2026-03-26T12:00:00"
}
```

#### Status Values

| status | Meaning |
|---|---|
| `pending` | Payment initiated, waiting for customer |
| `completed` | Payment confirmed, customer provisioned |
| `failed` | Payment failed or cancelled |

---

## PART 3 — Summary: What the Frontend Needs to Handle

### Reseller Dashboard (new settings page)

```
1. GET  /api/payment-methods                          → List configured methods
2. POST /api/payment-methods                          → Create (form based on method_type)
3. GET  /api/payment-methods/{id}                     → View single method
4. PUT  /api/payment-methods/{id}                     → Edit method
5. DELETE /api/payment-methods/{id}                   → Deactivate method
6. POST /api/payment-methods/{id}/test                → Test credentials
7. PUT  /api/routers/{router_id}/payment-method       → Assign method to router
```

### Customer Captive Portal (minimal changes)

The only change is in `POST /api/mpesa/initiate-payment`:

```
IF response has "gateway" === "zenopay":
   Poll GET /api/zenopay/order-status/{response.order_id}
   Check for status === "completed"
ELSE:
   Poll GET /api/hotspot/payment-status/{customerId}    ← existing flow, no change
```

The `POST /api/hotspot/register-and-pay` response is unchanged — always poll `GET /api/hotspot/payment-status/{customerId}` regardless of gateway.
