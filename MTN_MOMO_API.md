# MTN Mobile Money (Collection) Integration

Per-reseller **RequestToPay** integration with MTN MoMo.  Resellers bring their
own credentials (API User UUID, API Key, Primary Subscription Key, target
environment, currency) and assign the method to individual routers.  Once
assigned, every `POST /api/pay` or hotspot payment against that router
triggers an MTN prompt on the customer's phone, records a transaction, and
provisions the customer on success — exactly the same UX you already have for
M-Pesa and ZenoPay.

Reference: <https://momodeveloper.mtn.com/api-documentation/use-cases>

---

## Scope

Only the **Collection / RequestToPay** use case is implemented:

- `POST /collection/token/` — OAuth access token (Basic auth + subscription key)
- `POST /collection/v1_0/requesttopay` — initiate a pull payment
- `GET /collection/v1_0/requesttopay/{referenceId}` — poll status

Disbursement, Transfer, PreApproval, Validate Account Holder, and Get Balance
are **not** part of this iteration.

---

## What a reseller needs from the MTN developer portal

1. Sign up at <https://momodeveloper.mtn.com/> and subscribe to the
   **Collection** product.
2. Copy the **Primary Key** (this is the `Ocp-Apim-Subscription-Key`).
3. Create an **API User** (UUID v4) and generate an **API Key** for it.
   In sandbox, both are created from the portal's "Sandbox Provisioning" tool.

That yields the five pieces of information the reseller pastes into the
ISP billing app:

| Field                     | Example                                           |
| ------------------------- | ------------------------------------------------- |
| `mtn_api_user`            | `64f8c775-6dff-45c0-93e0-39a9cd78df8b`            |
| `mtn_api_key`             | `3eccb4f68c3241caad25b59823b7ac86`                |
| `mtn_subscription_key`    | `af8ced583a5849f5bcb7aa39f008ce4e` (Primary Key)  |
| `mtn_target_environment`  | `sandbox` / `mtnuganda` / `mtnghana` / ...        |
| `mtn_currency`            | `EUR` (sandbox) / `UGX` / `GHS` / ...             |
| `mtn_base_url` (optional) | `https://sandbox.momodeveloper.mtn.com`           |

The `mtn_api_key` and `mtn_subscription_key` are encrypted at rest with
`Fernet` (same helper as M-Pesa and ZenoPay credentials).

---

## Endpoint reference

### 1. Configure the method — `POST /api/payment-methods`

Reseller-authenticated.  See `payment-methods-endpoints.postman_collection.json`
for the full CRUD.

Request:

```json
{
  "method_type": "mtn_momo",
  "label": "MTN Uganda (Sandbox)",
  "mtn_api_user": "64f8c775-6dff-45c0-93e0-39a9cd78df8b",
  "mtn_api_key": "3eccb4f68c3241caad25b59823b7ac86",
  "mtn_subscription_key": "af8ced583a5849f5bcb7aa39f008ce4e",
  "mtn_target_environment": "sandbox",
  "mtn_base_url": "https://sandbox.momodeveloper.mtn.com",
  "mtn_currency": "EUR"
}
```

Response returns the newly-created method with the two secrets masked.
If `mtn_base_url` is omitted and `mtn_target_environment` is `sandbox`, we
default the base URL to `https://sandbox.momodeveloper.mtn.com`.

### 2. Validate credentials — `POST /api/payment-methods/{id}/test`

Calls `POST /collection/token/` with the stored credentials.  Returns
`{"status": "success", "message": "MTN MoMo credentials are valid"}` on 200,
or `{"status": "failed", ...}` otherwise.  This is the recommended smoke-test
before assigning the method to any router.

### 3. Assign to a router — `PUT /api/routers/{routerId}/payment-method`

```json
{ "payment_method_id": 42 }
```

### 4. Initiate a payment — `POST /api/pay`

Identical body to the existing M-Pesa / ZenoPay flow; the dispatcher routes
through MTN automatically because the router has an MTN method assigned.

Successful response:

```json
{
  "message": "Payment initiated successfully. Please check your phone to complete payment.",
  "customer_id": 7,
  "status": "PENDING",
  "gateway": "mtn_momo",
  "reference_id": "9f5b0b6a-4e29-4d03-9aa6-1b3b7e2a6a11"
}
```

Behind the scenes:

1. Server generates a UUID v4 and uses it as both `X-Reference-Id` and
   `externalId` in the MTN call.
2. A `MtnMomoTransaction` row is inserted with `status='pending'`.
3. The request is sent to `POST /collection/v1_0/requesttopay` with a
   `X-Callback-Url` pointing at the public webhook for this reseller.

### 5. Poll status — `GET /api/mtn-momo/status/{referenceId}`

Returns the local row.  If the local status is still `pending`, the handler
actively calls `GET /collection/v1_0/requesttopay/{referenceId}` and persists
the resulting status before returning.

Response:

```json
{
  "reference_id": "9f5b0b6a-4e29-4d03-9aa6-1b3b7e2a6a11",
  "external_id": "HOTSPOT-7-20260419083000",
  "status": "successful",
  "amount": 1000.0,
  "currency": "EUR",
  "phone": "46733123454",
  "financial_transaction_id": "1234567890",
  "reason_code": null,
  "reason_message": null,
  "target_environment": "sandbox",
  "customer_id": 7,
  "customer_status": "active",
  "plan_name": "Daily 2Mbps",
  "expiry": "2026-04-20T08:30:00",
  "created_at": "2026-04-19T08:30:00",
  "updated_at": "2026-04-19T08:30:42"
}
```

Valid `status` values: `pending`, `successful`, `failed`.

### 6. Callback (MTN → us) — `POST /api/mtn-momo/callback/{resellerId}`

**Public endpoint**, no auth header.  This is the URL to register as
`X-Callback-Url` in the MTN developer portal — but even if you leave it
unregistered, the polling endpoint (5) is a complete fallback.

MTN sends this call **once** with no retry on a final state.  Our handler:

1. Reads `referenceId` from the body (or `reference_id` / `externalId`).
2. Looks up the matching `mtn_momo_transactions` row for this reseller.
3. Re-issues `GET /collection/v1_0/requesttopay/{referenceId}` to get the
   authoritative status (the callback body is not fully trusted).
4. On `SUCCESSFUL`: records a customer payment via `record_customer_payment`,
   applies any pending plan change from `customer.pending_update_data`, and
   queues hotspot / PPPoE provisioning.
5. On `FAILED`: marks the transaction failed and flips any still-`PENDING`
   customer to `INACTIVE`.

Always returns `{"status": "received"}` on well-formed calls so MTN stops
pinging the URL.

The exact URL for a reseller is derived from `MPESA_CALLBACK_URL` in
[`app/config.py`](app/config.py):

```
https://<your-public-host>/api/mtn-momo/callback/<reseller_user_id>
```

---

## Sandbox testing

The MTN sandbox exposes a set of special MSISDNs that drive the RequestToPay
state machine deterministically:

| MSISDN         | Result       |
| -------------- | ------------ |
| `46733123450`  | PENDING      |
| `46733123451`  | REJECTED     |
| `46733123452`  | TIMEOUT      |
| `46733123453`  | FAILED       |
| `46733123454`  | SUCCESSFUL   |

Use `46733123454` for a happy-path smoke-test.  Sandbox currency is always
`EUR`; amounts are integer-valued strings (e.g. `"1000"`).

### Observed sandbox timing

The sandbox does **not** transition immediately — each state machine takes
~30–90 s to settle.  We saw the following real states come back from the
status endpoint during testing:

* On SUCCESSFUL (`46733123454`): `CREATED` → ... → `SUCCESSFUL` after ~40 s,
  with a populated `financialTransactionId`.
* On FAILED (`46733123453`): `PENDING` → ... → `FAILED` after 1–3 min.

Note that `CREATED` is not in MTN's public docs but the sandbox emits it.  Our
status handler treats anything other than `SUCCESSFUL` / `FAILED` as
non-terminal — the local row stays `pending` and the poll loop keeps running.

### Included smoke test

Run this from the repo root to verify your credentials and network
connectivity to MTN *without* touching the database or FastAPI stack:

```bash
python scripts/test_mtn_momo_live.py
```

It exercises `get_access_token` → `initiate_request_to_pay` → polling
`check_request_to_pay_status`, for both the SUCCESSFUL and FAILED sandbox
MSISDNs.  Replace the credentials at the top of the file for your own
subscription.

---

## Data model

### `reseller_payment_methods` (columns added)

| Column                            | Type         | Purpose                                         |
| --------------------------------- | ------------ | ----------------------------------------------- |
| `mtn_api_user`                    | `VARCHAR(64)`  | UUID v4 of the MTN API User (not a secret)    |
| `mtn_api_key_encrypted`           | `VARCHAR(500)` | Fernet-encrypted API Key                      |
| `mtn_subscription_key_encrypted`  | `VARCHAR(500)` | Fernet-encrypted Primary Subscription Key     |
| `mtn_target_environment`          | `VARCHAR(50)`  | `sandbox` / `mtnuganda` / `mtnghana` / ...    |
| `mtn_base_url`                    | `VARCHAR(255)` | Optional; defaults to sandbox host            |
| `mtn_currency`                    | `VARCHAR(10)`  | `EUR` (sandbox) / `UGX` / `GHS` / ...         |

### `mtn_momo_transactions`

| Column                      | Type               | Notes                                          |
| --------------------------- | ------------------ | ---------------------------------------------- |
| `reference_id`              | `VARCHAR(64) UNIQUE` | UUID v4 we send as `X-Reference-Id`          |
| `external_id`               | `VARCHAR(64)`      | Human-readable reference (e.g. `HOTSPOT-...`)  |
| `reseller_id`               | `INTEGER`          | FK → `users.id`                                |
| `customer_id`               | `INTEGER`          | FK → `customers.id`                            |
| `amount`                    | `NUMERIC(10,2)`    | Debited amount                                 |
| `currency`                  | `VARCHAR(10)`      | Matches `mtn_currency` on the method           |
| `phone`                     | `VARCHAR(20)`      | E.164 without `+`                              |
| `status`                    | `ENUM`             | `pending` / `successful` / `failed`            |
| `financial_transaction_id`  | `VARCHAR(128)`     | Populated on SUCCESSFUL                        |
| `reason_code`               | `VARCHAR(100)`     | Populated on FAILED                            |
| `reason_message`            | `VARCHAR(500)`     | Populated on FAILED                            |
| `target_environment`        | `VARCHAR(50)`      | Echoes what was used at initiation             |
| `payer_message`             | `VARCHAR(160)`     | Shown in MTN's payer transaction history       |
| `payee_note`                | `VARCHAR(160)`     | Shown in MTN's payee transaction history       |
| `created_at` / `updated_at` | `TIMESTAMP`        | —                                              |

---

## Migration

```bash
python migrations/create_mtn_momo_tables.py            # apply
python migrations/create_mtn_momo_tables.py --rollback # drop
```

The migration is idempotent; running it twice is safe.  Fresh installs using
`python init_db.py` pick up the new table automatically via the `Base.metadata`
reflection.

---

## Token caching

MTN access tokens are valid for ~1 hour.  `app/services/mtn_momo.py` keeps an
in-process cache keyed by `(api_user, base_url)` and refreshes 60 seconds
before expiry.  A `401` from any downstream call invalidates the cached token
so the next call fetches a fresh one.

---

## Error handling

- If a RequestToPay call fails (non-2xx response), the provisional
  `mtn_momo_transactions` row is deleted before the error bubbles up, so you
  never see orphaned PENDINGs from a bad call.
- If a callback arrives for a transaction that is already `SUCCESSFUL` or
  `FAILED`, the handler is a no-op (idempotent).
- Polling the status endpoint while PENDING may race with an incoming
  callback; both paths funnel through the same `_apply_remote_status` helper,
  which only advances the state machine when the local row is still PENDING.
