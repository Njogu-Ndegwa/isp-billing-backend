# What's New: Access Credentials + FUP / Usage Tracking

Two feature sets shipped together. This document is everything a frontend or
integrator needs to ship the corresponding UI / client work. The customer-facing
captive-portal login flow (`POST /api/public/access-login`) is intentionally
out of scope here and will be documented separately.

---

## TL;DR

| Feature | What it is |
|---|---|
| **Access Credentials** | Resellers can mint perpetual `username/password` Wi-Fi logins (no time limit, single concurrent device, optional per-credential rate-limit and lifetime data cap). Useful for free / comp accounts. |
| **FUP & per-customer usage** | PPPoE plans can now declare a monthly data cap and a Fair-Usage-Policy action (throttle, block, notify-only). Per-customer usage is tracked in billing periods anchored to renewal. |

Both sets are reseller-scoped (admins see everything). All new endpoints
require the standard JWT bearer token used by the rest of the dashboard.

---

## 1. Access Credentials

A perpetual hotspot login a reseller hands to a person they don't want to bill
through M-Pesa. It is **not** tied to a `Plan`. It is **not** time-bounded.
Single-concurrent-device is enforced (one MAC at a time per credential), and
the reseller can revoke / rotate / force-logout at any moment.

### 1.1 Resource shape

```json
{
  "id": 42,
  "router_id": 1,
  "username": "alice",
  "password": "s3cretpass",        // only present on create / rotate / GET ?reveal=true
  "rate_limit": "5M/2M",            // null = unlimited
  "data_cap_mb": null,              // null = unlimited; lifetime cap, not monthly
  "label": "Front desk laptop",     // free-form
  "status": "active",               // active | revoked
  "bound_mac_address": "AA:BB:CC:DD:EE:FF",
  "bound_at": "2026-04-25T12:00:00",
  "last_login_at": "2026-04-25T12:00:00",
  "last_seen_at": "2026-04-25T12:34:56",
  "last_seen_ip": "10.5.50.12",
  "total_bytes_in": 123456789,
  "total_bytes_out": 12345678,
  "created_at": "2026-04-20T08:00:00",
  "updated_at": "2026-04-25T12:34:56",
  "revoked_at": null,
  "live": {                         // best-effort live read from the router
    "is_online": true,
    "bound_mac_address": "AA:BB:CC:DD:EE:FF",
    "bound_ip_address": "10.5.50.12",
    "uptime_this_session": "1h22m13s",
    "idle_time": "0s",
    "current_rx_rate_bps": 5242880,
    "current_tx_rate_bps": 2097152
  }
}
```

`live` is included on every GET (single + list) and is filled with whatever the
router returned for the credential's bound MAC; if the router is offline or
nothing is bound, fields default to `null` and `is_online` is `false`.

### 1.2 Endpoints

All endpoints require `Authorization: Bearer <jwt>` and live under
`/api/access-credentials` except where noted.

#### Create

```http
POST /api/access-credentials
Content-Type: application/json

{
  "router_id": 1,
  "username": "alice",          // optional - server auto-generates if omitted
  "password": "s3cretpass",     // optional - server auto-generates if omitted
  "rate_limit": "5M/2M",        // optional, MikroTik-style "upload/download"
  "data_cap_mb": null,          // optional, lifetime cap in MB
  "label": "Front desk laptop"  // optional
}
```

* `username` validation: 3–64 chars, lowercase letters / digits / `.`/`_`/`-`,
  must start with a letter or digit. Server lowercases automatically.
* `rate_limit` validation: must look like `5M/2M` (uppercase or lowercase
  K/M/G suffix accepted).
* Response includes `password` so you can hand it to the user (this is the
  only time the password is returned without `?reveal=true`).
* `409 Conflict` if `(router_id, username)` already exists for the reseller.
* On success the credential is provisioned to the router immediately. If the
  router push fails, the credential is still created in the DB and the
  response includes a `warning` field; the reseller can fix the router and
  hit `POST /{id}/restore` (which re-pushes).

#### List

```http
GET /api/access-credentials?status=active&page=1&per_page=50
```

Query params:

| Param | Values | Notes |
|---|---|---|
| `status` | `active`, `revoked`, `in_use`, `idle` | `in_use` = active **and** has `bound_mac_address`; `idle` = active **and** no MAC bound |
| `router_id` | int | Filter to a single router |
| `q` | string | Case-insensitive substring match on `username` and `label` |
| `page` | int (default 1) | |
| `per_page` | int 1–200 (default 50) | |

Response:

```json
{
  "items": [ /* credential resource (no password) */ ],
  "total": 134,
  "page": 1,
  "per_page": 50,
  "pages": 3
}
```

#### Get one (with optional password reveal)

```http
GET /api/access-credentials/{id}?reveal=true
```

Returns the full resource. `?reveal=true` includes `password`. Always returns
a fresh `live` block fetched from the router.

#### Update

```http
PATCH /api/access-credentials/{id}
Content-Type: application/json

{
  "rate_limit": "10M/5M",
  "data_cap_mb": 5120,
  "label": "Updated label",
  "clear_rate_limit": false,
  "clear_data_cap":  false,
  "clear_label":     false
}
```

* Only fields present are touched.
* Use the `clear_*` booleans to wipe a field (set it back to null) — useful
  for "remove the rate cap" and "remove the data cap".
* Rate-limit changes are pushed to the router immediately, and if a MAC is
  currently bound, its per-MAC simple-queue is also updated so the new limit
  takes effect without forcing the user to re-login.

#### Rotate password

```http
POST /api/access-credentials/{id}/rotate-password
```

Generates a new password, pushes it to the router, returns the credential
including the new password. The next login attempt with the old password will
fail.

#### Revoke

```http
POST /api/access-credentials/{id}/revoke
```

Marks the credential `revoked`, removes the hotspot user record from the
router, kicks any active session, removes the IP-binding and per-MAC queue,
clears `bound_mac_address`. Reversible via `restore`.

#### Restore

```http
POST /api/access-credentials/{id}/restore
```

Re-activates a previously revoked credential and re-pushes it to the router.

#### Force-logout (free credential without revoking)

```http
POST /api/access-credentials/{id}/force-logout
```

Removes the bound device's IP-binding + per-MAC queue and clears
`bound_mac_address`. The credential remains active, so the user can move to
another device or the reseller can hand it off.

#### Delete

```http
DELETE /api/access-credentials/{id}
```

Hard-delete. Also removes the router-side artifacts. Prefer `revoke` unless
you really want it gone.

### 1.3 Concurrency rules

* Each credential can be in use by **one MAC at a time**. Enforced at three
  layers: MikroTik `shared-users=1` on the hotspot user profile, RADIUS
  `Simultaneous-Use := 1` (for RADIUS routers), and an application-level
  `bound_mac_address` field.
* When a user successfully logs in via the captive portal (the public login
  endpoint covered separately), the backend records the bound MAC and rejects
  any subsequent login from a different MAC with `409 credential_in_use`.
* If the bound device disappears from the router's hotspot host table for
  more than `ACCESS_CRED_IDLE_RELEASE_MINUTES` (default 15), the credential is
  auto-released so somebody else can use it. The reseller can also free it
  immediately via `POST /{id}/force-logout`.

### 1.4 Status filter cheatsheet

| `status=` | meaning | UI hint |
|---|---|---|
| `active` | Not revoked | "Active" |
| `revoked` | Reseller revoked it | "Revoked" — show greyed out |
| `in_use`  | Active + a device is currently bound | "In use on …" with bound MAC / IP |
| `idle`    | Active + no device bound | "Available" |

`in_use` / `idle` are computed from `bound_mac_address`, so they react to the
idle-MAC reaper without any extra polling on the frontend.

### 1.5 Error reference

| Status | Body | When |
|---|---|---|
| 400 | `"username must be 3-64 chars …"` | Bad username format |
| 400 | `"rate_limit must look like '5M/2M' …"` | Bad rate-limit format |
| 400 | `"data_cap_mb cannot be negative"` | Negative cap on update |
| 404 | `"Router not found"` | Router not owned by this reseller (or admin) |
| 404 | `"Access credential not found"` | Wrong id / not owned |
| 409 | `"A credential with username '<u>' already exists on this router"` | Create conflict |

---

## 2. FUP & per-customer usage tracking

PPPoE plans can now carry a monthly data cap and a Fair-Usage-Policy. When a
customer exceeds their cap within their billing period, the system applies the
configured action (throttle / block / notify-only) automatically. The full
spec (including how throttle profiles map to MikroTik PPP profiles) is in
[FUP_API.md](FUP_API.md); this section is the reseller-API delta.

### 2.1 New `Plan` fields

Three new fields, all PPPoE-only:

| Field | Type | Meaning |
|---|---|---|
| `data_cap_mb` | int (MB), nullable | Monthly cap. `null` or `0` = unlimited. |
| `fup_action` | `"throttle"` \| `"block"` \| `"notify_only"` \| null | Action when cap is exceeded. Default `null` falls back to throttle. |
| `fup_throttle_profile` | string, nullable | MikroTik PPP profile to switch the user to when throttled. Required if `fup_action = "throttle"`. |

`POST /api/plans/create` and `PATCH /api/plans/{id}` now accept these fields.
`GET /api/plans` includes them in every plan object.

### 2.2 Per-customer usage endpoints

Three new read-only endpoints. All require JWT and enforce reseller scoping
(admins see all customers; resellers see their own).

#### Current period

```http
GET /api/customers/{customer_id}/usage
```

```json
{
  "customer_id": 17,
  "pppoe_username": "user-mike",
  "plan_name": "Home 10Mbps",
  "plan_data_cap_mb": 100000,
  "plan_fup_action": "throttle",
  "period": {
    "id": 9234,
    "period_start": "2026-04-01T00:00:00",
    "period_end":   "2026-05-01T00:00:00",
    "upload_mb":    1234.56,
    "download_mb":  9876.54,
    "total_mb":    11111.10,
    "cap_mb":      100000,
    "percent_used": 11.11,
    "fup_action":          "throttle",
    "fup_triggered_at":    null,
    "fup_action_taken":    null,
    "fup_reverted_at":     null,
    "fup_active":          false,
    "closed_at":           null
  }
}
```

`period` is `null` if no period has been opened yet (e.g. brand-new customer
who hasn't paid yet, or non-PPPoE customer).

#### Period history

```http
GET /api/customers/{customer_id}/usage/history?limit=12
```

Returns the last `limit` (default 6, max 60) closed and open periods, most
recent first. Each entry has the same shape as `period` above.

#### Top usage for a reseller

```http
GET /api/resellers/me/usage/top?limit=20
```

Returns the reseller's PPPoE customers ordered by current-period usage,
descending. Useful for a "who's burning bandwidth right now" widget on the
dashboard.

```json
[
  {
    "customer_id": 17,
    "customer_name": "Mike",
    "pppoe_username": "user-mike",
    "plan_name": "Home 10Mbps",
    "cap_mb": 100000,
    "total_mb": 95432.10,
    "percent_used": 95.43,
    "fup_active": false
  },
  ...
]
```

`fup_active` is true once the cap has been exceeded and the throttle/block
has been applied; goes back to false on renewal.

### 2.3 Frontend implications

* **Plan editor**: add three new optional inputs (`data_cap_mb` MB,
  `fup_action` dropdown, `fup_throttle_profile` text). They only matter when
  `connection_type = pppoe`; you can hide them otherwise.
* **Customer detail**: show current-period usage (a progress bar from
  `total_mb / cap_mb` is enough). When `fup_active = true`, surface a "FUP
  triggered — throttled / blocked" banner.
* **Reseller dashboard**: the `/api/resellers/me/usage/top` endpoint is a
  drop-in for a "Top users this period" table.

### 2.4 What happens automatically (no UI work needed)

* On every renewal (cash payment, M-Pesa, ZenoPay, MTN MoMo, voucher,
  reseller-recorded payment), the previous billing period closes and a new
  one opens anchored to the customer's new `expiry`. Any active FUP throttle
  is lifted automatically.
* The bandwidth snapshot job (~157 s cadence) rolls each PPPoE user's bytes
  into their open period using reset-safe deltas, then evaluates the cap. If
  the user just crossed the cap, the configured `fup_action` is applied to
  the MikroTik PPP secret. Idempotent: applying twice is harmless.

---

## 3. Configuration changes

One new optional setting in `app/config.py` (reads from `.env`):

| Var | Default | What it does |
|---|---|---|
| `ACCESS_CRED_IDLE_RELEASE_MINUTES` | `15` | How long a bound MAC can be missing from the router's hotspot host table before the credential is auto-freed for the next device. |

No other config changes; M-Pesa / RADIUS / WireGuard settings are untouched.

---

## 4. Database migrations (auto-applied)

You don't need to run anything manually. On boot the app applies these
idempotently — re-running is a no-op:

| Migration | Adds |
|---|---|
| `run_access_credential_migrations` | `accesscredstatus` enum, `access_credentials` table, supporting indexes |
| `run_fup_usage_migrations` | `fupaction` enum; `data_cap_mb`, `fup_action`, `fup_throttle_profile` columns on `plans`; `last_upload_bytes`, `last_download_bytes` columns on `user_bandwidth_usage`; `customer_usage_periods` table + indexes |

A standalone script `migrations/add_fup_usage_tracking.py` exists as a
manual safety-net for environments where you want to apply the schema
before deploying the new code, but it is **not** required.

Expected log lines on first boot after deploy:

```
Migration: Ensured access_credentials table and indexes exist
Access credential migrations completed successfully
Migration: Ensured FUP enum, plans/user_bandwidth_usage columns, and customer_usage_periods table
FUP / usage tracking migrations completed successfully
```

---

## 5. Postman collection

Reseller-facing endpoints for access credentials are in
`access-credentials-endpoints.postman_collection.json`. Import via
**Postman → Import → Upload Files** and set the `baseUrl` and `token`
collection variables.

The FUP / usage endpoints can be hand-rolled from this document; they have
no body payload (all GET).
