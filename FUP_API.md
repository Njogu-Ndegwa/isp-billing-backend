# FUP & Per-Customer Usage API

PPPoE customers now have a per-period bandwidth tracker and a configurable Fair
Usage Policy (FUP). When a customer's plan has a non-null `data_cap_mb` and
they exceed it within their current billing period, the system will
automatically apply the configured `fup_action` (throttle / block / notify).

A "billing period" is anchored to the customer's renewal cycle — it opens when
the customer first becomes active and resets every time they renew (any
payment that pushes `customer.expiry` forward).

---

## 1. Configure FUP on a plan

Three new fields on `Plan` (PPPoE plans only):

| Field | Type | Meaning |
|---|---|---|
| `data_cap_mb` | integer (MB), nullable | Monthly cap. `null` or `0` = unlimited. |
| `fup_action` | `"throttle"` | `"block"` | `"notify_only"` | What to do when cap is exceeded. Default: `null` -> falls back to `THROTTLE`. |
| `fup_throttle_profile` | string, nullable | MikroTik PPP profile to switch the user to when throttled. Required if `fup_action` = `"throttle"`. |

### Create / update plan

```http
POST /api/plans/create
Authorization: Bearer <jwt>

{
  "name": "Home 10Mbps",
  "speed": "10M/10M",
  "price": 1500,
  "duration_value": 30,
  "duration_unit": "DAYS",
  "connection_type": "pppoe",
  "router_profile": "home-10m",
  "data_cap_mb": 100000,
  "fup_action": "throttle",
  "fup_throttle_profile": "home-10m-fup"
}
```

```http
PUT /api/plans/{plan_id}
{
  "data_cap_mb": 50000,
  "fup_action": "block",
  "fup_throttle_profile": null
}
```

Pass `data_cap_mb: 0` to clear the cap (keeps the column nullable).

### Read plan

`GET /api/plans` now includes `data_cap_mb`, `fup_action`,
`fup_throttle_profile` for every plan.

---

## 2. Read a customer's current usage

```http
GET /api/customers/{customer_id}/usage
Authorization: Bearer <jwt>
```

Response:

```json
{
  "customer_id": 42,
  "pppoe_username": "john_doe",
  "plan_name": "Home 10Mbps",
  "plan_data_cap_mb": 100000,
  "plan_fup_action": "throttle",
  "period": {
    "id": 17,
    "period_start": "2026-04-01T08:00:00",
    "period_end": "2026-05-01T08:00:00",
    "upload_mb": 1421.55,
    "download_mb": 18342.10,
    "total_mb": 19763.65,
    "cap_mb": 100000,
    "percent_used": 19.76,
    "fup_action": "throttle",
    "fup_triggered_at": null,
    "fup_action_taken": null,
    "fup_reverted_at": null,
    "fup_active": false,
    "closed_at": null
  }
}
```

`period` is `null` only for brand-new customers who have never been seen by
the bandwidth snapshot job.

`fup_active` is the convenience boolean (`fup_triggered_at && !fup_reverted_at`).

---

## 3. Customer usage history

```http
GET /api/customers/{customer_id}/usage/history?limit=6
```

Returns up to `limit` recent periods (most recent first), same item shape as
the `period` object above. Closed periods have `closed_at` set.

---

## 4. Top-N current usage (reseller dashboard)

```http
GET /api/resellers/me/usage/top?limit=20
```

Response:

```json
[
  {
    "customer_id": 42,
    "customer_name": "John Doe",
    "pppoe_username": "john_doe",
    "plan_name": "Home 10Mbps",
    "cap_mb": 100000,
    "total_mb": 87234.10,
    "percent_used": 87.23,
    "fup_active": false
  },
  ...
]
```

Admins see all PPPoE customers across resellers; resellers see only their own.

---

## 5. Behaviour & guarantees

- Tracking runs every ~157 s (background snapshot). Counter resets on the
  router are detected and handled (the current sample is treated as the new
  baseline).
- FUP is evaluated immediately after each snapshot; over-cap users are
  throttled / blocked at most one snapshot tick after they cross the cap
  (~3 min worst case).
- On payment / renewal:
  1. The current usage period is closed.
  2. A new period is opened, anchored to the new `customer.expiry`.
  3. Any throttle/block from the previous period is reverted (the user's PPP
     secret is restored to `plan.router_profile` and re-enabled).
- `notify_only` records the trigger but does not touch the router. Use this
  if you want to alert the customer first (frontend can poll
  `fup_triggered_at`).

---

## 6. Errors

| Status | When |
|---|---|
| `401` | Missing/invalid token |
| `404` | Customer not accessible to caller (reseller scoping) |
| `400` | Invalid `fup_action` / negative `data_cap_mb` on plan create/update |

---

## 7. Rollout / Pilot runbook

The implementation is gated on `plans.data_cap_mb IS NOT NULL`. Plans without
a cap are completely unaffected. Recommended pilot sequence:

### Step 1. Apply the migration

```bash
python migrations/add_fup_usage_tracking.py
```

The script is idempotent (safe to re-run). It adds the three plan columns,
the two `last_*_bytes` columns on `user_bandwidth_usage`, and creates the
`customer_usage_periods` table.

### Step 2. Restart the API

This picks up the new model fields, the new `/api/customers/{id}/usage*`
routes, and the renewal hook in `make_payment` /
`record_customer_payment` / the PPPoE activation route.

### Step 3. Verify the snapshot job is rolling deltas

Wait one snapshot cycle (~3 min), then for any active PPPoE customer:

```bash
curl -H "Authorization: Bearer $JWT" \
  https://<host>/api/customers/<id>/usage
```

Expect a `period` object whose `total_mb` increases over subsequent calls.

### Step 4. Pick one pilot plan and set a small cap

Pick a low-risk PPPoE plan with at most a handful of customers, and a
known throttle profile that already exists in MikroTik (create one via
WinBox / RouterOS first if needed, e.g. a 1M/1M `home-fup` profile).

```bash
curl -X PUT \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
        "data_cap_mb": 1000,
        "fup_action": "throttle",
        "fup_throttle_profile": "home-fup"
      }' \
  https://<host>/api/plans/<pilot_plan_id>
```

> Existing open `customer_usage_periods` rows for customers on this plan keep
> their original `cap_mb_snapshot` (NULL) until they renew. To make the cap
> apply mid-period, either wait for renewal or temporarily set
> `cap_mb_snapshot` on those rows directly in SQL.

### Step 5. Watch the logs

Look for `[FUP] Trigger throttle` / `[FUP] Auto-revert` lines. Verify the
customer's PPP secret profile flips to `home-fup` on MikroTik (`/ppp/secret
print where name=<username>`) and that `fup_active` becomes `true` in the
usage endpoint.

### Step 6. Verify renewal reset

When the pilot customer renews (cash payment via dashboard, M-Pesa, etc.),
confirm:

* A new `customer_usage_periods` row is opened (visible via
  `GET /api/customers/<id>/usage/history`).
* Their PPP secret profile is restored to `plan.router_profile`.
* `fup_active` is `false` again.

### Step 7. Roll out

Once the pilot plan behaves correctly for a full cycle, set `data_cap_mb` on
the remaining plans. Resellers can also self-serve via the plan admin UI
(the new fields are exposed in `POST /api/plans/create` and
`PUT /api/plans/{id}`).
