# Free Trial Plans API

Resellers can offer customers free internet for a limited time. A free trial is an ordinary
plan with `plan_type: "free_trial"` and price 0, on hotspot or PPPoE:

- **Hotspot:** the customer claims it from the captive portal with no payment (below).
- **PPPoE:** there is no portal. The reseller registers the customer on the trial plan and
  activates them (`POST /api/customers/{id}/activate-pppoe`). The customer gets the plan's
  PPPoE speed and device limit for its duration. The activation never records money, whatever
  `payment_method` is sent: it writes the same KES 0, `counts_as_revenue = false` row a portal
  claim does (reference `FREE-TRIAL-{plan_id}`), and the response has `payment_recorded: false`.
  The portal trial endpoints never list or grant a PPPoE trial.

## Reseller: creating a trial plan

`POST /api/plans/create` and `PUT /api/plans/{id}` accept:

| Field | Notes |
|---|---|
| `plan_type` | `"free_trial"` |
| `price` | must be `0` (400 otherwise) |
| `connection_type` | `"hotspot"` or `"pppoe"` (400 for `"static_ip"`) |
| `max_shared_users` | Hotspot: how many devices one claimed trial covers (default 1). PPPoE: the usual PPPoE device limit (logins with the same username). A data cap / FUP is allowed. |
| `trial_once_per_customer` | Hotspot only. `true` (default): each device can claim this trial once. `false`: it can claim again once its previous trial has ended. Ignored for PPPoE, where the reseller decides who gets activated. |

Every plan response now includes `trial_once_per_customer`.

Hide the plan (`is_hidden: true`) or set `valid_until` to switch the trial off without deleting it.

## Captive portal

### Which trials can this device claim?

`GET /api/public/free-trial/{router_id}/{mac_address}`

```json
{
  "success": true,
  "router_id": 12,
  "trials": [
    {
      "plan_id": 40,
      "name": "Free 30 min",
      "speed": "5M/5M",
      "duration_value": 30,
      "duration_unit": "MINUTES",
      "trial_once_per_customer": true,
      "eligible": false,
      "reason": "You have already used this free trial."
    }
  ]
}
```

### Claim a trial

`POST /api/public/free-trial/claim`

```json
{ "plan_id": 40, "mac_address": "AA:BB:CC:DD:EE:FF", "router_id": 12, "phone": "0712345678" }
```

`phone` is optional. When it is given, the once-only rule also matches it, so the same
person can't claim again from a second device. Phones are matched on their last 9 digits,
so `0712345678`, `+254712345678` and `254712345678` are the same person. Numbers shorter
than 9 digits are ignored for matching.

The success response has the same shape as `POST /api/public/voucher/redeem` (`auth_method`,
`expiry`, `plan_name`, `message`, plus `delivery`/`attempt_id` for direct-API routers or
`radius_username`/`radius_password` for RADIUS routers). Failures return 400/404/503 with a
human-readable `detail`:

- `You have already used this free trial.`
- `You already have active internet. The free trial is for new connections.`
- `This free trial is not available right now` (hidden), `This free trial has ended` (past `valid_until`)

The paid endpoints (hotspot pay, RADIUS pay, pair-and-pay) refuse free-trial plans.

## Accounting

A claim records a KES 0 `CustomerPayment` with `counts_as_revenue = false`, so it never shows up in
revenue, reseller charges or payouts, and a `free_trial_claims` row. The once-only rule reads
`free_trial_claims`, so deleting the customer does not make the device eligible again.

## Limits

"Once" is tracked per device MAC address (and per phone number when one is given). A phone
that uses a randomised Wi-Fi MAC and forgets the network can show up as a new device. The
optional phone number is the extra check against that.
