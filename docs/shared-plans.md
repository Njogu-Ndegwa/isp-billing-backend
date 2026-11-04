# Shared (multi-device) plans

How one paid plan covers several devices. Lifecycle tests:
`tests/test_shared_plan_lifecycle.py`. Written November 2026 after the router 446
incidents.

## The model

| Thing | Where | Meaning |
|---|---|---|
| Device allowance | `plans.max_shared_users` | Total devices on one plan, including the payer's. 1 = no sharing. |
| Per-customer override | `customers.max_devices_override` | Reseller's override of the plan's allowance. `max_devices_for_customer` is the only correct way to read the limit. |
| Owner | `customers` row with `subscription_owner_id IS NULL` | The row that pays. Its MAC is the "main device". |
| Shared device | `customers` row with `subscription_owner_id = owner.id` | An ordinary customer row with its own MAC, so every router job (delivery, queues, expiry, check-in) already handles it. |
| Slot | `device_pairings` with `is_subscription_share=true, is_active=true` | One taken slot. Stays active after expiry, so renewal brings the same devices back. |
| Paired device | `device_pairings` with `is_subscription_share=false` | A device paired with its own purchase. `device_type` is `tv`, `console`, `laptop`, `iot` or `other`. |
| Access code | `subscription_share_codes` (`status='access'`) | Multi-use code for M-Pesa payers. Vouchers and M-Pesa receipts work the same way. |

"Group plan" just means `max_shared_users > 1`. A "device pairing voucher" is a
voucher redeemed through `POST /api/public/device/pair-voucher` with a typed MAC: the
TV's row becomes the **owner**, with `phone=""`, and the pairing records its type.

## Adding devices

Every path ends in `_share_subscription_for_owner` (`app/api/device_pairing.py`), which
locks the owner row, recounts the slots, then creates the shared row and pairing and
schedules delivery.

| Path | Route | Notes |
|---|---|---|
| Portal code | `POST /api/public/access-code/redeem`, or `/api/public/reconnect` with a code | `redeem_code_on_device`. On a group plan a new MAC is added. |
| Phone number | `POST /api/public/reconnect` | Added as "Added by phone" while a slot is free and the plan has paid time left (not grace). |
| Typed MAC | `POST /api/public/device/share-subscription` | Needs the code. |
| Dashboard | `POST /api/customers/{id}/devices` (e79792b) | Needs a plan allowing 2 or more devices, or an override. |
| Legacy one-time code | `/api/public/device/share-subscription/code/redeem` | Old portals. |

- **At the limit:** 409 `device_limit_reached` with the device list. Nobody is kicked.
- **Same device again:** no extra slot or row, it is just re-delivered.
- **Single-device plans:** the code moves the plan only if its device is idle. See
  `app/services/device_entitlements.py` and PR #300 (paired TV/console/IoT never moves).

## Removing devices

- `disconnect_shared_pairing`: from the portal (`/api/public/access-code/disconnect`) or
  the dashboard (`DELETE /api/customers/{id}/devices/{pairing_id}`). Frees the slot, then
  removes the device from the router. A failed router call reports `cleanup_status: pending`.
- `release_main_device`: detaches the owner's MAC, for a phone whose MAC rotated on a full
  plan. The next device to enter the code becomes the main device.
- `unpair_device`: separately paid devices only.

## Data cap and FUP

- Each device meters into its own `customer_usage_periods` row. Each row snapshots the
  plan's cap when it opens.
- `pooled_period_usage_bytes` sums the group against the owner's period, so the cap covers
  all devices together. Devices removed this cycle still count up to their removal.
- Each device is evaluated by the cap sampler on its own. Once the pool is over the cap,
  each one throttles as it is next sampled, so expect a short spread, not one instant.
- A `plan`-window cap snapshot does not follow a lowered plan cap (`fup_cap_mb`). Raised
  caps are carried over by `_loosen_open_period_caps`.

## Renewal, top-up and stacking

Every purchase goes through `record_customer_payment`:

- Time **stacks**: `renewal_expiry` adds the new duration to the paid expiry while access
  remains, otherwise it starts from now.
- The plan is **replaced** by the plan just bought. Speed, cap and device allowance apply
  to all remaining time, including time stacked from the old plan.
- The usage period closes and a new one opens with the new plan's cap. Unused data from the
  old period is not carried over.
- `sync_shared_subscription_devices_after_owner_renewal` copies expiry and plan onto every
  shared device, renews each usage period, lifts FUP, and schedules delivery. If the new plan
  allows fewer devices, the extras are released, newest first.

A voucher on the owner's MAC follows the same rules, with one exception: a voucher for a
plan with fewer devices or a lower cap overwrites `plan_id`, but the new period keeps the old
cap and no devices are released until the next payment. That is open question 1. Owner edits
in the dashboard carry
expiry and plan to shared devices. Grace periods and outage compensation also propagate.

## Router delivery

- **Push:** `provision_hotspot_customer` for each device, with an attempt keyed by pairing.
- **Retry:** `retry_pending_hotspot_provisioning_background`. A renewal resets the reused
  attempt's window.
- **Check-in:** `load_checkin_state` offers every paid MAC a router does not report, shared
  devices included. This is how a rebooted router gets them back.
- **Expiry:** devices expire with the owner and are removed like any customer. The slots stay.

## PPPoE (66dd634)

No shared rows or pairings. One login, several sessions: profiles named `..._d<N>` use
`only-one=no` and an on-up script that drops sessions beyond N. The limit lives on the
router profile, so changing it needs a re-provision and devices reconnect once to pick it up.

## Detectors

- `paid-not-delivered` skill: `PAID_NOT_DELIVERED`, `PAIRED_DEVICE_WITHOUT_PLAN`.
- `shared-plan-consistency` skill: read-only fleet scan for the group states below.

| Scan code | Meaning |
|---|---|
| `GROUP_OVER_LIMIT` | More live shared devices than the owner's limit. The next renewal releases the extras. |
| `STALE_CAP_SNAPSHOT` | Open period snapshot equals the previous plan's cap, not the plan just paid for. |
| `EXPIRY_MISMATCH` | Owner and shared device disagree on expiry. |
| `PLAN_MISMATCH` | Owner and shared device disagree on plan. |
| `ORPHAN_SHARED` | A live shared device whose owner is not live or was deleted. |
| `OWNER_CHAIN` | A shared device that also owns devices. |
| `SHARED_NOT_ON_ROUTER` | A live shared device with no access on the router. |
| `EXPIRED_STILL_ON_ROUTER` | A shared device not live in the DB, still bypassed on the router. |
| `REPEAT_MOVES` | One purchase moved across 3 or more MACs in 14 days. |

## Open questions

1. **A smaller voucher redeemed on a live group (Dennis decides: refuse or stack).** Router
   446, customer 50758: NKIENDEM 240GB (limit 10, 18,000 XAF) became TV BUNDLE (limit 1) when
   a 2,500 XAF voucher was redeemed 38 minutes later. Time stacked. The group now reads as
   1 device with 6 attached, new devices are refused, and the next payment releases the
   devices. `tests/test_shared_plan_lifecycle.py` pins this behaviour until it is decided.
2. **Randomized MACs use up slots.** A rotated phone takes a new slot and the old one stays
   until someone removes it. Options: leave it manual, or auto-free idle randomized slots.
