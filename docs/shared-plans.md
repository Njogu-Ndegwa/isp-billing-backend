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
- **Same device again:** no extra slot or row, it is just re-delivered, even if the limit has
  since dropped below the devices attached. It keeps its device type.
- **Single-device plans:** the code moves the plan only if its device is idle. See
  `app/services/device_entitlements.py` and PR #300 (paired TV/console/IoT never moves).

## Removing devices

- `disconnect_shared_pairing`: from the portal (`/api/public/access-code/disconnect`) or
  the dashboard (`DELETE /api/customers/{id}/devices/{pairing_id}`). Frees the slot, then
  removes the device from the router. A failed router call reports `cleanup_status: pending`.
- `release_main_device`: detaches the owner's MAC, for a phone whose MAC rotated on a full
  plan. The next device to enter the code becomes the main device.
- `unpair_device`: separately paid devices only.
- Idle slot release (off by default): see open question 2.

## Data cap and FUP

- Each device meters into its own `customer_usage_periods` row. Each row snapshots the
  plan's cap when it opens.
- `pooled_period_usage_bytes` sums the group against the owner's period, so the cap covers
  all devices together. Devices removed this cycle still count up to their removal.
- Each device is evaluated by the cap sampler on its own. Once the pool is over the cap,
  each one throttles as it is next sampled, so expect a short spread, not one instant.
- A `plan`-window cap snapshot does not follow a lowered plan cap (`fup_cap_mb`). Raised
  caps are carried over by `_loosen_open_period_caps`.
- Moving a customer to another plan from the dashboard follows the same rule. A bigger or removed
  cap applies at once to the owner and shared devices (`raise_open_caps_after_plan_edit`), and a
  throttle or block it no longer justifies is lifted straight away. A smaller cap waits for the
  next period, unless the open period had no cap (the plan's cap applies at once) or the new plan
  is daily (a daily plan always uses the plan's cap).

## Renewal, top-up and stacking

Every purchase goes through `record_customer_payment`:

- Time **stacks**: `renewal_expiry` adds the new duration to the paid expiry while access
  remains, otherwise it starts from now.
- The plan is **replaced** by the plan just bought. Speed, cap and device allowance apply
  to all remaining time, including time stacked from the old plan.
- The usage period closes and a new one opens with the new plan's cap. Unused data from the
  old period is not carried over.
- `sync_shared_subscription_devices_after_owner_renewal` copies expiry and plan onto every
  shared device, renews each usage period, lifts FUP, and schedules delivery.

**When the new limit is too small for the devices attached** (`_split_for_device_limit`). This
applies to every renewal, M-Pesa included. With room for all of them, nothing changes.

| Order | Device | Why |
|---|---|---|
| 1 | Owner's main device | Always stays. It isn't a slot. |
| 2 | Paired shared devices (`tv`, `console`, `iot`), newest first | Can't enter a code to get back on. |
| 3 | Everything else (`other`, `laptop`), newest first | Can enter the code again if a slot is free. |

So with more paired devices than slots, the newest paired devices stay, and a phone goes even if
it is the newest device of all. A voucher for 1 device has no slots, so a shared TV goes too.
A released device keeps its row, loses its slot and isn't re-delivered. The type comes from the
pairing, so a TV added as `other` gets no priority. The dashboard's add-device panel and the share
page let you pick. The panel starts on `other`, and devices added from it before it had the choice
are saved as `other`. `PATCH /api/customers/{id}/devices/{pairing_id}` corrects a device's type from
the panel, without touching the router.

A voucher on the owner's MAC follows the same rules, with these exceptions:

- On a group with paid time left, a voucher giving fewer devices or a lower cap is refused and
  stays unused (`smaller_voucher_refusal`). A device limit too small for the devices attached
  counts as fewer. Single-device plans top up as normal, and a customer in grace is never refused.
- With no paid time left, including grace, the voucher applies its own cap and device limit
  (`apply_voucher_plan_if_plan_ended`). Other payments still keep the old limits if the plan they
  bought gives less and the old plan object is loaded, which is rare on M-Pesa (open question 3).

Owner edits in the dashboard carry expiry and plan to shared devices. Grace periods and outage
compensation also propagate.

## Router delivery

- **Dashboard plan edit:** a speed change is pushed at once to the owner and shared devices,
  except any under a FUP throttle or block (`push_plan_edit_to_router`). Devices drop for a
  moment. The fleet queue sync stays the fallback. For the cap, see "Data cap and FUP".
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

1. **Groups swapped before the refusal shipped.** Router 446, customer 50758 (NKIENDEM 240GB
   to TV BUNDLE) was repaired back to plan 3000 on 5 Nov 2026. `GROUP_OVER_LIMIT` in the
   `shared-plan-consistency` detector finds any others.
2. **Randomized MACs use up slots.** A rotated phone takes a new slot and the old one stays
   until someone removes it. `SHARED_SLOT_IDLE_RELEASE_ENABLED` (off) frees one slot when a new
   device enters a full plan's code. See `app/services/shared_slot_release.py`. Turning it on
   applies to every reseller.
3. **Non-voucher payments on an ended plan.** `record_customer_payment` keeps the old cap and
   device limit when the bought plan gives less and the old plan object is still loaded, even
   if the old plan has ended. On M-Pesa that needs a pending plan that differs from the
   customer's current plan, such as a reseller editing the plan mid-payment. Left as it is so
   vouchers don't change M-Pesa.
