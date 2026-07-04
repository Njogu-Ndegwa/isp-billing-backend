# 2026-06-19 PPPoE FastTrack Order And Profile Drift

## Summary

A reseller reported that customers on routers `42`, `110`, and `40` were not being speed-limited. Live diagnosis showed router `42` hotspot limits were healthy, router `40` was unreachable over the management tunnel, and router `110` had PPPoE enforcement drift.

Router `110` had active PPPoE customers still assigned to old symmetric profiles such as `pppoe_7M_7M` while their DB plans were asymmetric (`7M/4M`, `10M/5M`). It also had many duplicate PPPoE FastTrack bypass rules, with most pool-range bypasses positioned after the first FastTrack rule, so PPP dynamic queues could be skipped.

## Symptoms

- Router `110` active PPPoE sessions had dynamic queues such as `7560000/7560000` for customers whose selected plan expected `7560000/4320000` after the configured `PPPOE_RATE_LIMIT_HEADROOM=1.08`.
- Firewall filter order placed `ISP_BILLING_QUEUE_BYPASS_*` hotspot rules before FastTrack, but most `PPPoE bypass FastTrack (...)` rules after FastTrack.
- Router `42` had valid hotspot queues, no `hs-*` parent queue, and hotspot bypass rules immediately before FastTrack.
- Router `40` API access to `10.0.0.55:8728` timed out.

## Suspected Cause

Two likely causes overlapped:

- PPPoE customer plan changes had not fully moved older secrets from symmetric profiles (`pppoe_7M_7M`, `pppoe_10M_10M`) to the current asymmetric profile names.
- `ensure_pppoe_fasttrack_bypass` checked that accept rules existed, but did not verify they were before the earliest active FastTrack rule. Duplicate/manual/generated rules accumulated, leaving some valid-looking bypass rules ineffective.

## Fix Applied

- On production router `110` only:
  - Ensured `pppoe_7M_4M` and `pppoe_10M_5M` profiles with headroom-adjusted limits.
  - Moved affected PPP secrets to the correct profiles.
  - Removed duplicate PPPoE FastTrack bypass rules and rebuilt one ordered src/dst pair per `pppoe-pool` CIDR before the earliest FastTrack rule.
  - Disconnected affected active PPPoE sessions so RouterOS recreated dynamic queues with the corrected profile limits.

## Verification

- Router `110` verification after repair:
  - 16/16 active DB PPPoE customers had correct secret profile and profile rate-limit.
  - 13 active PPPoE sessions had already reconnected and their dynamic queues matched the expected limits.
  - No PPPoE bypass rules were missing.
  - No PPPoE bypass rules were after the first FastTrack rule.
- Three customers were still offline shortly after reconnect: `Kosgei`, `Eliud12`, and `Tuwei`. Their secrets were corrected; they will get the fixed profile when their CPE reconnects.

## Follow-Up Work

- Done 2026-07-04: `ensure_pppoe_fasttrack_bypass` now repairs rule order, not just existence, and has focused tests for stale rules after FastTrack plus already-correct rules before FastTrack.
- Add a PPPoE drift repair/admin action that compares DB plan speed to router secret profile and active dynamic queue limits.

## 2026-07-04 Follow-Up Audit

Read-only production sample checked four hotspot routers and eight PPPoE routers. Hotspot enforcement looked healthy in the sample: per-user queues matched DB plans, no active `hs-*` parent queues were shadowing plan queues, and queue FastTrack bypass rules were before FastTrack.

PPPoE still showed drift on some routers. Examples: router `44` had customers on stale profiles such as `pppoe_2M_1M` or `pppoe_3M_3M` while DB plans expected `3M/2M` after headroom; router `246` had several `9M/9M` customers still on `pppoe_10M_10M`. Routers `137` and `246` also had live sessions on `192.168.89.254` where the final `/32` pool bypass rule was missing, so FastTrack could skip the dynamic queue for that IP. Routers `238`, `175`, and `219` were unreachable over the management tunnel during the sample.

## 2026-07-04 Fleet Repair

With explicit operator approval, production PPPoE routers were processed slowly and sequentially, excluding reseller `salomonkiptanui@gmail.com`.

- Repaired and verified clean: routers `44`, `137`, `246`, `142`, and `236`.
- Already verified clean: routers `141`, `227`, and `243`.
- Unreachable and not modified: routers `175`, `219`, and `234`.
- Final reachable-router audit showed no profile-rate mismatches, active dynamic queue limit mismatches, or PPPoE FastTrack bypass order issues.

The repair path also exposed that RouterOS may report duplicate PPP secrets as `failure: secret with the same name already exists`; the provisioning helper now treats this as a duplicate and updates the existing secret by `.id`.
