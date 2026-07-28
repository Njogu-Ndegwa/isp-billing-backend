# 2026-07-26 PPPoE usage stuck at "0 MB" — snapshot attribution too strict

## Summary

A reseller (business account, direct-API MikroTik) reported a PPPoE customer
on a monthly plan showing "0 MB" data usage on the customer card
(screenshot 2026-07-22) while hotspot customers accumulated normally.
Investigated as PR-factory packet PKT-001.

## Symptoms

- Customer card "0 MB": the frontend renders "0 MB" only when an OPEN
  `CustomerUsagePeriod` exists with ~0 bytes (`/api/customers/{id}/usage`);
  a missing period renders "—". So the period was created (at activation via
  `on_renewal`) but never accrued.
- Fleet-wide (read-only prod query, one ssh batch, 2026-07-26 ~16:00 UTC):
  - `user_bandwidth_usage`: 172 `pppoe:*` rows, 169 with bytes, fresh
    samples — collection itself works — but 39/172 (23%) had
    `customer_id IS NULL` (orphaned: sampled, never attributed).
  - 332 active PPPoE customers vs only 126 open periods (108 nonzero).
  - Hotspot side healthy (10,724 rows, fresh).

## Suspected Cause

`collect_bandwidth_snapshot`'s `<pppoe-USERNAME>` branch
(`app/services/mikrotik_background.py`) attributed the dynamic queue to a
customer only on an EXACT, case-sensitive `pppoe_username` match scoped to
the sampled router row. On a miss it still advanced the stored byte
baseline, silently discarding the delta forever. Real-fleet drift that
breaks the exact match:

- resellers hand-recreate PPP secrets in Winbox with different case;
- replaced/re-registered routers leave `Customer.router_id` pointing at a
  stale router row (the pppoe-router-transfer workflow exists because this
  happens).

Contributing router-side causes for genuinely-zero counters (NOT fixed in
this repo, check on the specific router when a case recurs):

- PPP profile without `rate-limit` → RouterOS creates NO dynamic simple
  queue at all. Happens when `plan.speed` is empty:
  `parse_speed_to_mikrotik("")` returns `""` and provisioning builds an
  unlimited profile (`pppoe_`).
- FastTrack without the PPPoE-pool bypass rules → dynamic queue exists but
  counters stay ~0 (`ensure_pppoe_fasttrack_bypass` runs at provisioning but
  failures only log a warning).
- Client offline at every sample (dynamic queues exist only while the
  session is up).

## Fix Applied

- `app/services/mikrotik_background.py` (branch `factory/pkt-001`):
  case-insensitive username match on the sampled router; unique
  global-username fallback (usernames are globally unique app-wide —
  create/update/import all enforce it) that refuses ambiguous matches;
  usage-row key canonicalized to the DB username (`pppoe:<db_username>`) so
  the cap sampler and snapshot job share one row; row lookup switched off
  `scalar_one_or_none` so a duplicate key cannot abort the whole router's
  snapshot commit.
- Historical zero periods are NOT backfilled: the discarded deltas were
  never recorded anywhere; accrual starts at the next sample after deploy.

## Verification

- `tests/test_pppoe_usage_attribution.py`: two failing repros (case-drifted
  secret, stale router row) turned green, plus an ambiguity guard pin.
- Full suite: 602 passed; `scripts/check_session_discipline.py` OK.
- Production behavior to watch after deploy: orphaned `pppoe:*` rows
  (customer_id NULL) should stop growing and mostly re-attach; open PPPoE
  periods with 0 bytes should start accruing within one snapshot cycle.

## Follow-Up Work

- Backlog candidate: admin/diagnostic surface for "sampled but unattributed"
  PPPoE usage rows (customer_id NULL, fresh last_updated) so attribution
  drift is visible instead of silent.
- Backlog candidate: provisioning warning when a PPPoE plan has empty
  `speed` (profile ends up without rate-limit → no dynamic queue → no usage
  tracking, no speed enforcement).
- If a specific customer still reads 0 MB after deploy: check the router for
  a missing dynamic queue (profile rate-limit) and FastTrack bypass rules —
  both router-side, see Suspected Cause.
