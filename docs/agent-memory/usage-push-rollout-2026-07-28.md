# Usage-Push Rollout Record — 2026-07-28/29

Staged rollout of the router-push usage channel (PR #20, commit `893f339`),
executed the same night the pilot was proven. All times EAT.

## Why

Polling visited each router every ~49 min; sessions shorter than that were never
counted. Pilot router 277 (SkyNet Connect): 11.28 GB actual WAN traffic in 24h,
0.371 GB shown (3.3%). After push: **83.5% capture over a 40-min peak-hour
window** (240.4 MB banked of 287.8 MB WAN). The residual ~17% is unattributable
traffic (portal/DNS/router-own) plus session tails pending the on-logout hook.

## Eligibility filter (every stage)

DIRECT_API · identity known · router online · owner subscription active/trial ·
≥1 customer ACTIVE with unexpired plan · ≥100 MB WAN traffic in 24h with ≥5
snapshots. Ranked worst capture first. Server-side ingest additionally rejects
`owner_not_paying` / `customer_not_live` per report, so a stale install can
never serve a lapsed reseller.

## Stages

| stage | time (EAT) | routers | result |
|---|---|---|---|
| Pilot | 28 Jul 20:53 | 277 | 83.5% capture verdict 23:01 |
| Stage 1 | 28 Jul 23:00 | 307, 163, 256, 255, 227, 44, 303, 258, 226, 297, 210, 195, 157 | 13/13 OK; 50-min obs clean |
| Stage 2 | 29 Jul 00:56 | 166, 184, 174, 240, 75, 155, 221, 262, 141, 247, 182 (+2 deferred) | 11/13 OK; 50-min obs clean |
| Stage 3 | 29 Jul 02:5x | 291, 309, 236, 10, 293, 137, 224, 300, 222, 218, 265, 292, 249, 294, 118 | 15/15 OK |

**Total: 40 routers** across 29 resellers (all active/trial — verified zero stale
subscription flags at reseller level).

## Deferred — needs action

- **Router 131 (Major1 Net, Router-0305):** RouterOS device-mode lock refused the
  scheduler (`configuration flagged ... update device-mode`). Needs a physical
  button press on site to lift, then re-run the installer. Orphan script was
  removed; router left as found.
- **Router 289 (kinara digital, Router-0760):** unreachable at stage 2, offline
  by stage 3. Install when it returns.

## What was installed per router

`/system script bitwave-usage-push` (walks `/queue simple`, posts one JSON batch
of cumulative counters to `/api/router/usage-push` with a per-identity HMAC
token) + `/system scheduler bitwave-usage-push` (2m interval, start-time
startup). Live identity verified against DB before each install (the token is
bound to it). Additive only — hotspot config and payment flow untouched.

**Rollback per router:**
`/system scheduler remove [find name="bitwave-usage-push"]; /system script remove [find name="bitwave-usage-push"]`

**NOT yet installed anywhere: the hotspot profile `on-logout` hook** (exact
final session totals). Deliberately deferred — it touches live hotspot profiles.
Next step after a full day of periodic-push data.

## Observed load (nothing measurable)

Two 50-min observation windows + fleet checks: 0 load-shed events, 0 ingest
errors, pg active connections 1–3 throughout, app memory oscillating 115–219 MiB
around its historical ~172 MiB norm, host mem_avail 104–176 MB. CPU spikes to
~15% were pre-existing background jobs caught mid-tick.

## Follow-ups

1. Weekly sweep to install on newly-eligible routers (new/renewed resellers) —
   without it the fleet drifts back to polling as it grows. See backlog.
2. Attach `on-logout` hook (staged, quiet window) → recovers session tails.
3. 24h capture report per router vs old baselines; tell affected resellers
   (SkyNet reported the original bug and deserves the confirmation).
4. Retire/trim the queue-walk in `collect_bandwidth_snapshot` once push coverage
   is stable — it still provides interface counters + health, so trim, not delete.
5. Deferred routers above.
