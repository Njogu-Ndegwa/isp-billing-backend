# 2026-07-30 — Dashboard usage bars wrong in every direction (two sources of truth + stale-read reset races)

## Symptoms

After the usage-push rollout (2026-07-28/29) the per-customer usage pages became
accurate, but the dashboard usage bars disagreed with reality in *every
direction at once*, measured against WAN interface byte deltas:

| router | owner | bars vs interface |
|---|---|---|
| 277 (SkyNet) | Mwal-Networks | 53.4% |
| 236 (Ella net #2) | Ella net | 2.9% |
| 222 (Ella net #1) | Ella net | 142.3% |
| 249 (Ella net #3) | Ella net | 181.8% |
| 10 (Bitwave Wangige) | Bitwave | 104.6% down / 151.9% up |

Dennis's diagnosis, verbatim: "Does it mean you are getting this data from two
different places? Which is terrible. Don't get this data from two different
places. Make sure you only have one source of truth." He was exactly right.

## Root causes (three, compounding)

1. **Two bookkeeping systems.** Customer pages read `customer_usage_periods`
   (fed by push every ~2 min). Dashboard bars read `bandwidth_snapshots`
   hotspot/pppoe byte fields, fed by a DIFFERENT pipeline: the poller's own
   deltas plus an **in-memory** bank (`_bar_deltas`) of push deltas. Any
   restart/deploy dropped the bank (undercount); any imbalance between the
   pipelines showed as bars ≠ customer pages.
2. **Stale-read "reset" double-books.** The queue-counter stream had THREE
   readers (push ingest, bandwidth poller, cap sampler) sharing one baseline
   row. A reader that fetched counters *before* another reader's write but
   applied them *after* saw counter < baseline, and `usage_counter_delta`'s
   rule "counter went backwards ⇒ reset ⇒ book the full value" re-booked the
   queue's whole lifetime counter — into bars AND periods. This is the 142–182%
   overshoot, and it inflated billing-relevant period totals too.
3. **Sampler slivers never reached bars.** The cap sampler consumed stream
   slivers (tight tiers poll near-cap customers every 15–60 s) that fed
   periods but never the snapshot bar fields — a structural undercount on
   routers with many capped customers (the 2.9%).

## Fix (PR: bars-single-source)

* **One ledger, one write path.** New `router_usage_buckets` table (5-min
  buckets per router). Written inside `record_usage` — the single choke point
  every crediting path already flows through — in the SAME transaction that
  credits the customer's period. Bars ≡ sum of customer usage by construction.
  Durable across restarts. In-memory bank deleted.
* **Snapshots demoted to router health.** Interface counters, throughput,
  session counts only; bar fields stay zero from both writers (legacy rows
  still summed by the endpoint so old history displays).
* **Stale-sample guard.** `record_queue_usage_sample` takes `sampled_at` (when
  counters were READ from the router); a sample older than the row's
  `last_updated` is discarded whole. The poller stamps `fetched_at` before its
  router read and skips rows a fresher writer advanced; the cap sampler carries
  `sampled_at` per `QueueSample` and keeps its poll tier on a stale skip.
  Genuine reboot/relogin resets (fresh reads) keep booking the fresh counter.
* **Endpoint merge.** `/api/mikrotik/bandwidth-history` attaches each bucket to
  the first snapshot row of its router at/after the bucket (tail → last row),
  and synthesizes bar-only entries for routers with buckets but no snapshots
  (poller-unreachable, e.g. CGNAT/Starlink) — usage still displays.

## Verification

* 15 new tests in `tests/test_router_usage_buckets.py` (ledger, bars==periods
  invariant, stale-guard race replay, endpoint merge, retention) + updated
  pinned tests. Full suite 750 passed.
* Post-deploy check: per-router `sum(buckets)` vs interface delta should sit
  BELOW 100% by the unattributed-traffic margin (walled garden, unqueued
  devices) and match `sum(period deltas)` exactly.

## Residual / follow-up

* Historical inflated periods (from past reset re-books) were NOT repaired —
  if a capped customer complains about early FUP, check their period against
  reality before arguing.
* Router 236 (Ella net #2) at 2.9% may ALSO have a dead push script — verify
  push freshness after this deploys.
* Router 281 (Ella net #4) never got the push script (offline during rollout).
* Interface counters remain deliberately collected as an independent AUDIT
  metric (total WAN traffic ≥ attributed usage) — not a second source of the
  same number, a different number.
