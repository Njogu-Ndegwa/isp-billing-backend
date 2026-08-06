# 2026-08-06 — Hotspot customers displayed as PPPoE on the dashboard tile

## Symptom

Reseller dashboard for **Bitwave Wangige (router 10)** showed:

```
HOTSPOT  0   (updated 2m ago)
PPPOE   99   (live)
99 active • online
```

The router has **no PPPoE customers at all** — it is a hotspot-only site. Reported
by Dennis from the mobile dashboard at 17:57 EAT.

## What was actually wrong

Two defects compounding.

### 1. The push writer broke the `active_queues` contract

`mikrotik_background._collect_and_store` establishes the contract that
`bandwidth_snapshots.active_queues` is the **combined** count:

```python
active_devices = active_hotspot_users + pppoe_active_count
... active_queues=active_devices
```

The health endpoint depends on that, because it derives the PPPoE tile by
subtraction (`app/api/mikrotik_routes.py`, `_health_payload_from_live_result`):

```python
active_pppoe_users = max(0, (latest_snapshot.active_queues or 0) - active_hotspot_users)
```

But the newer push channel (`app/services/usage_push._persist_router_metrics`)
wrote the **raw simple-queue count** into that column, and put PPPoE into
`active_sessions` — a column the health endpoint never reads:

```python
active_hotspot_users=hotspot,
active_sessions=pppoe,
active_queues=queues,      # <-- queue_count, NOT hotspot + pppoe
```

So for router 10: `active_queues=102` (102 `plan_<MAC>` queues),
`active_hotspot_users=0` → tile PPPoE = 102 − 0 = **102 phantom PPPoE users**.

### 2. `/ip hotspot active` is empty on MAC-bypass hotspots

The router-side push script counts hotspot users as:

```
:local hs [:len [/ip hotspot active find]]
```

Bitwave admits customers by MAC ip-binding/bypass, not by a portal login, so
`/ip hotspot active` is legitimately empty. Confirmed fleet-wide: **all 273**
`[BANDWIDTH] ... summary:` log lines in a 6h window show `hotspot_sessions=0`.

Because the PPPoE figure is a *residual*, this zero did not surface as "hotspot
unknown" — it surfaced as "everyone is a PPPoE user".

## Evidence

```
 router_id |        recorded_at         | active_queues | active_hotspot_users | active_sessions
        10 | 2026-08-06 15:18:58        |           102 |                    0 |               0
        10 | 2026-08-06 15:00:58        |            99 |                    0 |               0
```

Background poller for the same router, same window — note `pppoe_sessions=0`:

```
[BANDWIDTH] Router 10 summary: hotspot_sessions=0, pppoe_sessions=0,
  hotspot_hosts=69, bypassed=31, arp_entries=446, active_queues=23, total_queues=97
```

Blast radius at the time of diagnosis (latest snapshot per router, 30 min window):
23 routers reporting, **6 showing phantom PPPoE, 131 phantom users**.

| router | name | owner | queues | hotspot shown | PPPoE shown |
|---|---|---|---|---|---|
| 10 | Bitwave Wangige | dennisndegwa001@gmail.com | 102 | 0 | 102 |
| 315 | skynet #1 | trevormutua66@gmail.com | 16 | 1 | 15 |
| 44 | ANTO #2 | antonymuinde364@gmail.com | 6 | 0 | 6 |
| 255 | AMANI APARTMENT #2 | gclinton312@gmail.com | 6 | 0 | 6 |
| 224 | RB951 UI | muchocyro@gmail.com | 6 | 5 | 1 |
| 258 | ENNIKO PROJECT #1 | lukhafenossichari@gmail.com | 8 | 7 | 1 |

## Fix

`app/services/usage_push._persist_router_metrics`:

- Derive the hotspot/PPPoE split from the **queue keys already in the push**
  (`plan_<MAC>` → hotspot, `pppoe:<user>` → PPPoE) via `_split_queue_keys`.
  This needs no router-side change and does not depend on `/ip hotspot active`.
- Write `active_queues = hotspot + pppoe`, honouring the contract the health
  endpoint subtracts from.
- Write the router's own hotspot-login count to `active_sessions`, matching what
  the poller stores there. PPPoE is no longer stashed in that column.

Regression tests: `tests/test_usage_push_router_metrics.py::
test_hotspot_customers_are_not_republished_as_pppoe` and
`::test_mixed_router_splits_hotspot_and_pppoe`.

## Verification

The tile reads the latest snapshot, so each router self-corrects on its next
push (~2 min after deploy). Confirm with:

```sql
SELECT router_id, active_queues, active_hotspot_users,
       GREATEST(0, active_queues - active_hotspot_users) AS pppoe_on_tile
FROM bandwidth_snapshots WHERE router_id = 10
ORDER BY recorded_at DESC LIMIT 3;
```

Router 10 should read `active_hotspot_users ≈ 102`, `pppoe_on_tile = 0`.

## Follow-up work (not in this change)

1. **The PPPoE tile is still a subtraction, not a measurement.**
   `_run_mikrotik_health_sync` hardcodes `pppoe_active = {..., "skipped": True}`,
   so the health endpoint never reads `/ppp/active`. Any future writer that gets
   `active_queues` wrong reintroduces exactly this class of bug. Persist
   `active_pppoe_users` as its own column and stop subtracting.
2. **The frontend hardcodes the caption "live" under the PPPoE number**
   (`../isp-billing-admin/app/dashboard/DashboardClient.tsx`). It is snapshot
   data, minutes old. Label it with the real snapshot age.
3. **Historical rows are not backfilled.** The bandwidth-history endpoint applies
   the same subtraction (`mikrotik_routes.py`, `active_pppoe = active_queues -
   active_hotspot`), so charts covering before this deploy still misattribute
   hotspot usage to PPPoE.
4. **`bypassed + authorized` can double-count** a host that is both, in
   `mikrotik_background`. Not the cause here, but it is not a distinct count.
