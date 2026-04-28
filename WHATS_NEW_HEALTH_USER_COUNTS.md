# What's New: `/api/mikrotik/health` user-count contract

> **Endpoint affected:** `GET /api/mikrotik/health?router_id={id}`
> **Change type:** Backward-compatible additions + restored documented semantics + slimmer default payload
> **Frontend action required:** None for tile-only views. Drill-down tables should switch data source (see [Migration](#migration-checklist)).

This document explains what changed, why, the **new response shape**, and **what every field means** so the frontend knows exactly how to display the data.

---

## TL;DR

1. `active_users` is **hotspot users only** again (matches the original documented contract).
2. New explicit count fields:
   - `active_hotspot_users` — hotspot only (same as `active_users`, clearer name)
   - `active_pppoe_users` — PPPoE only (live)
   - `active_total_users` — hotspot + PPPoE combined
3. The default response **no longer includes** the `active_pppoe_sessions` array. Per-session detail moved to dedicated drill-down endpoints. Pass `?include_sessions=true` for the legacy shape (capped at 50).
4. The three counts are guaranteed self-consistent: `active_total_users == active_hotspot_users + active_pppoe_users`. The "PPPoE > total" symptom is gone.

---

## Why this changed

### Problem 1 — `active_users` was returning the wrong number

The doc said `active_users` was hotspot-only, but the bandwidth-snapshot job was writing `active_queues = hotspot_hosts + pppoe_sessions` and the route exposed that combined value as `active_users`. So `active_users` was actually "everyone online", which contradicted the contract and confused dashboards.

### Problem 2 — `pppoe > total` was possible

The previous fix derived hotspot count by subtracting **live PPPoE** from the **stale snapshot total**. Snapshots are minutes old; PPPoE is read live. If a few PPPoE sessions reconnected between snapshots, the live PPPoE count exceeded the snapshot total and the subtraction went negative (clamped to 0, but the totals still didn't add up).

**Fix:** persist hotspot count separately on every snapshot (new column `bandwidth_snapshots.active_hotspot_users`), then compute total at request time as `hotspot + live_pppoe`. Always consistent.

### Problem 3 — payload bloat from inline session arrays

The health endpoint is the dashboard tile poll, called every 30–60 s. Returning the full PPPoE session list in every response wasted bandwidth (≈30 KB on routers with 170+ sessions) and put PII (MACs, IPs, usernames) into every tile fetch. Drill-down endpoints already exist for that data — the tile shouldn't carry it.

---

## New response shape

### Default (slim — what the dashboard tile gets)

`GET /api/mikrotik/health?router_id=110`

```json
{
  "system": {
    "uptime": "2h54m52s",
    "version": "7.22.1 (stable)",
    "platform": "MikroTik",
    "board_name": "CRS125-24G-1S",
    "architecture": "mipsbe",
    "cpu": "MIPS 74Kc V4.12",
    "cpu_count": 1,
    "cpu_frequency_mhz": 600
  },
  "cpu_load_percent": 95,
  "memory": {
    "total_bytes": 134217728,
    "free_bytes": 67125248,
    "used_bytes": 67092480,
    "used_percent": 50.0
  },
  "storage": {
    "total_bytes": 134217728,
    "free_bytes": 112771072,
    "used_bytes": 21446656,
    "used_percent": 16.0
  },
  "health_sensors": {
    "voltage": "24.2",
    "temperature": "29"
  },

  "active_users": 1,
  "active_hotspot_users": 1,
  "active_pppoe_users": 13,
  "active_total_users": 14,
  "sessions_truncated": false,

  "bandwidth": {
    "download_mbps": 16.55,
    "upload_mbps": 1.05
  },

  "snapshot_age_seconds": 159.8,
  "router_id": 110,
  "router_name": "SIMSEAS TECHNOLOGIES AND SERVICES #4",
  "generated_at": "2026-04-28T17:01:48.265980",
  "cached": true,
  "cache_age_seconds": 204.4
}
```

### Backward-compat (with sessions)

`GET /api/mikrotik/health?router_id=110&include_sessions=true`

Same as above, plus:

```json
{
  "active_pppoe_sessions": [
    {
      "user": "Suleiman",
      "service": "pppoe",
      "caller_id": "F4:1E:57:65:6D:3C",
      "address": "192.168.89.254",
      "uptime": "2h54m20s",
      "encoding": "",
      "session_id": "0x81100000"
    }
  ],
  "sessions_truncated": false
}
```

The array is **capped at 50 entries**. If the router had more than 50 PPPoE sessions, `sessions_truncated` becomes `true` and the frontend should switch to the dedicated drill-down endpoint.

---

## Field reference

### User-count fields (the ones that changed)

| Field | Type | Meaning | When to use |
|---|---|---|---|
| `active_users` | integer | **Hotspot users only.** Legacy alias of `active_hotspot_users`. | Backward compatibility only. New code should prefer `active_hotspot_users`. |
| `active_hotspot_users` | integer | Hotspot users only (devices authorized + bypassed on the hotspot). Persisted on the latest bandwidth snapshot. | "Hotspot users" tile. |
| `active_pppoe_users` | integer | PPPoE users currently online. **Live** from `/ppp/active/print` on every request. | "PPPoE users" tile. |
| `active_total_users` | integer | Combined hotspot + PPPoE. Always equals `active_hotspot_users + active_pppoe_users` — guaranteed consistent. | "Everyone online" tile. |
| `sessions_truncated` | boolean | Always present. `true` only when `include_sessions=true` AND there were >50 PPPoE sessions on the router. | Show a "view all" link to the drill-down endpoint when this is `true`. |
| `active_pppoe_sessions` | array | **Only present when `?include_sessions=true`.** Capped at 50 entries. | Backward-compat only — prefer the drill-down endpoint. |

> **Note:** Hotspot count comes from a snapshot that's a few minutes old (see `snapshot_age_seconds`); PPPoE count is live. The total is computed at request time so the three numbers always reconcile (`hotspot + pppoe == total`).

### Difference between `active_users` and `active_total_users`

This question came up — they sound similar but mean different things:

| Field | Counts | Example |
|---|---|---|
| `active_users` | **Hotspot only** (1 user on captive portal) | `1` |
| `active_total_users` | **Hotspot + PPPoE combined** (everyone online) | `1 + 13 = 14` |

The naming of `active_users` is historical. Use `active_hotspot_users` in new code so the meaning is obvious from the field name.

### System / health fields (unchanged)

| Field | Type | Meaning |
|---|---|---|
| `system.uptime` | string | Router uptime (e.g. `"2h54m52s"`). |
| `system.version` | string | RouterOS version. |
| `system.platform` / `board_name` / `architecture` / `cpu` | string | Hardware identifiers. |
| `system.cpu_count` / `cpu_frequency_mhz` | integer | CPU details. |
| `cpu_load_percent` | integer | Current CPU load %. |
| `memory.{total,free,used}_bytes` | integer | RAM usage in bytes. |
| `memory.used_percent` | number | RAM usage %. |
| `storage.{total,free,used}_bytes` | integer | Disk usage in bytes. |
| `storage.used_percent` | number | Disk usage %. |
| `health_sensors` | object | Voltage, temperature, fan, etc. — varies per board. |
| `bandwidth.download_mbps` / `upload_mbps` | number | Current router throughput. |

### Metadata fields

| Field | Type | Meaning |
|---|---|---|
| `router_id` / `router_name` | int / string | Router identity. |
| `generated_at` | ISO string | When the backend produced this response. |
| `snapshot_age_seconds` | number | Age of the bandwidth snapshot the hotspot count came from. Show as "updated Ns ago" near the hotspot tile. |
| `cached` | boolean | `true` if served from the 5-min server cache. |
| `cache_age_seconds` | number | How old the cached entry is. |
| `stale` | boolean (optional) | Present and `true` only when the router was unreachable and a previous cached snapshot is being served. Show an "offline, last known data" banner. |

---

## How to display each field

### Recommended dashboard tile layout

```
┌──────────────┬──────────────┬──────────────┐
│   Hotspot    │    PPPoE     │    Total     │
│      1       │      13      │      14      │
│ updated 160s │     live     │   live calc  │
└──────────────┴──────────────┴──────────────┘
```

- **Hotspot tile**: `active_hotspot_users`. Subtitle: `"updated ${snapshot_age_seconds}s ago"`.
- **PPPoE tile**: `active_pppoe_users`. Subtitle: `"live"`.
- **Total tile** (optional): `active_total_users`. Subtitle: `"hotspot + pppoe"`.
- **Stale banner**: if `stale === true`, show "Router offline — showing last known data".
- **Cache hint** (optional): if `cached && cache_age_seconds > 30`, show a subtle "data is Ns old".

### What NOT to do

- ❌ Don't display `active_users` and `active_total_users` side by side — they look like the same thing but aren't, which confuses users. Pick one (prefer `active_hotspot_users`).
- ❌ Don't poll with `?include_sessions=true` from the tile. The cap is 50 and the data is up to 5 min stale — the drill-down endpoints are the right source.
- ❌ Don't try to derive `active_hotspot_users` yourself by subtracting from `active_total_users`. The backend already gives you the right number.

---

## Drill-down endpoints (per-session detail)

When the user opens a "view all sessions" panel, fetch from these — not from `health?include_sessions=true`:

| Endpoint | Returns | Notes |
|---|---|---|
| `GET /api/mikrotik/{router_id}/pppoe/active` | All live PPPoE sessions | No cap. No health-cache lag. Live per request. |
| `GET /api/mikrotik/active-sessions?router_id={id}` | All live hotspot sessions | Includes per-session traffic stats. |

Both endpoints already existed; they're just now the preferred source for tables.

---

## Migration checklist

If your frontend currently uses `/api/mikrotik/health`:

- [ ] **Tile-only views** — no change required. The new count fields (`active_hotspot_users`, `active_pppoe_users`, `active_total_users`) are additive. `active_users` is preserved as a hotspot-only alias.
- [ ] **Tile that displayed "all online"** — if you were reading `active_users` and labelling it "All users", switch to `active_total_users`. (`active_users` now means hotspot only, matching the original contract.)
- [ ] **PPPoE drill-down table** — switch data source from `health.active_pppoe_sessions` to `GET /api/mikrotik/{router_id}/pppoe/active`. Live, unbounded, no cache lag.
- [ ] **Hotspot drill-down table** — switch to `GET /api/mikrotik/active-sessions?router_id={id}`.
- [ ] **Quick rollback** — pass `?include_sessions=true` to keep the old shape during the migration window.

No breaking changes if you only read the count fields. The session array silently disappearing from the default response is the only shape change, and that's what `?include_sessions=true` is there for.

---

## Backend changes (for reference)

- `app/db/models.py` — added `BandwidthSnapshot.active_hotspot_users` column.
- `app/services/mikrotik_background.py` — snapshot writer now persists hotspot count separately; carry-forward branch fixed to use the hotspot column instead of double-counting PPPoE.
- `app/api/mikrotik_routes.py` — `/api/mikrotik/health` reads the persisted hotspot count, computes total from live PPPoE, exposes the new field set, slims the default response, supports `?include_sessions=true` with a 50-entry cap.
- `migrations/add_bandwidth_snapshot_active_hotspot_users.py` — adds the new column with a backfill from the legacy combined value.

To apply on a deployment:

```bash
python migrations/add_bandwidth_snapshot_active_hotspot_users.py
# then restart the API + background snapshot worker
```

---

## Quick consistency check

For the example router used throughout this doc:

```
active_hotspot_users = 1
active_pppoe_users   = 13
active_total_users   = 14   ← always equals hotspot + pppoe
active_users         = 1    ← legacy alias of hotspot
```

If you ever see `active_total_users != active_hotspot_users + active_pppoe_users`, that's a backend bug — please file it.
