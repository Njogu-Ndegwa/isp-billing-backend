# MikroTik Health Endpoint (Dashboard)

> **Endpoint:** `GET /api/mikrotik/health?router_id={id}`
> **Auth:** Bearer JWT (same token used by the rest of the dashboard)
> **Server cache:** 5 minutes per router (`router_id`). Polling more often than that just returns cached data.
> **Body:** None (GET, only query params)

Returns a snapshot of a single router's health (CPU, memory, disk, uptime), live sensors, **active hotspot users**, **active PPPoE users**, and current bandwidth. Used by the main dashboard to show a per-router "connection stats" tile.

---


## Request

```http
GET /api/mikrotik/health?router_id=98
Authorization: Bearer <jwt_token>
```

### Query Parameters

| Param | Type | Required | Default | Description |
|---|---|---|---|---|
| `router_id` | integer | No | env default | ID of the router. If omitted, the backend uses the default router from env config. |
| `include_sessions` | boolean | No | `false` | If `true`, the response includes an inline (capped at 50) `active_pppoe_sessions` array. **The dashboard tile should leave this off** — use the dedicated drill-down endpoints for per-session detail (see "Related endpoints"). Provided only for backward compatibility. |

### Example (fetch)

```js
const res = await fetch(`/api/mikrotik/health?router_id=${routerId}`, {
  headers: { Authorization: `Bearer ${token}` },
});
const data = await res.json();
```

---

## Response `200 OK`

```json
{
  "system": {
    "uptime": "3h22m43s",
    "version": "6.49.18 (long-term)",
    "platform": "MikroTik",
    "board_name": "hEX S",
    "architecture": "mmips",
    "cpu": "MIPS 1004Kc V2.15",
    "cpu_count": 4,
    "cpu_frequency_mhz": 880
  },
  "cpu_load_percent": 22,
  "memory": {
    "total_bytes": 268435456,
    "free_bytes": 212492288,
    "used_bytes": 55943168,
    "used_percent": 20.8
  },
  "storage": {
    "total_bytes": 16777216,
    "free_bytes": 3764224,
    "used_bytes": 13012992,
    "used_percent": 77.6
  },
  "health_sensors": {},

  "active_users": 59,
  "active_hotspot_users": 59,
  "active_pppoe_users": 12,
  "active_total_users": 71,
  "sessions_truncated": false,

  "bandwidth": {
    "download_mbps": 71.28,
    "upload_mbps": 5.6
  },

  "snapshot_age_seconds": 369.2,
  "router_id": 98,
  "router_name": "NMK internet servicee  #4",
  "generated_at": "2026-04-24T17:56:02.538354",
  "cached": true,
  "cache_age_seconds": 200.8
}
```

### Fields for the Hotspot vs PPPoE dashboard tile

| Field | Type | Meaning |
|---|---|---|
| `active_users` | integer | **Hotspot users only** (persisted on the latest bandwidth snapshot). Same value as `active_hotspot_users`; kept for backward compatibility. |
| `active_hotspot_users` | integer | Explicit alias for hotspot-only users — prefer this in new code for clarity |
| `active_pppoe_users` | integer | **PPPoE** users currently online on the router (live from `/ppp/active/print`) |
| `active_total_users` | integer | Combined hotspot + PPPoE active users (`active_hotspot_users + active_pppoe_users`). Use this if you want a single "everyone online" tile. |
| `active_pppoe_sessions` | array | **Only present when `?include_sessions=true`.** Capped at 50 entries. Per-user PPPoE session details (`user`, `service`, `caller_id`, `address`, `uptime`, `encoding`, `session_id`). For drill-down tables, prefer `GET /api/mikrotik/{router_id}/pppoe/active` instead — it isn't capped and isn't tied to the 5-minute health cache. |
| `sessions_truncated` | boolean | Always present. `true` only when `include_sessions=true` AND there were more than 50 PPPoE sessions, in which case the inline array was capped — switch to the drill-down endpoint. `false` otherwise (including when sessions weren't requested). |
| `bandwidth.download_mbps` / `bandwidth.upload_mbps` | number | Current total router throughput |
| `router_id` / `router_name` | — | Router identity |
| `generated_at` | ISO string | When the backend produced this snapshot |
| `cached` / `cache_age_seconds` | boolean / number | True if served from backend cache and how old it is |
| `stale` | boolean (optional) | Present and `true` if the router is unreachable and a stale cache is being served |

If you only need the dashboard tile counts, use `active_hotspot_users` (Hotspot), `active_pppoe_users` (PPPoE), and `active_total_users` (combined). `active_users` is preserved as an alias for `active_hotspot_users`. **Do not pass `include_sessions=true` from the dashboard tile** — it bloats every poll and the array is capped anyway. Drill-down tables should call the dedicated endpoints listed below.

---

## Error Responses

| Status | When | Body |
|---|---|---|
| `401` | Missing or invalid JWT | `{ "detail": "Invalid token..." }` |
| `404` | `router_id` does not exist or is not accessible to the caller | `{ "detail": "Router not found or not accessible" }` |
| `500` | RouterOS returned an error | `{ "detail": "<router error>" }` |
| `503` | Could not connect to the router AND no cached snapshot exists | `{ "detail": "Failed to connect to router: <name>" }` |

> If the router is unreachable but a previous cached snapshot exists, the backend returns that snapshot with `stale: true` instead of `503`. Frontend should display a "router offline, showing last known data" banner when `stale === true`.

---

## Notes for Frontend

- **Polling cadence:** every 30–60 s is fine; backend cache is 5 min, so more frequent polling is just a cheap re-read of the cache.
- **Stale data:** check `stale` and `cache_age_seconds` → show a subtle "last updated Xs ago" label next to the tile.
- **Multi-router dashboards:** call this endpoint once per `router_id`. Each has an independent cache key. The dashboard tile poll should leave `include_sessions` off so the response stays small (~1–2 KB) regardless of how many users are online.
- Bandwidth and `active_hotspot_users` come from the backend's background bandwidth-snapshot job (more reliable, no extra load on the router). `active_pppoe_users` is live per request (reuses the same open MikroTik connection — no extra connection overhead). `active_total_users` is always computed as `active_hotspot_users + active_pppoe_users`, so the three counts are guaranteed to be self-consistent (no more "PPPoE > total" weirdness when fresh PPPoE sessions land between snapshots).
- **Related endpoints if you need drill-downs:** these are the right place to fetch per-session data. Don't lean on `include_sessions=true` for tables — it's capped and tied to the dashboard cache.
  - `GET /api/mikrotik/active-sessions?router_id={id}` — detailed hotspot sessions with traffic
  - `GET /api/mikrotik/{router_id}/pppoe/active` — detailed PPPoE sessions

### Migrating an existing frontend

If your tile currently relies on `active_pppoe_sessions` being inline in `/api/mikrotik/health`:

1. **Tile-only views** (just want counts): no change beyond reading the new count fields. The session array is no longer there by default — the tile gets smaller and faster automatically.
2. **Drill-down tables**: switch the data source from `health.active_pppoe_sessions` to `GET /api/mikrotik/{router_id}/pppoe/active`. That endpoint is live (no cache lag), unbounded, and fetches per-row traffic stats.
3. **Quick rollback path**: if you need the old shape during the migration, pass `include_sessions=true` — the inline array is back (capped at 50 with a `sessions_truncated` flag).
