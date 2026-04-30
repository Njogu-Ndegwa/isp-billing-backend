# What's New: Hotspot User Monitoring (parity with PPPoE)

> **Endpoint added:** `GET /api/hotspot/{router_id}/users`
> **Change type:** New endpoint, no existing routes touched
> **Frontend action required:** Optional — only needed if you want to ship a hotspot users page mirroring the PPPoE one
> **Companion docs:** [`HOTSPOT_MONITORING_FRONTEND_GUIDE.md`](./HOTSPOT_MONITORING_FRONTEND_GUIDE.md)

---

## TL;DR

The dashboard already shows "amount of internet used by PPPoE users per session" along with live up/down rate, uptime, online/offline status, etc. via `GET /api/pppoe/{router_id}/users`. **The same view is now available for hotspot clients** at `GET /api/hotspot/{router_id}/users`, with an intentionally identical response shape so existing components can be reused.

For each hotspot client (whether they are a captive-portal voucher user *or* a bypassed ISP-billed customer) you now get:

- `online` flag and `online_source` (`"active"` for portal sessions, `"host"` for bypass)
- Live `upload_rate` / `download_rate` in **bps**
- Cumulative session `upload_bytes` / `download_bytes`
- `address` (current IP), `uptime`, `idle_time`, `mac_address`
- `max_limit` (the speed cap the user is currently subject to)
- `binding_type` (`bypassed` / `regular` / `blocked`)
- DB customer cross-reference matched by **MAC**

Plus a `summary` block that gives you total/online/offline/disabled counts and aggregated total upload/download throughput in bps — perfect for the same summary cards already used on the PPPoE page.

---

## Why this exists

The dashboard had a clear asymmetry: PPPoE users got rich per-user monitoring (rate, session bytes, uptime, online status) while hotspot users were only visible as raw active sessions via `GET /api/mikrotik/active-sessions`, which:

- Returns *only currently online sessions* (no offline / bypassed-but-idle clients)
- Has no DB customer cross-reference
- Doesn't expose the per-user simple-queue rate, so you can't see "this hotspot customer is currently downloading at 8.2 Mbps"
- Doesn't include IP-binding bypass clients that never go through the captive portal — which is the **majority** of paid ISP customers in this app

The new endpoint folds together every relevant MikroTik table on the router and gives the frontend one well-shaped list to render.

---

## Data sources joined behind the scenes

A single MikroTik connection now reads:

1. `/ip/hotspot/user/print` — captive-portal user accounts
2. `/ip/hotspot/ip-binding/print` — IP bindings (bypassed, regular, blocked) — primary identity for ISP customers
3. `/ip/hotspot/active/print` — currently online portal sessions
4. `/ip/hotspot/host/print` — every device the hotspot service has seen, including bypassed clients that skip auth
5. `/queue/simple/print` — per-user `plan_<username>` simple queues

The API joins all five and emits a unified, deduplicated `users` array. Each entry is keyed on a stable identity (username + MAC where available). The Python helper that does this lives in `mikrotik_api.py::get_hotspot_users_with_bandwidth`.

### Online detection

Hotspot has two ways to be "online":

| Path | Signal | `online_source` |
|------|--------|----------------|
| Portal-authenticated voucher session | matching MAC/user in `/ip/hotspot/active/print` | `"active"` |
| Bypassed ISP customer | host entry with `authorized=true` or `bypassed=true` | `"host"` |
| Otherwise | — | `null` (offline) |

This is necessary because bypassed customers **never appear in `/active`** — MikroTik short-circuits authentication before a session is created. The host table is the only durable signal for them.

### Live bandwidth

For each user we look up their `plan_<username>` simple queue (the queue this app creates at provisioning) and read:

- `rate` → split into `upload_rate` / `download_rate` (bps strings, identical convention to PPPoE)
- `bytes` → cumulative `upload_bytes` / `download_bytes` since the queue was last reset
- `max-limit` → returned as `max_limit`

For active portal sessions we prefer `bytes-in` / `bytes-out` from `/ip/hotspot/active/print` (per-session counters, more meaningful for vouchers) and fall back to the queue totals for bypassed customers (because their "session" is their entire subscription period).

---

## New response shape (abbreviated)

```json
{
  "router_id": 1,
  "router_name": "Main Router",
  "generated_at": "2026-04-28T22:30:00.000000",
  "cached": false,
  "cache_age_seconds": null,
  "success": true,
  "summary": {
    "total": 32,
    "online": 19,
    "offline": 13,
    "disabled": 1,
    "total_upload_rate_bps": 7500000,
    "total_download_rate_bps": 62000000
  },
  "users": [
    {
      "username": "aabbccddeeff",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "profile": "plan_2M_10M",
      "disabled": false,
      "comment": "USER:aabbccddeeff|EXPIRES:DB_MANAGED|...",
      "online": true,
      "online_source": "host",
      "address": "192.168.88.42",
      "uptime": "1h22m15s",
      "idle_time": "0s",
      "login_by": "",
      "upload_bytes": 142331904,
      "download_bytes": 1180319744,
      "upload_rate": "950000",
      "download_rate": "8200000",
      "max_limit": "2M/10M",
      "binding_type": "bypassed",
      "bypassed": true,
      "authorized": false,
      "has_queue": true,
      "customer": {
        "id": 117,
        "name": "Mary Wanjiku",
        "phone": "0712345678",
        "status": "active",
        "plan": "Home 10Mbps",
        "plan_speed": "10M",
        "expiry": "2026-05-12T00:00:00"
      }
    }
  ]
}
```

The shape is intentionally a superset of `GET /api/pppoe/{router_id}/users` plus three hotspot-specific fields (`mac_address`, `binding_type`, `online_source`) and a `bypassed` / `authorized` flag pair.

See [`HOTSPOT_MONITORING_FRONTEND_GUIDE.md`](./HOTSPOT_MONITORING_FRONTEND_GUIDE.md) for the full field reference and a ready-to-use React component.

---

## Caching & polling

| Behaviour | Value |
|-----------|-------|
| Server cache TTL | **30 seconds** per router (matches PPPoE) |
| Bypass cache | `?refresh=true` |
| Stale-on-router-down | `cached: true, stale: true` is returned with the last good payload if the router is unreachable; HTTP `503` only if there's no cache to fall back to |
| Recommended poll | every 30 s for the live page; manual refresh button forces `refresh=true` |

The cache is keyed per router, so multiple routers on the dashboard cache independently. The cache also doubles as a fallback when the router is unreachable, so users on the page won't see flicker if the router connection blips.

---

## Differences vs PPPoE (intentional)

| | PPPoE `/users` | Hotspot `/users` |
|---|---|---|
| Primary identity field | `username` | `mac_address` (with `username` as a stable secondary key) |
| Disconnect reason | `last_disconnect_reason`, `last_logged_out` | **Not exposed** — hotspot doesn't track this. Use `GET /api/hotspot/{router_id}/logs` instead. |
| Online signal | active session only | active session **or** authorised/bypassed host entry — captured in `online_source` |
| DB customer match key | `Customer.pppoe_username` | `Customer.mac_address` (normalised) |
| Bandwidth source queue | `<pppoe-USERNAME>` (auto-created by PPP profile) | `plan_<username>` (created by this app at provisioning) |

Everything else (the summary block, byte counters, rate strings, max_limit semantics, error codes, cache headers) is the same so you can ship a single shared "Users page" component and switch the data source URL based on the connection type.

---

## Postman collection

The endpoint is also added to `pppoe-hotspot-monitoring.postman_collection.json` under "Hotspot Monitoring → Hotspot Users (online/offline + live bandwidth)". Import via Postman → Import → Upload Files.

---

## Migration / rollout notes

- **No breaking changes.** All existing endpoints (including `/api/mikrotik/active-sessions`, `/api/hotspot/{router_id}/overview`, `/api/hotspot/{router_id}/logs`) continue to behave exactly as before.
- The `/api/mikrotik/active-sessions` endpoint is still useful when you only need currently-active portal sessions (no DB join, no per-user queue lookup). Prefer the new `/api/hotspot/{router_id}/users` for any UI that needs offline visibility, customer matching, or live throughput.
- If you already render a PPPoE users page, the fastest path to a hotspot users page is:
  1. Copy the PPPoE component
  2. Change the fetch URL to `/api/hotspot/{router_id}/users`
  3. Add a `MAC` column and (optional) `binding_type` chip
  4. Drop the `last_disconnect_reason` column (hotspot doesn't surface it)

That's it.
