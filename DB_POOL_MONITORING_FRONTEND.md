# DB Pool Monitoring Frontend Guide

This guide documents the admin endpoint the frontend can use to monitor backend database pool pressure.

## Endpoint

```http
GET /api/admin/db-pool
Authorization: Bearer <admin-token>
```

Admin-only. Use this as the normal lightweight polling endpoint.

## Detailed Mode

```http
GET /api/admin/db-pool?include_activity=true
Authorization: Bearer <admin-token>
```

Use this only when the lightweight response shows elevated pressure or when an admin explicitly opens a detail view.

Detailed mode adds a small `pg_stat_activity` summary:

- connection states
- wait events
- total Postgres connections for the current database
- up to 10 long-running or idle-in-transaction connections

## Polling Rules

- Normal admin dashboard polling: every 30-60 seconds.
- Do not poll faster than every 30 seconds.
- Do not call `include_activity=true` continuously.
- If `pressure.level` is `warning` or `critical`, fetch detailed mode once and show the details.
- If the tab is hidden, pause polling.

## Key Fields

```json
{
  "generated_at": "2026-05-31T...",
  "pool_snapshot_timing": "before_admin_auth_db_checkout",
  "pool": {
    "status": "Pool size: 15 ...",
    "configured_pool_size": 15,
    "configured_max_overflow": 15,
    "configured_max_app_connections": 30,
    "checked_out": 4,
    "checkout_headroom": 26,
    "checked_out_percent": 13.33,
    "pressure": {
      "level": "healthy",
      "patterns": ["normal_pool_pressure"],
      "read": "Pool pressure looks normal."
    }
  },
  "postgres_activity": {
    "skipped": true,
    "reason": "Pass include_activity=true to query pg_stat_activity."
  },
  "long_running_connections": []
}
```

## UI Status Mapping

- `healthy`: show normal/green state.
- `watch`: show low-priority warning text.
- `warning`: show amber warning and fetch detailed mode once.
- `critical`: show red critical state and fetch detailed mode once.

## Pattern Meanings

- `normal_pool_pressure`: pool looks fine.
- `moderate_pool_checkout`: pressure is rising but still has room.
- `high_pool_checkout`: watch closely.
- `very_high_pool_checkout`: near trouble.
- `low_checkout_headroom`: few checkout slots remain.
- `very_low_checkout_headroom`: likely close to outage.
- `overflow_connections_in_use`: app is using overflow beyond the base pool.
- `pool_exhausted`: critical; normal endpoints may start failing.

## Important Caveat

The default endpoint is lightweight, but it still performs admin authentication. That authentication does one short indexed DB lookup for the current admin user.

The pool counters are captured before that auth lookup, so the displayed pool pressure is not inflated by the monitoring request itself.

If the pool is already fully exhausted, the endpoint may fail because auth cannot get a DB connection. In that case, inspect Postgres directly from the server.

## Suggested Frontend Behavior

1. Poll `GET /api/admin/db-pool` every 30-60 seconds while the admin monitoring UI is visible.
2. Display `pool.pressure.level`, `pool.checked_out_percent`, and `pool.checkout_headroom`.
3. When `level` is `warning` or `critical`, call `GET /api/admin/db-pool?include_activity=true` once.
4. Show `postgres_activity.states`, `postgres_activity.wait_events`, and `long_running_connections` in an expandable detail panel.
5. Avoid loud alerts for a single `watch` result. Alert only on sustained `warning` or any `critical`.
