# PPPoE User Monitoring — Frontend Integration Guide

This document describes the PPPoE monitoring API endpoint and how to build a frontend page that shows which PPPoE users are online/offline and how much bandwidth they are using in real time. All endpoints use JWT Bearer auth.

---

## Table of Contents

1. [Endpoint Reference](#1-endpoint-reference)
2. [Response Shape](#2-response-shape)
3. [Field Reference](#3-field-reference)
4. [Summary Cards](#4-summary-cards)
5. [Users Table](#5-users-table)
6. [Formatting Helpers](#6-formatting-helpers)
7. [Polling & Refresh Strategy](#7-polling--refresh-strategy)
8. [Filtering & Sorting](#8-filtering--sorting)
9. [Error Handling](#9-error-handling)
10. [Full Page Example (React)](#10-full-page-example-react)

---

## 1. Endpoint Reference

### `GET /api/pppoe/{router_id}/users`

Returns **every PPPoE user** on a router with real-time online/offline status and live bandwidth.

| Parameter | Location | Type | Required | Default | Description |
|-----------|----------|------|----------|---------|-------------|
| `router_id` | path | `int` | yes | — | Router ID |
| `refresh` | query | `bool` | no | `false` | Pass `true` to bypass the 30-second cache |

**Headers:**

```
Authorization: Bearer <token>
```

**Example call:**

```
GET /api/pppoe/1/users
GET /api/pppoe/1/users?refresh=true
```

---

## 2. Response Shape

```json
{
  "router_id": 1,
  "router_name": "Main Router",
  "generated_at": "2026-04-11T14:30:00.000000",
  "cached": false,
  "cache_age_seconds": null,
  "success": true,
  "summary": {
    "total": 25,
    "online": 18,
    "offline": 7,
    "disabled": 0,
    "total_upload_rate_bps": 15000000,
    "total_download_rate_bps": 85000000
  },
  "users": [
    {
      "username": "john_doe",
      "service": "pppoe",
      "profile": "10Mbps-Plan",
      "disabled": false,
      "comment": "Customer #42",
      "online": true,
      "address": "192.168.89.5",
      "uptime": "3d12h05m",
      "caller_id": "AA:BB:CC:DD:EE:FF",
      "upload_bytes": 524288000,
      "download_bytes": 2147483648,
      "upload_rate": "1500000",
      "download_rate": "8500000",
      "max_limit": "2M/10M",
      "last_logged_out": "",
      "last_disconnect_reason": "",
      "last_caller_id": "",
      "customer": {
        "id": 42,
        "name": "John Doe",
        "phone": "0712345678",
        "status": "active",
        "plan": "Home 10Mbps",
        "plan_speed": "10M",
        "expiry": "2026-05-01T00:00:00"
      }
    },
    {
      "username": "jane_smith",
      "service": "pppoe",
      "profile": "5Mbps-Plan",
      "disabled": false,
      "comment": "",
      "online": false,
      "address": null,
      "uptime": null,
      "caller_id": null,
      "upload_bytes": 0,
      "download_bytes": 0,
      "upload_rate": "0",
      "download_rate": "0",
      "max_limit": "1M/5M",
      "last_logged_out": "apr/11/2026 10:15:00",
      "last_disconnect_reason": "peer-not-responding",
      "last_caller_id": "11:22:33:44:55:66",
      "customer": {
        "id": 58,
        "name": "Jane Smith",
        "phone": "0723456789",
        "status": "active",
        "plan": "Home 5Mbps",
        "plan_speed": "5M",
        "expiry": "2026-04-20T00:00:00"
      }
    }
  ]
}
```

When the router is unreachable but stale cached data is available, the response includes:

```json
{
  "cached": true,
  "stale": true,
  "cache_age_seconds": 120.5
}
```

---

## 3. Field Reference

### `summary` object

| Field | Type | Description |
|-------|------|-------------|
| `total` | `int` | Total PPPoE users (secrets) on this router |
| `online` | `int` | Users with an active session right now |
| `offline` | `int` | Users without an active session |
| `disabled` | `int` | Users whose secret is disabled on the router |
| `total_upload_rate_bps` | `int` | Combined upload throughput of all online users (bits/sec) |
| `total_download_rate_bps` | `int` | Combined download throughput of all online users (bits/sec) |

### Each `users[]` entry

| Field | Type | When online | When offline |
|-------|------|------------|-------------|
| `username` | `string` | PPPoE username | PPPoE username |
| `service` | `string` | `"pppoe"` | `"pppoe"` |
| `profile` | `string` | PPP profile name (e.g. `"10Mbps-Plan"`) | Same |
| `disabled` | `bool` | Whether secret is disabled on router | Same |
| `comment` | `string` | Secret comment on router | Same |
| `online` | `bool` | `true` | `false` |
| `address` | `string \| null` | Assigned IP (e.g. `"192.168.89.5"`) | `null` |
| `uptime` | `string \| null` | Session duration (e.g. `"3d12h05m"`) | `null` |
| `caller_id` | `string \| null` | Client MAC address | `null` |
| `upload_bytes` | `int` | Cumulative upload bytes this session | `0` |
| `download_bytes` | `int` | Cumulative download bytes this session | `0` |
| `upload_rate` | `string` | Current upload throughput (bits/sec as string) | `"0"` |
| `download_rate` | `string` | Current download throughput (bits/sec as string) | `"0"` |
| `max_limit` | `string` | Speed cap (e.g. `"2M/10M"` = upload/download) | From PPP profile |
| `last_logged_out` | `string` | Empty | Timestamp of disconnection (e.g. `"apr/11/2026 10:15:00"`) |
| `last_disconnect_reason` | `string` | Empty | Reason for disconnect (e.g. `"peer-not-responding"`, `"admin-disconnect"`, `"tcp-connection-reset"`) |
| `last_caller_id` | `string` | Empty | MAC of last connected device |
| `customer` | `object \| null` | DB customer match (see below) | Same, `null` if no DB match |

### `customer` sub-object (when matched)

| Field | Type | Description |
|-------|------|-------------|
| `id` | `int` | Customer ID in the database |
| `name` | `string` | Customer name |
| `phone` | `string` | Phone number |
| `status` | `string` | `"active"`, `"inactive"`, `"pending"` |
| `plan` | `string \| null` | Plan name |
| `plan_speed` | `string \| null` | Plan speed (e.g. `"10M"`) |
| `expiry` | `string \| null` | ISO timestamp of subscription expiry |

---

## 4. Summary Cards

Display these at the top of the page as stat cards:

| Card | Value | Color / Style |
|------|-------|--------------|
| **Total Users** | `summary.total` | Neutral |
| **Online** | `summary.online` | Green |
| **Offline** | `summary.offline` | Red or gray |
| **Disabled** | `summary.disabled` | Orange (only show if > 0) |
| **Total Download** | `summary.total_download_rate_bps` → format as Mbps | Blue |
| **Total Upload** | `summary.total_upload_rate_bps` → format as Mbps | Teal / lighter blue |

**Formatting the rate values:**

```
total_download_rate_bps = 85000000 → 85.0 Mbps
total_upload_rate_bps = 15000000 → 15.0 Mbps
```

Divide by `1,000,000` and display with 1 decimal place + " Mbps".

---

## 5. Users Table

### Recommended columns

| Column Header | Source | Notes |
|---------------|--------|-------|
| **Customer** | `user.customer?.name ?? user.username` | Show customer name, fall back to PPPoE username. Show both if you have space. |
| **Phone** | `user.customer?.phone ?? "—"` | |
| **Status** | `user.online` | Green dot + "Online" or gray dot + "Offline". Red dot if `user.disabled`. |
| **IP Address** | `user.address ?? "—"` | Only populated when online |
| **Uptime** | `user.uptime ?? "—"` | Only populated when online |
| **Download** | `formatRate(user.download_rate)` | Current speed, see formatting below |
| **Upload** | `formatRate(user.upload_rate)` | Current speed, see formatting below |
| **Session Usage** | `formatBytes(user.download_bytes)` ↓ / `formatBytes(user.upload_bytes)` ↑ | Cumulative for this session |
| **Speed Limit** | `user.max_limit` | e.g. `"2M/10M"` (upload/download) |
| **Plan** | `user.customer?.plan ?? "—"` | |
| **Expiry** | `user.customer?.expiry` | Format as date |
| **Last Seen** | `user.last_logged_out` | Only useful when offline. MikroTik format: `"apr/11/2026 10:15:00"` |
| **Disconnect Reason** | `user.last_disconnect_reason` | Only when offline. Common values below. |

### Common disconnect reasons

| Value | Meaning |
|-------|---------|
| `peer-not-responding` | Client device stopped responding (power off, cable unplugged, etc.) |
| `admin-disconnect` | Disconnected by the system (expired, manually kicked) |
| `tcp-connection-reset` | Connection reset (network issue) |
| `session-timeout` | Session exceeded configured timeout |
| `port-disabled` | Physical port was disabled on the router |
| (empty string) | User has never disconnected or no info available |

---

## 6. Formatting Helpers

### Rate (bits per second → human readable)

`upload_rate` and `download_rate` come as string representations of bits per second from MikroTik.

```typescript
function formatRate(bpsStr: string): string {
  const bps = parseInt(bpsStr, 10) || 0;
  if (bps === 0) return "—";
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} Kbps`;
  return `${bps} bps`;
}
```

### Bytes → human readable

```typescript
function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return "—";
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(2)} GB`;
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(0)} KB`;
  return `${bytes} B`;
}
```

### Summary rate (bps integer → Mbps)

```typescript
function formatMbps(bps: number): string {
  if (!bps || bps === 0) return "0 Mbps";
  return `${(bps / 1_000_000).toFixed(1)} Mbps`;
}
```

---

## 7. Polling & Refresh Strategy

The backend caches results for **30 seconds** per router. Recommended approach:

### Auto-refresh every 30 seconds

```typescript
useEffect(() => {
  let cancelled = false;

  const load = async () => {
    try {
      const data = await fetchPPPoEUsers(routerId);
      if (!cancelled) setData(data);
    } catch (err) {
      if (!cancelled) setError(err);
    }
  };

  load();
  const interval = setInterval(load, 30_000);
  return () => {
    cancelled = true;
    clearInterval(interval);
  };
}, [routerId]);
```

### Manual refresh button

When the user clicks "Refresh", pass `?refresh=true` to bypass the cache and get fresh data from the router:

```typescript
const handleRefresh = () => {
  setLoading(true);
  fetchPPPoEUsers(routerId, true)
    .then(setData)
    .finally(() => setLoading(false));
};
```

### Show cache status

If `data.cached` is true, show a subtle indicator:

```typescript
{data.cached && (
  <span className="text-xs text-gray-400">
    Cached ({Math.round(data.cache_age_seconds)}s ago)
    {data.stale && " • Router unreachable, showing last known data"}
  </span>
)}
```

---

## 8. Filtering & Sorting

### Status filter (tabs or dropdown)

```typescript
type StatusFilter = "all" | "online" | "offline";

const filteredUsers = users.filter((u) => {
  if (statusFilter === "online") return u.online;
  if (statusFilter === "offline") return !u.online;
  return true;
});
```

### Search

Filter by customer name, PPPoE username, or phone:

```typescript
const searchedUsers = filteredUsers.filter((u) => {
  const q = search.toLowerCase();
  return (
    u.username.toLowerCase().includes(q) ||
    (u.customer?.name ?? "").toLowerCase().includes(q) ||
    (u.customer?.phone ?? "").includes(q)
  );
});
```

### Sorting

Useful sort options:

- **Bandwidth (download)** — `parseInt(u.download_rate) || 0` descending → see who's using the most right now
- **Bandwidth (upload)** — `parseInt(u.upload_rate) || 0` descending
- **Session usage** — `u.download_bytes` descending → biggest session data consumers
- **Uptime** — online users by how long they've been connected
- **Customer name** — alphabetical
- **Status** — online first, then offline

---

## 9. Error Handling

| HTTP Status | Meaning | Frontend behavior |
|-------------|---------|-------------------|
| `200` | Success | Render data normally |
| `200` with `cached: true, stale: true` | Router unreachable, stale data returned | Show data with a warning banner: "Router unreachable — showing cached data" |
| `404` | Router not found or not accessible | Show "Router not found" error |
| `503` | Router unreachable, no cache available | Show "Cannot connect to router. Please try again later." |
| `504` | Router operation timed out, no cache | Show "Router timed out. The router may be overloaded." |
| `500` | Server error | Show generic error message |

---

## 10. Full Page Example (React)

This is a minimal but functional example. Adapt to your component library and styling.

```tsx
import { useState, useEffect } from "react";

const API_BASE = "/api";

interface PPPoEUser {
  username: string;
  online: boolean;
  address: string | null;
  uptime: string | null;
  caller_id: string | null;
  upload_bytes: number;
  download_bytes: number;
  upload_rate: string;
  download_rate: string;
  max_limit: string;
  last_logged_out: string;
  last_disconnect_reason: string;
  profile: string;
  disabled: boolean;
  customer: {
    id: number;
    name: string;
    phone: string;
    status: string;
    plan: string | null;
    plan_speed: string | null;
    expiry: string | null;
  } | null;
}

interface PPPoESummary {
  total: number;
  online: number;
  offline: number;
  disabled: number;
  total_upload_rate_bps: number;
  total_download_rate_bps: number;
}

interface PPPoEResponse {
  router_id: number;
  router_name: string;
  generated_at: string;
  cached: boolean;
  stale?: boolean;
  cache_age_seconds: number | null;
  success: boolean;
  summary: PPPoESummary;
  users: PPPoEUser[];
}

function formatRate(bpsStr: string): string {
  const bps = parseInt(bpsStr, 10) || 0;
  if (bps === 0) return "—";
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} Kbps`;
  return `${bps} bps`;
}

function formatBytes(bytes: number): string {
  if (!bytes) return "—";
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(2)} GB`;
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function formatMbps(bps: number): string {
  return `${(bps / 1_000_000).toFixed(1)} Mbps`;
}

type StatusFilter = "all" | "online" | "offline";

export default function PPPoEUsersPage({ routerId, token }: { routerId: number; token: string }) {
  const [data, setData] = useState<PPPoEResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [search, setSearch] = useState("");

  const fetchData = async (refresh = false) => {
    try {
      const res = await fetch(
        `${API_BASE}/pppoe/${routerId}/users?refresh=${refresh}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }
      const json: PPPoEResponse = await res.json();
      setData(json);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => fetchData(), 30_000);
    return () => clearInterval(interval);
  }, [routerId]);

  const handleRefresh = () => {
    setLoading(true);
    fetchData(true);
  };

  if (error && !data) return <div className="text-red-500">Error: {error}</div>;
  if (!data) return <div>Loading...</div>;

  const filtered = data.users
    .filter((u) => {
      if (statusFilter === "online") return u.online;
      if (statusFilter === "offline") return !u.online;
      return true;
    })
    .filter((u) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        u.username.toLowerCase().includes(q) ||
        (u.customer?.name ?? "").toLowerCase().includes(q) ||
        (u.customer?.phone ?? "").includes(q)
      );
    });

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-bold">
          PPPoE Users — {data.router_name}
        </h1>
        <button onClick={handleRefresh} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {data.stale && (
        <div className="bg-yellow-50 border border-yellow-200 rounded p-3 mb-4 text-sm text-yellow-800">
          Router unreachable — showing cached data from{" "}
          {Math.round(data.cache_age_seconds ?? 0)}s ago
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-6">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">Total Users</div>
          <div className="text-2xl font-bold">{data.summary.total}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-green-600">Online</div>
          <div className="text-2xl font-bold text-green-600">{data.summary.online}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">Offline</div>
          <div className="text-2xl font-bold text-gray-400">{data.summary.offline}</div>
        </div>
        {data.summary.disabled > 0 && (
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-sm text-orange-500">Disabled</div>
            <div className="text-2xl font-bold text-orange-500">{data.summary.disabled}</div>
          </div>
        )}
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-blue-600">Total Download</div>
          <div className="text-2xl font-bold text-blue-600">
            {formatMbps(data.summary.total_download_rate_bps)}
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-teal-600">Total Upload</div>
          <div className="text-2xl font-bold text-teal-600">
            {formatMbps(data.summary.total_upload_rate_bps)}
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-4 mb-4">
        <div className="flex gap-1">
          {(["all", "online", "offline"] as StatusFilter[]).map((f) => (
            <button
              key={f}
              onClick={() => setStatusFilter(f)}
              className={`px-3 py-1 rounded text-sm ${
                statusFilter === f ? "bg-blue-600 text-white" : "bg-gray-100"
              }`}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
              {f === "online" && ` (${data.summary.online})`}
              {f === "offline" && ` (${data.summary.offline})`}
              {f === "all" && ` (${data.summary.total})`}
            </button>
          ))}
        </div>
        <input
          type="text"
          placeholder="Search by name, username, or phone..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="border rounded px-3 py-1 text-sm flex-1 max-w-xs"
        />
      </div>

      {/* Users Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-gray-500">
              <th className="py-2 px-3">Customer</th>
              <th className="py-2 px-3">Status</th>
              <th className="py-2 px-3">IP Address</th>
              <th className="py-2 px-3">Uptime</th>
              <th className="py-2 px-3">Download</th>
              <th className="py-2 px-3">Upload</th>
              <th className="py-2 px-3">Session Usage</th>
              <th className="py-2 px-3">Limit</th>
              <th className="py-2 px-3">Plan</th>
              <th className="py-2 px-3">Last Seen / Reason</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((u) => (
              <tr key={u.username} className="border-b hover:bg-gray-50">
                <td className="py-2 px-3">
                  <div className="font-medium">{u.customer?.name ?? u.username}</div>
                  {u.customer && (
                    <div className="text-xs text-gray-400">{u.username}</div>
                  )}
                  {u.customer?.phone && (
                    <div className="text-xs text-gray-400">{u.customer.phone}</div>
                  )}
                </td>
                <td className="py-2 px-3">
                  {u.disabled ? (
                    <span className="inline-flex items-center gap-1 text-orange-500">
                      <span className="w-2 h-2 rounded-full bg-orange-400" /> Disabled
                    </span>
                  ) : u.online ? (
                    <span className="inline-flex items-center gap-1 text-green-600">
                      <span className="w-2 h-2 rounded-full bg-green-500" /> Online
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-gray-400">
                      <span className="w-2 h-2 rounded-full bg-gray-300" /> Offline
                    </span>
                  )}
                </td>
                <td className="py-2 px-3 font-mono text-xs">{u.address ?? "—"}</td>
                <td className="py-2 px-3">{u.uptime ?? "—"}</td>
                <td className="py-2 px-3 font-medium text-blue-600">
                  {formatRate(u.download_rate)}
                </td>
                <td className="py-2 px-3 text-teal-600">
                  {formatRate(u.upload_rate)}
                </td>
                <td className="py-2 px-3 text-xs">
                  {u.online ? (
                    <>↓ {formatBytes(u.download_bytes)} / ↑ {formatBytes(u.upload_bytes)}</>
                  ) : "—"}
                </td>
                <td className="py-2 px-3 font-mono text-xs">{u.max_limit || "—"}</td>
                <td className="py-2 px-3">{u.customer?.plan ?? "—"}</td>
                <td className="py-2 px-3 text-xs text-gray-500">
                  {!u.online && u.last_logged_out ? (
                    <>
                      <div>{u.last_logged_out}</div>
                      {u.last_disconnect_reason && (
                        <div className="text-orange-500">{u.last_disconnect_reason}</div>
                      )}
                    </>
                  ) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="text-xs text-gray-400 mt-4">
        Generated: {new Date(data.generated_at).toLocaleString()}
        {data.cached && ` • Cached (${Math.round(data.cache_age_seconds ?? 0)}s ago)`}
      </div>
    </div>
  );
}
```

---

## Existing Related Endpoints (for reference)

These endpoints already existed before this update and may be useful for additional features:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/pppoe/{router_id}/overview` | Infrastructure health check (bridge, ports, server, pool, NAT) |
| `GET /api/pppoe/{router_id}/diagnose/{username}` | Deep layered diagnosis for one PPPoE user |
| `GET /api/pppoe/{router_id}/logs?username=&limit=50` | PPPoE-related router log entries |
| `GET /api/pppoe/{router_id}/secrets` | All secrets with online status (less data than `/users`) |
| `GET /api/mikrotik/{router_id}/pppoe/active` | Active sessions only (no offline users, no bandwidth) |
| `GET /api/mikrotik/top-users?router_id=&limit=10` | Top bandwidth consumers (now includes PPPoE users) |
| `GET /api/mikrotik/bandwidth-history?router_id=&hours=24` | Historical bandwidth graphs (active_queues now includes PPPoE count) |
