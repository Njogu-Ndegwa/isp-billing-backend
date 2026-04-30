# Hotspot User Monitoring — Frontend Integration Guide

This document describes the hotspot monitoring API endpoint and how to build a frontend page that shows which hotspot clients are online/offline and how much bandwidth they are using in real time. It is the hotspot equivalent of `PPPOE_MONITORING_FRONTEND_GUIDE.md` and uses the same response shape and helpers, so most React/TS code can be shared. All endpoints use JWT Bearer auth.

---

## Table of Contents

1. [Endpoint Reference](#1-endpoint-reference)
2. [Response Shape](#2-response-shape)
3. [Field Reference](#3-field-reference)
4. [Hotspot vs PPPoE: what's different](#4-hotspot-vs-pppoe-whats-different)
5. [Summary Cards](#5-summary-cards)
6. [Users Table](#6-users-table)
7. [Formatting Helpers](#7-formatting-helpers)
8. [Polling & Refresh Strategy](#8-polling--refresh-strategy)
9. [Filtering & Sorting](#9-filtering--sorting)
10. [Error Handling](#10-error-handling)
11. [Full Page Example (React)](#11-full-page-example-react)

---

## 1. Endpoint Reference

### `GET /api/hotspot/{router_id}/users`

Returns **every hotspot client** on a router with real-time online/offline status and live bandwidth. This includes both:

- **Captive-portal users** — voucher-style accounts in `/ip/hotspot/user/print`.
- **IP-binding clients** — typically `bypassed` ISP-billed customers in `/ip/hotspot/ip-binding/print` who skip the portal. **This is the common case** for paid ISP customers.

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
GET /api/hotspot/1/users
GET /api/hotspot/1/users?refresh=true
```

---

## 2. Response Shape

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
      "comment": "USER:aabbccddeeff|EXPIRES:DB_MANAGED|2026-04-15 09:00:00",
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
    },
    {
      "username": "voucher_a8f3",
      "mac_address": "11:22:33:44:55:66",
      "profile": "plan_1M_5M",
      "disabled": false,
      "comment": "Hotspot voucher #214",
      "online": true,
      "online_source": "active",
      "address": "192.168.88.91",
      "uptime": "0h42m05s",
      "idle_time": "12s",
      "login_by": "https-chap",
      "upload_bytes": 25600000,
      "download_bytes": 312000000,
      "upload_rate": "420000",
      "download_rate": "4800000",
      "max_limit": "1M/5M",
      "binding_type": "",
      "bypassed": false,
      "authorized": true,
      "has_queue": true,
      "customer": null
    },
    {
      "username": "ddeeff001122",
      "mac_address": "DD:EE:FF:00:11:22",
      "profile": "",
      "disabled": false,
      "comment": "USER:ddeeff001122|EXPIRES:DB_MANAGED|2026-04-26 12:30:00",
      "online": false,
      "online_source": null,
      "address": null,
      "uptime": null,
      "idle_time": null,
      "login_by": "",
      "upload_bytes": 0,
      "download_bytes": 0,
      "upload_rate": "0",
      "download_rate": "0",
      "max_limit": "",
      "binding_type": "bypassed",
      "bypassed": true,
      "authorized": false,
      "has_queue": false,
      "customer": {
        "id": 89,
        "name": "John Mwangi",
        "phone": "0723456789",
        "status": "expired",
        "plan": "Home 5Mbps",
        "plan_speed": "5M",
        "expiry": "2026-04-25T00:00:00"
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
| `total` | `int` | Total hotspot clients on this router (configured users + IP bindings, deduped) |
| `online` | `int` | Clients with an active session OR an authorized/bypassed host entry |
| `offline` | `int` | Clients without any current online signal |
| `disabled` | `int` | Hotspot users with `disabled=true` plus bindings of type `blocked` |
| `total_upload_rate_bps` | `int` | Combined upload throughput of all online clients (bits/sec) |
| `total_download_rate_bps` | `int` | Combined download throughput of all online clients (bits/sec) |

### Each `users[]` entry

| Field | Type | When online | When offline |
|-------|------|------------|-------------|
| `username` | `string` | Hotspot user name. For bypass-only clients this is the MAC with no colons (e.g. `aabbccddeeff`) — the same convention used at provisioning. | Same |
| `mac_address` | `string` | Normalised `XX:XX:XX:XX:XX:XX` | Same (or empty for portal-only voucher users that have never logged in) |
| `profile` | `string` | Hotspot profile name (e.g. `plan_2M_10M`) | Same |
| `disabled` | `bool` | `true` if the user record is disabled OR the binding is `blocked` | Same |
| `comment` | `string` | Comment from the hotspot user record, falling back to the binding comment | Same |
| `online` | `bool` | `true` | `false` |
| `online_source` | `string \| null` | `"active"` for portal sessions, `"host"` for bypassed customers seen by the hotspot host table | `null` |
| `address` | `string \| null` | Live IP from the active session / host entry / binding | `null` for offline portal users; bindings keep their static address if any |
| `uptime` | `string \| null` | Session duration (e.g. `"3h12m"`) | `null` |
| `idle_time` | `string \| null` | Idle duration (e.g. `"15s"`) | `null` |
| `login_by` | `string` | Auth method (`"https-chap"`, `"mac"`, `"http-pap"`, etc.) for portal sessions; empty for pure-bypass | Empty |
| `upload_bytes` | `int` | Cumulative upload bytes for the current session (active session counters first, queue running total as fallback for bypassed clients) | `0` |
| `download_bytes` | `int` | Cumulative download bytes for the current session | `0` |
| `upload_rate` | `string` | Current upload throughput (bits/sec, as string for parity with PPPoE) | `"0"` |
| `download_rate` | `string` | Current download throughput (bits/sec) | `"0"` |
| `max_limit` | `string` | Speed cap from the per-user `plan_<username>` simple queue (e.g. `"2M/10M"` = upload/download) | Same when known, otherwise empty |
| `binding_type` | `string` | `"bypassed"` for ISP-billed customers, `"regular"` for portal-managed bindings, `"blocked"` for kicked customers, empty when no binding exists | Same |
| `bypassed` | `bool` | `true` if the host entry is bypassed OR the binding type is `bypassed` | Same |
| `authorized` | `bool` | `true` if the hotspot host table marks the device authorized (typical for active portal sessions) | `false` |
| `has_queue` | `bool` | Whether a `plan_<username>` simple queue was found on the router. If `false`, rates / max-limit will be empty. | Same |
| `customer` | `object \| null` | DB customer match (see below), looked up by **MAC** | Same, `null` if no DB match |

### `customer` sub-object (when matched)

| Field | Type | Description |
|-------|------|-------------|
| `id` | `int` | Customer ID in the database |
| `name` | `string` | Customer name |
| `phone` | `string` | Phone number |
| `status` | `string` | `"active"`, `"inactive"`, `"pending"`, `"expired"` |
| `plan` | `string \| null` | Plan name |
| `plan_speed` | `string \| null` | Plan speed (e.g. `"10M"`) |
| `expiry` | `string \| null` | ISO timestamp of subscription expiry |

---

## 4. Hotspot vs PPPoE: what's different

The response shape mirrors `/api/pppoe/{router_id}/users` so existing components can be reused, but a few hotspot-specific quirks are worth knowing:

| Aspect | PPPoE | Hotspot |
|--------|-------|---------|
| Primary identity | Username | MAC address (most ISP customers) |
| Online signal | `/ppp/active/print` only | `/ip/hotspot/active/print` **or** the host table marking the MAC `authorized`/`bypassed` (`online_source` tells you which) |
| Per-session bytes | `<pppoe-USERNAME>` queue | `plan_<username>` queue (where `<username>` is usually the MAC with no colons) |
| Disabled state | `disabled` flag on the secret | `disabled` flag on the hotspot user **or** binding type set to `blocked` |
| Last disconnect reason | Available on the PPP secret | **Not exposed** by hotspot; we don't include it. Use the hotspot logs endpoint instead. |
| Customer DB match | By PPPoE username | By MAC address |

---

## 5. Summary Cards

Display these at the top of the page as stat cards. Same layout as the PPPoE page:

| Card | Value | Color / Style |
|------|-------|--------------|
| **Total Clients** | `summary.total` | Neutral |
| **Online** | `summary.online` | Green |
| **Offline** | `summary.offline` | Red or gray |
| **Blocked / Disabled** | `summary.disabled` | Orange (only show if > 0) |
| **Total Download** | `summary.total_download_rate_bps` → format as Mbps | Blue |
| **Total Upload** | `summary.total_upload_rate_bps` → format as Mbps | Teal / lighter blue |

**Formatting the rate values:**

```
total_download_rate_bps = 62000000 → 62.0 Mbps
total_upload_rate_bps   = 7500000  → 7.5 Mbps
```

Divide by `1,000,000` and display with 1 decimal place + " Mbps".

---

## 6. Users Table

### Recommended columns

| Column Header | Source | Notes |
|---------------|--------|-------|
| **Customer** | `user.customer?.name ?? user.username` | Show customer name, fall back to hotspot username (the MAC with no colons for bypass clients). |
| **MAC** | `user.mac_address` | Render as `font-mono`. Primary handle for hotspot. |
| **Phone** | `user.customer?.phone ?? "—"` | |
| **Status** | `user.online`, `user.disabled`, `user.binding_type` | Green dot + "Online" or gray dot + "Offline". Orange dot if `user.disabled` or `binding_type === "blocked"`. |
| **IP Address** | `user.address ?? "—"` | Only populated when online or known via binding |
| **Uptime** | `user.uptime ?? "—"` | Only populated when online |
| **Download** | `formatRate(user.download_rate)` | Current speed, see formatting below |
| **Upload** | `formatRate(user.upload_rate)` | Current speed |
| **Session Usage** | `formatBytes(user.download_bytes)` ↓ / `formatBytes(user.upload_bytes)` ↑ | Cumulative for this session |
| **Speed Limit** | `user.max_limit` | e.g. `"2M/10M"` (upload/download). Empty if `has_queue === false`. |
| **Plan** | `user.customer?.plan ?? "—"` | |
| **Expiry** | `user.customer?.expiry` | Format as date |
| **Mode** | `user.binding_type \|\| user.login_by` | "Bypassed" / "Voucher" / "Blocked" — gives a quick sense of how this client got on the network |

### Online-source badge

`online_source` lets you show a subtle source badge:

- `"active"` → "Portal session" (voucher / captive-portal users)
- `"host"` → "Bypass" (ISP-billed customers using IP-binding bypass)
- `null` → user is offline

---

## 7. Formatting Helpers

The exact same helpers used for PPPoE work here unchanged, because the wire shape is the same.

### Rate (bits per second → human readable)

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

## 8. Polling & Refresh Strategy

The backend caches results for **30 seconds** per router (same as PPPoE). Recommended approach:

### Auto-refresh every 30 seconds

```typescript
useEffect(() => {
  let cancelled = false;
  const load = async () => {
    try {
      const data = await fetchHotspotUsers(routerId);
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

When the user clicks "Refresh", pass `?refresh=true` to bypass the cache and read fresh data from the router:

```typescript
const handleRefresh = () => {
  setLoading(true);
  fetchHotspotUsers(routerId, true)
    .then(setData)
    .finally(() => setLoading(false));
};
```

### Show cache status

If `data.cached` is true, show a subtle indicator:

```tsx
{data.cached && (
  <span className="text-xs text-gray-400">
    Cached ({Math.round(data.cache_age_seconds)}s ago)
    {data.stale && " • Router unreachable, showing last known data"}
  </span>
)}
```

---

## 9. Filtering & Sorting

### Status filter (tabs)

```typescript
type StatusFilter = "all" | "online" | "offline";
const filteredUsers = users.filter((u) => {
  if (statusFilter === "online") return u.online;
  if (statusFilter === "offline") return !u.online;
  return true;
});
```

### Mode filter (optional)

For hotspot you'll often want a second filter for "what kind of client":

- `binding_type === "bypassed"` → ISP customer
- `binding_type === "blocked"` → kicked customer
- `online_source === "active"` → portal-authenticated voucher session
- everything else → walk-in / one-off

### Search

Filter by customer name, MAC, hotspot username, or phone:

```typescript
const searchedUsers = filteredUsers.filter((u) => {
  const q = search.toLowerCase();
  return (
    u.username.toLowerCase().includes(q) ||
    u.mac_address.toLowerCase().includes(q) ||
    (u.customer?.name ?? "").toLowerCase().includes(q) ||
    (u.customer?.phone ?? "").includes(q) ||
    (u.address ?? "").includes(q)
  );
});
```

### Sorting

Useful sort options:

- **Bandwidth (download)** — `parseInt(u.download_rate) || 0` descending
- **Bandwidth (upload)** — `parseInt(u.upload_rate) || 0` descending
- **Session usage** — `u.download_bytes` descending → biggest data consumers
- **Uptime** — online users by how long they've been connected
- **Customer name** — alphabetical
- **Status** — online first, then offline

---

## 10. Error Handling

| HTTP Status | Meaning | Frontend behavior |
|-------------|---------|-------------------|
| `200` | Success | Render data normally |
| `200` with `cached: true, stale: true` | Router unreachable, stale data returned | Show data with a warning banner: "Router unreachable — showing cached data" |
| `404` | Router not found or not accessible | Show "Router not found" error |
| `503` | Router unreachable, no cache available | Show "Cannot connect to router. Please try again later." |
| `504` | Router operation timed out, no cache | Show "Router timed out. The router may be overloaded." |
| `500` | Server error | Show generic error message |

---

## 11. Full Page Example (React)

This is a minimal but functional example. The shape lines up with the PPPoE page so you can fork that component and just swap the fetch URL plus a few hotspot-specific columns.

```tsx
import { useState, useEffect } from "react";

const API_BASE = "/api";

interface HotspotUser {
  username: string;
  mac_address: string;
  profile: string;
  disabled: boolean;
  comment: string;
  online: boolean;
  online_source: "active" | "host" | null;
  address: string | null;
  uptime: string | null;
  idle_time: string | null;
  login_by: string;
  upload_bytes: number;
  download_bytes: number;
  upload_rate: string;
  download_rate: string;
  max_limit: string;
  binding_type: string;
  bypassed: boolean;
  authorized: boolean;
  has_queue: boolean;
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

interface HotspotSummary {
  total: number;
  online: number;
  offline: number;
  disabled: number;
  total_upload_rate_bps: number;
  total_download_rate_bps: number;
}

interface HotspotResponse {
  router_id: number;
  router_name: string;
  generated_at: string;
  cached: boolean;
  stale?: boolean;
  cache_age_seconds: number | null;
  success: boolean;
  summary: HotspotSummary;
  users: HotspotUser[];
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

export default function HotspotUsersPage({ routerId, token }: { routerId: number; token: string }) {
  const [data, setData] = useState<HotspotResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [search, setSearch] = useState("");

  const fetchData = async (refresh = false) => {
    try {
      const res = await fetch(
        `${API_BASE}/hotspot/${routerId}/users?refresh=${refresh}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }
      const json: HotspotResponse = await res.json();
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
        u.mac_address.toLowerCase().includes(q) ||
        (u.customer?.name ?? "").toLowerCase().includes(q) ||
        (u.customer?.phone ?? "").includes(q) ||
        (u.address ?? "").includes(q)
      );
    });

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-bold">
          Hotspot Clients — {data.router_name}
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
        <Card label="Total" value={data.summary.total} />
        <Card label="Online" value={data.summary.online} color="green" />
        <Card label="Offline" value={data.summary.offline} color="gray" />
        {data.summary.disabled > 0 && (
          <Card label="Blocked" value={data.summary.disabled} color="orange" />
        )}
        <Card label="Total Download" value={formatMbps(data.summary.total_download_rate_bps)} color="blue" />
        <Card label="Total Upload" value={formatMbps(data.summary.total_upload_rate_bps)} color="teal" />
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
          placeholder="Search by name, MAC, phone, IP..."
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
              <th className="py-2 px-3">MAC</th>
              <th className="py-2 px-3">Status</th>
              <th className="py-2 px-3">IP Address</th>
              <th className="py-2 px-3">Uptime</th>
              <th className="py-2 px-3">Download</th>
              <th className="py-2 px-3">Upload</th>
              <th className="py-2 px-3">Session Usage</th>
              <th className="py-2 px-3">Limit</th>
              <th className="py-2 px-3">Mode</th>
              <th className="py-2 px-3">Plan</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((u) => (
              <tr key={u.mac_address || u.username} className="border-b hover:bg-gray-50">
                <td className="py-2 px-3">
                  <div className="font-medium">{u.customer?.name ?? u.username}</div>
                  {u.customer?.phone && (
                    <div className="text-xs text-gray-400">{u.customer.phone}</div>
                  )}
                </td>
                <td className="py-2 px-3 font-mono text-xs">{u.mac_address || "—"}</td>
                <td className="py-2 px-3">
                  {u.disabled || u.binding_type === "blocked" ? (
                    <span className="inline-flex items-center gap-1 text-orange-500">
                      <span className="w-2 h-2 rounded-full bg-orange-400" /> Blocked
                    </span>
                  ) : u.online ? (
                    <span className="inline-flex items-center gap-1 text-green-600">
                      <span className="w-2 h-2 rounded-full bg-green-500" /> Online
                      {u.online_source && (
                        <span className="text-xs text-gray-400 ml-1">
                          ({u.online_source === "active" ? "portal" : "bypass"})
                        </span>
                      )}
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
                <td className="py-2 px-3 text-xs text-gray-500">
                  {u.binding_type || u.login_by || "—"}
                </td>
                <td className="py-2 px-3">{u.customer?.plan ?? "—"}</td>
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

| Endpoint | Purpose |
|----------|---------|
| `GET /api/hotspot/{router_id}/overview` | Hotspot infrastructure health check (bridge, ports, DHCP, NAT, walled garden, profiles) |
| `GET /api/hotspot/{router_id}/logs?search=&limit=50` | Hotspot/DHCP log entries from the router |
| `GET /api/mikrotik/active-sessions?router_id=` | Active hotspot sessions only (no offline clients, no rate from queue) |
| `GET /api/mikrotik/top-users?router_id=&limit=10` | Top bandwidth consumers (cached snapshot, includes hotspot users by MAC) |
| `GET /api/mikrotik/bandwidth-history?router_id=&hours=24` | Historical bandwidth graphs |
| `GET /api/pppoe/{router_id}/users` | The PPPoE counterpart to this endpoint — same response shape |
