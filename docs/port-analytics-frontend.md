# Port Analytics Frontend Integration

## Endpoint

`GET /api/routers/{router_id}/port-analytics`

Optional query:

- `refresh=true` requests a fresh live router probe.

The endpoint is authenticated like the existing router diagnostics endpoints.

## Purpose

Use this endpoint to show what the MikroTik can see behind each physical port:

- link state, speed, duplex, flaps, errors, traffic
- downstream learned MACs by port
- likely AP/switch/infrastructure devices
- known customers matched by MAC
- unknown devices
- hotspot/PPPoE activity counts
- warnings such as silent links

This endpoint is read-only and intentionally separate from `GET /api/routers/{id}/ports`.

## Safety Behavior

The backend is designed to be kind to the constrained production server:

- `60s` per-router in-memory cache
- `20s` forced-refresh floor, even with `refresh=true`
- one live refresh per router at a time
- returns cached/stale data when a refresh is already running
- skips fresh live work during DB pool pressure when cached data exists
- bounded MikroTik diagnostic executor with timeout
- no DB writes and no schema changes

The UI should avoid fast polling. Prefer manual refresh, or a slow refresh interval of at least
`60s`.

## Response Shape

Top-level fields:

```ts
interface PortAnalyticsResponse {
  success: boolean;
  router: {
    id: number;
    name: string;
    identity_db?: string | null;
    identity_live?: string;
    ip: string;
  };
  generated_at: string;
  cached: boolean;
  cache_age_seconds?: number;
  stale?: boolean;
  refresh_pending?: boolean;
  refresh_skipped?: boolean;
  refresh_skip_reason?: 'recent_cache' | 'db_pool_pressure' | 'refresh_already_running' | 'busy' | 'timeout';
  system: RouterSystemSummary;
  totals: PortAnalyticsTotals;
  warnings: PortWarning[];
  infrastructure_candidates: InfrastructureDevice[];
  ports: PortAnalyticsPort[];
}
```

Port fields:

```ts
interface PortAnalyticsPort {
  port: string;
  bridge: string;
  bridge_status: string;
  link: {
    up: boolean;
    status: string;      // e.g. link-ok, no-link
    rate: string;        // e.g. 1Gbps, 100Mbps
    full_duplex: boolean;
    last_link_up_time: string;
    link_downs: number;
  };
  traffic: {
    rx_byte: number;
    tx_byte: number;
    rx_packet: number;
    tx_packet: number;
    rx_error: number;
    tx_error: number;
    rx_drop: number;
    tx_drop: number;
  };
  counts: {
    learned_macs: number;
    known_customers_seen: number;
    known_customers_connected: number;
    hotspot_hosts_seen: number;
    hotspot_authorized: number;
    hotspot_bypassed: number;
    active_hotspot_sessions: number;
    active_ppp_sessions: number;
    unknown_devices: number;
    infrastructure_devices: number;
  };
  health: {
    status: 'active' | 'silent_link' | 'down';
    warnings: string[];
  };
  infrastructure: InfrastructureDevice[];
  downstream_devices_sample: DownstreamDeviceSample[];
}
```

Supporting types:

```ts
interface InfrastructureDevice {
  port?: string;
  mac: string;
  name: string;
  ip: string;
  board: string;
  platform: string;
  version: string;
  source: 'neighbor' | 'dhcp/arp';
  last_seen: string;
}

interface DownstreamDeviceSample {
  mac: string;
  kind: 'known_customer' | 'unknown_device' | 'infrastructure';
  name: string;
  ip: string;
  last_seen: string;
  hotspot_authorized: boolean;
  hotspot_bypassed: boolean;
  hotspot_active: boolean;
  ppp_active: boolean;
  customer_id?: number;
  customer_status?: string;
}

interface PortWarning {
  port: string;
  warnings: string[];
}
```

## UI Recommendations

Show ports as operational rows/cards:

- `active`: green/normal, downstream MACs are visible
- `silent_link`: amber, physical link is up but no downstream devices are visible
- `down`: muted, no physical link

Useful columns:

- port
- link rate
- health
- infrastructure/AP names
- known customers seen
- connected customers
- hotspot hosts
- unknown devices
- errors/flaps

For a port detail drawer, show:

- infrastructure list
- downstream customer/device samples
- warning text
- traffic counters and errors

If `refresh_pending` or `refresh_skipped` is true, show a small stale/cache badge rather than
an error. A cached result is still useful operationally.

## Example Summary

```text
ether8
  Link: up, 1Gbps, full duplex
  Infrastructure: Ruijie AP
  Known customers seen: 19
  Hotspot hosts seen: 22
  Unknown devices: 5
  Health: active

ether7
  Link: up, 1Gbps, full duplex
  Learned MACs: 0
  Health: silent_link
  Warning: local link is up but nothing downstream is talking
```
