# Router Remote Access API

This feature opens just-in-time operator access to a MikroTik router over the
existing management VPN. The API is used only to configure RouterOS services and
firewall rules; the operator access itself is WinBox, SSH, or WebFig.

It does not expose router management ports to the public internet and it does not
return router passwords.

## Preview Targets

`GET /api/admin/routers/{router_id}/remote-access`

Returns the default trusted source CIDR and connection targets.

```json
{
  "success": true,
  "router_id": 12,
  "router_name": "Router-0012",
  "management_ip": "10.0.0.12",
  "access_path": "management_vpn",
  "default_source_cidrs": ["10.0.0.1/32"],
  "available_services": ["winbox", "ssh", "webfig"],
  "targets": [
    {
      "service": "winbox",
      "label": "WinBox",
      "host": "10.0.0.12",
      "port": 8291,
      "winbox_address": "10.0.0.12:8291"
    }
  ]
}
```

## Enable Or Disable Access

`POST /api/admin/routers/{router_id}/remote-access`

```json
{
  "enable": true,
  "services": ["winbox", "ssh"],
  "source_cidrs": ["10.0.0.1/32"]
}
```

`services` may be `winbox`, `ssh`, or `webfig`. Both `services` and
`source_cidrs` also accept comma-separated strings for simple clients.

On enable, the backend:

1. Adds managed RouterOS input firewall accept rules for the selected service
   ports from the trusted source CIDRs.
2. Enables the matching RouterOS `/ip service` entry.
3. Restricts that RouterOS service to the trusted source CIDRs.

On disable, the backend removes its managed firewall rules and disables the
selected RouterOS service.

The DB session is committed before RouterOS network I/O starts.

## Simple WebFig Flow

The dashboard should use the dedicated WebFig flow instead of sending users to
`http://10.0.0.x/`, because their browser usually cannot route to the management
VPN directly.

### Open WebFig

`POST /api/admin/routers/{router_id}/webfig/open`

This endpoint enables RouterOS `www` from the trusted management source and
creates a short-lived browser proxy session.

```json
{
  "success": true,
  "router_id": 12,
  "router_name": "Router-0012",
  "management_ip": "10.0.0.12",
  "proxy_path": "/api/admin/routers/12/webfig/?remote_access_token=...",
  "expires_at": "2026-06-14T14:30:00.000000",
  "message": "WebFig access opened. Use the proxy URL in a browser."
}
```

Frontend should open `API_ORIGIN + proxy_path` in a new tab. The proxy route sets
an HTTP-only cookie scoped to `/api/admin/routers/{router_id}/webfig`, then
forwards browser requests to `http://10.0.0.x/` over the management VPN.

### Close WebFig

`POST /api/admin/routers/{router_id}/webfig/close`

Revokes active in-memory proxy sessions and disables RouterOS `www`.

### Proxy Route

`GET|POST|PUT|PATCH|DELETE|OPTIONS /api/admin/routers/{router_id}/webfig/{path}`

This is the browser-facing WebFig proxy. It accepts the one-time
`remote_access_token` query parameter on the first request or the scoped
`webfig_access_{router_id}` cookie on subsequent asset/form requests.
