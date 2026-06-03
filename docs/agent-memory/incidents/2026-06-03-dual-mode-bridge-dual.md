# 2026-06-03 Dual Mode Ports Stranded On Bridge-Dual

## Summary

Router 175 (`Fiber Wave Tech #1`) reported all access ports in dual mode on
`bridge-dual`, while the normal hotspot `bridge` had zero member ports. This
can make hotspot access and local router visibility appear broken after
PPPoE+hotspot port provisioning.

## Symptoms

- `GET /api/routers/175/ports?refresh=true` returned `bridge-dual` for
  `ether2` through `ether10` and `sfp-sfpplus1`.
- `bridge` was running but had `port_count: 0`.
- Affected ports were reported as `service: dual` with
  `pppoe_server_interface: bridge-dual`.
- Users reported provisioned ports stopped working for hotspot/PPPoE and router
  visibility.

## Suspected Cause

The old dual-mode topology moved customer access ports onto a separate
`bridge-dual` subnet with separate hotspot/DHCP/PPPoE infrastructure. That can
strand customer APs/ONTs outside the router's normal hotspot bridge, firewall,
neighbor, and management behavior. The safer topology is to keep access ports on
the normal hotspot `bridge` and bind PPPoE to that same bridge.

## Fix Applied

- Updated dual-mode setup to treat `bridge-dual` as legacy and restore those
  ports to `bridge`.
- Added shared-hotspot-bridge PPPoE detection so healed dual ports still appear
  as `dual` in port status.
- Added `POST /api/routers/{router_id}/heal-dual-mode` to repair existing
  routers without changing customer billing, expiry, or passwords.

## Verification

- Compile check passed for `app/api/router_operations.py`,
  `app/services/mikrotik_api.py`, and `tests/test_pppoe_router_defaults.py`.
- Import check passed for `app.api.router_operations`.
- Focused pytest could not run because the local virtualenv does not have
  `pytest` installed.

## Follow-Up Work

- Run the heal endpoint against router 175 after deployment and verify
  `/api/routers/175/ports?refresh=true` shows access ports on `bridge` with
  `service: dual` and `pppoe_server_interface: bridge`.
- Add live-router diagnostics for interface-list/firewall trust assumptions if
  any customer remains unreachable after the bridge layout is healed.
