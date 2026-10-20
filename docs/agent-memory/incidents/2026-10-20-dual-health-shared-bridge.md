# 2026-10-20 False dual-mode health warning on the shared hotspot bridge

## Summary

Router 174's PPPoE overview reported a failed dual-port check even though its
saved dual ports, ether2 and ether3, were on the normal hotspot bridge with an
enabled PPPoE server. The other infrastructure checks passed.

## Symptoms

- The live overview returned `healthy: false` and `dual_ports.passed: false`.
- Both ports had link and `actual_bridge: bridge`.
- Access discovery correctly reported `shared_hotspot_bridge`, but the overview
  showed `pppoe_attachment_mode: none` for both ports.

## Cause

Dual-mode setup now keeps ports on `bridge`. Access discovery deliberately
reports that shared server separately so ordinary hotspot ports do not become
dedicated PPPoE ports. The overview still required the legacy `bridge-dual`
attachment and ignored the shared server.

## Fix

The overview accepts a configured dual port on `bridge` when access discovery
finds an enabled PPPoE server there. It also accepts legacy dual attachments.
Each configured port must satisfy one of those conditions; an unrelated server
or a port on another bridge does not pass. The check label no longer requires
a separate dual bridge. No router configuration or billing data changes.

## Verification

- Regression tests reproduced the false warning before the code change.
- 39 focused PPPoE and hotspot-repair tests passed after the change.
- The database session discipline guard passed.
- No active PPPoE session was present during the initial router diagnosis. A
  correct infrastructure health report does not establish that a customer CPE
  has authenticated or has working internet.
