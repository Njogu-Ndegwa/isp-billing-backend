# 2026-09-19 Hotspot Reconnect Old-Device Overlap

## Summary

Phone-number self-service reconnects could briefly or indefinitely authorize
both the old and new device on direct-API MikroTik routers. The database kept
only one MAC, but the route provisioned the new MAC before a best-effort
background cleanup of the old MAC, and never verified that cleanup.

## Symptoms

- A reseller demonstrated the same two-hour subscription moving between two
  phones while both phones were connected to the hotspot.
- The affected customer had one database row, one payment, and a one-device
  plan; this was not duplicate billing data.
- In the preceding 48 hours, logs contained 42 explicit old-MAC cleanup
  connection failures affecting 21 customers. Six still had active,
  unexpired subscriptions at audit time.
- Live checks on reachable affected routers found no second bypass binding at
  audit time, but five of six retained stale old hotspot users or queues. One
  old phone was still physically connected as an unauthorized host while the
  new phone was bypassed.

## Cause

`restore_customer_on_device` committed the new MAC and queued new-device
provisioning before it queued old-device cleanup. Cleanup failure only emitted
a warning. The cleanup helper omitted hotspot-host and DHCP-lease removal,
ignored individual RouterOS command failures, and returned success without
reading the router back. Concurrent reconnect requests could also read the
same old MAC and race to provision different new MACs.

## Fix Applied

- Serialize reconnects per customer and use a row-lock/compare-and-swap as a
  cross-process backstop.
- Release the database transaction before all RouterOS I/O.
- On direct-API routers, revoke the old binding, active session, host, user,
  queues, DHCP lease, and load-balancer paid entry before changing the DB MAC.
- Read authorization-bearing state back from RouterOS and fail closed with a
  retryable 503 unless revocation can be proven.
- Provision the new MAC only after the DB move commits, and re-check that the
  target MAC is still current before background provisioning runs.
- Keep RADIUS reconnects on the database-authoritative path.

## Verification

- Unit tests cover complete cleanup, a removal failure that leaves a bypass
  binding, and an old phone immediately reappearing as an explicitly
  unauthorized host.
- Route tests prove cleanup sees the old DB MAC, provisioning follows the DB
  update, failed cleanup preserves the old DB MAC, and stale background
  provisioning is skipped.
- The database-session guard proves no pooled transaction crosses router I/O.

## Follow-Up Work

- Run a separately approved, rate-limited cleanup of stale old hotspot users,
  queues, hosts, and leases already left on affected routers. Do not fan this
  out from the 1 GB production server.

