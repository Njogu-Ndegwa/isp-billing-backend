# Static-IP load balancing stops after router reboot

## Symptoms and cause

Hassan Server #1 (router 606) had healthy gigabit WAN links and successful
internet probes through both ports, but all customer traffic used ether1.
After a reboot, LB_PAID was empty and both PCC connection-mark counters were
zero. Timeout-bearing address-list entries do not survive a router reboot.

At base f7fa92c, the periodic LB reconciler selected only customers with
`mac_address`. Static subscribers use `static_ip` and may have no hotspot MAC,
so the reconciler could never restore them. Removing the unauthenticated
guard would break captive-portal delivery; it is not a workaround.

## Immediate repair and audit

Restored 72 active, unexpired static customers on router 606 after checking
their exact customer-owned enabled bypass bindings. Every entry has an
expiry-bound timeout. Live WAN1 and WAN2 connections immediately resumed
with the correct source NAT addresses.

All four LB-enabled routers were audited: 606, 354 (RB951), 221 (KARAMA),
and 537 (MIKROTIK HOME). RB951 also had one eligible static customer missing
from LB_PAID. Its second WAN separately had no DHCP lease. KARAMA and
MIKROTIK HOME had no missing eligible static customers in this audit.

## Permanent repair

The existing 271-second reconciler now includes active static subscribers,
including their effective grace expiry. Static recovery requires one exact,
enabled, customer-owned STATIC bypass binding. It rejects unbypassed hosts,
works before a static device appears in the host table, restores entries lost
on reboot, and refreshes expiry when a subscription changes. Failed reads
abort without mutation. Expired or unverified managed static entries are
removed; hotspot entries retain their existing lifecycle.

Static suspend, deletion, and IP changes remove LB_PAID before disabling or
removing the bypass binding, preventing routing marks from breaking unpaid
clients' portal access. No guard, WAN route, or customer entitlement is relaxed.

## Verification

Regression tests cover reboot recovery without a MAC or online host, renewal
and shortened expiry, grace, inactive/expired exclusion, binding ownership,
failed reads, idempotency, and cleanup order on suspend/delete/IP changes.
Live verification must distinguish marked connections from physical egress:
when a WAN is unavailable, both connection marks can correctly exit the
surviving WAN through fallback routes. A cable-pull test is separate from
read-only reachability and conntrack checks.
