# 2026-08-05 LAN ports stranded on a leftover bridge — captive portal never appears

## Summary

Router-0826 ("Speed Wifi #1", id 316, owner `wycliffegetaro305@gmail.com`) was
provisioned 2026-08-04 and reported success, but no client was ever redirected to
the captive portal. Every hotspot-layer check was clean. The cause sat one level
below: `ether2`–`ether5` were members of a **leftover bridge `bridgeLocal`**, not
of `bridge` — the bridge that carries the hotspot server, the DHCP server and
192.168.88.1. The hotspot could not see a single client because nothing was
electrically attached to it.

Impact: one reseller's only router, unusable as a hotspot from provisioning until
repair. No customers had been onboarded yet, so no billing was lost.

## Symptoms

- Owner: "clients connect but are not directed to the captive portal page."
- `diagnose_router.py` returned **`findings: []`** — html-directory complete (27
  files incl. `redirect.html`), `login.html` the real portal, walled garden and
  hotspot NAT correct, hotspot server `hotspot1` enabled and valid.
- `hotspot_hosts: 0`, `hotspot_active: 0`, DHCP leases empty.
- Decisive tell: **`bridge` had `rx-byte: 0`** since provisioning, while
  `bridgeLocal` had passed traffic. `/interface bridge port print` showed
  ether2–5 on `bridgeLocal` and only `wlan1` on `bridge`.
- `wlan1` additionally `disabled=yes` and `mode=station` (factory leftover), so
  the one interface that *was* on the right bridge was switched off.
- Secondary fault: `bridgeLocal` carried a `defconf` DHCP **client** which had
  leased `192.168.0.103/24` from a downstream Tenda, while the WAN on `ether1`
  held `192.168.0.100/24` from the upstream — the same /24 reachable via two
  interfaces, and two default routes via `192.168.0.1`.

## Suspected Cause

Confirmed, not suspected. `app/services/provisioning.py` STEP 1 attached a LAN
port only when it was in **no** bridge at all:

```
:if ([:len [/interface bridge port find where interface=$iface]] = 0) do={
    /interface bridge port add interface=$iface bridge=bridge
}
```

On any router with a pre-existing bridge — an ex-provider base, or an old
RouterOS default config whose bridge is named `bridgeLocal` — that length is 1,
the guard is false, and the add is skipped. The whole step sits inside
`:do {...} on-error={}`, so nothing is logged and provisioning reports success.

Same silent-skip class as the RouterOS 7.23 `reset-html` rename
(`docs/agent-memory/` + `routeros-723-reset-html-rename`): a step that cannot
fail loudly will eventually fail quietly.

## Fix Applied

Router 316, live repair (11 API writes, all OK, verified before/after):

- `ether2`–`ether5` moved `bridgeLocal` → `bridge`.
- Removed the `defconf` DHCP client on `bridgeLocal` (which took
  `192.168.0.103/24` with it), leaving one unambiguous default route.
- Disabled `bridgeLocal` — kept, not deleted, so it is reversible.
- `wlan1` → `mode=ap-bridge`, open (portal does the auth), `band=2ghz-b/g/n`,
  `frequency=auto`, `channel-width=20/40mhz-XX`, enabled. SSID **"Flash WiFi"**.

Code fix, branch `fix/provisioning-bridge-port-move`:

- `app/services/mikrotik_api.py` — new `MANAGED_BRIDGE_NAMES`
  (`bridge`, `bridge-plain`, `bridge-pppoe`, `bridge-dual`) as the single source
  of truth for "a bridge this platform owns".
- `app/services/provisioning.py` — the LAN-port step now **moves** a port off a
  FOREIGN bridge and attaches it to `bridge`; a port already on one of OUR
  bridges is left untouched, so a re-provision cannot destroy a reseller's
  plain-port or PPPoE layout. Covers `wifi1` as well as `wlan1`. A foreign bridge
  left with no ports has its DHCP client and addresses removed and is disabled —
  deliberately *after* ether1's DHCP client and NAT exist, so the router is never
  routeless.
- `tests/test_provisioning_bridge_ports.py` — 16 tests, run by the existing
  `tests.yml` CI on every push and PR.

## Verification

- Full suite green locally; the new file's guards were mutation-tested by
  reintroducing the pre-fix block — 4 tests go red, including the exact-predicate
  guard `test_lan_port_attach_is_not_guarded_on_being_in_no_bridge`.
- Router 316 after repair: all five ports on `bridge`, radio `status: running-ap`,
  one default route, `192.168.0.0/24` via `ether1` only.
- End-to-end: three handsets (realme-C30s, 2× TECNO-SPARK-40-Pro) now hold
  `192.168.88.251/252/254` leases and register as hotspot hosts. The owner's phone
  showed **"Flash WiFi — Sign in to network"**, i.e. the OS captive-portal probe
  fired. Was 0 hosts / 0 leases before.
- Read-only fleet sweep (`sweep_bridges.py` pattern, 52 online routers, 50
  reachable): **0 routers currently have LAN ports stranded on a foreign bridge.**
  RouterOS `bridge` property was confirmed to serialise as a name string, and
  name-matching to be exact, on both v6.49 and v7.23 — the fix relies on that.

## Follow-Up Work

- **Three routers carry a leftover bridge with live addressing** — the rogue
  default-route hazard, not yet the portal fault. Needs Dennis's approval to
  clean (production write):
  - 240 `fastnet #3` — `bridgeLocal` + DHCP client
  - 262 `zoid tech 1` — `bridgeLocal` + DHCP client
  - 255 `AMANI APARTMENT #2` — `centipid-bridge` holding `172.31.0.1/16`
- The sweep only covers routers that were **online**; re-run it after an offline
  batch comes back.
- Router 316 site: the downstream Tenda (`D8:32:14:…`) still runs its own DHCP
  server on 192.168.0.1. Our leases are winning right now, but it should be put
  in AP/bridge mode with DHCP off to remove the race.
- Provisioning still never configures the radio (no SSID/mode/enable). Router 316
  shipped with `wlan1` disabled in `station` mode and needed a manual fix. Worth
  deciding whether provisioning should set up an AP by default.
