---
name: diagnose-customer-router
description: >
  Use when a customer's already-provisioned MikroTik router misbehaves for end users —
  "connected, no internet", captive portal / hotspot login page not appearing, clients
  not redirected, no WiFi sign-in, or the router shows online but customers can't get on —
  and you have the router's numeric ID (or its 10.0.0.x management-tunnel IP). For routers
  already in the ISP billing system and reachable over the production WireGuard tunnel.
---

# Diagnose Customer Router

## Overview

Diagnose hotspot / captive-portal faults on a live, already-provisioned router by querying
it **read-only** through the production server, comparing against a known-good router, and
matching the result against a catalog of proven failure modes.

**Core principle: diagnose read-only first; propose fixes and get explicit approval before
ANY write. This is a 1 GB-RAM production box — never restart anything.**

## When to use
- Customer router is online but clients get "no internet" / no captive portal / no redirect.
- You have the router's `id` (from the admin panel / `routers` table) or its `10.0.0.x` IP.
- The router is reachable via the management tunnel (if WAN is down, the tunnel is down too —
  it must be fixed locally first; see [[feedback-mikrotik-hardware-debugging]]).

Not for: provisioning a brand-new router, or routers not yet in the system.

## Safety rules (do not violate)
1. **Read-only by default.** The diagnostic script only runs `print` commands. Never run a
   writing command without showing the user the exact command and getting approval first.
2. **Never restart** the router, a container, or a service. No reboots, no `/system reset`.
3. **DB session discipline.** Read router creds in a short DB section, commit/close, THEN do
   RouterOS I/O. Never hold a DB session across network calls (see AGENTS.md).
4. **Never serve hotspot files from a foreign/leftover directory** (e.g. `flash/billing` = a
   previous provider's files). Only use a known-good Bitwave router as the template.
5. **Mind the 1 GB RAM.** One short-lived `docker exec python` at a time; the script is light.

## Step 0 — Connect (routers are reachable ONLY through the prod server)

**REQUIRED SUB-SKILL:** use `accessing-production-server` to connect and for the safety rules.
In short: customer routers live on the WireGuard `10.0.0.x` network and are reachable **only**
*through* the `isp_billing_app` container on `ssh dennis@54.91.202.229` — never directly from
your workstation. Read-only by default; never restart; mind the ~1 GB RAM.

Quick reachability check:
```bash
ssh -o BatchMode=yes dennis@54.91.202.229 \
  "docker exec isp_billing_app python -c \"import socket;s=socket.socket();s.settimeout(4);s.connect(('10.0.0.78',8728));print('router API reachable')\""
```

## Step 1 — Run the read-only diagnostic

From your workstation, pipe the bundled script (`diagnose_router.py` — it lives in this skill's
folder; `cd` there or use its absolute path) into the app container. You only need the router's
numeric **id**; the script resolves its `10.0.0.x` IP from the DB:

```bash
ssh -o BatchMode=yes dennis@54.91.202.229 \
  "docker exec -e ROUTER_ID=<id> -i isp_billing_app python -" \
  < diagnose_router.py
```

It prints JSON with `findings` (auto-flagged issues, each with `severity` + a *suggested*
fix) and `report` (raw facts). `severity: blocker` = almost certainly the cause;
`warning` = likely contributing or cosmetic. Known-good baseline router for comparison:
**RB951 id 207 / `10.0.0.78`** (and the now-fixed hEX id 213 / `10.0.0.84`).

## Step 2 — Match findings to the failure catalog

| Finding code | Symptom | Root cause | Proven fix (WRITE — get approval first) |
|---|---|---|---|
| `INCOMPLETE_HTML_DIR` | No popup / "no internet"; clients reach the hotspot (hosts > 0) but can't be redirected; `html-directory` has only `login.html` | Provisioning's default-file population (`reset-html-directory`) didn't run, so only the custom `login.html` landed. Seen on **RouterOS 7.18 and 7.23** alike — *not* version-specific; most common when the html-directory is `flash/hotspot` (hEX/RouterBOARD) | Copy a known-good router's hotspot files into the dir via `/file/add` (per-file, **text only**; `/file print` contents are capped ~4 KB so large files like `md5.js` read empty — skip them, they're non-essential for the redirect portal). See **Fix A**. |
| `DHCP_SUBNET_MISMATCH` / `DHCP_NO_MATCHING_NETWORK` | Client gets an IP but no gateway/DNS, never redirected (wired AND wireless) | Dirty base: `default-dhcp` pool is a leftover subnet (e.g. `192.168.10.x`) while hotspot/dhcp-network are `192.168.88.x` | `/ip pool set [find name=<pool>] ranges=192.168.88.10-192.168.88.254` then remove stray non-`192.168.88.x` bridge addresses. See **Fix B**. |
| `POSSIBLE_LEFTOVER_CONFIG` | Non-standard dirs (e.g. `flash/billing`) | Second-hand ex-provider router, not cleanly factory-reset before onboarding | Do **not** serve from them. Root cause is a dirty base — see [[project-secondhand-router-onboarding]]. |
| `NO_CLIENTS_REACHING_HOTSPOT` | 0 hosts, all LAN ports down, `wlan1` not running | AP unplugged/off; or hEX has no radio and the external AP isn't connected; or router flapping offline | Physical: confirm AP powered + cabled into a bridged ether port (or `wlan1` running if customers use built-in WiFi). |
| `WALLED_GARDEN_MISSING_PORTAL` | Portal page can't load | `*.vercel.app` not allowed pre-auth | Add walled-garden allow for `isp-frontend-two.vercel.app` + `*.vercel.app`. |
| `HOTSPOT_INVALID` / `NO_HOTSPOT_SERVER` / `NO_HOTSPOT_NAT` | Hotspot not running | Provisioning incomplete / hotspot package missing | Re-run provisioning; on hEX/smips 7.20+ the hotspot package may need installing. |

## Step 3 — Propose, confirm, apply, verify

Present the findings + the exact fix command(s). **Wait for approval.** Apply only after the
user agrees, then re-run the diagnostic (Step 1) to confirm the blocker finding is gone.
Final proof that the portal works needs a real client device on the AP (the script can't be
a hotspot client). Note any remaining `warning` findings.

### Fix A — repopulate hotspot files (INCOMPLETE_HTML_DIR)
Copy from a known-good router's `hotspot/` into the target's active html-directory:
read each text file from the baseline via `/file print` (per-file `?name=` query),
`/file/add name=<target>/<rel> contents=<text>` on the target, create subdirs with
`/file/add ... type=directory`, skip `login.html` if already correct, skip binaries.

### Fix B — align DHCP subnet (DHCP_SUBNET_MISMATCH)
```
/ip pool set [find name=default-dhcp] ranges=192.168.88.10-192.168.88.254
/ip address remove [find address="192.168.10.1/24"]
```
Safe when no clients are connected (the script reports host/lease counts); no restart.

## Common mistakes
- Treating every "no portal" the same — **always run the diagnostic**; 213 was missing files,
  201 was a DHCP subnet mismatch. Same symptom, different cause.
- Copying support files from `flash/billing` — that's the previous provider's config.
- Applying a fix without approval, or that could restart the box.

## References
- [[project-hotspot-redirect-debug]] — the 7.20+ hotspot-file bug, full diagnosis + fix.
- [[project-secondhand-router-onboarding]] — dirty-base pattern, DHCP mismatch, prevention.
- `accessing-production-server` skill — how to connect + run commands/scripts on the prod box safely (REQUIRED first).
- [[feedback-mikrotik-hardware-debugging]] — give RouterOS commands for hardware faults.
