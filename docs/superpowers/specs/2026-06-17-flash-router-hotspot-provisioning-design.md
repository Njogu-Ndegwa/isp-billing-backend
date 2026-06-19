# Flash-Router Hotspot Provisioning — Design Spec

**Date:** 2026-06-17
**Status:** Approved design, pending implementation plan

## Problem

Provisioning relies on `/ip hotspot profile reset-html-directory` (provisioning.py STEP 4,
~line 542) to materialise the full default hotspot HTML file set, then STEP 5 `/tool fetch`es
only the custom `login.html` into the active html-directory. That `reset-html-directory` step
is unreliable — **unavailable on RouterOS 7.23, and did not populate on 7.18** — leaving the
html-directory with **only `login.html`** and none of the support files (`redirect.html`,
`errors.txt`, `alogin.html`, …). The hotspot then can't run its captive-portal redirect
handshake → clients connect but are never redirected → "connected, no internet."

Confirmed on **router 213** (hEX S, 7.23.1) and **router 215** (RB951, 7.18). Most visible on
flash-filesystem devices, where the html-directory resolves to `flash/hotspot` (RouterOS
auto-rewrites `hotspot`→`flash/hotspot` on devices that expose a `flash` namespace). The issue
is NOT model- or version-specific.

## Goal

Guarantee the **complete** hotspot file set lands in the active html-directory on
flash-filesystem routers (hEX and any device exposing a `flash` namespace, RouterOS v6 & v7),
**without relying on `reset-html-directory`**. Averts the incomplete-html-directory failure for
newly provisioned routers, via both the add-router flow and the onboarding wizard.

## Decisions (from brainstorming)

1. **Dedicated flash-device path**, kept distinct from the standard flow (testable in isolation).
2. **Triggered by runtime flash detection** — the effective html-directory resolving to
   `flash/...` — NOT by model or an operator flag. Covers non-hEX flash devices (e.g. the 7.18
   RB951) too.
3. **Files delivered by `/tool fetch` of a canonical bundle served by the backend** — deterministic,
   RouterOS-version-independent, and binary-safe (handles `md5.js`/`favicon.ico`, which the
   `/file print` API method cannot — it caps `contents` at ~4 KB).

## Architecture / Components

### 1. Canonical hotspot bundle (single source of truth)
Commit a `hotspot_template/` directory in the backend repo containing the full standard hotspot
file set sourced from a clean router (e.g. id 207) plus the custom `login.html`:
`login.html, redirect.html, alogin.html, rlogin.html, logout.html, status.html, error.html,
errors.txt, radvert.html, api.json, md5.js, favicon.ico, css/style.css, img/user.svg,
img/password.svg, xml/{login,alogin,rlogin,logout,flogout,error}.html, xml/WISPAccessGatewayParam.xsd`.
`login.html` in the bundle is the **same** file the existing `/login-page` endpoint serves
(refactor `serve_login_page` to read from the bundle) — no drift between the two.

### 2. Backend asset endpoint
`GET /api/provision/{token}/hotspot-asset/{relpath}` — token-validated (token must exist;
accepts PROVISIONED/expired like `/login-page`), serves the bundle file at `relpath`
(binary-safe), with strict path-traversal guarding (relpath constrained to the bundle).
The `.rsc` generator knows the bundle's file list at generation time, so it emits explicit
fetch commands — **no runtime manifest endpoint required.**

### 3. `.rsc` generator — flash path
After STEP 4 (profile created) and reading back the effective html-directory (`$htmlDir`):
- `:if ($htmlDir ~ "^flash/")` → **flash path**: for each bundle file `relpath`, ensure its parent
  subdir exists (`/file add type=directory`, idempotent), then
  `/tool fetch url="{base}/api/provision/{token}/hotspot-asset/{relpath}" dst-path="$htmlDir/{relpath}"{cert_flag}`,
  inside the existing retry loop. Reuses `provision_base_url_for_vpn` and
  `fetch_certificate_flag_for_url` (v6 https→http + `check-certificate=no`).
- else → unchanged current behavior (`reset-html-directory` + `login.html`), which works on the
  non-flash devices observed (207/201). **`reset-html-directory` is no longer relied on for flash devices.**

### 4. Add-router & onboarding (inherit automatically — no separate wiring)
Both `isp-billing-admin/app/routers/page.tsx` (add-router, line ~281) and
`app/setup/page.tsx` (onboarding "Add Your First Router", line ~265) call the same
`api.createProvisionToken(vpnType)` → `/api/provision/create` → the generated `.rsc`. Updating
the backend generator propagates the new flash path to **both** flows with no frontend logic
change. Deliberate frontend-facing change: the backend-generated `note` (shown in both via
`result.note`) is updated to mention robust hotspot-file auto-install + a pointer to the
`diagnose-customer-router` check if a customer isn't redirected. No `is_routerboard` UI toggle
exists (frontend passes only `vpnType`); auto-detect supersedes the flag server-side (kept as a
back-compat no-op). `HotspotPackageTroubleshoot.tsx` is unchanged — it covers the separate
smips hotspot-*package*-missing issue, not file population.

## v6 & v7
One path serves both: v6 hEX (l2tp, `flash/hotspot`) and v7 flash devices alike. The
`is_routerboard` flag becomes redundant for file population.

## Idempotency & safety
Re-runnable (fetch overwrites; dir-create idempotent). Touches only the html-directory — no
effect on bridges/DHCP/plain-ports, no restart. Fetch failures handled by the existing retry loop.

## Testing
- **Unit:** `.rsc` generator emits the flash block + exactly one fetch per bundle file (assert on
  generated text); asset endpoint serves correct bytes, validates the token, and rejects
  path traversal.
- **Live:** provision/re-provision a real hEX (213) and a flash RB951 (215) from **both** the
  add-router page and the onboarding wizard; confirm the full file set in `flash/hotspot` and a
  working portal; run the `diagnose-customer-router` skill → 0 findings.
- Run focused backend tests; frontend build in `../isp-billing-admin` (note-text change only).

## Out of scope / optional follow-ups
- **Universal gate:** run fetch-full-set on *all* devices (not just `flash/`) as a safety net
  against a future non-flash RouterOS dropping `reset-html-directory`. One-line gate change.
  Defaulting to flash-only per decision.
- **Repair reuse:** point the existing `remediate-captive-portal` endpoint at the same bundle so
  it can repair already-provisioned broken routers (213/215-style) without hand-fixing.

## References
- `diagnose-customer-router` skill + failure catalog (`.claude/skills/`).
- `project-hotspot-redirect-debug` memory (root cause + 213/215).
- `app/services/provisioning.py` STEP 4/5 (~542, ~573); `app/api/provisioning.py` `serve_login_page` (~177).
