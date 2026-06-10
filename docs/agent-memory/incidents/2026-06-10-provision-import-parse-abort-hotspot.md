# 2026-06-10 Provisioning import aborts: "expected end of command (line 112 column 51)"

## Summary

Provisioning a MikroTik with the standard one-liner (`/tool fetch ...;/import
provision.rsc`) aborted mid-import with a RouterOS *parse* error, leaving the
router half-provisioned: WAN/LAN/VPN applied, but no hotspot, no custom login
page, no walled garden, no API service, no `bitwave-api` user, no identity, and
no `/complete` callback (token stays PENDING, router never registers). The
operator has hit this class of failure before.

## Symptoms

- Console: `Script Error: expected end of command (line 112 column 51)`
  immediately after `/import provision.rsc` (fetch itself succeeds, code 200).
- Line 112 col 51 of the generated wireguard-variant script is the `=` inside
  `[find where name=hsprof1]` on
  `:do { /ip hotspot profile set [find where name=hsprof1] html-directory=$bwHtmlDir } on-error={`
  — the first `[find where ...]` under the `/ip hotspot` menu.

## Suspected Cause

On routers where the hotspot feature is unavailable, the `/ip hotspot` console
menus do not exist at all. A direct `[find where ...]` under a missing menu is
a RouterOS **parse-time** error, which `:do ... on-error` cannot catch; the
import aborts at that statement. (Plain `add key=value` lines under a missing
menu defer to runtime and are caught — that's why line 109's `add` wasn't the
reported position.)

Hotspot is unavailable when:

- RouterOS v7.13+ device-mode blocks it — newer RouterBOARDs ship in
  `mode=home`, which disables hotspot; or
- RouterOS v6 with the hotspot package disabled/missing.

The old v7 preflight was supposed to abort early but had a hole: for any mode
other than `enterprise` it read `/system/device-mode/get hotspot`, and on
preset modes (like `home`) that per-feature flag is not readable — the read
failed, the `on-error` logged "proceeding anyway", and the script crashed at
the parse-fragile line. The preflight also referenced `/system/device-mode`
directly, itself a parse error on v7 builds older than 7.13.

Confidence: high on the mechanism (error position reproduced exactly by
regenerating the script; identical `find where` syntax parses fine in earlier
lines under menus that exist); the specific router's device-mode state was not
inspected directly.

## Fix Applied

`app/services/provisioning.py`:

- Replaced `_rsc_preflight_v7()` with `_rsc_preflight_hotspot(token)`: probes
  `/ip hotspot profile find` via `[:parse "..."]` (the same trick the v6
  `use-ipsec` block already used), so a missing menu becomes a *catchable
  runtime* error. On failure it logs the platform-specific remedy and
  `:error`-aborts **before any configuration is applied**. Runs for both v6
  and v7 scripts; no direct `/system/device-mode` reference remains.
- Made STEP 3 (WireGuard) re-run safe with add-then-set fallbacks (mirroring
  the L2TP block), because the remediation is "enable hotspot, re-run the same
  one-liner" on a router that already applied steps 1–3, and a bare
  `/interface wireguard add` would abort the re-import with "already have such
  name". The fetch endpoint already allows re-fetching PENDING tokens.

New tests: `tests/test_provisioning_script.py` (probe present and ordered
before STEP 1, no direct hotspot/device-mode references before/outside the
probe, re-run-safe wireguard step, per-platform remedy text).

## Verification

- `python -m pytest tests/test_provisioning_script.py tests/test_provisioning_urls.py -q` — 9 passed.
- Regenerated the wireguard script: brace balance 0, probe renders before
  STEP 1, single-line statements only.
- Not verified on a live router with hotspot blocked — watch the next
  provisioning attempt: expected behavior on an affected router is now an
  immediate abort with `PROVISION ABORTED: the hotspot feature is not
  available...` in `/log print`, and nothing configured.

## Operator remediation for an affected router

1. On the router: `/system/device-mode/update hotspot=yes` then briefly press
   the physical reset button (or power-cycle) within ~5 minutes when prompted.
   (Newer builds may want the flags form; the backend endpoint
   `POST /routers/{id}/device-mode` with `{"flags": {"hotspot": "yes"}}` does
   this remotely, but physical confirmation is still required on site.)
2. Re-run the same provisioning one-liner — the token stays PENDING/valid for
   24h and the script now converges on a half-provisioned router.

## Follow-Up Work

- STEP 4–6 still reference `/ip hotspot` directly; they are only reached when
  the probe passed, so they're safe today — but any future reordering that
  puts hotspot references before the preflight reintroduces the crash
  (guard test covers this).
- Walled-garden `add` lines create duplicate rows on re-runs (harmless, no
  unique key). Consider find-before-add if dupes get noisy.
- Consider surfacing "token PENDING > N hours after script fetch" in the admin
  UI as a hint that an import died on the router.
