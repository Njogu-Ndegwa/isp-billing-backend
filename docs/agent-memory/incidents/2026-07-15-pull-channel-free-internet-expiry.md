# 2026-07-15 Pull-channel served expired customers → free internet

## Summary

Ella net #1 (router id 222 / `Router-0577`) was handing out free internet to a
couple of devices. Root cause was **not** a hotspot misconfiguration — the hotspot
was enforcing correctly. Expired customers' `type=bypassed` ip-bindings were not
being de-provisioned, and the **pull-provisioning channel was actively re-adding one
expired customer every 30s**, so cleanup could never win.

## Symptoms

- Owner reported router "giving out free internet".
- Audit of 222 (2026-07-15 ~08:25 UTC): hotspot server running, redirect/NAT rules
  intact, no wildcard bypass. 6 bypassed ip-bindings; 4 were valid active payers.
- 2 were bad: an **orphan** MAC `66:01:A8:9E:10:B9` (no customer row at all), and
  expired Guest 9251 `1E:5B:60:A6:3D:05` (customer 12306, INACTIVE, expired 07:48).
- Router log showed `hotspot ip binding rule changed by scheduler:pull-agent` for
  `1E5B60A63D05` every 30s — the pull-agent re-applying an expired customer.
- Separately, Major1 Net (id 131 / `Router-0305`) had **13 undelivered pull commands
  piled up** (agent never installed → nothing pulled → never pruned).

## Suspected Cause

The pull channel was **add-only**. `handoff_to_pull_service` queued a paid customer's
provisioning command; the on-router `pull-agent` fetched and `/import`ed it every 30s.
There was no awareness of the customer lifecycle:

1. **No expiry bound.** A command kept being served (and re-applied) after the
   customer's plan ended, until the mtime TTL (1h) lapsed — up to ~1h of free access,
   worse for short packages that expire inside that window. `clear_pull_service`
   existed but was never called.
2. **Lazy TTL prune.** Pruning only happened on GET, so a router whose agent never
   checks in (Major1) accumulated commands indefinitely — a latent free-internet
   burst if that agent were ever installed.

The 21h Starlink outage on 222 also blocked the app's normal expired-cleanup from
reaching the router, which is why non-pull expired bindings lingered too (inherent to
push as well; not changed by this fix).

## Fix Applied

Operational (immediate):
- Cleared Guest 9251's stale command from the pull service (re-add stopped, confirmed).
- Removed the orphan `66:01` binding on 222 (Guest 9251's binding was already
  auto-removed by the app once the re-add stopped). Kept all 4 active payers.
- Cleared Major1's 13 stale commands.

Code (commit `02da225`, pushed to `main`, CI/CD deployed 2026-07-15 ~10:12 UTC):
- `app/services/pull_provisioning.py` — `render_hotspot_provision_rsc` emits a leading
  `# PULL-EXPIRES <unixts>` comment (RouterOS ignores `#` on import).
- `app/services/hotspot_provisioning.py` — passes the customer's real `expiry`, skips
  the handoff for an already-expired customer, and calls `clear_pull_service` after a
  successful push.
- `pull_service.py` (secondary server, now versioned in the repo) — serves/prunes by
  the expiry header; a background pruner thread sweeps every router (fixes agent-less
  accumulation); legacy no-header commands still fall back to the mtime TTL.

No schema change (expiry rides inside the queued command).

## Verification

- `tests/test_pull_service.py` (8) + expiry cases in `tests/test_pull_provisioning.py`;
  36 focused tests pass locally.
- End-to-end on the live pull service: a future-dated command is served, an
  already-expired one is dropped and never served; the background pruner removed an
  agent-less command with no GET.
- Deployed app container confirmed running the new render (emits `# PULL-EXPIRES`).

## Follow-Up Work

- **Pull-based de-provisioning (enhancement):** when a customer expires while their
  router is still unreachable, serve a *remove-binding* command so the flaky router
  de-provisions itself on its next check-in (today the binding lingers until the app
  can push, same as the push path).
- Pruner leaves empty per-identity directories; harmless (served as `# idle`) — could
  `rmdir` on empty for tidiness.
- Investigate whether the app re-hands-off already-expired customers on retry (guard
  added in provisioning, but confirm the retry safety-net also skips them).
- Only after the above, consider re-enabling the pull channel on more routers.
