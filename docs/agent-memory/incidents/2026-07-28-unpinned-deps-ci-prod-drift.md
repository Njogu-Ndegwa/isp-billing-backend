# 2026-07-28 — Unpinned dependencies: prod upgrades itself on every deploy

**Status:** finding recorded, guard test fixed, pinning queued (PKT-009). Not yet fixed.

## Symptoms

The first-ever CI run of the new `tests.yml` gate failed on a green-locally suite:

```
FAILED tests/test_app_boot.py::test_main_imports_and_exposes_full_app
AssertionError: expected >100 routes, got 42
```

Full suite locally: 648/648 pass. Same commit on a GitHub runner: 1 failure. Pristine
`git archive` checkout locally: still passes. So the difference was not the code, not
uncommitted files, and not the committed `__pycache__/*.pyc`.

## Root cause

`requirements.txt` pins almost nothing — `fastapi`, `sqlalchemy`, `pydantic`,
`starlette`, `httpx` are bare names — and `deploy.yml` builds with
`docker build --no-cache`. So **CI and production each install whatever version is
newest at build time**, while a long-lived dev machine keeps whatever it resolved
months ago.

| Environment | fastapi | starlette |
|---|---|---|
| Production (live container, 2026-07-28) | 0.140.1 | 1.3.1 |
| GitHub CI runner (same week) | 0.140.7 | 1.3.1 |
| Dev machine | 0.116.1 | 0.47.3 |

Under FastAPI 0.14x / Starlette 1.x, `include_router()` keeps each included router as a
lazy `_IncludedRouter` wrapper instead of flattening its routes into the parent at include
time. So `len(app.routes)` went from **380** (4 default + all flattened) to **42**
(4 default `Route` + 38 `_IncludedRouter`) with **no behaviour change** — the running app
still serves 332 OpenAPI paths, confirmed against production's `/openapi.json`.

The test was not detecting a broken app. It was detecting that nobody had ever run the
suite against the dependency set production runs.

## Two separate problems

1. **The test encoded one version's internals.** Fixed here: `test_app_boot` now asserts
   on `app.openapi()["paths"]` (stable across both generations, and exactly what prod
   serves) plus four named money/access routes — `/api/c2b/confirmation`,
   `/api/mpesa/callback`, `/api/auth/login`, `/api/public/voucher/redeem` — so a vanished
   router fails loudly by name instead of shrinking a count. Verified green on BOTH
   fastapi 0.116/starlette 0.47 and fastapi 0.140/starlette 1.3.
2. **Production upgrades itself, untested.** NOT fixed — queued as PKT-009. Prod crossed a
   Starlette major version (0.47 → 1.3) at some unknown deploy with no test having run
   against it. It works, but that is luck, not a gate. Any breaking release in any direct
   or transitive dependency lands in prod on the next merge.

## Verification

- Prod dependency versions and the 332-path OpenAPI surface read read-only from the live
  container (no writes, no restart).
- Fixed test green on both dependency generations, run in a dedicated venv resolved from
  the unpinned `requirements.txt` (i.e. what CI/prod get).

## Follow-up

- **PKT-009**: pin `requirements.txt` to the versions prod runs *today* (verify against the
  live container — do NOT pin to a dev machine's older set), pin dev deps, prove the suite
  green against the pinned set, document the deliberate-upgrade path. No version bumps in
  that packet.
- Separate packet: `Query(regex=...)` is deprecated in current FastAPI (warns ~10× at
  import) — migrate to `pattern=` before removal.
- Lesson for agents: a local green is not evidence. CI must agree, and CI is only
  meaningful once it resolves the same versions as prod.
