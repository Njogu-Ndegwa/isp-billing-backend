# 2026-10-02 Deploy Pulled SQLAlchemy 2.1 Without greenlet — App Crash-Looped

## Summary

The deploy of PRs #171/#172 rebuilt the production image and pulled SQLAlchemy 2.1.2.
That release no longer installs `greenlet`, which the asyncio engine needs, so the app
died on import and crash-looped. The API returned Cloudflare 502 for about 12 minutes
(14:02–14:14 UTC, 17:02–17:14 EAT): no portal, payments, router check-ins or dashboard.
Neither PR's code caused it.

## Symptoms

- `https://isp.bitwavetechnologies.net/health` returned 502 from Cloudflare.
- `isp_billing_hetzner_app` showed `Restarting (1)`, with 16+ restarts.
- Log: `ImportError: The SQLAlchemy asyncio module requires that the Python 'greenlet'
  library is installed` raised from `app/db/database.py` at import time.
- The unit suite was green, because `requirements-dev.txt` installs `greenlet` itself.

## Suspected Cause

Confirmed, not suspected. Four gaps lined up:

1. `requirements.txt` had a bare `sqlalchemy`, and most packages had no version, so
   every build re-resolved the whole stack against PyPI at that moment.
2. Nothing ever booted the production image before it went live. The tests used a
   different dependency set.
3. `deploy.yml` built over the `candidate` tag, swapped the live container, and only
   then checked `/health`. It had no rollback.
4. The end-of-deploy `docker image prune` had already deleted the previous good image,
   so there was nothing on the box to roll back to.

## Fix Applied

- Hotfix on the box: a one-layer image on top of the broken build that installs
  `SQLAlchemy==2.0.54 greenlet==3.5.6` (the versions the last good image ran). It was
  tagged `candidate` and only `web` was recreated with
  `docker compose --env-file .env.hetzner -f docker-compose.hetzner.yml up -d --no-deps --no-build web`.
  The broken image was kept as `isp-billing-hetzner:broken-sqla21-20261002`.
  - Trap: without `--env-file .env.hetzner`, compose falls back to `SHADOW_MODE=true`
    with the scheduler off. Always check the resolved `config web` before `up`.
- PR #173:
  - `constraints.txt`: `pip freeze` of the healthy prod image. `Dockerfile` and
    `tests.yml` install with `-c constraints.txt`.
  - `prod-boot.yml` (every PR, and required by `deploy.yml`): builds the prod
    Dockerfile, runs `pip check`, creates the schema in Postgres 15, boots the image's
    CMD in live mode with the compose hardening, then requires `/health`, a 90 s soak,
    and no import errors.
  - `deploy.yml` on the host: tags the healthy running image `last-good`, runs an
    import smoke test in a throwaway container before the swap (the live container is
    never touched on failure), and rolls back automatically if `/health` fails after
    the swap.

## Verification

- Prod after the hotfix: public `/health` returned 200 `runtime_mode: active`, with 0
  restarts, and router check-ins and usage pushes were flowing.
- On the box, with the new `deploy.yml` steps fed over stdin as CI does: a fresh build
  of the branch passed and matched `constraints.txt` exactly (46 packages). The real
  broken image was refused with rc=1. The live container was untouched.
- In CI, the boot test passed on #173 and **failed** on #174, a negative control with
  `main`'s old requirements, on `No module named 'greenlet'`.
- Two bugs in the first draft of the gate were caught only by that testing, so watch
  for them in future edits: `timeout` cannot exec a shell function, and
  `docker compose run` reads stdin, which in an ssh-heredoc deploy swallows the rest of
  the script while the job still reports success. It needs `</dev/null`.

## Follow-Up Work

- Upgrading a dependency now means editing `constraints.txt`. A package newly added to
  `requirements.txt` stays unpinned until it is also added there.
- The automatic rollback after the swap has not been exercised for real. It reuses the
  verified tag and `compose up` commands.
- `deploy.yml` deploys on push to `main` without waiting for `tests.yml`. Consider
  branch protection that requires `pytest` and `boot` before merge.
