"""Boot/import check for the app entrypoint (main.py at repo root).

Guards against the 2026-07-21 class of outage: wiring pushed to main.py whose
imports don't exist in the deploy, crash-looping uvicorn on ModuleNotFoundError.
CI never exercised `import main` before this test.

Why importing main is safe here:
  * tests/conftest.py sets DATABASE_URL (in-memory SQLite) and the required
    M-Pesa/SECRET_KEY env vars BEFORE any `app.*` import, so Settings() resolves
    without a real environment.
  * main.py's module level only configures logging, builds the FastAPI app,
    includes routers, and constructs (but never starts) the APScheduler.
    Migrations, plan-cache warmup, and scheduler.start() all live inside the
    @app.on_event("startup") handler, which does not run at import time; the
    SQLAlchemy engine is lazy and opens no connection at import.
If someone moves work to module level, the scheduler/route assertions below are
the tripwire.

Dependency note (2026-07-28): requirements.txt is unpinned and deploy.yml builds
with --no-cache, so CI and production install whatever is latest at build time
while a long-lived dev machine can sit generations behind. Assertions here must
therefore hold across dependency generations, not encode one version's internals.
"""

from fastapi import FastAPI


def test_main_imports_and_exposes_full_app():
    import main

    assert isinstance(main.app, FastAPI)

    # Assert on the OpenAPI surface, NOT len(app.routes).
    #
    # FastAPI 0.14x / Starlette 1.x keep every include_router() call as a lazy
    # `_IncludedRouter` wrapper instead of flattening its routes into the parent
    # at include time. Same app, same served endpoints, but app.routes collapsed
    # from 380 entries to 42 (4 default routes + 38 wrappers) — which silently
    # broke the old `> 100` assertion the moment CI installed current deps.
    # openapi()["paths"] is stable across both generations and is exactly what
    # the app serves: 332 on production (fastapi 0.140.1 / starlette 1.3.1) on
    # 2026-07-28, verified against the running container's /openapi.json.
    paths = main.app.openapi()["paths"]
    assert len(paths) > 100, f"expected >100 OpenAPI paths, got {len(paths)}"

    # One included router silently vanishing is the 2026-07-21 crash-loop class.
    # Name the endpoints that carry money and access explicitly, so losing the
    # router that serves them fails loudly instead of shrinking a count.
    for critical in (
        "/api/c2b/confirmation",      # money in — Safaricom C2B confirmation
        "/api/mpesa/callback",        # money in — STK callback
        "/api/auth/login",            # reseller access
        "/api/public/voucher/redeem",  # customer access
    ):
        assert critical in paths, f"critical route missing: {critical}"


def test_import_does_not_start_scheduler():
    import main

    assert main.scheduler.running is False
    # Jobs are registered inside the startup event, never at import.
    assert main.scheduler.get_jobs() == []
