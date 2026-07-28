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
"""

from fastapi import FastAPI


def test_main_imports_and_exposes_full_app():
    import main

    assert isinstance(main.app, FastAPI)

    # The app registers ~40 routers; a collapse in route count means a router
    # import silently vanished (or include_router wiring was lost).
    route_count = len(main.app.routes)
    assert route_count > 100, f"expected >100 routes, got {route_count}"


def test_import_does_not_start_scheduler():
    import main

    assert main.scheduler.running is False
    # Jobs are registered inside the startup event, never at import.
    assert main.scheduler.get_jobs() == []
