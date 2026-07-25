"""Prove the Database-Session-Discipline static guard actually guards.

scripts/check_session_discipline.py is wired into CI (tests.yml) to fail the
build when an `async with async_session()/AsyncSessionLocal()` block awaits a
known network boundary while its transaction is still open (AGENTS.md rule 1 —
the #1 cause of DB-pool outages). These tests run the checker against small
fixture modules with known-violating and known-clean shapes so a regression in
the checker itself (e.g. it stops detecting anything and CI goes green forever)
is caught here.
"""

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from check_session_discipline import run_check  # noqa: E402


def _write_module(tmp_path: Path, name: str, source: str) -> Path:
    pkg = tmp_path / "app"
    pkg.mkdir(exist_ok=True)
    mod = pkg / name
    mod.write_text(textwrap.dedent(source), encoding="utf-8")
    return mod


def _check(tmp_path: Path, allowlist_text: str | None = None):
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text(allowlist_text or "", encoding="utf-8")
    return run_check(["app"], allowlist, repo_root=tmp_path.resolve())


VIOLATING = """
    import asyncio
    import httpx
    from app.db.database import async_session

    async def bad_sleep_inside_session():
        async with async_session() as db:
            row = await db.get(object, 1)
            await asyncio.sleep(5)          # transaction open -> violation
            await db.commit()

    async def bad_httpx_inside_session():
        async with async_session() as db:
            row = await db.get(object, 1)
            async with httpx.AsyncClient() as client:
                resp = await client.post("https://api.example.com")  # violation
            row.field = resp
            await db.commit()

    async def bad_to_thread_inside_session():
        async with async_session() as db:
            row = await db.get(object, 1)
            result = await asyncio.to_thread(_run_mikrotik_operation_sync, row)  # violation
            await db.commit()

    async def bad_provider_helper_inside_session():
        from app.services.mpesa import initiate_stk_push
        async with async_session() as db:
            row = await db.get(object, 1)
            await initiate_stk_push("254700000000", 10, "ref")  # violation
            await db.commit()
"""


CLEAN = """
    import asyncio
    import httpx
    from app.db.database import AsyncSessionLocal

    async def good_commit_then_network():
        # The AGENTS.md GOOD pattern: read, commit (connection released),
        # THEN the slow I/O — even though it is textually inside the block.
        async with AsyncSessionLocal() as db:
            row = await db.get(object, 1)
            await db.commit()
            await asyncio.sleep(5)

    async def good_network_outside_block():
        async with AsyncSessionLocal() as db:
            data = await db.get(object, 1)
            await db.commit()
        async with httpx.AsyncClient() as client:
            result = await client.post("https://api.example.com")
        async with AsyncSessionLocal() as db:
            await db.merge(result)
            await db.commit()

    async def good_sleep_zero_yield():
        async with AsyncSessionLocal() as db:
            await db.get(object, 1)
            await asyncio.sleep(0)   # pure event-loop yield, not a wait
            await db.commit()

    async def good_fast_to_thread():
        async with AsyncSessionLocal() as db:
            user = await db.get(object, 1)
            user.password_hash = await asyncio.to_thread(pwd_context.hash, "pw")
            await db.commit()
"""


REUSE_AFTER_COMMIT = """
    import asyncio
    from app.db.database import async_session

    async def bad_reuse_reopens_transaction():
        async with async_session() as db:
            await db.get(object, 1)
            await db.commit()
            await db.execute("SELECT 1")    # autobegin: transaction open again
            await asyncio.sleep(5)          # -> violation
            await db.commit()
"""


def test_detects_all_violation_shapes(tmp_path):
    _write_module(tmp_path, "violating.py", VIOLATING)
    failing, allowed, _ = _check(tmp_path)

    assert not allowed
    flagged_functions = {v.function for v in failing}
    assert flagged_functions == {
        "bad_sleep_inside_session",
        "bad_httpx_inside_session",
        "bad_to_thread_inside_session",
        "bad_provider_helper_inside_session",
    }
    # Each function contributes exactly one violation site.
    assert len(failing) == 4


def test_clean_module_passes(tmp_path):
    _write_module(tmp_path, "clean.py", CLEAN)
    failing, allowed, _ = _check(tmp_path)
    assert failing == []
    assert allowed == []


def test_session_reuse_after_commit_reopens_transaction(tmp_path):
    """commit() releases the connection, but ANY later session use autobegins
    a new transaction — I/O after that point must be flagged again."""
    _write_module(tmp_path, "reuse.py", REUSE_AFTER_COMMIT)
    failing, _, _ = _check(tmp_path)
    assert len(failing) == 1
    assert failing[0].function == "bad_reuse_reopens_transaction"
    assert failing[0].call.endswith("sleep")


def test_allowlist_suppresses_known_hit_and_reports_stale_entries(tmp_path):
    _write_module(tmp_path, "violating.py", VIOLATING)
    allowlist = """
    # TODO(violation): example accepted-debt entry for the fixture
    app/violating.py::bad_sleep_inside_session::asyncio.sleep
    app/violating.py::bad_httpx_inside_session::client.post
    app/violating.py::bad_to_thread_inside_session::asyncio.to_thread
    app/violating.py::bad_provider_helper_inside_session::initiate_stk_push
    app/gone.py::deleted_function::asyncio.sleep   # stale — matches nothing
    """
    failing, allowed, unused = _check(tmp_path, textwrap.dedent(allowlist))
    assert failing == []
    assert len(allowed) == 4
    assert unused == {"app/gone.py::deleted_function::asyncio.sleep"}


def test_real_repo_scan_is_currently_clean():
    """The actual CI gate: app/ + main.py must have no un-allowlisted hits.

    If this fails you either introduced a session-held-across-I/O bug (fix the
    code: commit/close the session before the network call) or hit a checker
    false positive (allowlist it WITH a justification comment).
    """
    failing, _, _ = run_check(
        ["app", "main.py"],
        REPO_ROOT / "scripts" / "session_discipline_allowlist.txt",
        repo_root=REPO_ROOT,
    )
    assert failing == [], "\n".join(str(v) for v in failing)
