#!/usr/bin/env python3
"""Static guard for the Database Session Discipline rule (AGENTS.md).

Flags `await`s of known network/slow-I/O boundaries that happen while a
pooled DB session opened via ``async with async_session() / AsyncSessionLocal()``
is still inside an open transaction. A transaction held across slow I/O pins
one of the app's 30 pooled connections and has repeatedly taken production
down (see docs/agent-memory/incidents/2026-06-05-db-pool-lock-convoy.md).

Scope and heuristics
--------------------
* Only explicit ``async with <factory>() as <var>`` session blocks are
  analyzed. Functions that *receive* an ``AsyncSession`` argument are the
  caller's responsibility (the caller's block is where the hold happens).
* The checker tracks whether the session is "active" (inside a transaction)
  linearly through the block body:
    - ``await db.commit() / db.rollback() / db.close()`` releases the pooled
      connection (SQLAlchemy returns it to the pool at transaction end), so
      network I/O after that point — even inside the same ``async with`` —
      is fine.
    - Any later use of the session re-begins a transaction (autobegin) and
      marks it active again.
  Loop bodies are scanned twice so state wrapping around an iteration is seen.
* Composite helpers that take a session but internally commit BEFORE their
  own network phase (e.g. ``mpesa_b2b.initiate_b2b_payment`` /
  ``payout_reseller``) are deliberately NOT on the denylist: the discipline
  lives inside them, and their callers' sessions are not pinned during the
  provider call.
* Anything the checker cannot prove is reported; false positives are
  suppressed via ``scripts/session_discipline_allowlist.txt`` with a
  justification comment per entry.

Exit status: 0 when every hit is allowlisted, 1 otherwise (CI fails).

Usage:
    python scripts/check_session_discipline.py
    python scripts/check_session_discipline.py --paths app main.py
    python scripts/check_session_discipline.py --allowlist my_allowlist.txt
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Configuration — derived from the real names in this codebase (grep first,
# then add; do not invent names that nothing calls).
# ---------------------------------------------------------------------------

# `async with <name>() as db:` factories that hand out pooled DB sessions.
SESSION_FACTORY_NAMES = {"async_session", "AsyncSessionLocal"}

# Session methods that END the open transaction and release the pooled
# connection back to the pool.
SESSION_RELEASE_METHODS = {"commit", "rollback", "close", "invalidate"}

# Awaited dotted names (suffix-matched) that are always network / provider
# I/O. Matching is on the trailing segments, so `mpesa.get_access_token`
# and `get_access_token` both match "get_access_token".
NETWORK_CALL_SUFFIXES = {
    # M-Pesa STK / OAuth (app/services/mpesa.py)
    "initiate_stk_push",
    "initiate_stk_push_direct",
    "initiate_stk_push_via_graphql_microservice",
    "query_stk_push_status",
    "get_access_token",
    "_get_access_token",
    # M-Pesa B2B network-only helper (initiate_b2b_payment itself commits
    # before I/O and is intentionally not listed here)
    "query_b2b_transaction_status",
    # MTN MoMo (app/services/mtn_momo.py)
    "initiate_request_to_pay",
    "check_request_to_pay_status",
    # ZenoPay (app/services/zenopay.py)
    "initiate_zenopay_payment",
    "check_zenopay_order_status",
    # Pull-provisioning secondary server (app/services/pull_provisioning.py)
    "handoff_to_pull_service",
    "clear_pull_service",
    # WG-manager / provisioning HTTP (app/services/provisioning.py)
    "remove_wireguard_peer",
    "remove_l2tp_peer",
    "add_wireguard_peer",
    "add_l2tp_peer",
    # Insurance manager on the new AWS server (insurance_wireguard.py)
    "insurance_manager_request",
    "list_insurance_peers",
    "register_insurance_peer",
    "remove_insurance_peer",
    "verify_insurance_router",
    # Email (app/services/email_service.py)
    "send_email",
    "send_password_reset_email",
    "_send_via_resend",
    # SMS providers (app/services/messaging/*.py) — provider.send_bulk(...)
    "send_bulk",
    "_send_individual",
}

# Calls that CREATE an HTTP client; a variable bound from one of these
# (``async with httpx.AsyncClient() as client`` or ``client = _wg_client()``)
# is tracked, and awaited HTTP-verb methods on it are flagged.
HTTP_CLIENT_FACTORY_SUFFIXES = {"httpx.AsyncClient", "_wg_client"}
HTTP_METHOD_NAMES = {"get", "post", "put", "patch", "delete", "head",
                     "options", "request", "send", "stream"}

# asyncio.to_thread targets that are known-fast (CPU-bound, no network) and
# therefore fine to run with a session open. Everything else pushed through
# to_thread in this app is RouterOS/SMTP/provider work — presumed slow.
TO_THREAD_FAST_ALLOW = {"pwd_context.hash", "pwd_context.verify"}

DEFAULT_ALLOWLIST = REPO_ROOT / "scripts" / "session_discipline_allowlist.txt"
DEFAULT_PATHS = ["app", "main.py"]


@dataclass
class Violation:
    file: str          # repo-relative, forward slashes
    line: int
    function: str      # dotted qualname within the module
    call: str          # dotted name of the awaited call
    reason: str

    @property
    def key(self) -> str:
        return f"{self.file}::{self.function}::{self.call}"

    def __str__(self) -> str:
        return f"{self.file}:{self.line} [{self.function}] await {self.call} — {self.reason}"


def dotted_name(node: ast.AST) -> str | None:
    """Return 'a.b.c' for Name/Attribute chains, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def suffix_match(name: str, suffixes: set[str]) -> bool:
    for suf in suffixes:
        if name == suf or name.endswith("." + suf):
            return True
    return False


class FunctionChecker:
    """Analyzes one async function body for session-held-across-I/O."""

    def __init__(self, module_path: str, qualname: str):
        self.module_path = module_path
        self.qualname = qualname
        # session var name -> active (inside an open transaction)
        self.session_state: dict[str, bool] = {}
        self.http_clients: set[str] = set()
        self.violations: list[Violation] = []

    # -- helpers -----------------------------------------------------------

    def _any_session_active(self) -> bool:
        return any(self.session_state.values())

    def _active_sessions(self) -> list[str]:
        return [v for v, active in self.session_state.items() if active]

    def _names_in(self, node: ast.AST) -> set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    # -- network-call classification ---------------------------------------

    def _classify_call(self, call: ast.Call) -> str | None:
        """Return a human reason if this (awaited) call is a network boundary."""
        name = dotted_name(call.func)
        if name is None:
            return None

        if suffix_match(name, {"asyncio.sleep", "sleep"}) and name.endswith("sleep"):
            # asyncio.sleep(0) is a pure event-loop yield — allowed.
            if call.args:
                arg = call.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, (int, float)):
                    if arg.value <= 0:
                        return None
                    return f"asyncio.sleep({arg.value}) with a DB transaction open"
                return "asyncio.sleep(<non-literal>) with a DB transaction open"
            return None

        if name.endswith("to_thread") and suffix_match(name, {"asyncio.to_thread", "to_thread"}):
            target = dotted_name(call.args[0]) if call.args else None
            if target and target in TO_THREAD_FAST_ALLOW:
                return None
            return (f"asyncio.to_thread({target or '<expr>'}) — presumed slow "
                    f"router/provider work off-thread")

        # HTTP-verb call on a tracked httpx client variable
        if isinstance(call.func, ast.Attribute) and call.func.attr in HTTP_METHOD_NAMES:
            base = dotted_name(call.func.value)
            if base and base.split(".")[0] in self.http_clients:
                return f"HTTP client call {name}()"

        if suffix_match(name, NETWORK_CALL_SUFFIXES):
            return f"network helper {name}()"

        # await asyncio.gather(...) wrapping network calls
        if suffix_match(name, {"asyncio.gather", "gather"}):
            for arg in list(call.args):
                if isinstance(arg, ast.Call):
                    reason = self._classify_call(arg)
                    if reason:
                        return f"asyncio.gather(...{dotted_name(arg.func)}...) — {reason}"
        return None

    # -- statement walking --------------------------------------------------

    def _handle_await(self, node: ast.Await) -> str | None:
        """Process one awaited call. Returns the released session var name if
        this await was a commit()/rollback()/close() on a tracked session."""
        if not isinstance(node.value, ast.Call):
            return None
        call = node.value
        name = dotted_name(call.func)

        # Session release: await db.commit()/rollback()/close()
        if (
            name
            and isinstance(call.func, ast.Attribute)
            and call.func.attr in SESSION_RELEASE_METHODS
        ):
            base = name.rsplit(".", 1)[0]
            if base in self.session_state:
                self.session_state[base] = False
                return base

        if self._any_session_active():
            reason = self._classify_call(call)
            if reason:
                self.violations.append(Violation(
                    file=self.module_path,
                    line=node.lineno,
                    function=self.qualname,
                    call=name or "<unknown>",
                    reason=f"{reason} (session(s) held: "
                           f"{', '.join(self._active_sessions())})",
                ))
        return None

    def _scan_node(self, node: ast.AST) -> None:
        """Scan one statement/expression: handle awaits, then account for
        session re-use (any touch of a released session autobegins a new
        transaction and pins a connection again).

        The release-awaits themselves (await db.commit() etc.) must NOT count
        as re-use, so their subtrees are excluded from the name scan.
        """
        release_subtrees: list[ast.AST] = []
        for n in ast.walk(node):
            if isinstance(n, ast.Await):
                released = self._handle_await(n)
                if released is not None:
                    release_subtrees.append(n)

        excluded_ids: set[int] = set()
        for sub in release_subtrees:
            excluded_ids.update(id(x) for x in ast.walk(sub))
        names = {
            n.id
            for n in ast.walk(node)
            if isinstance(n, ast.Name) and id(n) not in excluded_ids
        }
        for var in self.session_state:
            if var in names:
                self.session_state[var] = True

    def _is_session_factory_call(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name and suffix_match(name, SESSION_FACTORY_NAMES):
                return True
        return False

    def _is_http_client_factory(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name and suffix_match(name, HTTP_CLIENT_FACTORY_SUFFIXES):
                return True
        return False

    def walk_body(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self._walk_stmt(stmt)

    def _walk_stmt(self, stmt: ast.stmt) -> None:
        # Never descend into nested function/class definitions: they run later,
        # not while this block's session is open.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return

        if isinstance(stmt, ast.AsyncWith):
            self._walk_async_with(stmt)
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._scan_node(stmt.iter)
            # Two passes so state wrapping around an iteration is observed
            # (e.g. network call at the top, session re-use at the bottom).
            for _ in range(2):
                self.walk_body(stmt.body)
            self.walk_body(stmt.orelse)
            return

        if isinstance(stmt, ast.While):
            self._scan_node(stmt.test)
            for _ in range(2):
                self.walk_body(stmt.body)
                self._scan_node(stmt.test)
            self.walk_body(stmt.orelse)
            return

        if isinstance(stmt, ast.If):
            self._scan_node(stmt.test)
            self.walk_body(stmt.body)
            self.walk_body(stmt.orelse)
            return

        if isinstance(stmt, ast.Try):
            self.walk_body(stmt.body)
            for handler in stmt.handlers:
                self.walk_body(handler.body)
            self.walk_body(stmt.orelse)
            self.walk_body(stmt.finalbody)
            return

        if isinstance(stmt, ast.With):
            for item in stmt.items:
                self._scan_node(item.context_expr)
            self.walk_body(stmt.body)
            return

        # Plain statement: examine awaits, track http-client assignments,
        # then account for session re-use.
        self._scan_node(stmt)

        if isinstance(stmt, ast.Assign) and self._is_http_client_factory(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    self.http_clients.add(target.id)

    def _walk_async_with(self, stmt: ast.AsyncWith) -> None:
        opened_sessions: list[str] = []
        opened_clients: list[str] = []
        for item in stmt.items:
            var = item.optional_vars.id if isinstance(item.optional_vars, ast.Name) else None
            if self._is_session_factory_call(item.context_expr):
                name = var or f"<anon@{stmt.lineno}>"
                self.session_state[name] = True
                opened_sessions.append(name)
            elif self._is_http_client_factory(item.context_expr) and var:
                self.http_clients.add(var)
                opened_clients.append(var)
            else:
                # e.g. `async with lock:` — awaits inside item exprs still count
                self._scan_node(item.context_expr)

        self.walk_body(stmt.body)

        for name in opened_sessions:
            # Block exit closes the session and releases the connection.
            del self.session_state[name]
        for name in opened_clients:
            self.http_clients.discard(name)


def check_module(path: Path, repo_root: Path) -> list[Violation]:
    rel = path.resolve().relative_to(repo_root).as_posix()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as e:
        return [Violation(rel, e.lineno or 0, "<module>", "<syntax-error>", str(e))]

    violations: list[Violation] = []

    def visit_functions(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{child.name}"
                if isinstance(child, ast.AsyncFunctionDef):
                    checker = FunctionChecker(rel, qual)
                    checker.walk_body(child.body)
                    violations.extend(checker.violations)
                visit_functions(child, f"{qual}.")
            elif isinstance(child, ast.ClassDef):
                visit_functions(child, f"{prefix}{child.name}.")
            else:
                visit_functions(child, prefix)

    visit_functions(tree, "")

    # The two-pass loop scan can report the same site twice — dedupe.
    seen: set[tuple] = set()
    unique: list[Violation] = []
    for v in violations:
        marker = (v.file, v.line, v.function, v.call)
        if marker not in seen:
            seen.add(marker)
            unique.append(v)
    return unique


def load_allowlist(path: Path) -> dict[str, str]:
    """Return {allowlist key -> line} for reporting. Lines are
    'file::function::call'; '#' starts a comment."""
    entries: dict[str, str] = {}
    if not path.exists():
        return entries
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            entries[line] = raw.strip()
    return entries


def run_check(
    paths: list[str], allowlist_path: Path, repo_root: Path = REPO_ROOT
) -> tuple[list[Violation], list[Violation], set[str]]:
    """Returns (failing, allowlisted, unused_allowlist_entries)."""
    files: list[Path] = []
    for p in paths:
        full = (repo_root / p) if not Path(p).is_absolute() else Path(p)
        if full.is_dir():
            files.extend(sorted(full.rglob("*.py")))
        elif full.suffix == ".py":
            files.append(full)

    all_violations: list[Violation] = []
    for f in files:
        all_violations.extend(check_module(f, repo_root))

    allow = load_allowlist(allowlist_path)
    failing = [v for v in all_violations if v.key not in allow]
    allowed = [v for v in all_violations if v.key in allow]
    used_keys = {v.key for v in allowed}
    unused = set(allow) - used_keys
    return failing, allowed, unused


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--paths", nargs="+", default=DEFAULT_PATHS,
                        help="Files/dirs to scan, relative to the repo root")
    parser.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST),
                        help="Allowlist file (file::function::call per line)")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    failing, allowed, unused = run_check(
        args.paths, Path(args.allowlist), repo_root
    )

    if allowed:
        print(f"[session-discipline] {len(allowed)} allowlisted hit(s) (accepted):")
        for v in allowed:
            print(f"  ALLOWED  {v}")
    if unused:
        print(f"[session-discipline] WARNING: {len(unused)} stale allowlist "
              f"entr(y/ies) matched nothing (clean up when convenient):")
        for key in sorted(unused):
            print(f"  STALE    {key}")

    if failing:
        print(f"[session-discipline] FAIL: {len(failing)} violation(s) — a DB "
              f"session is held across network/slow I/O. Fix the code "
              f"(commit/close before the I/O) or, for a justified false "
              f"positive, add 'file::function::call' with a comment to "
              f"{args.allowlist}.")
        for v in failing:
            print(f"  VIOLATION {v}")
        return 1

    print(f"[session-discipline] OK — no un-allowlisted session-held-across-I/O "
          f"hits in {', '.join(args.paths)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
