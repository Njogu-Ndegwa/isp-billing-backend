"""Guard: a schema change cannot merge without its startup migration.

The outage this prevents has already happened here more than once — a model
gains a column, nobody writes the ALTER, the deploy goes out, and every query
touching that table starts failing in production. AGENTS.md makes writing the
migration a rule; these tests make forgetting it impossible to merge.

Why `create_all` does not cover this:
  * it only creates tables that are MISSING — it never alters an existing one,
    so a new column on a live table is invisible to it;
  * this app never calls it for the whole metadata anyway. Both call sites in
    main.py pass an explicit `tables=` list, so even a brand-new table needs
    deliberate wiring.

The baseline lives in tests/schema_snapshot.json. After writing your migration:

    python scripts/schema_snapshot.py --write
"""

import ast
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts.schema_snapshot import (  # noqa: E402
    columns_added_by_migrations,
    current_schema,
    load_snapshot,
    migration_source,
    tables_created_by_migrations,
)

FIX_HINT = (
    "\n\nIf this change is intended:"
    "\n  1. Add an idempotent startup migration in main.py (AGENTS.md First Rule)."
    "\n  2. Re-run: python scripts/schema_snapshot.py --write"
    "\n  3. Commit the updated tests/schema_snapshot.json with your change."
)


@pytest.fixture(scope="module")
def schemas():
    return current_schema(), load_snapshot()


def test_schema_matches_snapshot(schemas):
    """Tripwire: any schema drift must be acknowledged deliberately."""
    current, baseline = schemas

    added_tables = sorted(set(current) - set(baseline))
    dropped_tables = sorted(set(baseline) - set(current))

    added_cols, dropped_cols = [], []
    for table in sorted(set(current) & set(baseline)):
        for col in sorted(set(current[table]) - set(baseline[table])):
            added_cols.append(f"{table}.{col}")
        for col in sorted(set(baseline[table]) - set(current[table])):
            dropped_cols.append(f"{table}.{col}")

    if not (added_tables or dropped_tables or added_cols or dropped_cols):
        return

    report = ["The database schema changed since the last recorded baseline."]
    if added_tables:
        report.append(f"  new tables:     {', '.join(added_tables)}")
    if dropped_tables:
        report.append(f"  removed tables: {', '.join(dropped_tables)}")
    if added_cols:
        report.append(f"  new columns:    {', '.join(added_cols)}")
    if dropped_cols:
        report.append(f"  removed columns:{', '.join(dropped_cols)}")
    pytest.fail("\n".join(report) + FIX_HINT)


def test_new_columns_on_existing_tables_have_a_migration(schemas):
    """The exact outage: column added to a live table, no ALTER written.

    A column added to a table that already exists in production will never
    appear there on its own. main.py must contain an ADD COLUMN for it.
    """
    current, baseline = schemas
    known_added = columns_added_by_migrations(migration_source())

    missing = []
    for table in sorted(set(current) & set(baseline)):
        for col in sorted(set(current[table]) - set(baseline[table])):
            if col.lower() not in known_added:
                missing.append(f"{table}.{col}")

    assert not missing, (
        "These columns were added to tables that already exist in production, but "
        "no ADD COLUMN for them exists in main.py. Production would keep the old "
        "table and every query touching it would fail:\n  "
        + "\n  ".join(missing)
        + FIX_HINT
    )


def test_new_tables_are_wired_for_creation(schemas):
    """A new table needs explicit wiring — create_all is not called globally."""
    current, baseline = schemas
    source = migration_source()
    created = tables_created_by_migrations(source)

    unwired = []
    for table in sorted(set(current) - set(baseline)):
        # Either a CREATE TABLE statement, or added to a create_all target list
        # (those lists name the model class, so accept a mention of the table).
        if table.lower() not in created and table not in source:
            unwired.append(table)

    assert not unwired, (
        "These new tables are not created anywhere at startup. main.py never calls "
        "create_all() over the full metadata, so they will simply not exist in "
        "production:\n  " + "\n  ".join(unwired) + FIX_HINT
    )


def test_every_add_column_is_idempotent():
    """Startup runs on every boot — a bare ALTER would crash the second time.

    Three accepted forms are in use here, all genuinely idempotent:
      1. `ADD COLUMN IF NOT EXISTS`
      2. a plain `ADD COLUMN` preceded by an information_schema existence check
      3. a plain `ADD COLUMN` inside `DO $$ ... EXCEPTION WHEN duplicate_column`
    """
    lines = migration_source().splitlines()
    unguarded = []

    for i, line in enumerate(lines):
        if "ADD COLUMN" not in line.upper():
            continue
        if "IF NOT EXISTS" in line.upper():
            continue
        # Form 2: the check-then-act guard sits above the statement.
        if "information_schema" in "\n".join(lines[max(0, i - 30):i]).lower():
            continue
        # Form 3: the EXCEPTION clause sits below, inside the same DO block.
        if "duplicate_column" in "\n".join(lines[i:i + 10]).lower():
            continue
        unguarded.append(f"main.py:{i + 1}: {line.strip()}")

    assert not unguarded, (
        "These ADD COLUMN statements are neither `IF NOT EXISTS` nor guarded by an "
        "information_schema check. Startup migrations run on EVERY boot, so this "
        "crashes the app the second time it starts:\n  " + "\n  ".join(unguarded)
    )


def test_outage_compensation_migration_runs_on_normal_startup():
    """The outage tables must be created on a healthy startup path.

    A migration call accidentally nested in another migration's ``except`` block
    is syntactically valid but only runs when that unrelated migration fails.
    """
    tree = ast.parse(migration_source())
    startup = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "startup_event"
    )

    def calls_outage_migration(statements):
        block = ast.Module(body=statements, type_ignores=[])
        return any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "run_outage_compensation_migrations"
            for node in ast.walk(block)
        )

    startup_tries = [node for node in startup.body if isinstance(node, ast.Try)]
    assert any(calls_outage_migration(node.body) for node in startup_tries), (
        "run_outage_compensation_migrations() is not called from a normal "
        "startup try block; production would start without creating its tables"
    )
    assert not any(
        calls_outage_migration(handler.body)
        for node in startup_tries
        for handler in node.handlers
    ), "The outage migration must not be conditional on another migration failing"
