"""Shared helpers for the schema-drift guard, plus a CLI to refresh the baseline.

The guard exists because of a real outage class: a model gains a column, the
startup migration to add it is never written, and every query touching that
table fails in production the moment it deploys. `create_all` does not save us —
it only creates MISSING TABLES, never alters an existing one, and in this app it
isn't even called for the whole metadata (both call sites pass an explicit table
list). So new tables AND new columns both need deliberate wiring.

Refresh the baseline after you have written the migration:

    python scripts/schema_snapshot.py --write
"""

import argparse
import json
import os
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = REPO_ROOT / "tests" / "schema_snapshot.json"
MAIN_PATH = REPO_ROOT / "main.py"

# Importing app.db.models pulls in Settings, which needs these present. Mirrors
# tests/conftest.py so the CLI works outside pytest too.
_TEST_ENV = {
    "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
    "SECRET_KEY": "test-secret",
    "MPESA_CONSUMER_KEY": "test-key",
    "MPESA_CONSUMER_SECRET": "test-secret",
    "MPESA_SHORTCODE": "600980",
    "MPESA_PASSKEY": "test-passkey",
    "MPESA_CALLBACK_URL": "https://example.com/cb",
    "MPESA_ENVIRONMENT": "sandbox",
}


def current_schema() -> dict:
    """{table: [column, ...]} as the CODE currently expects it."""
    for key, value in _TEST_ENV.items():
        os.environ.setdefault(key, value)
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from app.db.database import Base
    import app.db.models  # noqa: F401 — registers every table on Base.metadata

    return {
        name: sorted(c.name for c in table.columns)
        for name, table in sorted(Base.metadata.tables.items())
    }


def load_snapshot() -> dict:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def migration_source() -> str:
    return MAIN_PATH.read_text(encoding="utf-8", errors="replace")


def columns_added_by_migrations(source: str) -> set:
    """Column names main.py knows how to ADD to an existing table.

    Handles both forms in use: `ADD COLUMN IF NOT EXISTS x`, and plain
    `ADD COLUMN x` guarded by an information_schema existence check.
    """
    pattern = re.compile(
        r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"']?([a-zA-Z_][a-zA-Z0-9_]*)",
        re.IGNORECASE,
    )
    return {m.group(1).lower() for m in pattern.finditer(source)}


def tables_created_by_migrations(source: str) -> set:
    pattern = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"']?([a-zA-Z_][a-zA-Z0-9_]*)",
        re.IGNORECASE,
    )
    return {m.group(1).lower() for m in pattern.finditer(source)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true",
                    help="overwrite the baseline with the current models")
    args = ap.parse_args()

    schema = current_schema()
    if not args.write:
        print(json.dumps(schema, indent=1, sort_keys=True))
        return 0

    SNAPSHOT_PATH.write_text(
        json.dumps(schema, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    tables = len(schema)
    columns = sum(len(c) for c in schema.values())
    print(f"wrote {SNAPSHOT_PATH.relative_to(REPO_ROOT)}: {tables} tables, {columns} columns")
    return 0


if __name__ == "__main__":
    sys.exit(main())
