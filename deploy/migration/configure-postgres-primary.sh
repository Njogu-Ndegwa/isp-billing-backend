#!/usr/bin/env bash
# Prepare the active PostgreSQL container for an SSH-tunnelled physical standby.
# Audit is the default. REPLICATION_PASSWORD is required only with --apply.
set -euo pipefail

MODE="${1:-audit}"
DB_CONTAINER="${DB_CONTAINER:-isp_billing_postgres}"
DB_USER="${DB_USER:-isp_user}"
REPLICATION_USER="${REPLICATION_USER:-isp_replica}"

psql_cmd() {
  docker exec -i "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U "$DB_USER" -d postgres "$@"
}

if [ "$MODE" != "--apply" ]; then
  echo "mode=audit"
  psql_cmd -Atc "select current_setting('wal_level'), current_setting('max_wal_senders'), current_setting('wal_keep_size');"
  psql_cmd -Atc "select rolname, rolreplication from pg_roles where rolname='${REPLICATION_USER}';"
  docker exec "$DB_CONTAINER" sh -c 'grep -E "^[[:space:]]*host[[:space:]]+replication" /var/lib/postgresql/data/pg_hba.conf || true'
  exit 0
fi

test -n "${REPLICATION_PASSWORD:-}" || { echo "ERROR: REPLICATION_PASSWORD is required" >&2; exit 1; }
case "$REPLICATION_PASSWORD" in *$'\n'*|*:*|*\\*)
  echo "ERROR: replication password must not contain newline, colon, or backslash" >&2
  exit 1
esac

psql_cmd \
  --set=repl_user="$REPLICATION_USER" \
  --set=repl_password="$REPLICATION_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I WITH LOGIN REPLICATION PASSWORD %L', :'repl_user', :'repl_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'repl_user') \gexec
SELECT format('ALTER ROLE %I WITH LOGIN REPLICATION PASSWORD %L', :'repl_user', :'repl_password') \gexec
ALTER SYSTEM SET wal_keep_size = '512MB';
SELECT pg_reload_conf();
SQL

hba_line="host replication ${REPLICATION_USER} all scram-sha-256"
docker exec -u postgres "$DB_CONTAINER" sh -c \
  'grep -Fqx "$1" /var/lib/postgresql/data/pg_hba.conf || printf "%s\n" "$1" >>/var/lib/postgresql/data/pg_hba.conf' \
  sh "$hba_line"
psql_cmd -Atc "select pg_reload_conf();"

echo "OK: replication role, HBA rule, and 512MB WAL retention are ready"
