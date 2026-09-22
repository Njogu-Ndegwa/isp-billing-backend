#!/usr/bin/env bash
# Destructively replace the stale Hetzner candidate DB with a physical standby.
# The web app must report shadow mode before this script will proceed.
set -euo pipefail

MODE="${1:-audit}"
COMPOSE_DIR="${COMPOSE_DIR:-/opt/isp-billing-shadow/repo}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.hetzner.yml}"
DB_CONTAINER="${DB_CONTAINER:-isp_billing_hetzner_db}"
WEB_CONTAINER="${WEB_CONTAINER:-isp_billing_hetzner_app}"
VOLUME="${VOLUME:-isp_billing_hetzner_postgres_data}"
NETWORK="${NETWORK:-isp_billing_hetzner_private}"
REPLICATION_USER="${REPLICATION_USER:-isp_replica}"
PRIMARY_PORT="${PRIMARY_PORT:-15434}"

cd "$COMPOSE_DIR"
gateway=$(docker network inspect "$NETWORK" --format '{{(index .IPAM.Config 0).Gateway}}')

runtime_mode=$(docker exec "$WEB_CONTAINER" python -c \
  "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8000/health'))['runtime_mode'])" \
  2>/dev/null || true)

if [ "$MODE" != "--apply" ]; then
  echo "mode=audit runtime_mode=${runtime_mode:-unavailable} gateway=$gateway"
  docker exec "$DB_CONTAINER" psql -U isp_user -d isp_billing_db -Atc \
    "select pg_is_in_recovery(), coalesce(pg_last_wal_receive_lsn()::text,''), coalesce(pg_last_wal_replay_lsn()::text,'');" \
    2>/dev/null || true
  exit 0
fi

test "$runtime_mode" = "shadow" || {
  echo "ERROR: target web must report runtime_mode=shadow before destructive clone" >&2
  exit 1
}
test -n "${REPLICATION_PASSWORD:-}" || { echo "ERROR: REPLICATION_PASSWORD is required" >&2; exit 1; }
case "$REPLICATION_PASSWORD" in *$'\n'*|*:*|*\\*)
  echo "ERROR: replication password must not contain newline, colon, or backslash" >&2
  exit 1
esac
timeout 3 nc -z "$gateway" "$PRIMARY_PORT" || {
  echo "ERROR: replication tunnel ${gateway}:${PRIMARY_PORT} is unreachable" >&2
  exit 1
}

docker compose -f "$COMPOSE_FILE" stop web freeradius db
docker run --rm \
  --network "$NETWORK" \
  -e PGPASSWORD="$REPLICATION_PASSWORD" \
  -e REPLICATION_USER="$REPLICATION_USER" \
  -e PRIMARY_HOST="$gateway" \
  -e PRIMARY_PORT="$PRIMARY_PORT" \
  -v "$VOLUME:/var/lib/postgresql/data" \
  postgres:15-alpine sh -euc '
    find /var/lib/postgresql/data -mindepth 1 -delete
    pg_basebackup -h "$PRIMARY_HOST" -p "$PRIMARY_PORT" -U "$REPLICATION_USER" \
      -D /var/lib/postgresql/data -Fp -Xs -P
    printf "%s:%s:*:%s:%s\n" "$PRIMARY_HOST" "$PRIMARY_PORT" "$REPLICATION_USER" "$PGPASSWORD" \
      >/var/lib/postgresql/data/.pgpass
    chmod 600 /var/lib/postgresql/data/.pgpass
    printf "primary_conninfo = '\''host=%s port=%s user=%s passfile=/var/lib/postgresql/data/.pgpass application_name=hetzner_dr'\''\n" \
      "$PRIMARY_HOST" "$PRIMARY_PORT" "$REPLICATION_USER" >>/var/lib/postgresql/data/postgresql.auto.conf
    touch /var/lib/postgresql/data/standby.signal
  '

docker compose -f "$COMPOSE_FILE" up -d db
for _ in $(seq 1 30); do
  recovery=$(docker exec "$DB_CONTAINER" psql -U isp_user -d isp_billing_db -Atc 'select pg_is_in_recovery();' 2>/dev/null || true)
  [ "$recovery" = "t" ] && break
  sleep 2
done
test "${recovery:-}" = "t" || { echo "ERROR: target DB did not enter recovery" >&2; exit 1; }

# Radius remains stopped while the DB is read-only; web is safe in shadow mode.
docker compose -f "$COMPOSE_FILE" up -d web
echo "OK: Hetzner is streaming as a read-only PostgreSQL standby; FreeRADIUS remains stopped"
