#!/usr/bin/env bash
# Planned-cutover fence: stop every AWS database writer but keep PostgreSQL and
# the tunnel manager running long enough for the Hetzner standby to catch up.
set -euo pipefail

MODE="${1:-audit}"
APP_CONTAINER="${APP_CONTAINER:-isp_billing_app}"
RADIUS_CONTAINER="${RADIUS_CONTAINER:-isp_billing_radius}"
DB_CONTAINER="${DB_CONTAINER:-isp_billing_postgres}"
PROOF_FILE="${PROOF_FILE:-/home/dennis/apps/isp-billing/.primary-fenced}"

state() {
  docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo missing
}

if [ "$MODE" != "--apply" ]; then
  echo "mode=audit app=$(state "$APP_CONTAINER") radius=$(state "$RADIUS_CONTAINER")"
  test -f "$PROOF_FILE" && sed -n '1,5p' "$PROOF_FILE" || true
  exit 0
fi

docker stop "$APP_CONTAINER" "$RADIUS_CONTAINER"
test "$(state "$APP_CONTAINER")" = "false"
test "$(state "$RADIUS_CONTAINER")" = "false"
lsn=$(docker exec "$DB_CONTAINER" psql -U isp_user -d isp_billing_db -Atc 'select pg_current_wal_lsn();')
umask 077
printf 'fenced_at=%s\nwal_lsn=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$lsn" >"$PROOF_FILE"
echo "OK: AWS writers fenced at WAL $lsn; PostgreSQL and tunnel manager remain running"
