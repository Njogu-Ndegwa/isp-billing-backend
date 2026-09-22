#!/usr/bin/env bash
# Promote the caught-up Hetzner physical standby after proving AWS is fenced.
# For an unreachable/dead AWS host, --disaster additionally requires the caller
# to accept the measured replay lag with ALLOW_DATA_LOSS=yes.
set -euo pipefail

MODE="${1:-audit}"
COMPOSE_DIR="${COMPOSE_DIR:-/opt/isp-billing-shadow/repo}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.hetzner.yml}"
ENV_FILE="${ENV_FILE:-.env.hetzner}"
DB_CONTAINER="${DB_CONTAINER:-isp_billing_hetzner_db}"
WEB_CONTAINER="${WEB_CONTAINER:-isp_billing_hetzner_app}"
AWS_SSH_TARGET="${AWS_SSH_TARGET:-dennis@54.91.202.229}"
SSH_KEY_PATH="${SSH_KEY_PATH:-/root/.ssh/isp-billing-replica}"

cd "$COMPOSE_DIR"

db_query() {
  docker exec "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U isp_user -d isp_billing_db -Atc "$1"
}

set_env() {
  local key="$1" value="$2"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
}

recovery=$(db_query 'select pg_is_in_recovery();')
replay_lsn=$(db_query "select coalesce(pg_last_wal_replay_lsn()::text,'');")
replay_lag=$(db_query "select coalesce(extract(epoch from now()-pg_last_xact_replay_timestamp())::int,0);")

if [ "$MODE" = "audit" ] || [ -z "$MODE" ]; then
  echo "mode=audit recovery=$recovery replay_lsn=$replay_lsn replay_lag_seconds=$replay_lag"
  exit 0
fi
test "$MODE" = "--apply" -o "$MODE" = "--disaster" || { echo "usage: $0 [audit|--apply|--disaster]" >&2; exit 1; }
test "$recovery" = "t" || { echo "ERROR: Hetzner DB is not a standby" >&2; exit 1; }

if [ "$MODE" = "--apply" ]; then
  test -f "$SSH_KEY_PATH" || { echo "ERROR: missing $SSH_KEY_PATH" >&2; exit 1; }
  aws_app=$(ssh -i "$SSH_KEY_PATH" -o BatchMode=yes -o ConnectTimeout=5 "$AWS_SSH_TARGET" \
    "docker inspect -f '{{.State.Running}}' isp_billing_app 2>/dev/null || echo missing")
  aws_radius=$(ssh -i "$SSH_KEY_PATH" -o BatchMode=yes -o ConnectTimeout=5 "$AWS_SSH_TARGET" \
    "docker inspect -f '{{.State.Running}}' isp_billing_radius 2>/dev/null || echo missing")
  test "$aws_app" = "false" -a "$aws_radius" = "false" || {
    echo "ERROR: AWS app/radius are not both fenced" >&2
    exit 1
  }
  source_lsn=$(ssh -i "$SSH_KEY_PATH" -o BatchMode=yes -o ConnectTimeout=5 "$AWS_SSH_TARGET" \
    "docker exec isp_billing_postgres psql -U isp_user -d isp_billing_db -Atc 'select pg_current_wal_lsn();'")
  for _ in $(seq 1 30); do
    caught_up=$(db_query "select pg_wal_lsn_diff('${source_lsn}', pg_last_wal_replay_lsn()) <= 0;")
    [ "$caught_up" = "t" ] && break
    sleep 2
  done
  test "${caught_up:-}" = "t" || { echo "ERROR: standby did not catch up to $source_lsn" >&2; exit 1; }
else
  test "${ALLOW_DATA_LOSS:-no}" = "yes" || {
    echo "ERROR: disaster promotion requires ALLOW_DATA_LOSS=yes; measured replay lag=${replay_lag}s" >&2
    exit 1
  }
fi

docker stop "$WEB_CONTAINER" 2>/dev/null || true
docker exec -u postgres "$DB_CONTAINER" pg_ctl -D /var/lib/postgresql/data promote -w
test "$(db_query 'select pg_is_in_recovery();')" = "f"

cp -a "$ENV_FILE" "${ENV_FILE}.pre-promote-$(date -u +%Y%m%dT%H%M%SZ)"
set_env SHADOW_MODE false
set_env RUN_SCHEDULER true
set_env SCHEDULER_ENABLED true

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" --profile active up -d db web freeradius
for _ in $(seq 1 60); do
  runtime=$(docker exec "$WEB_CONTAINER" python -c \
    "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8000/health'))['runtime_mode'])" \
    2>/dev/null || true)
  [ "$runtime" = "active" ] && break
  sleep 2
done
test "${runtime:-}" = "active" || { echo "ERROR: promoted app did not report active mode" >&2; exit 1; }
echo "OK: Hetzner database promoted and app is active; switch the Cloudflare backend origin next"
