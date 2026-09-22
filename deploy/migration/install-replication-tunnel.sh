#!/usr/bin/env bash
# Install the Hetzner -> AWS SSH tunnel used only by PostgreSQL streaming.
# The dedicated private key must already exist on Hetzner and its public half
# must already be authorized for the AWS deploy user.
set -euo pipefail

MODE="${1:-audit}"
AWS_SSH_TARGET="${AWS_SSH_TARGET:-dennis@54.91.202.229}"
SSH_KEY_PATH="${SSH_KEY_PATH:-/root/.ssh/isp-billing-replica}"
DOCKER_NETWORK="${DOCKER_NETWORK:-isp_billing_hetzner_private}"
LOCAL_PORT="${LOCAL_PORT:-15434}"
UNIT=/etc/systemd/system/isp-billing-replication-tunnel.service

gateway=$(docker network inspect "$DOCKER_NETWORK" --format '{{(index .IPAM.Config 0).Gateway}}')
test -n "$gateway" || { echo "ERROR: could not resolve Docker bridge gateway" >&2; exit 1; }

if [ "$MODE" != "--apply" ]; then
  echo "mode=audit gateway=$gateway port=$LOCAL_PORT"
  systemctl is-active isp-billing-replication-tunnel.service 2>/dev/null || true
  timeout 2 nc -z "$gateway" "$LOCAL_PORT" && echo "tunnel=reachable" || echo "tunnel=unreachable"
  exit 0
fi

test "$(id -u)" -eq 0 || { echo "ERROR: run as root" >&2; exit 1; }
test -f "$SSH_KEY_PATH" || { echo "ERROR: missing $SSH_KEY_PATH" >&2; exit 1; }
chmod 600 "$SSH_KEY_PATH"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s\n' \
  '[Unit]' \
  'Description=ISP billing PostgreSQL replication tunnel to AWS' \
  'After=network-online.target docker.service' \
  'Wants=network-online.target' \
  '' \
  '[Service]' \
  'Type=simple' \
  "ExecStart=/usr/bin/ssh -NT -i ${SSH_KEY_PATH} -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new -L ${gateway}:${LOCAL_PORT}:127.0.0.1:5434 ${AWS_SSH_TARGET}" \
  'Restart=always' \
  'RestartSec=5' \
  '' \
  '[Install]' \
  'WantedBy=multi-user.target' >"$tmp"
install -m 644 "$tmp" "$UNIT"
systemctl daemon-reload
systemctl enable --now isp-billing-replication-tunnel.service

for _ in $(seq 1 10); do
  timeout 2 nc -z "$gateway" "$LOCAL_PORT" && {
    echo "OK: replication tunnel listening on ${gateway}:${LOCAL_PORT}"
    exit 0
  }
  sleep 1
done
systemctl --no-pager --full status isp-billing-replication-tunnel.service || true
exit 1
