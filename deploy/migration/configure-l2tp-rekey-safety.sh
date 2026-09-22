#!/usr/bin/env bash
# Audit by default. Use --apply on an L2TP/IPsec server to enable immediate
# cleanup of superseded CHILD_SAs without restarting charon or active tunnels.
set -euo pipefail

MODE="${1:-audit}"
DROP_IN=/etc/strongswan.d/charon/99-delete-rekeyed.conf

if [ "$MODE" != "--apply" ]; then
  echo "mode=audit"
  if grep -RqsE '^[[:space:]]*delete_rekeyed[[:space:]]*=[[:space:]]*yes' \
      /etc/strongswan.conf /etc/strongswan.d 2>/dev/null; then
    echo "delete_rekeyed=yes"
  else
    echo "delete_rekeyed=missing"
  fi
  exec python3 "$(dirname "$0")/../../scripts/cleanup_ipsec_connmarks.py"
fi

test "$(id -u)" -eq 0 || { echo "ERROR: run as root" >&2; exit 1; }
install -d -m 755 "$(dirname "$DROP_IN")"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s\n' 'charon {' '    delete_rekeyed = yes' '}' >"$tmp"
install -m 644 "$tmp" "$DROP_IN"

charon_pid=$(pidof charon || true)
test -n "$charon_pid" || { echo "ERROR: charon is not running" >&2; exit 1; }
kill -HUP "$charon_pid"
sleep 2

grep -qsE '^[[:space:]]*delete_rekeyed[[:space:]]*=[[:space:]]*yes' "$DROP_IN"
python3 "$(dirname "$0")/../../scripts/cleanup_ipsec_connmarks.py" --apply
echo "OK: delete_rekeyed=yes loaded and superseded connmark rules removed"
