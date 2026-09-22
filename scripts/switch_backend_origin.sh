#!/usr/bin/env bash
# Repoint the Cloudflare-proxied ISP billing backend between AWS and Hetzner.
set -euo pipefail

FQDN="${FQDN:-isp.bitwavetechnologies.net}"
ZONE_NAME="${ZONE_NAME:-bitwavetechnologies.net}"
AWS_TARGET="${AWS_TARGET:-54.91.202.229}"
HETZNER_TARGET="${HETZNER_TARGET:-91.98.238.12}"
ACTION="${1:-status}"

die() { echo "ERROR: $*" >&2; exit 1; }
cf() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" -H "Authorization: Bearer ${CF_API_TOKEN}" -H 'Content-Type: application/json')
  [ -n "$body" ] && args+=(--data "$body")
  curl "${args[@]}" "https://api.cloudflare.com/client/v4${path}"
}

probe() {
  curl -sS --max-time 10 -D - -o /tmp/isp-backend-health.json "https://${FQDN}/health" \
    | tr -d '\r' | grep -Ei '^(HTTP/|x-served-by:|x-isp-runtime-mode:)' || true
  sed -n '1p' /tmp/isp-backend-health.json 2>/dev/null || true
  rm -f /tmp/isp-backend-health.json
}

if [ "$ACTION" = status ]; then
  probe
  exit 0
fi
[ -n "${CF_API_TOKEN:-}" ] || die "CF_API_TOKEN is required"
case "$ACTION" in
  aws) target="$AWS_TARGET" ;;
  hetzner) target="$HETZNER_TARGET" ;;
  *) die "action must be status, aws, or hetzner" ;;
esac

zone_id=$(cf GET "/zones?name=${ZONE_NAME}" | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r[0]["id"] if r else "")')
[ -n "$zone_id" ] || die "zone not found"
record=$(cf GET "/zones/${zone_id}/dns_records?name=${FQDN}")
record_id=$(printf '%s' "$record" | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r[0]["id"] if r else "")')
[ -n "$record_id" ] || die "record not found"
old=$(printf '%s' "$record" | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"][0]; print(r["content"])')
echo "before=${old} target=${target}"
payload=$(python3 -c 'import json,sys; print(json.dumps({"type":"A","name":sys.argv[1],"content":sys.argv[2],"ttl":1,"proxied":True}))' "$FQDN" "$target")
response=$(cf PUT "/zones/${zone_id}/dns_records/${record_id}" "$payload")
ok=$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["success"])')
[ "$ok" = True ] || { printf '%s\n' "$response"; die "Cloudflare rejected update"; }
sleep 5
probe
