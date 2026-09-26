#!/usr/bin/env bash
# One-time: create the router-management CA and the SSTP server certificate
# in /etc/accel-ppp-router-mgmt/. Already done on Hetzner (2026-09-24).
#
# Every SSTP router trusts ca.crt and checks the server cert against it
# (verify-server-certificate=yes). Re-creating the CA would break the tunnel
# on every router, so this script refuses to run when ca.crt or ca.key exist.
# Keys stay on the server: never copy ca.key/server.key anywhere, never commit.
# Only ca.crt (public) goes to the app, as ROUTER_MGMT_CA_PEM.
set -euo pipefail
cd /etc/accel-ppp-router-mgmt
if [[ -e ca.crt || -e ca.key ]]; then
  echo "ca.crt/ca.key already exist -- refusing to replace the router CA" >&2
  exit 1
fi
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
  -subj '/CN=Bitwave Router Management CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout ca.key -out ca.crt 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=91.98.238.12' \
  -keyout server.key -out server.csr 2>/dev/null
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:91.98.238.12
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 3650 -sha256 \
  -extfile server.ext 2>/dev/null
chmod 0600 ca.key server.key
chmod 0644 ca.crt server.crt
openssl verify -CAfile ca.crt server.crt
