#!/usr/bin/env bash
# H1 host prep for the Hetzner billing target (egress-nbg1, 91.98.238.12).
# Idempotent; run as root. Executed 2026-08-06 — kept for replicability.
# Deliberately NO ufw here (Docker bypasses it; wg-egress iptables must stay
# untouched). Network filtering = Hetzner Cloud Firewall (see hetzner-cloud-firewall.md).
set -euo pipefail

OPERATOR_PUBKEY="${OPERATOR_PUBKEY:?set to the operator ed25519 public key line}"
CI_PUBKEY="${CI_PUBKEY:?set to the github-actions deploy public key line}"

# --- 4G swap (the box ships with none; factory builds + billing stack need headroom) ---
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 4G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
sysctl -w vm.swappiness=10
grep -q 'vm.swappiness' /etc/sysctl.d/99-billing.conf 2>/dev/null \
  || echo 'vm.swappiness=10' >> /etc/sysctl.d/99-billing.conf

# --- deploy user for CI + operators (docker group; no sudo) ---
id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy
usermod -aG docker deploy
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
touch /home/deploy/.ssh/authorized_keys
grep -qF "$CI_PUBKEY"       /home/deploy/.ssh/authorized_keys || echo "$CI_PUBKEY"       >> /home/deploy/.ssh/authorized_keys
grep -qF "$OPERATOR_PUBKEY" /home/deploy/.ssh/authorized_keys || echo "$OPERATOR_PUBKEY" >> /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

# --- fail2ban (sshd jail; sshd is already key-only on this box) ---
if ! systemctl is-active --quiet fail2ban; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
  systemctl enable --now fail2ban
fi

echo "OK: swap=$(swapon --show --noheadings | wc -l) deploy=$(id -u deploy) fail2ban=$(systemctl is-active fail2ban)"
