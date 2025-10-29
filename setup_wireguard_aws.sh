#!/bin/bash
# AWS Ubuntu WireGuard Setup Script
# Run this on your AWS Ubuntu VM to configure WireGuard for MikroTik connection
# Usage: sudo bash setup_wireguard_aws.sh

set -e

echo "=========================================="
echo "MikroTik WireGuard VPN Setup (AWS)"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (use sudo)"
    exit 1
fi

# Update system
echo "[1/6] Updating system packages..."
apt-get update -qq

# Install WireGuard
echo "[2/6] Installing WireGuard..."
apt-get install -y wireguard wireguard-tools

# Enable IP forwarding
echo "[3/6] Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

# Generate WireGuard keys
echo "[4/6] Generating WireGuard keys..."
WG_DIR="/etc/wireguard"
cd "$WG_DIR"

if [ ! -f "$WG_DIR/server_private.key" ]; then
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key
    echo "Keys generated successfully"
else
    echo "Keys already exist, skipping generation"
fi

SERVER_PRIVATE_KEY=$(cat server_private.key)
SERVER_PUBLIC_KEY=$(cat server_public.key)

# Create WireGuard configuration
echo "[5/6] Creating WireGuard configuration..."
cat > "$WG_DIR/wg0.conf" << EOF
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY

# MikroTik Peer (update PublicKey after MikroTik setup)
[Peer]
# IMPORTANT: Replace this with MikroTik's public key after generating it
PublicKey = REPLACE_WITH_MIKROTIK_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
EOF

chmod 600 "$WG_DIR/wg0.conf"
echo "Configuration created: /etc/wireguard/wg0.conf"

# Configure firewall
echo "[6/6] Configuring firewall..."
ufw allow 51820/udp comment 'WireGuard VPN' > /dev/null 2>&1 || true
ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1 || true
echo "y" | ufw enable > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "✅ WireGuard Setup Complete!"
echo "=========================================="
echo ""
echo "📋 IMPORTANT INFORMATION:"
echo ""
echo "1. AWS Server Public Key (give this to MikroTik):"
echo "   $SERVER_PUBLIC_KEY"
echo ""
echo "2. AWS Server Private Key (keep this secret):"
echo "   $SERVER_PRIVATE_KEY"
echo ""
echo "3. WireGuard VPN IPs:"
echo "   - AWS Server: 10.0.0.1"
echo "   - MikroTik:   10.0.0.2"
echo ""
echo "=========================================="
echo "⚠️  NEXT STEPS:"
echo "=========================================="
echo ""
echo "1. Configure AWS Security Group:"
echo "   - Add inbound rule: UDP port 51820"
echo "   - Source: Your MikroTik's public IP (or 0.0.0.0/0 for testing)"
echo ""
echo "2. Setup MikroTik (via Winbox):"
echo "   a) WireGuard → Add → Generate keys"
echo "   b) IP → Addresses → Add: 10.0.0.2/24 on wg-aws"
echo "   c) WireGuard → Peers → Add AWS peer with endpoint"
echo ""
echo "3. Get MikroTik's public key and update /etc/wireguard/wg0.conf:"
echo "   sudo nano /etc/wireguard/wg0.conf"
echo "   (Replace REPLACE_WITH_MIKROTIK_PUBLIC_KEY with actual key)"
echo ""
echo "4. Start WireGuard:"
echo "   sudo systemctl enable wg-quick@wg0"
echo "   sudo systemctl start wg-quick@wg0"
echo ""
echo "5. Verify connection:"
echo "   ping 10.0.0.2 -c 5"
echo "   telnet 10.0.0.2 8728"
echo ""
echo "6. Update your application .env:"
echo "   MIKROTIK_HOST=10.0.0.2"
echo ""
echo "=========================================="
echo "📚 See WIREGUARD_SETUP.md for detailed guide"
echo "=========================================="

