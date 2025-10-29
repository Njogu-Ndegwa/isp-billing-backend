# WireGuard Quick Start Guide

## TL;DR - Fast Setup

### AWS Server (5 minutes)

```bash
# Install WireGuard
sudo apt update && sudo apt install -y wireguard

# Generate keys
cd /etc/wireguard
sudo wg genkey | sudo tee server_private.key | wg pubkey | sudo tee server_public.key
sudo chmod 600 server_private.key

# Create config
sudo nano /etc/wireguard/wg0.conf
```

**Paste this (update PRIVATE_KEY):**
```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <PASTE_SERVER_PRIVATE_KEY>

[Peer]
# MikroTik - will update after getting its public key
PublicKey = <MIKROTIK_PUBLIC_KEY_HERE>
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
```

```bash
# Add AWS Security Group rule: UDP 51820
# Then enable firewall
sudo ufw allow 51820/udp
sudo ufw enable

# DON'T start yet - wait for MikroTik setup
```

---

### MikroTik (via Winbox - 5 minutes)

1. **WireGuard → Add (+)**
   - Name: `wg-aws`
   - Generate keys (save the public key)
   - OK

2. **IP → Addresses → Add (+)**
   - Address: `10.0.0.2/24`
   - Interface: `wg-aws`
   - OK

3. **WireGuard → wg-aws → Peers → Add (+)**
   - Public Key: *AWS server public key*
   - Endpoint: `YOUR_AWS_PUBLIC_IP:51820`
   - Allowed Address: `10.0.0.1/32`
   - Persistent Keepalive: `25`
   - OK

4. **Terminal:** Test ping
   ```
   /ping 10.0.0.1 count=5
   ```

---

### Finish AWS Setup

```bash
# Update config with MikroTik public key
sudo nano /etc/wireguard/wg0.conf
# Replace <MIKROTIK_PUBLIC_KEY_HERE> with actual key

# Start WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Test
ping 10.0.0.2 -c 5
telnet 10.0.0.2 8728
```

---

### Update Application

**Edit `.env`:**
```env
MIKROTIK_HOST=10.0.0.2
MIKROTIK_PORT=8728
MIKROTIK_USERNAME=admin
MIKROTIK_PASSWORD=your_password
```

**Run app:**
```bash
uvicorn main:app --reload
```

---

## Verify It's Working

```bash
# AWS
sudo wg show  # Should show handshake and data transfer
ping 10.0.0.2

# MikroTik (Winbox Terminal)
/interface/wireguard/peers/print
/ping 10.0.0.1
```

---

## Common Issues

**No handshake?**
- Check AWS Security Group allows UDP 51820
- Verify public keys are correct
- Check MikroTik can reach internet

**Ping works but API doesn't?**
- Check MikroTik API is enabled (Services → API)
- Verify `.env` has `MIKROTIK_HOST=10.0.0.2`
- Test: `telnet 10.0.0.2 8728`

**Connection drops?**
- WireGuard auto-reconnects
- Check MikroTik internet stability
- Increase keepalive: `PersistentKeepalive = 60`

---

## Key Information

| Item | Value |
|------|-------|
| AWS VPN IP | 10.0.0.1 |
| MikroTik VPN IP | 10.0.0.2 |
| WireGuard Port | 51820 (UDP) |
| MikroTik API Port | 8728 (TCP) |
| Min RouterOS Version | v7.0+ |

---

For detailed instructions, see **WIREGUARD_SETUP.md**

