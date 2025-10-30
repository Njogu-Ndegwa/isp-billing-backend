# MikroTik to AWS WireGuard VPN Setup Guide

## Overview

This guide shows you how to connect your MikroTik router to your AWS-hosted ISP billing system using WireGuard VPN. WireGuard creates a secure, encrypted tunnel allowing your AWS server to access the MikroTik API as if it were on the same network.

**Why WireGuard over SSH Tunnel?**
- ✅ More reliable and stable
- ✅ Better performance (faster, lower latency)
- ✅ Simpler configuration
- ✅ Native support in MikroTik RouterOS v7+
- ✅ Automatic reconnection built-in
- ✅ Lower overhead

## Architecture

```
┌─────────────────────┐         WireGuard VPN         ┌──────────────────────┐
│  MikroTik Router    │ ◄────────────────────────────► │  AWS Ubuntu VM       │
│  (Local Network)    │      Encrypted Tunnel          │  (Cloud)             │
│                     │                                │                      │
│  VPN IP: 10.0.0.2   │                                │  VPN IP: 10.0.0.1    │
│  Port 8728 (API)    │                                │                      │
└─────────────────────┘                                │  ┌────────────────┐  │
                                                       │  │  ISP Billing   │  │
                                                       │  │  App connects  │  │
                                                       │  │  to 10.0.0.2   │  │
                                                       │  └────────────────┘  │
                                                       └──────────────────────┘
```

---

## Part 1: AWS Ubuntu Server Setup

### Step 1: Connect to Your AWS Ubuntu VM

```bash
ssh -i your-key.pem ubuntu@your-aws-public-ip
```

### Step 2: Install WireGuard

```bash
# Update system
sudo apt update
sudo apt install -y wireguard wireguard-tools

# Enable IP forwarding (if needed)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Step 3: Generate WireGuard Keys (AWS Server)

```bash
# Generate server keys
cd /etc/wireguard
sudo wg genkey | sudo tee server_private.key | wg pubkey | sudo tee server_public.key

# Set proper permissions
sudo chmod 600 server_private.key
```

### Step 4: Display Keys (You'll Need These)

```bash
# Server Private Key (keep this secret!)
sudo cat /etc/wireguard/server_private.key

# Server Public Key (you'll give this to MikroTik)
sudo cat /etc/wireguard/server_public.key
```

**Save both keys somewhere safe - you'll need them.**

### Step 5: Create WireGuard Configuration

```bash
sudo nano /etc/wireguard/wg0.conf
```

Paste this configuration:

```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <PASTE_SERVER_PRIVATE_KEY_HERE>

# Optional: Add PostUp/PostDown rules for NAT if needed
# PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# MikroTik Router
PublicKey = <MIKROTIK_PUBLIC_KEY_WILL_GO_HERE>
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
```

**Note:** Leave `<MIKROTIK_PUBLIC_KEY_WILL_GO_HERE>` as placeholder for now. We'll update it after generating MikroTik keys.

Save and exit (Ctrl+O, Enter, Ctrl+X).

### Step 6: Configure AWS Security Group

In AWS Console:
1. Go to **EC2 → Security Groups**
2. Find your instance's security group
3. Add **Inbound Rule**:
   - **Type:** Custom UDP
   - **Port:** 51820
   - **Source:** Your MikroTik's public IP (or 0.0.0.0/0 for testing)
   - **Description:** WireGuard VPN

### Step 7: Configure Firewall (UFW)

```bash
# Allow WireGuard port
sudo ufw allow 51820/udp comment 'WireGuard VPN'

# Allow SSH (if not already allowed)
sudo ufw allow 22/tcp comment 'SSH'

# Enable firewall
sudo ufw --force enable
sudo ufw status
```

### Step 8: Start WireGuard (After MikroTik Setup)

**DON'T start yet** - we'll do this after configuring MikroTik and updating the peer public key.

---

## Part 2: MikroTik Router Setup (via Winbox)

### Step 1: Check RouterOS Version

1. Open **Winbox** and connect to your MikroTik
2. Go to **System → Resources**
3. Check **Version** - Must be **v7.0 or higher** for WireGuard support

**If you're on v6.x:**
- Upgrade to RouterOS v7+ via **System → Packages → Check For Updates**
- Or download from [mikrotik.com/download](https://mikrotik.com/download)

### Step 2: Create WireGuard Interface (Auto-generates Keys)

Open **New Terminal** in Winbox and run:

```routeros
/interface wireguard add name=wg-aws listen-port=51820
```

### Step 3: View Generated Keys

In Terminal, run:

```routeros
/interface wireguard print detail
```

**Save the output** - you'll see:
- `private-key` (keep secret)
- `public-key` (give to AWS server)

You can also retrieve individual keys:

```routeros
/interface wireguard get wg-aws private-key
/interface wireguard get wg-aws public-key
```

### Step 4: Add IP Address to WireGuard Interface

In Terminal, run:

```routeros
/ip address add address=10.0.0.2/24 interface=wg-aws
```

Or via Winbox GUI:

1. Go to **IP → Addresses**
2. Click **+** (Add New)
3. Configure:
   - **Address:** `10.0.0.2/24`
   - **Interface:** `wg-aws`
4. Click **OK**

### Step 5: Add WireGuard Peer (AWS Server)

In Terminal, run (replace placeholders with your actual values):

```routeros
/interface wireguard peers add interface=wg-aws public-key="<AWS_SERVER_PUBLIC_KEY>" endpoint-address=<YOUR_AWS_PUBLIC_IP> endpoint-port=51820 allowed-address=10.0.0.1/32 persistent-keepalive=25s
```

Example:
```routeros
/interface wireguard peers add interface=wg-aws public-key="abc123XYZ456==" endpoint-address=54.123.45.67 endpoint-port=51820 allowed-address=10.0.0.1/32 persistent-keepalive=25s
```

Or via Winbox GUI:

1. Go to **WireGuard** (left menu)
2. Select your `wg-aws` interface
3. Click **Peers** tab
4. Click **+** (Add New)
5. Configure:
   - **Interface:** `wg-aws`
   - **Public Key:** Paste AWS server public key from Part 1, Step 4
   - **Endpoint:** `<YOUR_AWS_PUBLIC_IP>:51820`
   - **Allowed Address:** `10.0.0.1/32`
   - **Persistent Keepalive:** `25` seconds
6. Click **OK**

### Step 6: Add Firewall Rules (Optional but Recommended)

In Terminal, run:

```routeros
/ip firewall filter add chain=input protocol=udp dst-port=51820 action=accept comment="Allow WireGuard"
```

Or via Winbox GUI:

1. Go to **IP → Firewall → Filter Rules**
2. Add rule to accept WireGuard:
   - **Chain:** `input`
   - **Protocol:** `udp`
   - **Dst. Port:** `51820`
   - **Action:** `accept`
   - **Comment:** `Allow WireGuard`
3. Click **OK**

### Step 7: Test Connection

Open **Terminal** in Winbox:

```routeros
# Check WireGuard interface status
/interface wireguard print detail

# Check peers
/interface wireguard peers print detail

# Ping AWS server through VPN
/ping 10.0.0.1 count=5
```

**Expected output:** You should see successful ping responses.

---

## Part 3: Complete AWS Configuration

Now that you have the MikroTik public key:

### Step 1: Update AWS WireGuard Config

```bash
# Edit config
sudo nano /etc/wireguard/wg0.conf
```

Replace `<MIKROTIK_PUBLIC_KEY_WILL_GO_HERE>` with the actual MikroTik public key from Part 2, Step 3.

### Step 2: Start WireGuard on AWS

```bash
# Enable and start WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Check status
sudo systemctl status wg-quick@wg0

# Verify interface
sudo wg show
ip addr show wg0
```

### Step 3: Test Connection from AWS

```bash
# Ping MikroTik through VPN
ping 10.0.0.2 -c 5

# Test MikroTik API port
telnet 10.0.0.2 8728
```

If telnet connects and shows binary output, press `Ctrl+]` then type `quit`.

---

## Part 4: Application Configuration

### Step 1: Update `.env` File

Edit or create `.env` in your project root:

```env
# Database Configuration
DATABASE_URL=sqlite+aiosqlite:///./isp_billing.db

# JWT Authentication
SECRET_KEY=your-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# MikroTik Configuration (via WireGuard VPN)
MIKROTIK_HOST=10.0.0.2
MIKROTIK_PORT=8728
MIKROTIK_USERNAME=admin
MIKROTIK_PASSWORD=your_mikrotik_password_here
```

**Important:** Change `MIKROTIK_HOST` from `127.0.0.1` to `10.0.0.2` (MikroTik's VPN IP).

### Step 2: Update `app/config.py` (If Not Already Done)

Your config should have:

```python
class Settings(BaseSettings):
    # ... other settings ...
    
    # MikroTik Configuration
    MIKROTIK_HOST: str = "10.0.0.2"  # MikroTik VPN IP
    MIKROTIK_PORT: int = 8728
    MIKROTIK_USERNAME: str = "admin"
    MIKROTIK_PASSWORD: str = ""  # Set in .env

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
```

### Step 3: Test Your Application

```bash
cd /path/to/isp-billing
source myEnv/bin/activate  # or .\myEnv\Scripts\activate on Windows
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Check logs for: "Successfully logged in to 10.0.0.2"

---

## Part 5: Monitoring & Maintenance

### Check WireGuard Status

**On AWS:**
```bash
sudo wg show
sudo systemctl status wg-quick@wg0

# View logs
sudo journalctl -u wg-quick@wg0 -f
```

**On MikroTik (Winbox Terminal):**
```routeros
/interface wireguard print detail
/interface wireguard peers print detail
/ping 10.0.0.1 count=10
```

### Restart WireGuard

**On AWS:**
```bash
sudo systemctl restart wg-quick@wg0
```

**On MikroTik (Winbox Terminal):**
```routeros
/interface wireguard disable wg-aws
/interface wireguard enable wg-aws
```

---

## Troubleshooting

### Problem: Ping Doesn't Work Between AWS and MikroTik

**Check on AWS:**
```bash
sudo wg show
# Should show: latest handshake, transfer data

# Check if interface is up
ip addr show wg0
```

**Check on MikroTik:**
```routeros
/interface wireguard peers print detail
# Look for "last-handshake" - should be recent
```

**Solution:**
- Verify public keys are correct on both sides
- Check AWS Security Group allows UDP 51820
- Verify MikroTik can reach AWS public IP
- Check firewall rules

### Problem: Handshake Not Establishing

**Possible causes:**
1. **Wrong public keys** - Double-check keys match
2. **Firewall blocking** - Check AWS Security Group and MikroTik firewall
3. **Wrong endpoint** - Verify AWS public IP is correct
4. **NAT issues** - MikroTik behind NAT? Make sure router can initiate outbound UDP

**Debug on MikroTik:**
```routeros
/log print where topics~"wireguard"
```

### Problem: VPN Works But Can't Access MikroTik API

**Test API directly:**
```bash
# From AWS
telnet 10.0.0.2 8728
```

**If telnet fails:**
- Check MikroTik API is enabled: `Services → API` (port 8728)
- Check MikroTik firewall isn't blocking API access from VPN

**If telnet works but app fails:**
- Check `.env` has correct `MIKROTIK_HOST=10.0.0.2`
- Restart your application

### Problem: Connection Drops Frequently

**Solution:**
- Increase `PersistentKeepalive` to 30-60 seconds on both sides
- Check MikroTik internet stability
- Verify AWS instance isn't being stopped/restarted

---

## Security Best Practices

1. **Keep Private Keys Secret** - Never share or commit to git
2. **Restrict AWS Security Group** - Limit UDP 51820 to MikroTik's public IP only
3. **Use Strong MikroTik Password** - Store securely in `.env`
4. **Regular Updates** - Keep RouterOS and Ubuntu updated
5. **Monitor Access** - Check WireGuard logs regularly
6. **Firewall Rules** - Only allow necessary ports on MikroTik

---

## Advantages Over SSH Tunnel

| Feature | WireGuard | SSH Tunnel |
|---------|-----------|------------|
| Speed | ⚡ Very fast | Slower |
| CPU Usage | Low | Higher |
| Reconnection | Automatic | Requires scripting |
| Setup Complexity | Simple | More complex |
| NAT Traversal | Excellent | Can be tricky |
| Mobile/Roaming | Excellent | Poor |
| Built-in Keepalive | Yes | Requires config |

---

## Quick Reference

### Important IPs
- **AWS VPN IP:** `10.0.0.1`
- **MikroTik VPN IP:** `10.0.0.2`
- **WireGuard Port:** `51820` (UDP)
- **MikroTik API Port:** `8728` (TCP)

### Important Commands

**AWS:**
```bash
sudo systemctl status wg-quick@wg0  # Check status
sudo wg show                         # Show connections
ping 10.0.0.2                        # Test connectivity
```

**MikroTik:**
```routeros
/interface wireguard print detail    # Show interfaces
/interface wireguard peers print     # Show peers
/ping 10.0.0.1                       # Test connectivity
```

---

## Checklist

- [ ] AWS Ubuntu VM has public IP
- [ ] Installed WireGuard on AWS
- [ ] Generated AWS WireGuard keys
- [ ] Created `/etc/wireguard/wg0.conf`
- [ ] AWS Security Group allows UDP 51820
- [ ] MikroTik RouterOS v7+ installed
- [ ] Generated MikroTik WireGuard keys
- [ ] Created WireGuard interface on MikroTik
- [ ] Added IP 10.0.0.2/24 to MikroTik WireGuard interface
- [ ] Added AWS peer on MikroTik
- [ ] Updated AWS config with MikroTik public key
- [ ] Started WireGuard on AWS
- [ ] Ping works: AWS ↔ MikroTik (10.0.0.1 ↔ 10.0.0.2)
- [ ] Telnet to port 8728 works: `telnet 10.0.0.2 8728`
- [ ] Updated `.env` with `MIKROTIK_HOST=10.0.0.2`
- [ ] Application connects successfully
- [ ] Tested API operations (add user, check status, etc.)

Once all steps are complete, your ISP billing system will communicate securely with your MikroTik router over WireGuard VPN! 🎉

