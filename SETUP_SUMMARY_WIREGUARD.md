# Setup Summary - MikroTik WireGuard VPN

## ✅ What's Been Done

### 1. Application Code Updated
- ✅ `app/config.py` - Changed to use WireGuard VPN IP (`10.0.0.2`)
- ✅ `main.py` - All MikroTik connections use settings-based configuration

### 2. Documentation Created
- ✅ `WIREGUARD_SETUP.md` - Complete detailed setup guide
- ✅ `WIREGUARD_QUICK_START.md` - Fast setup reference (10 minutes)
- ✅ `setup_wireguard_aws.sh` - Automated AWS setup script

## 🚀 Quick Setup (Choose One)

### Option A: Follow Quick Start (10 minutes)
Read `WIREGUARD_QUICK_START.md` for fast setup with commands only.

### Option B: Follow Detailed Guide
Read `WIREGUARD_SETUP.md` for step-by-step explanations.

### Option C: Use Automation Script
```bash
# On AWS
sudo bash setup_wireguard_aws.sh
# Then follow the printed instructions
```

## 📋 Setup Checklist

### AWS Server Setup
- [ ] Run `setup_wireguard_aws.sh` or manually install WireGuard
- [ ] Note down AWS server public key
- [ ] Configure AWS Security Group (UDP 51820)
- [ ] Create `/etc/wireguard/wg0.conf`

### MikroTik Setup (Winbox)
- [ ] Verify RouterOS v7.0+ installed
- [ ] WireGuard → Create interface `wg-aws`
- [ ] Generate and note down MikroTik public key
- [ ] IP → Addresses → Add `10.0.0.2/24` to `wg-aws`
- [ ] WireGuard → Peers → Add AWS peer
- [ ] Test ping: `/ping 10.0.0.1`

### Complete Setup
- [ ] Update AWS `/etc/wireguard/wg0.conf` with MikroTik public key
- [ ] Start WireGuard on AWS: `sudo systemctl start wg-quick@wg0`
- [ ] Verify connectivity: `ping 10.0.0.2` from AWS
- [ ] Test API access: `telnet 10.0.0.2 8728`

### Application Configuration
- [ ] Create/update `.env` file with `MIKROTIK_HOST=10.0.0.2`
- [ ] Set `MIKROTIK_PASSWORD` in `.env`
- [ ] Test application: `uvicorn main:app --reload`
- [ ] Verify logs show: "Successfully logged in to 10.0.0.2"

## 🔧 Your Next Step

**Create/Update `.env` file:**

```env
# Database Configuration
DATABASE_URL=sqlite+aiosqlite:///./isp_billing.db

# JWT Authentication
SECRET_KEY=your-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# MikroTik Configuration (WireGuard VPN)
MIKROTIK_HOST=10.0.0.2
MIKROTIK_PORT=8728
MIKROTIK_USERNAME=admin
MIKROTIK_PASSWORD=your_actual_mikrotik_password
```

## 🌐 Network Diagram

```
Internet
   │
   ├─── AWS Ubuntu VM (Public IP: X.X.X.X)
   │    │
   │    └─── WireGuard wg0 (VPN IP: 10.0.0.1)
   │              │
   │              │ Encrypted Tunnel (UDP 51820)
   │              │
   └─── MikroTik Router (Behind NAT)
        │
        └─── WireGuard wg-aws (VPN IP: 10.0.0.2)
             │
             └─── API Port 8728
```

## 🔍 Key Information

| Component | Value |
|-----------|-------|
| AWS VPN IP | `10.0.0.1` |
| MikroTik VPN IP | `10.0.0.2` |
| WireGuard Port | `51820` (UDP) |
| MikroTik API Port | `8728` (TCP) |
| Min RouterOS Version | v7.0+ |

## ✨ Why WireGuard?

Compared to SSH reverse tunnel:
- ⚡ **Faster** - Lower latency, better throughput
- 🔄 **Auto-reconnects** - No need for scripts/schedulers
- 🛡️ **More secure** - Modern cryptography
- 💪 **More reliable** - Better NAT traversal
- 🎯 **Simpler** - Native RouterOS support
- 📱 **Mobile-friendly** - Handles IP changes gracefully

## 🧪 Testing

### Verify WireGuard Connection

**On AWS:**
```bash
sudo wg show
# Should show: latest handshake, transfer rx/tx

ping 10.0.0.2 -c 5
# Should get replies
```

**On MikroTik (Winbox Terminal):**
```routeros
/interface/wireguard/peers/print detail
# Should show: last-handshake (recent), rx/tx bytes

/ping 10.0.0.1 count=5
# Should get replies
```

### Test MikroTik API

```bash
# From AWS
telnet 10.0.0.2 8728
# Should connect and show binary output
# Press Ctrl+] then type: quit
```

### Test Application

```bash
cd /path/to/isp-billing
source myEnv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Check logs for:
# "Successfully logged in to 10.0.0.2"
```

## 🔧 Troubleshooting

### No Handshake
```bash
# Check AWS Security Group allows UDP 51820
# Verify public keys are correct on both sides
# Check MikroTik can reach AWS public IP

# View AWS logs
sudo journalctl -u wg-quick@wg0 -f

# View MikroTik logs
/log print where topics~"wireguard"
```

### Ping Works But API Doesn't
```bash
# Check MikroTik API is enabled
# Services → API (port 8728)

# Test from AWS
telnet 10.0.0.2 8728

# Check .env has correct IP
cat .env | grep MIKROTIK_HOST
# Should show: MIKROTIK_HOST=10.0.0.2
```

### Connection Drops
- WireGuard auto-reconnects (no action needed)
- Check MikroTik internet stability
- Increase keepalive if needed (60 seconds)

## 📚 Documentation Files

1. **WIREGUARD_SETUP.md** - Complete step-by-step guide (detailed)
2. **WIREGUARD_QUICK_START.md** - Fast setup (commands only)
3. **setup_wireguard_aws.sh** - Automated AWS setup script
4. **SETUP_SUMMARY_WIREGUARD.md** - This file (overview)

## 🎉 Success Indicators

You know it's working when:
- ✅ `ping 10.0.0.2` succeeds from AWS
- ✅ `ping 10.0.0.1` succeeds from MikroTik
- ✅ `telnet 10.0.0.2 8728` connects
- ✅ `sudo wg show` shows recent handshake and data transfer
- ✅ Application logs show "Successfully logged in to 10.0.0.2"
- ✅ You can add/remove hotspot users via API

---

**Ready to start?** → Open `WIREGUARD_QUICK_START.md` for fast setup! 🚀

