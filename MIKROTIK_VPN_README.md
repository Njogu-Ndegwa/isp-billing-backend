# MikroTik to AWS Connection Setup

## Overview

This project uses **WireGuard VPN** to securely connect your MikroTik router (on local network) to your AWS-hosted ISP billing system.

## 📚 Documentation Files

Choose the guide that fits your needs:

### 🚀 Quick Start (10 minutes)
**→ Start here: `WIREGUARD_QUICK_START.md`**
- Fast setup with commands only
- Minimal explanation
- Get running quickly

### 📖 Detailed Guide
**→ Use this: `WIREGUARD_SETUP.md`**
- Step-by-step instructions
- Explanations for each step
- Troubleshooting included
- Best for first-time setup

### 📋 Summary & Checklist
**→ Reference: `SETUP_SUMMARY_WIREGUARD.md`**
- Overview of changes made
- Setup checklist
- Testing procedures
- Quick troubleshooting

### ⚙️ Automated Setup
**→ Use script: `setup_wireguard_aws.sh`**
- Automated AWS server configuration
- Generates keys automatically
- Creates WireGuard config
- Run with: `sudo bash setup_wireguard_aws.sh`

## 🎯 What You Need

### Prerequisites
- ✅ AWS Ubuntu VM with public IP
- ✅ MikroTik hAP router with RouterOS v7.0+
- ✅ Winbox installed (to configure MikroTik)
- ✅ SSH access to AWS server

### Time Required
- **Quick setup:** 10-15 minutes
- **Detailed setup:** 20-30 minutes

## 🌟 Quick Reference

### Network Configuration
```
AWS Server VPN IP:   10.0.0.1
MikroTik VPN IP:     10.0.0.2
WireGuard Port:      51820 (UDP)
MikroTik API Port:   8728 (TCP)
```

### Key Commands

**On AWS:**
```bash
# Check WireGuard status
sudo wg show

# Test connectivity
ping 10.0.0.2
telnet 10.0.0.2 8728
```

**On MikroTik (Winbox Terminal):**
```routeros
# Check WireGuard
/interface/wireguard/peers/print

# Test connectivity
/ping 10.0.0.1
```

### Application Configuration

Your `.env` file should have:
```env
MIKROTIK_HOST=10.0.0.2
MIKROTIK_PORT=8728
MIKROTIK_USERNAME=admin
MIKROTIK_PASSWORD=your_password
```

## 🔄 Setup Flow

```
1. AWS Setup (5 min)
   ├─ Install WireGuard
   ├─ Generate keys
   └─ Create config

2. MikroTik Setup (5 min)
   ├─ Create WireGuard interface
   ├─ Generate keys
   └─ Add AWS peer

3. Complete Connection (2 min)
   ├─ Update AWS config with MikroTik key
   ├─ Start WireGuard
   └─ Test connectivity

4. Application Setup (3 min)
   ├─ Update .env file
   └─ Test application
```

## ✅ Verification

Your setup is complete when:
- ✅ Both servers can ping each other via VPN IPs
- ✅ `telnet 10.0.0.2 8728` connects from AWS
- ✅ Your application logs show: "Successfully logged in to 10.0.0.2"
- ✅ You can manage hotspot users via API

## 🆘 Need Help?

### Quick Troubleshooting

**Problem: Can't ping through VPN**
```bash
# Check WireGuard status
sudo wg show  # Should show recent handshake

# Check AWS Security Group allows UDP 51820
# Check MikroTik firewall allows UDP 51820
```

**Problem: API connection fails**
```bash
# Test API port directly
telnet 10.0.0.2 8728

# Check MikroTik API is enabled
# Services → API (port 8728)

# Verify .env has correct IP
cat .env | grep MIKROTIK_HOST
```

**Problem: WireGuard won't start**
```bash
# Check configuration
sudo wg-quick up wg0

# View detailed errors
sudo journalctl -u wg-quick@wg0 -xe
```

### Get More Help
See detailed troubleshooting in `WIREGUARD_SETUP.md`

## 📝 What's Changed in Your Code

The application has been updated to connect via WireGuard VPN:

**Before:**
```python
# Tried to connect to router's local IP (won't work from AWS)
api = MikroTikAPI(router.ip_address, ...)
```

**After:**
```python
# Connects to MikroTik via VPN
api = MikroTikAPI(settings.MIKROTIK_HOST, ...)  # 10.0.0.2
```

Files modified:
- `app/config.py` - Added WireGuard VPN configuration
- `main.py` - Updated all MikroTik connections to use VPN IP

## 🔐 Security Notes

1. **Keep private keys secret** - Never commit to git
2. **Restrict AWS Security Group** - Only allow MikroTik's public IP (not 0.0.0.0/0)
3. **Use strong passwords** - Store in `.env` file
4. **Regular updates** - Keep RouterOS and Ubuntu updated
5. **Monitor access** - Check WireGuard logs regularly

## 🎓 Learn More

### About WireGuard
- Official site: [wireguard.com](https://www.wireguard.com/)
- Fast, modern, secure VPN tunnel
- Built into Linux kernel (5.6+)
- Native support in RouterOS v7+

### Why WireGuard vs SSH Tunnel?
- ⚡ Faster (much lower latency)
- 🔄 Auto-reconnects (no scripts needed)
- 🛡️ More secure (modern cryptography)
- 💪 More reliable (better NAT traversal)
- 🎯 Simpler (native RouterOS support)

## 📞 Support

If you encounter issues:

1. Check the troubleshooting section in `WIREGUARD_SETUP.md`
2. Verify all checklist items in `SETUP_SUMMARY_WIREGUARD.md`
3. Review AWS CloudWatch logs for application errors
4. Check MikroTik logs: System → Logs in Winbox

---

## 🚀 Ready to Start?

1. **Quick setup?** → Read `WIREGUARD_QUICK_START.md`
2. **First time?** → Read `WIREGUARD_SETUP.md`
3. **Use automation?** → Run `setup_wireguard_aws.sh`

Good luck! 🎉

