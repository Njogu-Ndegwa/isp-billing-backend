# MikroTik External Captive Portal Setup Guide

## Overview

This guide shows you how to set up a MikroTik Hotspot with an **external captive portal** hosted on AWS. Unlike the built-in MikroTik login page, this setup redirects users to your custom-branded web portal where they can register, pay via M-Pesa, and get internet access automatically.

**Architecture: External Portal (Option B)**
- ✅ Full control over login UI/UX
- ✅ Custom branding and payment integrations
- ✅ Centralized user management in your database
- ✅ M-Pesa STK Push integration
- ✅ Multi-router support from one portal

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Guest User Device                                                  │
│  ├─ Connects to WiFi                                                │
│  └─ Tries to access internet → HTTP request intercepted            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  MikroTik Router (Hotspot)                                          │
│  ├─ Intercepts HTTP traffic                                         │
│  ├─ Serves login.html from /hotspot directory                       │
│  └─ login.html contains redirect to external portal                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ (Redirect with MAC, IP, etc.)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  External Captive Portal (Vercel + AWS)                             │
│  ├─ Frontend: Vercel (https://isp-frontend-two.vercel.app)          │
│  │   └─ User selects plan, enters phone, pays via M-Pesa           │
│  └─ Backend: AWS FastAPI (Your isp-billing app)                     │
│      └─ POST /api/clients/mac-register/{router_id}                  │
│          └─ Calls MikroTik API to authorize MAC (bypass)            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ (MikroTik API call via WireGuard VPN)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  MikroTik API (Port 8728)                                           │
│  ├─ /ip/hotspot/user/add                                            │
│  ├─ /ip/hotspot/ip-binding/add (type=bypassed)                      │
│  ├─ /queue/simple/add (bandwidth limit)                             │
│  └─ User gets internet access! ✅                                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- ✅ MikroTik RouterOS v7.0+ (for WireGuard support)
- ✅ WireGuard VPN already configured (see WIREGUARD_SETUP.md)
- ✅ AWS FastAPI backend running (isp-billing app)
- ✅ External portal URL (e.g., Vercel frontend)
- ✅ MikroTik API enabled (port 8728)

---

## Part 1: MikroTik Hotspot Configuration

### Step 1: Verify Hotspot Exists

Open **Winbox Terminal** and check if hotspot is already configured:

```routeros
/ip hotspot print detail
```

**Expected Output:**
```
 0   name="hotspot1" interface=bridge profile=hs_prof 
     idle-timeout=5m keepalive-timeout=none addresses-per-mac=2
     proxy-status="running"
```

If you don't see a hotspot, create one:

```routeros
/ip hotspot setup
```

Follow the wizard:
1. **Hotspot Interface:** `bridge` (your local network interface)
2. **Local Address:** `192.168.88.1/24` (your gateway IP)
3. **Address Pool:** `192.168.88.10-192.168.88.254`
4. **SSL Certificate:** `none` (unless you have one)
5. **SMTP Server:** `0.0.0.0` (not needed)
6. **DNS Servers:** Your DNS or `8.8.8.8,8.8.4.4`
7. **DNS Name:** Leave empty
8. **Username:** Create default admin user (you'll delete this later)

### Step 2: Check Hotspot Profile

```routeros
/ip hotspot profile print detail
```

**Important settings:**
- `login-by=http-chap,http-pap` (allows login methods)
- `html-directory=hotspot` (default HTML directory)

If your profile is named `hs_prof`, verify it:

```routeros
/ip hotspot profile print detail where name=hs_prof
```

### Step 3: Enable MikroTik API

**Via Terminal:**
```routeros
/ip service print
```

Check if `api` is enabled on port `8728`:

```routeros
/ip service set api address="" port=8728 disabled=no
```

**Via Winbox GUI:**
1. Go to **IP → Services**
2. Double-click **api**
3. Check **Port:** `8728`
4. **Available From:** `10.0.0.1/32` (only from AWS via WireGuard)
5. Click **OK**

### Step 4: Configure Walled Garden

The walled garden allows users to access your external portal **before authentication**.

**Add your external portal domain to walled garden:**

```routeros
/ip hotspot walled-garden add dst-host=isp-frontend-two.vercel.app action=allow comment="External Portal"
/ip hotspot walled-garden add dst-host=*.vercel.app action=allow comment="Vercel CDN"
```

**If your AWS backend has a public domain (e.g., api.yourisp.com):**

```routeros
/ip hotspot walled-garden add dst-host=api.yourisp.com action=allow comment="Backend API"
```

**Important:** Also add IP addresses if DNS might fail:

```routeros
# Get IP of your Vercel app
/tool fetch url=https://isp-frontend-two.vercel.app mode=https
# Add the IP shown in results
/ip hotspot walled-garden ip add dst-address=76.76.21.21/32 action=allow comment="Vercel IP"
```

**Check walled garden:**

```routeros
/ip hotspot walled-garden print
```

### Step 5: Upload Custom login.html

You need to upload your custom `login.html` file to MikroTik's `/hotspot` directory.

**Option A: Via FTP (Easiest)**

1. Enable FTP on MikroTik:
```routeros
/ip service set ftp disabled=no
```

2. Use FileZilla or any FTP client:
   - **Host:** MikroTik IP (e.g., `192.168.88.1`)
   - **Username:** `admin`
   - **Password:** Your MikroTik password
   - **Port:** `21`

3. Navigate to `/hotspot` directory
4. Upload your `login.html` file (see Part 3 for the HTML code)
5. **Disable FTP after upload:**
```routeros
/ip service set ftp disabled=yes
```

**Option B: Via Winbox (Drag & Drop)**

1. Open **Winbox** → **Files**
2. Drag and drop `login.html` into the `/hotspot` folder
3. If `/hotspot` doesn't exist, create it or use the default hotspot directory

**Option C: Via Terminal (Paste HTML)**

```routeros
/file print
# Check if hotspot directory exists
/file set hotspot/login.html contents="<!DOCTYPE html>..."
```

**Verify upload:**

```routeros
/file print where name~"login.html"
```

### Step 6: Configure Hotspot to Use Custom login.html

**Set your hotspot profile to use the custom HTML directory:**

```routeros
/ip hotspot profile set hs_prof html-directory=hotspot
```

**Verify:**

```routeros
/ip hotspot profile print detail where name=hs_prof
```

Should show: `html-directory=hotspot`

### Step 7: Test Hotspot Redirection

1. Connect a device to your WiFi
2. Open browser and go to `http://example.com` or any HTTP site (not HTTPS!)
3. You should be redirected to your external portal with parameters like:
   ```
   https://isp-frontend-two.vercel.app/?mac=AA:BB:CC:DD:EE:FF&ip=192.168.88.100&dst=...
   ```

**Troubleshooting if not redirecting:**
- Make sure you're using HTTP, not HTTPS (HTTPS won't be intercepted)
- Try: `http://detectportal.firefox.com`
- Check hotspot is running: `/ip hotspot print`

---

## Part 2: AWS Backend Configuration

### Step 1: Verify MikroTik API Endpoint

Your FastAPI app already has the MAC registration endpoint. Check it exists:

```bash
# In your AWS server
cd /path/to/isp-billing
grep -n "mac-register" main.py
```

Should show: `POST /api/clients/mac-register/{router_id}` around line 393

### Step 2: Verify WireGuard VPN is Working

Your backend needs to reach MikroTik via WireGuard:

```bash
# On AWS server
ping 10.0.0.2 -c 5
telnet 10.0.0.2 8728
```

If this fails, fix WireGuard first (see WIREGUARD_SETUP.md).

### Step 3: Update .env File

```bash
cd /path/to/isp-billing
nano .env
```

Ensure these values are correct:

```env
# MikroTik Configuration (via WireGuard VPN)
MIKROTIK_HOST=10.0.0.2
MIKROTIK_PORT=8728
MIKROTIK_USERNAME=admin
MIKROTIK_PASSWORD=your_mikrotik_password_here

# Database
DATABASE_URL=sqlite+aiosqlite:///./isp_billing.db

# JWT Authentication
SECRET_KEY=your-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
```

### Step 4: Test Backend API

Start your FastAPI app:

```bash
cd /path/to/isp-billing
source myEnv/bin/activate  # or .\myEnv\Scripts\activate on Windows
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Test the MAC registration endpoint:

```bash
curl -X POST "http://localhost:8000/api/clients/mac-register/1" \
  -H "Content-Type: application/json" \
  -d '{
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "time_limit": "24h",
    "bandwidth_limit": "2M/2M"
  }'
```

**Expected response:**
```json
{
  "success": true,
  "message": "MAC address AA:BB:CC:DD:EE:FF registered successfully",
  "user_details": {
    "username": "AABBCCDDEEFF",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "binding_created": true
  }
}
```

### Step 5: Verify Database Has Router

Your API requires a `router_id`. Check database:

```bash
sqlite3 isp_billing.db "SELECT id, name, ip_address FROM routers;"
```

If empty, create a router:

```bash
curl -X POST "http://localhost:8000/api/routers/create" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Main Router",
    "ip_address": "10.0.0.2",
    "username": "admin",
    "password": "your_password",
    "port": 8728,
    "user_id": 1
  }'
```

---

## Part 3: Custom login.html File

### The Redirect HTML

This file is stored on MikroTik at `/hotspot/login.html`:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Redirecting…</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script>
    (function () {
      var portal = "https://isp-frontend-two.vercel.app/";
      var url = portal
        + "?mac=" + encodeURIComponent("$(mac)")
        + "&ip=" + encodeURIComponent("$(ip)")
        + "&dst=" + encodeURIComponent("$(link-orig-esc)")
        + "&gw=" + encodeURIComponent("$(hostname)")
        + "&router=" + encodeURIComponent("$(identity)");
      window.location.replace(url);
    })();
  </script>
  <noscript>
    <meta http-equiv="refresh" content="0; url=https://isp-frontend-two.vercel.app/?mac=$(mac)&ip=$(ip)&dst=$(link-orig-esc)&gw=$(hostname)&router=$(identity)">
  </noscript>
  <style>
    body{font-family:system-ui,Arial,sans-serif;padding:24px}
    .note{opacity:.65}
  </style>
</head>
<body>
  <h1>Connecting…</h1>
  <p class="note">If you are not redirected automatically, <a href="https://isp-frontend-two.vercel.app/?mac=$(mac)&ip=$(ip)&dst=$(link-orig-esc)&gw=$(hostname)&router=$(identity)">tap here</a>.</p>
</body>
</html>
```

### MikroTik Variables Explained

MikroTik replaces these variables before serving the HTML:

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `$(mac)` | Client's MAC address | `AA:BB:CC:DD:EE:FF` |
| `$(ip)` | Client's IP address | `192.168.88.100` |
| `$(link-orig-esc)` | Original URL user tried to access | `http://example.com` |
| `$(hostname)` | MikroTik hostname | `MikroTik` |
| `$(identity)` | Router identity | `Main-Router` |

Your frontend receives these in the URL and can use them to:
1. Identify the user (via MAC)
2. Know which router they're on
3. Call backend API to authorize them

---

## Part 4: Frontend Integration (Vercel)

Your frontend should:

### Step 1: Extract URL Parameters

```javascript
// In your Vercel frontend
const urlParams = new URLSearchParams(window.location.search);
const mac = urlParams.get('mac');
const ip = urlParams.get('ip');
const routerIdentity = urlParams.get('router');
const originalDest = urlParams.get('dst');
```

### Step 2: Show Payment/Registration Form

Display your custom UI:
- Welcome message
- Available plans (fetch from `/api/plans`)
- Payment options (M-Pesa STK Push)
- Terms and conditions

### Step 3: Call Backend API After Payment

Once user pays successfully via M-Pesa callback:

```javascript
// Your frontend calls this endpoint
POST https://your-aws-backend.com/api/clients/mac-register/1
Content-Type: application/json

{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "time_limit": "24h",
  "bandwidth_limit": "2M/2M"
}
```

Backend automatically:
1. Creates hotspot user on MikroTik
2. Adds IP binding (bypassed mode)
3. Sets bandwidth limits
4. User gets internet access immediately

### Step 4: Redirect User Back

After successful registration:

```javascript
// Redirect user to their originally requested URL or success page
if (originalDest) {
  window.location.href = originalDest;
} else {
  window.location.href = 'http://google.com'; // Or success page
}
```

---

## Part 5: Complete Flow Example

### User Journey

1. **User connects to WiFi** → Gets IP from DHCP
2. **User opens browser** → Types `http://google.com`
3. **MikroTik intercepts** → Serves `/hotspot/login.html`
4. **login.html redirects** → To your Vercel portal with MAC, IP, etc.
5. **User sees portal** → Branded login/payment page
6. **User selects plan** → e.g., "24 Hours - $2"
7. **User enters phone** → `254712345678`
8. **Frontend calls backend** → `POST /api/hotspot/register-and-pay`
9. **Backend initiates STK** → User gets M-Pesa prompt on phone
10. **User enters PIN** → Payment confirmed
11. **M-Pesa callback** → Hits `/api/mpesa/callback`
12. **Backend provisions user** → Calls MikroTik API to authorize MAC
13. **MikroTik updates** → User's MAC added to bypass list
14. **User gets internet** → Redirected to original destination
15. **Session expires** → After 24 hours, user must pay again

### API Flow (Backend to MikroTik)

When payment is confirmed, your backend runs:

```python
# From main.py - call_mikrotik_bypass function
api = MikroTikAPI(
    settings.MIKROTIK_HOST,  # 10.0.0.2 via WireGuard
    settings.MIKROTIK_USERNAME,
    settings.MIKROTIK_PASSWORD,
    settings.MIKROTIK_PORT
)

api.connect()
result = api.add_customer_bypass_mode(
    mac_address="AA:BB:CC:DD:EE:FF",
    username="AABBCCDDEEFF",
    password="AABBCCDDEEFF",
    time_limit="24h",
    bandwidth_limit="2M/2M",
    comment="Payment confirmed - $2 for 24h",
    router_ip="10.0.0.2",
    router_username="admin",
    router_password="your_password"
)
api.disconnect()
```

This automatically:
1. Adds user to `/ip/hotspot/user`
2. Creates IP binding: `/ip/hotspot/ip-binding` (type=bypassed)
3. Assigns IP via DHCP: `/ip/dhcp-server/lease`
4. Sets bandwidth limit: `/queue/simple/add`

---

## Part 6: Testing End-to-End

### Test 1: Hotspot Redirect

1. Connect device to WiFi
2. Open browser → `http://detectportal.firefox.com`
3. **Expected:** Redirected to your Vercel portal with parameters

### Test 2: Walled Garden Access

Before authentication:
- `https://isp-frontend-two.vercel.app` → Should load
- `https://google.com` → Should NOT load (blocked by hotspot)

### Test 3: Backend API

```bash
curl -X POST "http://your-aws-ip:8000/api/clients/mac-register/1" \
  -H "Content-Type: application/json" \
  -d '{
    "mac_address": "AA:BB:CC:DD:EE:01",
    "time_limit": "1h",
    "bandwidth_limit": "1M/1M"
  }'
```

### Test 4: Check MikroTik

After API call, verify on MikroTik:

```routeros
# Check hotspot user was created
/ip hotspot user print

# Check IP binding
/ip hotspot ip-binding print where type=bypassed

# Check bandwidth queue
/queue simple print
```

### Test 5: Internet Access

After successful registration:
1. Open `https://google.com` → Should work
2. Check speed → Should match bandwidth limit
3. Wait until time expires → Internet should stop

### Test 6: Check Active Sessions

```routeros
/ip hotspot active print
```

Should show your MAC with session details.

---

## Part 7: Troubleshooting

### Problem: Hotspot Not Redirecting

**Symptoms:** Browser doesn't show captive portal, goes to HTTPS error

**Solutions:**
1. Try HTTP sites: `http://example.com`, `http://detectportal.firefox.com`
2. Disable HTTPS-Only mode in browser
3. Check hotspot is running:
```routeros
/ip hotspot print
# Should show proxy-status="running"
```

4. Restart hotspot:
```routeros
/ip hotspot disable hotspot1
/ip hotspot enable hotspot1
```

### Problem: Redirect Works but Portal Doesn't Load

**Symptoms:** Browser shows "Cannot connect to portal"

**Solutions:**
1. Check walled garden allows your domain:
```routeros
/ip hotspot walled-garden print
```

2. Add your portal to walled garden (see Part 1, Step 4)

3. Test DNS resolution:
```routeros
/tool fetch url=https://isp-frontend-two.vercel.app mode=https
```

### Problem: Backend Can't Connect to MikroTik

**Symptoms:** API returns "Failed to connect to router"

**Solutions:**
1. Check WireGuard VPN is up:
```bash
# On AWS
sudo systemctl status wg-quick@wg0
ping 10.0.0.2
```

2. Check MikroTik API is enabled:
```routeros
/ip service print where name=api
# Should show disabled=no
```

3. Test API port:
```bash
telnet 10.0.0.2 8728
```

4. Check firewall rules allow API:
```routeros
/ip firewall filter print where dst-port=8728
```

### Problem: User Registered but No Internet

**Symptoms:** MAC shows in hotspot users, but still no access

**Check 1: IP Binding**
```routeros
/ip hotspot ip-binding print where mac-address="AA:BB:CC:DD:EE:FF"
```

Must show `type=bypassed` and status `P` (Bypassed flag)

**Check 2: Active Session**
```routeros
/ip hotspot active print
```

If no session, manually trigger login by browsing to HTTP site

**Check 3: Remove and Re-add**
```routeros
/ip hotspot ip-binding remove [find mac-address="AA:BB:CC:DD:EE:FF"]
/ip hotspot user remove [find name="AABBCCDDEEFF"]
```

Then register again via API.

### Problem: Users Get Kicked Out Randomly

**Symptoms:** User has internet, then loses it after few minutes

**Solutions:**
1. Check idle-timeout:
```routeros
/ip hotspot print detail
# Set idle-timeout to longer or none
/ip hotspot set hotspot1 idle-timeout=none
```

2. Check keepalive:
```routeros
/ip hotspot set hotspot1 keepalive-timeout=2m
```

3. Check time limit hasn't expired:
```routeros
/ip hotspot user print detail where name="AABBCCDDEEFF"
# Check limit-uptime and uptime
```

### Problem: Bandwidth Limit Not Working

**Symptoms:** User gets full speed despite bandwidth_limit set

**Solutions:**
1. Check queue was created:
```routeros
/queue simple print where name~"queue_"
```

2. Check queue is enabled:
```routeros
/queue simple print detail
# Should show disabled=no
```

3. Manually test queue:
```routeros
/queue simple add name=test target=192.168.88.100/32 max-limit=1M/1M
```

4. Check IP is correct:
```routeros
/ip hotspot active print
# Note the IP, make sure queue targets that IP
```

### Problem: Multiple Devices, Same MAC

**Symptoms:** User gets internet on phone but not laptop

**Solution:** Increase addresses-per-mac:
```routeros
/ip hotspot set hotspot1 addresses-per-mac=3
```

### Problem: M-Pesa Callback Not Received

**Symptoms:** User pays, but no provisioning happens

**Check 1: Callback URL**
Ensure your M-Pesa callback URL is publicly accessible:
```bash
curl -X POST "https://your-aws-public-ip/api/mpesa/callback" \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

**Check 2: Database Transaction**
```bash
sqlite3 isp_billing.db "SELECT * FROM mpesa_transactions ORDER BY id DESC LIMIT 5;"
```

**Check 3: Logs**
```bash
# On AWS
tail -f /path/to/app/logs/app.log
# Or check journalctl if running as service
```

---

## Part 8: Advanced Configuration

### Auto-cleanup Expired Users

Create scheduled task to remove expired users:

```routeros
/system scheduler add name=cleanup-expired-users interval=1h on-event={
  :foreach i in=[/ip/hotspot/user find limit-uptime!=""] do={
    :local uptime [/ip/hotspot/user get $i uptime]
    :local limit [/ip/hotspot/user get $i limit-uptime]
    :if ($uptime >= $limit) do={
      :log info ("Removing expired user: " . [/ip/hotspot/user get $i name])
      /ip/hotspot/user remove $i
    }
  }
}
```

### HTTPS Redirect (Optional)

By default, hotspot only redirects HTTP. To handle HTTPS:

1. Install SSL certificate on MikroTik
2. Enable HTTPS in hotspot profile:
```routeros
/ip hotspot profile set hs_prof login-by=https,http-pap
```

Note: This shows browser warning since certificate won't match all domains.

### Multiple Routers

If you have multiple MikroTik routers:

1. Create separate router entries in database:
```bash
curl -X POST "http://localhost:8000/api/routers/create" \
  -d '{"name": "Router 2", "ip_address": "10.0.0.3", ...}'
```

2. Update `login.html` to detect router_id dynamically:
```html
<script>
var routerIdentity = "$(identity)";
var routerId = 1; // Default
if (routerIdentity === "Router2") routerId = 2;
// Pass routerId to frontend
</script>
```

3. Frontend passes correct router_id to backend API

### Rate Limiting (Prevent Abuse)

Add firewall rules to prevent rapid reconnections:

```routeros
/ip firewall filter add chain=input protocol=tcp dst-port=8728 \
  connection-limit=3,32 action=drop comment="API rate limit"
```

---

## Part 9: Production Checklist

- [ ] WireGuard VPN is stable and auto-reconnects
- [ ] MikroTik API is only accessible from AWS (not public)
- [ ] Hotspot walled garden includes all required domains
- [ ] Backend `.env` has correct MIKROTIK_HOST=10.0.0.2
- [ ] SSL certificate installed on AWS for HTTPS API
- [ ] M-Pesa callback URL is whitelisted in Safaricom portal
- [ ] Database backups are automated
- [ ] Router credentials are strong and rotated
- [ ] Logs are monitored for errors
- [ ] Test payment flow end-to-end
- [ ] Test user expiry after time limit
- [ ] Test bandwidth limits are enforced
- [ ] Document emergency rollback procedure

---

## Quick Reference

### MikroTik Commands

```routeros
# Check hotspot status
/ip hotspot print detail

# List all hotspot users
/ip hotspot user print

# List IP bindings (bypassed users)
/ip hotspot ip-binding print where type=bypassed

# List active sessions
/ip hotspot active print

# Remove expired user
/ip hotspot user remove [find name="AABBCCDDEEFF"]

# Check walled garden
/ip hotspot walled-garden print

# Restart hotspot
/ip hotspot disable hotspot1
/ip hotspot enable hotspot1
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/clients/mac-register/{router_id}` | POST | Register MAC (no auth) |
| `/api/hotspot/register-and-pay` | POST | Register + initiate M-Pesa |
| `/api/mpesa/callback` | POST | M-Pesa callback |
| `/api/public/mac-status/{router_id}/{mac}` | GET | Check if MAC is registered |
| `/api/public/disconnect/{router_id}/{mac}` | POST | Disconnect user |
| `/api/public/remove-bypassed/{router_id}/{mac}` | DELETE | Remove bypassed user |

### Important IPs

- **MikroTik Local IP:** `192.168.88.1`
- **MikroTik VPN IP:** `10.0.0.2` (via WireGuard)
- **AWS VPN IP:** `10.0.0.1`
- **Guest DHCP Range:** `192.168.88.10-192.168.88.254`

### Logs

**AWS Backend:**
```bash
journalctl -u your-app-service -f
```

**MikroTik:**
```routeros
/log print where topics~"hotspot"
```

---

## Summary

You now have a fully functional external captive portal with:
- ✅ MikroTik hotspot intercepting guest traffic
- ✅ Custom branded login page on Vercel
- ✅ AWS backend handling payments and provisioning
- ✅ M-Pesa integration for automated payments
- ✅ Secure WireGuard VPN for API communication
- ✅ Automatic user provisioning and expiry

**Next Steps:**
1. Test with real users
2. Monitor logs and performance
3. Adjust bandwidth limits based on usage
4. Add more routers as you scale
5. Implement reporting dashboard

For advanced features like user portals, analytics, and bulk operations, see the main ISP Billing documentation.

---

**Need Help?**
- Check logs: Backend (journalctl), MikroTik (/log print)
- Test connectivity: WireGuard ping, API telnet
- Verify walled garden: Add more domains if portal doesn't load
- Check database: Ensure router_id and plans exist

Good luck! 🚀

