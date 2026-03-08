# MikroTik Router Setup Guide

## For Bitwave ISP Billing System

> **Tested on:** RouterOS 7.18.2
> **Last updated:** March 2026

---

## Prerequisites

Before starting, ensure you have:
- Physical access to the MikroTik router (required for device-mode changes)
- WinBox installed on your PC
- Access to an existing MikroTik router with hotspot files (or downloaded from mikrotik.com)
- FileZilla installed for file transfers
- AWS WireGuard server already configured (see `WIREGUARD_SETUP.md`)

---

## STEP 0: DEVICE MODE (RouterOS v7 — CRITICAL)

RouterOS v7 ships with `device-mode=home` which **blocks hotspot functionality**.
You must enable hotspot in device-mode **before** running the hotspot wizard.
This requires physical access to the router (button press).

### 0.1 Check Current Device Mode

```routeros
/system/device-mode/print
```

If `hotspot: no`, it must be changed.

### 0.2 Enable Hotspot in Device Mode

```routeros
/system/device-mode/update hotspot=yes
```

The router will prompt you to **press the physical reset button** within ~60 seconds.

> **WARNING:** Quickly tap and release the reset button. Do NOT hold it down — a long press will factory reset the router.

### 0.3 Verify

```routeros
/system/device-mode/print
```


Confirm `hotspot: yes` before proceeding.

> **Why this matters:** Without this step, the hotspot setup wizard will appear to succeed
> but the hotspot will show `I` (INVALID) with the comment "inactivated, not allowed by device-mode"
> and no client redirection will occur.

---

## STEP 1: INITIAL SETUP (After Factory Reset)

### 1.1 Disable CAPsMAN (if enabled by default)

```routeros
/interface wireless cap set enabled=no
```

### 1.2 Remove ether1 from the bridge

ether1 is the WAN/uplink port — it must NOT be in the hotspot bridge.
If ether1 is in the bridge, the hotspot will block ALL internet traffic.

```routeros
/interface bridge port remove [find where interface=ether1]
```

### 1.3 Set up ether1 as WAN port with DHCP client

```routeros
/ip dhcp-client add interface=ether1 disabled=no comment="WAN uplink"
```

### 1.4 Add masquerade NAT

```routeros
/ip firewall nat add chain=srcnat out-interface=ether1 action=masquerade comment="NAT for internet access"
```

### 1.5 Enable DNS

```routeros
/ip dns set servers=8.8.8.8,8.8.4.4 allow-remote-requests=yes
```

### 1.6 Verify internet connectivity

```routeros
/ping 8.8.8.8 count=3
```

Must get replies before proceeding.

---

## STEP 2: WIRELESS SETUP

### 2.1 Configure wireless interface

```routeros
/interface wireless security-profiles set default mode=none
/interface wireless set wlan1 mode=ap-bridge ssid=Skypnet security-profile=default disabled=no
```

### 2.2 Add wlan1 to the LAN bridge

```routeros
/interface bridge port add interface=wlan1 bridge=bridge
```

> If you get "already added as bridge port" — that's fine, skip it.

### 2.3 Assign a static IP to the bridge

```routeros
/ip address add address=192.168.88.1/24 interface=bridge
```

> If you get "already have such address" — the default config already has it.

### 2.4 Create DHCP pool and server

Check if DHCP is already running first:

```routeros
/ip dhcp-server print
```

If no DHCP server exists on the bridge, create one:

```routeros
/ip pool add name=dhcp-pool ranges=192.168.88.10-192.168.88.254
/ip dhcp-server add name=dhcp1 interface=bridge address-pool=dhcp-pool disabled=no
/ip dhcp-server network add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=8.8.8.8,8.8.4.4
```

> If these return "already exists" errors, the default config handles it. No action needed.

### 2.5 Verify wireless is broadcasting

```routeros
/interface wireless monitor wlan1 once
```

Should show `status: running-ap`. Connect a phone to "Skypnet" WiFi and confirm it gets a `192.168.88.x` IP.

---

## STEP 3: WIREGUARD SETUP

### On MikroTik

```routeros
/interface wireguard add name=wg-aws listen-port=51820
/interface wireguard print
```

Note down the `public-key` from the output.

```routeros
/ip address add address=10.0.0.X/24 interface=wg-aws
```

Replace `X` with the next available IP. Check the AWS server first to see what's taken:

### On AWS Server

```bash
sudo wg show wg0
```

Register the new router peer (use the public-key from the MikroTik output above):

```bash
sudo wg set wg0 peer <MIKROTIK_PUBLIC_KEY> allowed-ips 10.0.0.X/32
```

Confirm it was registered:

```bash
sudo wg show wg0
```

### Back on MikroTik

```routeros
/interface wireguard peers add interface=wg-aws public-key="<AWS_SERVER_PUBLIC_KEY>" endpoint-address=54.91.202.229 endpoint-port=51820 allowed-address=10.0.0.0/24 persistent-keepalive=25
```

Add firewall rule:

```routeros
/ip firewall filter add chain=input protocol=udp dst-port=51820 action=accept comment="Allow WireGuard"
```

Test the tunnel:

```routeros
/ping 10.0.0.1 count=3
```

Must get replies before proceeding.

---

## STEP 4: HOTSPOT FILE PREPARATION

> **RouterOS v7 Change:** The hotspot setup wizard no longer auto-generates the default
> HTML files (`login.html`, `alogin.html`, `status.html`, etc.) on disk. They are embedded
> in the firmware. You must upload them manually if you need custom pages.

### Option A: Copy from another MikroTik (v6 or v7 with existing files)

If you have another router that already has the hotspot files:

1. Open **FileZilla** and connect to the source router:
   - Host: source router IP
   - Username: `admin`
   - Password: router password
   - Port: `21` (FTP) or `22` (SFTP)
2. Download the entire `hotspot` folder to your PC
3. Disconnect, then connect to the **new router**
4. Upload the `hotspot` folder

### Option B: Download from mikrotik.com

Go to https://www.mikrotik.com/download and get the default hotspot pages for your RouterOS version.

### Option C: Let the wizard generate defaults (may work on some models)

Proceed to Step 5 — on some devices the firmware-embedded defaults are sufficient.

### FileZilla Connection Troubleshooting

If FileZilla shows `ECONNREFUSED`:

1. **The hotspot is probably blocking IP access.** The hotspot intercepts all client traffic before authentication. WinBox via MAC address works because it bypasses IP.

2. **Fix: Temporarily disable the hotspot** (via WinBox MAC connection):
   ```routeros
   /ip hotspot disable [find]
   ```

3. **Or bypass your PC:**
   ```routeros
   /ip hotspot ip-binding add type=bypassed address=<YOUR_PC_IP>
   ```

4. **Or set a static IP on your PC** if DHCP isn't working:
   - IP: `192.168.88.10`
   - Subnet: `255.255.255.0`
   - Gateway: `192.168.88.1`

5. After uploading files, re-enable the hotspot:
   ```routeros
   /ip hotspot enable [find]
   ```

---

## STEP 5: HOTSPOT SETUP

### 5.1 Run the hotspot setup wizard

```routeros
/ip hotspot setup
```

Wizard answers:
- **Interface:** `bridge` (your LAN bridge — must NOT contain ether1)
- **Local Address:** `192.168.88.1/24`
- **Address Pool:** `192.168.88.10-192.168.88.254`
- **SSL Certificate:** `none`
- **SMTP Server:** `0.0.0.0`
- **DNS Servers:** `8.8.8.8,8.8.4.4`
- **DNS Name:** (leave empty)
- **Username:** `admin` (will delete later)

### 5.2 Verify ether1 is NOT in the bridge

```routeros
/interface bridge port print
```

If ether1 appears, remove it immediately:

```routeros
/interface bridge port remove [find where interface=ether1]
```

### 5.3 Verify hotspot is valid and running

```routeros
/ip hotspot print
```

**Expected:** No `I` (INVALID) or `X` (DISABLED) flags.

If you see `"inactivated, not allowed by device-mode"`, go back to **Step 0** — you missed the device-mode change.

### 5.4 Verify internet still works

```routeros
/ping 8.8.8.8 count=3
```

### 5.5 Delete the temp admin hotspot user

```routeros
/ip hotspot user remove [find where name=admin]
```

---

## STEP 6: UPLOAD CUSTOM LOGIN PAGE

Upload `login.html` to the `hotspot` folder on the router. This file redirects users to the external captive portal.

### Via FileZilla

1. Connect to the router (see Step 4 for troubleshooting)
2. Navigate to the `hotspot` folder on the router side
3. Upload your custom `login.html` (overwrites the default)

### Via WinBox

1. Open WinBox → Files
2. Open the `hotspot` folder
3. Drag and drop `login.html` from your PC

### Verify

```routeros
/file print where name~"login.html"
```

> The `login.html` must contain the JavaScript redirect to the external portal. See `CAPTIVE_PORTAL_SETUP.md` Part 3 for the HTML code.

---

## STEP 7: WALLED GARDEN & API ACCESS

### 7.1 Allow external portal and backend

```routeros
/ip hotspot walled-garden add dst-host=isp-frontend-two.vercel.app action=allow comment="External Portal"
/ip hotspot walled-garden add dst-host=*.vercel.app action=allow comment="Vercel CDN"
/ip hotspot walled-garden add dst-host=isp.bitwavetechnologies.com action=allow comment="Backend API"
```

### 7.2 Allow backend API IP

```routeros
/ip hotspot walled-garden ip add dst-address=54.91.202.229/32 action=accept comment="Backend API"
```

### 7.3 Enable MikroTik API (only accessible from AWS via WireGuard)

```routeros
/ip service set api address=10.0.0.1/32 port=8728 disabled=no
```

### 7.4 Allow API in firewall

```routeros
/ip firewall filter add chain=input protocol=tcp dst-port=8728 src-address=10.0.0.1 action=accept comment="Allow API from AWS" place-before=0
```

---

## STEP 8: SET ROUTER IDENTITY & REGISTER

### 8.1 Set identity

```routeros
/system identity set name=Router-XXXX
```

Replace `XXXX` with the router number (e.g., `Router-0003`).

### 8.2 Reboot

```routeros
/system reboot
```

### 8.3 Register in the database

Register the router via the admin panel or API (see `CAPTIVE_PORTAL_SETUP.md` Part 2).

---

## DIAGNOSTICS: Quick Health Check

Run this block to get a full status snapshot:

```routeros
/system/device-mode/print
/ip hotspot print
/ip hotspot profile print
/interface wireless print where name=wlan1
/interface bridge port print
/ip address print
/ip dhcp-server print
/ip dhcp-server lease print
/ip firewall filter print where chain=input
/interface wireguard peers print detail
/file print where name~"hotspot"
```

### What to look for

| Check | Expected | Problem if wrong |
|-------|----------|-----------------|
| `device-mode` → `hotspot` | `yes` | Hotspot blocked entirely |
| `hotspot print` → flags | No `I` or `X` | Hotspot not running |
| `wireless monitor` → status | `running-ap` | WiFi not broadcasting |
| `bridge port` → ether1 | **Not listed** | Hotspot blocks WAN |
| `bridge port` → wlan1 | Listed, no `I` flag | WiFi not bridged |
| `wireguard peers` → last-handshake | Recent timestamp | VPN tunnel down |
| `file print` → hotspot/ | Files exist | No login page to serve |

---

## TROUBLESHOOTING

### Hotspot shows "inactivated, not allowed by device-mode"

**Cause:** RouterOS v7 `device-mode=home` blocks hotspot.

**Fix:**
```routeros
/system/device-mode/update hotspot=yes
```
Press the physical reset button on the router within 60 seconds (quick tap, don't hold).

### Hotspot files not generated after setup wizard

**Cause:** RouterOS v7 no longer writes default hotspot HTML files to disk. They're served from firmware.

**Fix:** Upload hotspot files manually from another router or from mikrotik.com (see Step 4).

### WinBox works via MAC but not via IP

**Cause:** The hotspot is intercepting all traffic on the bridge. Unauthenticated clients can't access anything via IP, including FTP/SSH/WinBox-IP.

**Fix:** Connect via WinBox MAC mode and either:
- Temporarily disable the hotspot: `/ip hotspot disable [find]`
- Or bypass your PC: `/ip hotspot ip-binding add type=bypassed address=<YOUR_PC_IP>`

### FileZilla ECONNREFUSED

**Cause:** Same as above — hotspot blocking IP-based connections.

**Fix:** Disable hotspot or bypass your IP first, then reconnect FileZilla.

### Internet stops working after hotspot setup

**Cause:** The wizard may have added ether1 (WAN) back into the bridge.

**Fix:**
```routeros
/interface bridge port print
/interface bridge port remove [find where interface=ether1]
```

### WiFi wlan1 shows INACTIVE in bridge port

**Fix:** Toggle the wireless interface:
```routeros
/interface wireless disable wlan1
/interface wireless enable wlan1
```

Then verify:
```routeros
/interface wireless monitor wlan1 once
```

### Clients connect to WiFi but don't get redirected

**Check in order:**
1. Device mode: `/system/device-mode/print` → `hotspot: yes`?
2. Hotspot running: `/ip hotspot print` → no `I` or `X` flags?
3. Login page exists: `/file print where name~"login.html"`?
4. Try an HTTP URL (not HTTPS): `http://detectportal.firefox.com`

### Duplicate DHCP pools after running setup commands

If you see duplicate pools (e.g., `default-dhcp` and `dhcp-pool` with the same ranges):

```routeros
/ip pool print
/ip pool remove dhcp-pool
```

Only keep the pool that the DHCP server is actually using.
