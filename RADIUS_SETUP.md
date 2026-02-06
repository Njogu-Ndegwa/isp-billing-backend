# RADIUS Server Setup Guide for ISP Billing

This guide explains how to set up and use RADIUS authentication for your MikroTik hotspot routers. RADIUS allows the router to handle session expiry and bandwidth limits natively, eliminating the need for polling-based expiry management.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Detailed Setup](#detailed-setup)
5. [MikroTik Router Configuration](#mikrotik-router-configuration)
6. [Testing](#testing)
7. [Migration Guide](#migration-guide)
8. [Troubleshooting](#troubleshooting)

---

## Overview

### How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Customer      │────▶│  MikroTik       │────▶│  FreeRADIUS     │
│   Device        │     │  Router         │     │  Server         │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │                        │
                               │                        ▼
                               │                ┌─────────────────┐
                               │                │  PostgreSQL     │
                               │                │  Database       │
                               └───────────────▶└─────────────────┘
                                    (Accounting)
```

1. Customer connects to hotspot captive portal
2. Customer pays via M-Pesa (or cash)
3. ISP Billing creates RADIUS user with expiry and bandwidth
4. MikroTik authenticates user via RADIUS
5. RADIUS returns session timeout and rate limit
6. MikroTik enforces limits - user auto-expires without polling!

### Benefits Over Direct API

| Feature | Direct API | RADIUS |
|---------|-----------|--------|
| Expiry accuracy | ~67 second polling | To-the-second (handled by router) |
| Bandwidth enforcement | Multiple layers, sync needed | Native MikroTik enforcement |
| Server dependency | Must be reachable for expiry | Router continues independently |
| Multi-vendor | MikroTik only | Any RADIUS-compatible device |
| Accounting | Manual tracking | Automatic session accounting |

---

## Prerequisites

1. **ISP Billing server** running with Docker
2. **PostgreSQL database** with RADIUS tables (migration provided)
3. **MikroTik router** with hotspot configured
4. **Network connectivity** between router and server (ports 1812, 1813 UDP)

---

## Quick Start

### 1. Run Database Migrations

```bash
# From the isp-billing directory
python migrations/add_router_auth_method.py
python migrations/create_radius_tables.py
```

### 2. Start FreeRADIUS Container

```bash
# Start with RADIUS server
docker-compose -f docker-compose.yml -f docker-compose.radius.yml up -d
```

### 3. Enable RADIUS for a Router (via API)

```bash
curl -X POST "http://your-server:8000/api/radius/routers/1/enable" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"radius_secret": "your_shared_secret_here"}'
```

### 4. Configure MikroTik Router

```routeros
# Add RADIUS server
/radius add address=YOUR_SERVER_IP secret=your_shared_secret_here service=hotspot

# Enable RADIUS for hotspot
/ip hotspot profile set default use-radius=yes

# Enable RADIUS incoming (for CoA disconnects)
/radius incoming set accept=yes port=3799
```

### 5. Test the Setup

```bash
curl "http://your-server:8000/api/radius/test/1" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Detailed Setup

### Step 1: Database Migrations

The system requires two migrations:

```bash
# Add auth_method column to routers table
python migrations/add_router_auth_method.py

# Create RADIUS tables
python migrations/create_radius_tables.py
```

**Tables created:**
- `radius_check` - User authentication (password, simultaneous-use)
- `radius_reply` - Reply attributes (bandwidth, session timeout)
- `radius_accounting` - Session accounting (bytes, time, etc.)
- `radius_postauth` - Authentication logging
- `radius_nas` - NAS client management

### Step 2: Configure RADIUS Clients

Edit `radius/clients.conf` to add your MikroTik routers:

```
client router_office {
    ipaddr = 10.0.0.1
    secret = your_shared_secret_123
    shortname = office_router
    nas_type = mikrotik
}

client router_branch {
    ipaddr = 10.0.1.1
    secret = another_secret_456
    shortname = branch_router
    nas_type = mikrotik
}
```

**Important:** The `secret` must match what you configure on the MikroTik router.

### Step 3: Start the RADIUS Server

```bash
# Start all services including RADIUS
docker-compose -f docker-compose.yml -f docker-compose.radius.yml up -d

# Check RADIUS logs
docker logs isp_billing_radius -f

# Verify RADIUS is listening
docker exec isp_billing_radius netstat -tulpn | grep 1812
```

### Step 4: Include RADIUS Endpoints in Your App

Add to your `main.py` (near other router inclusions):

```python
from app.api.radius_endpoints import router as radius_router

# Add with other app.include_router() calls
app.include_router(radius_router)
```

---

## MikroTik Router Configuration

### Basic RADIUS Setup

Connect to your MikroTik via WinBox or terminal:

```routeros
# 1. Add RADIUS server
/radius add \
    address=YOUR_ISP_BILLING_SERVER_IP \
    secret=your_shared_secret \
    service=hotspot \
    timeout=3000ms \
    accounting-backup=yes

# 2. Configure hotspot profile to use RADIUS
/ip hotspot profile set [find name=default] \
    use-radius=yes \
    radius-default-domain="" \
    radius-accounting=yes \
    radius-interim-update=5m

# 3. Enable RADIUS incoming for CoA (Change of Authorization)
# This allows the server to disconnect users remotely
/radius incoming set accept=yes port=3799
```

### Advanced Configuration

```routeros
# Optional: Separate accounting server
/radius add \
    address=YOUR_SERVER_IP \
    secret=your_secret \
    service=hotspot \
    accounting-port=1813

# Set NAS identifier (should match what you configure in ISP Billing)
/system identity set name=MyHotspotRouter

# Configure hotspot server
/ip hotspot set [find] \
    radius-interim-update=5m \
    accounting=yes
```

### Verify Configuration

```routeros
# Check RADIUS status
/radius print

# Check hotspot profile
/ip hotspot profile print

# Monitor RADIUS authentication (real-time)
/log print where topics~"radius"
```

---

## Testing

### 1. Test from Server

```bash
# Test RADIUS authentication manually (requires radclient)
echo "User-Name=AABBCCDDEEFF,User-Password=testpass" | \
    radclient -x YOUR_SERVER_IP:1812 auth your_secret
```

### 2. Test via API

```bash
# Check router RADIUS status
curl "http://your-server:8000/api/radius/routers/1/status" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Run connectivity test
curl "http://your-server:8000/api/radius/test/1" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Create a test user
curl -X POST "http://your-server:8000/api/radius/users" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "TESTUSER123",
    "password": "testpass",
    "rate_limit": "2M/2M",
    "expiry_hours": 1
  }'
```

### 3. Test from MikroTik

```routeros
# This will show if RADIUS is responding
/radius monitor 0
```

---

## Migration Guide

### Migrating a Single Router

1. **Prepare the router:**
   - Don't remove existing hotspot users yet
   - They'll continue to work with IP bindings

2. **Enable RADIUS in ISP Billing:**
   ```bash
   curl -X POST "http://your-server:8000/api/radius/routers/1/enable" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{"radius_secret": "your_secret"}'
   ```

3. **Configure MikroTik:**
   ```routeros
   /radius add address=SERVER_IP secret=your_secret service=hotspot
   /ip hotspot profile set default use-radius=yes
   ```

4. **Test with a new customer:**
   - Register a new customer
   - Verify they authenticate via RADIUS
   - Check accounting data appears

5. **Gradual transition:**
   - Existing customers continue with IP bindings until they expire
   - New customers use RADIUS
   - Eventually all users are RADIUS-authenticated

### Rollback Procedure

If something goes wrong:

1. **Disable RADIUS on MikroTik:**
   ```routeros
   /ip hotspot profile set default use-radius=no
   ```

2. **Disable RADIUS in ISP Billing:**
   ```bash
   curl -X POST "http://your-server:8000/api/radius/routers/1/disable" \
     -H "Authorization: Bearer YOUR_TOKEN"
   ```

3. **System returns to direct API provisioning**

---

## Troubleshooting

### RADIUS Not Responding

```bash
# Check if FreeRADIUS is running
docker ps | grep radius

# Check RADIUS logs
docker logs isp_billing_radius

# Test port connectivity
nc -uvz YOUR_SERVER_IP 1812
```

### Authentication Rejected

```bash
# Check RADIUS logs for rejection reason
docker logs isp_billing_radius | grep -i reject

# Verify user exists in database
psql -d isp_billing_db -c "SELECT * FROM radius_check WHERE username='AABBCCDDEEFF'"

# Check shared secret matches
# On MikroTik:
/radius print detail

# In clients.conf - secret must match exactly
```

### User Not Disconnecting

```bash
# Check if CoA is enabled on MikroTik
/radius incoming print

# Test manual disconnect
curl -X POST "http://your-server:8000/api/radius/sessions/USERNAME/disconnect?router_id=1" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Bandwidth Not Applied

Check the RADIUS reply attributes:

```sql
SELECT * FROM radius_reply WHERE username = 'AABBCCDDEEFF';
```

Should show `Mikrotik-Rate-Limit` attribute with value like `5M/5M`.

On MikroTik, verify the hotspot user has the rate limit:
```routeros
/ip hotspot user print detail where name=AABBCCDDEEFF
```

---

## API Reference

### Router Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/radius/routers/{id}/enable` | POST | Enable RADIUS for router |
| `/api/radius/routers/{id}/disable` | POST | Disable RADIUS for router |
| `/api/radius/routers/{id}/status` | GET | Get RADIUS status |
| `/api/radius/routers` | GET | List all routers with status |

### User Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/radius/users` | POST | Create RADIUS user |
| `/api/radius/users/{username}` | GET | Get user info |
| `/api/radius/users/{username}` | DELETE | Delete user |

### Session Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/radius/sessions` | GET | List active sessions |
| `/api/radius/sessions/{username}/disconnect` | POST | Disconnect user |
| `/api/radius/accounting/{username}` | GET | Get accounting stats |

### Maintenance

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/radius/cleanup` | POST | Remove expired users |
| `/api/radius/test/{router_id}` | GET | Test connectivity |

---

## Support

If you encounter issues:

1. Check the logs: `docker logs isp_billing_radius`
2. Verify network connectivity between router and server
3. Confirm shared secrets match exactly
4. Test with a simple user first before complex configurations
