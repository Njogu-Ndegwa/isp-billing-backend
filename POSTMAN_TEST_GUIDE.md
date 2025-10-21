# 🧪 ISP Billing System - Guest Hotspot User Testing Guide

## 📋 Overview

This guide focuses **exclusively on guest hotspot users** - customers who pay for temporary internet access (e.g., 1 hour, 24 hours, 7 days).

### Guest Hotspot User Flow:
1. Customer connects to WiFi and gets captive portal
2. Customer selects a plan and pays via M-Pesa
3. System provisions them on MikroTik with time limit
4. When time expires, access is automatically cut off

---

## 🔧 Test Environment Setup

### Prerequisites
- ✅ Server running on `http://localhost:8000`
- ✅ SQLite database (auto-created)
- ✅ MikroTik router accessible with hotspot configured
- ✅ Postman installed

### Base URL
```
http://localhost:8000
```

---

## 🚀 Quick Start (5 Steps to Test Guest Hotspot)

1. **Setup Router** → Add your MikroTik router
2. **Create Plans** → Define time-based plans (1h, 24h, 7d)
3. **Test Registration** → Register guest with MAC address
4. **Test Payment** → Simulate payment callback
5. **Verify Access** → Check MikroTik provisioning

---

## ✅ **STEP 1: Setup Router**

### 1.1: Create Router

#### Purpose
Add your MikroTik router to the system

#### Request
```
Method: POST
URL: http://localhost:8000/api/routers/create
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "name": "Guest Hotspot Router",
    "ip_address": "192.168.88.1",
    "username": "admin",
    "password": "password",
    "port": 8728
}
```

**⚠️ Important:** Update with your actual MikroTik credentials!

#### Expected Response
```json
{
    "id": 1,
    "name": "Guest Hotspot Router",
    "ip_address": "192.168.88.1",
    "username": "admin",
    "port": 8728,
    "user_id": 1,
    "created_at": "2025-10-20T10:30:00.000000"
}
```

#### Status Code
`200 OK`

---

## ✅ **STEP 2: Create Hotspot Plans**

### 2.1: Create 1 Hour Plan

#### Purpose
Create a short-duration guest plan

#### Request
```
Method: POST
URL: http://localhost:8000/api/plans/create
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "name": "1 Hour Plan",
    "speed": "1M/2M",
    "price": 50,
    "duration_value": 1,
    "duration_unit": "HOURS",
    "connection_type": "hotspot"
}
```

#### Expected Response
```json
{
    "id": 1,
    "name": "1 Hour Plan",
    "speed": "1M/2M",
    "price": 50,
    "duration_value": 1,
    "duration_unit": "HOURS",
    "connection_type": "hotspot",
    "router_profile": null,
    "user_id": 1,
    "created_at": "2025-10-20T10:30:00.000000"
}
```

---

### 2.2: Create 24 Hour (Daily) Plan

#### Request
```
Method: POST
URL: http://localhost:8000/api/plans/create
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "name": "24 Hours Plan",
    "speed": "2M/3M",
    "price": 100,
    "duration_value": 24,
    "duration_unit": "HOURS",
    "connection_type": "hotspot"
}
```

---

### 2.3: Create 7 Day (Weekly) Plan

#### Request
```
Method: POST
URL: http://localhost:8000/api/plans/create
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "name": "7 Days Plan",
    "speed": "3M/5M",
    "price": 500,
    "duration_value": 7,
    "duration_unit": "DAYS",
    "connection_type": "hotspot"
}
```

---

### 2.4: Verify Plans Created

#### Request
```
Method: GET
URL: http://localhost:8000/api/plans
Headers: None
Body: None
```

#### Expected Response
```json
[
    {
        "id": 1,
        "name": "1 Hour Plan",
        "speed": "1M/2M",
        "price": 50,
        "duration_value": 1,
        "duration_unit": "HOURS",
        "connection_type": "hotspot"
    },
    {
        "id": 2,
        "name": "24 Hours Plan",
        "speed": "2M/3M",
        "price": 100,
        "duration_value": 24,
        "duration_unit": "HOURS",
        "connection_type": "hotspot"
    },
    {
        "id": 3,
        "name": "7 Days Plan",
        "speed": "3M/5M",
        "price": 500,
        "duration_value": 7,
        "duration_unit": "DAYS",
        "connection_type": "hotspot"
    }
]
```

---

## ✅ **STEP 3: Register Guest Customer**

### 3.1: Register Guest with MAC Address

#### Purpose
Register a guest customer who will pay for access

#### Request
```
Method: POST
URL: http://localhost:8000/api/customers/register
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "name": "Guest User 1",
    "phone": "+254712345678",
    "plan_id": 2,
    "router_id": 1,
    "mac_address": "AA:BB:CC:DD:EE:FF"
}
```

**Note:** 
- `plan_id: 2` = 24 Hours Plan
- `mac_address` = Customer's device MAC address from captive portal

#### Expected Response
```json
{
    "id": 1,
    "name": "Guest User 1",
    "phone": "+254712345678",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "pppoe_username": null,
    "static_ip": null,
    "status": "INACTIVE",
    "plan_id": 2,
    "router_id": 1,
    "user_id": 1,
    "expiry": null,
    "created_at": "2025-10-20T10:30:00.000000"
}
```

**Status:** `INACTIVE` - Customer registered but hasn't paid yet

---

### 3.2: Verify Customer Registered

#### Request
```
Method: GET
URL: http://localhost:8000/api/customers
Headers: None
Body: None
```

#### Expected Response
```json
[
    {
        "id": 1,
        "name": "Guest User 1",
        "phone": "+254712345678",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "status": "INACTIVE",
        "expiry": null,
        "plan": {
            "id": 2,
            "name": "24 Hours Plan",
            "price": 100
        },
        "router": {
            "id": 1,
            "name": "Guest Hotspot Router"
        }
    }
]
```

---

## ✅ **STEP 4: Process Payment (Guest Pays for Access)**

### 4.1: Simulate M-Pesa Payment Callback

#### Purpose
Test the complete payment-to-provisioning workflow for guest user

#### Real-World Flow:
1. Guest selects "24 Hours Plan" on captive portal
2. Enters phone number and initiates M-Pesa payment
3. Pays KES 100 via M-Pesa
4. Payment gateway calls this webhook
5. System provisions guest on MikroTik with 24h time limit

#### Request
```
Method: POST
URL: http://localhost:8000/api/lipay/callback
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "customer_ref": "AA:BB:CC:DD:EE:FF",
    "status": "completed",
    "amount": 100,
    "lipay_tx_no": "QAB12345678",
    "checkout_request_id": "ws_CO_12345678901234567890",
    "receipt_number": "QAB12345678"
}
```

**Note:** `customer_ref` is the MAC address

#### Expected Response
```json
{
    "ResultCode": 0,
    "ResultDesc": "Customer 1 updated to ACTIVE, payment recorded, and MikroTik user created. New expiry: 2025-10-21T10:30:00.000000"
}
```

#### Status Code
`200 OK`

---

## ✅ **STEP 5: Verify Guest Provisioning**

### 5.1: Check Customer Status in Database

#### Request
```
Method: GET
URL: http://localhost:8000/api/customers
Headers: None
Body: None
```

#### Expected Response
```json
[
    {
        "id": 1,
        "name": "Guest User 1",
        "phone": "+254712345678",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "status": "ACTIVE",
        "expiry": "2025-10-21T10:30:00.000000",
        "plan": {
            "id": 2,
            "name": "24 Hours Plan",
            "price": 100
        }
    }
]
```

**✅ Status changed:** `INACTIVE` → `ACTIVE`  
**✅ Expiry set:** 24 hours from payment time

---

### 5.2: Check MAC Registration Status

#### Purpose
Verify guest is provisioned on MikroTik

#### Request
```
Method: GET
URL: http://localhost:8000/api/public/mac-status/1/AA:BB:CC:DD:EE:FF
Headers: None
Body: None
```

#### Expected Response
```json
{
    "registered": true,
    "username": "AABBCCDDEEFF",
    "disabled": false,
    "profile": "default",
    "comment": "MAC: AA:BB:CC:DD:EE:FF | Router: Guest Hotspot Router | Owner: 1 | Expires: 2025-10-21 10:30",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "router_id": 1,
    "active_session": false
}
```

---

### 5.3: Verify on MikroTik Router

#### Manual Verification Steps:

**1. Check Hotspot User Created:**
```
/ip hotspot user print where name="AABBCCDDEEFF"
```

**Expected Output:**
- Name: `AABBCCDDEEFF`
- Password: `AABBCCDDEEFF`
- Limit-uptime: `24h`
- Profile: `default`
- Comment: Contains guest info and expiry

**2. Check IP Binding:**
```
/ip hotspot ip-binding print where mac-address="AA:BB:CC:DD:EE:FF"
```

**Expected Output:**
- MAC: `AA:BB:CC:DD:EE:FF`
- Type: `bypassed`

**3. Check Queue (Bandwidth Limit):**
```
/queue simple print where name~"AABBCCDDEEFF"
```

**Expected Output:**
- Target: Guest IP address
- Max-limit: `2M/3M` (from 24h plan)

---

## ✅ **BONUS: Additional Tests**

### Test Guest Disconnect

#### Purpose
Manually disconnect a guest user session

#### Request
```
Method: POST
URL: http://localhost:8000/api/public/disconnect/1/AA:BB:CC:DD:EE:FF
Headers: None
Body: None
```

#### Expected Response
```json
{
    "success": true,
    "message": "Disconnected 1 session(s) for MAC AA:BB:CC:DD:EE:FF",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "sessions_disconnected": 1
}
```

---

### Test Remove Guest User

#### Purpose
Completely remove guest from router (after time expires)

#### Request
```
Method: DELETE
URL: http://localhost:8000/api/public/remove-bypassed/1/AA:BB:CC:DD:EE:FF
Headers: None
Body: None
```

#### Expected Response
```json
{
    "success": true,
    "message": "User with MAC AA:BB:CC:DD:EE:FF removed successfully",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "router_id": 1
}
```

---

### Test Payment Renewal (Guest Buys More Time)

#### Scenario
Guest's 24h access is about to expire, they pay again for another 24h

#### Request
```
Method: POST
URL: http://localhost:8000/api/lipay/callback
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "customer_ref": "AA:BB:CC:DD:EE:FF",
    "status": "completed",
    "amount": 100,
    "lipay_tx_no": "QAB87654321",
    "checkout_request_id": "ws_CO_98765432109876543210",
    "receipt_number": "QAB87654321"
}
```

#### Expected Result
Expiry extended by another 24 hours

---

## 🐛 Troubleshooting

### Issue: "Router not found or not accessible"
**Solution:**
- Verify MikroTik router is reachable
- Check IP address, username, password
- Ensure port 8728 (API port) is open
- Test: `ping 192.168.88.1`

### Issue: "Customer not found"
**Solution:**
- Ensure customer registered first (STEP 3)
- Verify MAC address matches exactly
- MAC format: `AA:BB:CC:DD:EE:FF` (uppercase with colons)

### Issue: Payment callback doesn't provision user
**Solution:**
- Check server logs for errors
- Verify customer has `plan_id` and `router_id` set
- Ensure customer status is `INACTIVE` before payment
- Check MikroTik API is accessible

### Issue: "MAC address already registered"
**Solution:**
- Remove existing user from MikroTik first
- Use "Remove Guest User" endpoint
- Or manually: `/ip hotspot user remove [find name="AABBCCDDEEFF"]`

---

## 📝 Test Execution Checklist

### Initial Setup (One-Time)
- [ ] Router added to system
- [ ] 3 plans created (1h, 24h, 7d)
- [ ] Plans verified with GET request

### Guest User Testing
- [ ] Guest registered with MAC address
- [ ] Customer status shows INACTIVE
- [ ] Payment callback sent
- [ ] Customer status changes to ACTIVE
- [ ] Expiry date is set correctly
- [ ] MikroTik user created
- [ ] IP binding created
- [ ] Queue/bandwidth limit set
- [ ] Guest can connect and browse

### Edge Cases
- [ ] Failed payment handling
- [ ] Duplicate MAC registration
- [ ] Guest disconnection
- [ ] Guest removal after expiry
- [ ] Payment renewal/extension

---

## 🎯 Success Criteria

✅ Guest can register with MAC address  
✅ Payment creates MikroTik hotspot user  
✅ Time limit matches plan duration  
✅ Bandwidth limit matches plan speed  
✅ Expiry date calculated correctly  
✅ Guest can connect immediately after payment  
✅ Access automatically expires after time limit  
✅ Guest can renew/extend access by paying again  

---

## 📊 Common Guest Hotspot Plans

| Duration | Price | Speed | Use Case |
|----------|-------|-------|----------|
| 1 Hour | KES 50 | 1M/2M | Quick browsing |
| 3 Hours | KES 80 | 1M/2M | Short visit |
| 24 Hours | KES 100 | 2M/3M | Day pass |
| 3 Days | KES 250 | 2M/3M | Weekend |
| 7 Days | KES 500 | 3M/5M | Weekly |

---

## 🔑 Key Endpoints Summary

### Setup
- `POST /api/routers/create` - Add router
- `POST /api/plans/create` - Create time-based plan
- `GET /api/plans` - List all plans

### Guest Operations
- `POST /api/customers/register` - Register guest (MAC + plan)
- `POST /api/lipay/callback` - Payment callback (activates guest)
- `GET /api/public/mac-status/{router_id}/{mac}` - Check status
- `POST /api/public/disconnect/{router_id}/{mac}` - Disconnect
- `DELETE /api/public/remove-bypassed/{router_id}/{mac}` - Remove

### Monitoring
- `GET /api/customers` - List all guests
- `GET /api/routers/{id}/users` - Active users on router

---

**Good luck testing your guest hotspot system! 🚀**

**Next Step:** Connect to your WiFi, get your device's MAC address, and test the complete flow!
