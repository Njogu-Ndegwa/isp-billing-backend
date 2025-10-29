# 🧪 ISP Billing System - Guest Hotspot User Testing Guide

## 📋 Overview

This guide focuses **exclusively on guest hotspot users** - customers who pay for temporary internet access (e.g., 1 hour, 24 hours, 7 days).

### Guest Hotspot User Flow:
1. **Unknown guest** connects to WiFi → Gets captive portal with MAC address
2. Guest selects plan (1h, 24h, 7d) and enters phone number
3. Captive portal calls `POST /api/hotspot/register-and-pay` → Creates customer with status `PENDING`
4. System sends STK Push to guest's phone with MAC as reference
5. Guest enters M-Pesa PIN and pays
6. Payment gateway calls `POST /api/lipay/callback` → Customer updated to `ACTIVE`
7. System provisions guest on MikroTik with time limit
8. When time expires, access is automatically cut off

**✨ Key Flow:** REST API → STK Push → Payment → Callback → Provisioning

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

## 🚀 Quick Start (4 Steps to Test Guest Hotspot)

1. **Setup Router** → Add your MikroTik router
2. **Create Plans** → Define time-based plans (1h, 24h, 7d)
3. **Initiate Payment** → Call REST API to register guest & send STK Push
4. **Verify Access** → Check customer created & MikroTik provisioning

**Flow:** `POST /api/hotspot/register-and-pay` → STK Push → Guest pays → Payment callback → MikroTik provisioning

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

## ✅ **STEP 3: Initiate Guest Payment**

### 3.1: Register Guest and Initiate Payment

#### Purpose
Guest registers and initiates M-Pesa STK Push payment

#### Real-World Flow:
1. **Unknown guest** connects to WiFi → Gets captive portal with MAC address
2. Guest selects "24 Hours Plan" on captive portal
3. Enters phone number `+254712345678` 
4. **Captive portal calls REST API** `/api/hotspot/register-and-pay`
5. System creates customer record with status `PENDING`
6. System sends STK Push to guest's phone (with MAC as `customer_ref`)
7. Guest enters M-Pesa PIN and pays KES 100
8. **Payment gateway calls `/api/lipay/callback`** with payment confirmation
9. Callback receives `customer_ref` (MAC address) from gateway
10. System updates customer to `ACTIVE` and provisions on MikroTik

**🎯 Key Point:** Guest registration happens BEFORE payment, provisioning happens AFTER payment.

#### Request - REST API
```
Method: POST
URL: http://localhost:8000/api/hotspot/register-and-pay
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "phone": "+254712345678",
    "plan_id": 2,
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "router_id": 1,
    "payment_method": "mobile_money"
}
```

**Request Fields:**
- `phone` = Guest's M-Pesa phone number
- `plan_id` = Plan selected (2 = 24 Hours Plan)
- `mac_address` = Guest's device MAC address from captive portal
- `router_id` = Router at the location (1 = Guest Hotspot Router)
- `payment_method` = "mobile_money" (triggers STK Push) or "cash"
- `name` = (Optional) Guest name, defaults to "Guest XXXX" (last 4 digits of phone)

#### Expected Response
```json
{
    "id": 1,
    "name": "Guest 5678",
    "phone": "+254712345678",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "status": "pending",
    "plan_id": 2,
    "router_id": 1,
    "message": "STK Push sent to phone"
}
```

**What Happened:**
1. ✅ Customer created with status `pending`
2. ✅ STK Push sent to `+254712345678` with `customer_ref=AA:BB:CC:DD:EE:FF`
3. ✅ Guest receives prompt on phone to enter M-Pesa PIN
4. ⏳ Waiting for payment confirmation...

#### Status Code
`200 OK`

---

### 3.2: Simulate Payment Callback (For Testing Only)

#### Purpose
Simulate what the payment gateway does after successful payment (for testing without actual M-Pesa)

**⚠️ NOTE:** In production, this endpoint is called by the payment gateway, NOT by your captive portal!

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
    "phone_number": "+254712345678",
    "plan_id": 2,
    "router_id": 1,
    "status": "completed",
    "amount": 100,
    "lipay_tx_no": "QAB12345678",
    "checkout_request_id": "ws_CO_12345678901234567890",
    "receipt_number": "QAB12345678"
}
```

**Payload Fields:**
- `customer_ref` = MAC address (echoed back from STK Push request)
- `phone_number` = Guest's M-Pesa phone number
- `plan_id` = Plan ID
- `router_id` = Router ID
- `amount` = Payment amount
- `status` = "completed" for successful payment

#### Expected Response
```json
{
    "ResultCode": 0,
    "ResultDesc": "Customer 1 updated to ACTIVE, payment recorded, and MikroTik user created. New expiry: 2025-10-21T10:30:00.000000"
}
```

**What Happened:**
1. ✅ Callback received `customer_ref=AA:BB:CC:DD:EE:FF`
2. ✅ Found customer with MAC address
3. ✅ Updated customer status from `PENDING` to `ACTIVE`
4. ✅ Calculated expiry: 24 hours from now
5. ✅ Provisioned on MikroTik router with time limit

#### Status Code
`200 OK`

---

## ✅ **STEP 4: Verify Guest Provisioning**

### 4.1: Check Customer Auto-Created

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
        "name": "Guest 5678",
        "phone": "+254712345678",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "status": "ACTIVE",
        "expiry": "2025-10-21T10:30:00.000000",
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

**✅ Customer auto-created:** `Guest 5678` (from phone number)  
**✅ Status:** `ACTIVE`  
**✅ Expiry set:** 24 hours from payment time  
**✅ Assigned to router:** Router ID 1

---

### 4.2: Check MAC Registration Status

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

### 4.3: Verify on MikroTik Router

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
- `PUT /api/routers/{id}` - Update router
- `POST /api/plans/create` - Create time-based plan
- `DELETE /api/plans/{id}` - Delete plan
- `GET /api/plans` - List all plans

### Guest Operations
- `POST /api/customers/register` - Register guest (MAC + plan)
- `POST /api/lipay/callback` - Payment callback (activates guest)
- `GET /api/public/mac-status/{router_id}/{mac}` - Check status
- `POST /api/public/disconnect/{router_id}/{mac}` - Disconnect
- `DELETE /api/public/remove-bypassed/{router_id}/{mac}` - Remove

### Dashboard & Analytics
- `GET /api/dashboard/overview` - Complete dashboard with revenue & metrics
- `GET /api/customers/active` - List currently active guests
- `GET /api/plans/performance` - Plan sales & revenue analysis

### Monitoring
- `GET /api/customers` - List all guests
- `GET /api/routers/{id}/users` - Active users on router
- `GET /api/mpesa/transactions` - View M-Pesa transactions with filters
- `GET /api/mpesa/transactions/summary` - Transaction statistics

---

## 📊 **Dashboard Endpoints for Business Management**

### Get Dashboard Overview

#### Purpose
Get complete business metrics for your dashboard homepage

#### Request
```
Method: GET
URL: http://localhost:8000/api/dashboard/overview
Headers: None
Body: None
```

#### Expected Response
```json
{
    "revenue": {
        "today": 500.0,
        "this_week": 3500.0,
        "this_month": 15000.0,
        "all_time": 50000.0
    },
    "customers": {
        "total": 150,
        "active": 45,
        "inactive": 105
    },
    "revenue_by_router": [
        {
            "router_id": 1,
            "router_name": "Guest Hotspot Router",
            "transaction_count": 120,
            "revenue": 12000.0
        }
    ],
    "revenue_by_plan": [
        {
            "plan_id": 1,
            "plan_name": "1 Hour Plan",
            "plan_price": 50,
            "sales_count": 80,
            "revenue": 4000.0
        },
        {
            "plan_id": 2,
            "plan_name": "24 Hours Plan",
            "plan_price": 100,
            "sales_count": 60,
            "revenue": 6000.0
        }
    ],
    "recent_transactions": [
        {
            "payment_id": 10,
            "amount": 100.0,
            "customer_name": "Guest 5678",
            "customer_phone": "+254712345678",
            "plan_name": "24 Hours Plan",
            "payment_date": "2025-10-20T15:30:00.000000",
            "payment_method": "mobile_money"
        }
    ],
    "expiring_soon": [
        {
            "customer_id": 5,
            "customer_name": "Guest 1234",
            "customer_phone": "+254798765432",
            "mac_address": "BB:CC:DD:EE:FF:00",
            "expiry": "2025-10-21T10:30:00.000000",
            "hours_remaining": 3.5
        }
    ],
    "generated_at": "2025-10-20T16:00:00.000000"
}
```

**Use Cases:**
- Homepage dashboard widget
- Quick business overview
- Identify guests expiring soon (renewal opportunities)
- Compare router performance
- Identify best-selling plans

---

### Get Active Guests

#### Purpose
List all currently active guests with time remaining

#### Request
```
Method: GET
URL: http://localhost:8000/api/customers/active
Headers: None
Body: None
```

#### Expected Response
```json
[
    {
        "id": 1,
        "name": "Guest 5678",
        "phone": "+254712345678",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "status": "active",
        "expiry": "2025-10-21T10:30:00.000000",
        "hours_remaining": 18.5,
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

**Sorted by:** Expiry time (soonest first)

**Use Cases:**
- Monitor who's online
- See when guests will expire
- Proactive customer service

---

### Get Plan Performance

#### Purpose
Analyze which plans are selling best

#### Request - All Time
```
Method: GET
URL: http://localhost:8000/api/plans/performance
Headers: None
Body: None
```

#### Request - Specific Period
```
Method: GET
URL: http://localhost:8000/api/plans/performance?start_date=2025-10-01&end_date=2025-10-31
Headers: None
Body: None
```

#### Expected Response
```json
{
    "plans": [
        {
            "plan_id": 1,
            "plan_name": "1 Hour Plan",
            "plan_price": 50,
            "duration": "1 hours",
            "total_customers": 80,
            "total_sales": 120,
            "total_revenue": 6000.0,
            "average_revenue_per_sale": 50.0,
            "active_customers": 15
        },
        {
            "plan_id": 2,
            "plan_name": "24 Hours Plan",
            "plan_price": 100,
            "duration": "24 hours",
            "total_customers": 60,
            "total_sales": 80,
            "total_revenue": 8000.0,
            "average_revenue_per_sale": 100.0,
            "active_customers": 25
        },
        {
            "plan_id": 3,
            "plan_name": "7 Days Plan",
            "plan_price": 500,
            "duration": "7 days",
            "total_customers": 10,
            "total_sales": 15,
            "total_revenue": 7500.0,
            "average_revenue_per_sale": 500.0,
            "active_customers": 5
        }
    ],
    "period": {
        "start_date": "2025-10-01",
        "end_date": "2025-10-31"
    }
}
```

**Insights:**
- Which plans generate most revenue
- Which plans are most popular
- Repeat purchase rate (total_sales vs total_customers)
- Current active users per plan

---

### Update Router

#### Purpose
Update router IP, credentials, or name

#### Request
```
Method: PUT
URL: http://localhost:8000/api/routers/1
Headers: 
    Content-Type: application/json
Body: (raw JSON)
```

```json
{
    "name": "Updated Router Name",
    "ip_address": "192.168.88.2",
    "username": "admin",
    "password": "newpassword",
    "port": 8728
}
```

#### Expected Response
```json
{
    "id": 1,
    "name": "Updated Router Name",
    "ip_address": "192.168.88.2",
    "username": "admin",
    "port": 8728,
    "user_id": 1,
    "updated_at": "2025-10-20T16:00:00.000000"
}
```

---

### Delete Plan

#### Purpose
Remove a plan (only if no active customers using it)

#### Request
```
Method: DELETE
URL: http://localhost:8000/api/plans/1
Headers: None
Body: None
```

#### Expected Response - Success
```json
{
    "success": true,
    "message": "Plan '1 Hour Plan' deleted successfully"
}
```

#### Expected Response - Has Active Customers
```json
{
    "detail": "Cannot delete plan. 15 active customer(s) are using this plan"
}
```

**Status Code:** `400 Bad Request`

**Safety:** Cannot delete plans with active users

---

## 📊 **M-Pesa Transaction Monitoring**

### View All Transactions

#### Purpose
View all M-Pesa payment transactions with filtering options

#### Request - Get All Transactions
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions
Headers: None
Body: None
```

#### Expected Response
```json
[
    {
        "transaction_id": 1,
        "checkout_request_id": "ws_CO_12345678901234567890",
        "phone_number": "+254712345678",
        "amount": 100.0,
        "reference": "AA:BB:CC:DD:EE:FF",
        "lipay_tx_no": "QAB12345678",
        "status": "completed",
        "mpesa_receipt_number": "QAB12345678",
        "transaction_date": "2025-10-20T10:30:00.000000",
        "created_at": "2025-10-20T10:25:00.000000",
        "customer": {
            "id": 1,
            "name": "Guest User 1",
            "phone": "+254712345678",
    "mac_address": "AA:BB:CC:DD:EE:FF",
            "status": "active"
        },
        "router": {
            "id": 1,
            "name": "Guest Hotspot Router",
            "ip_address": "192.168.88.1"
        },
        "plan": {
            "id": 2,
            "name": "24 Hours Plan",
            "price": 100,
            "duration_value": 24,
            "duration_unit": "HOURS"
        }
    }
]
```

---

### Filter Transactions by Router

#### Purpose
View transactions for a specific router only

#### Request
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?router_id=1
Headers: None
Body: None
```

**Filter:** Only shows transactions from guests connected to Router ID 1

---

### Filter Transactions by Date Range

#### Purpose
View transactions within a specific time period

#### Request - Daily Report
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?start_date=2025-10-20&end_date=2025-10-20
Headers: None
Body: None
```

#### Request - Monthly Report
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?start_date=2025-10-01&end_date=2025-10-31
Headers: None
Body: None
```

#### Request - With Specific Time
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?start_date=2025-10-20T00:00:00&end_date=2025-10-20T23:59:59
Headers: None
Body: None
```

**Date Format Options:**
- `YYYY-MM-DD` - Full day (e.g., `2025-10-20`)
- `YYYY-MM-DDTHH:MM:SS` - Specific time (e.g., `2025-10-20T14:30:00`)

---

### Filter Transactions by Status

#### Purpose
View only completed, pending, or failed transactions

#### Request - Completed Payments Only
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?status=completed
Headers: None
Body: None
```

#### Request - Failed Payments Only
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?status=failed
Headers: None
Body: None
```

#### Request - Pending Payments
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?status=pending
Headers: None
Body: None
```

**Valid Status Values:**
- `completed` - Successful payments
- `pending` - Payment in progress
- `failed` - Failed payments
- `expired` - Expired payment requests

---

### Combined Filters

#### Purpose
Combine multiple filters for specific reports

#### Request - Router Transactions for Today (Completed)
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?router_id=1&start_date=2025-10-20&end_date=2025-10-20&status=completed
Headers: None
Body: None
```

#### Request - Last Week's Failed Payments
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions?start_date=2025-10-13&end_date=2025-10-20&status=failed
Headers: None
Body: None
```

---

### Get Transaction Summary (Statistics)

#### Purpose
Get aggregated statistics about transactions

#### Request
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions/summary
Headers: None
Body: None
```

#### Expected Response
```json
{
    "total_transactions": 15,
    "total_amount": 1500.0,
    "status_breakdown": {
        "completed": {
            "count": 12,
            "amount": 1200.0
        },
        "pending": {
            "count": 2,
            "amount": 200.0
        },
        "failed": {
            "count": 1,
            "amount": 100.0
        }
    },
    "router_breakdown": {
        "Guest Hotspot Router": {
            "count": 15,
            "amount": 1500.0,
            "router_id": 1
        }
    },
    "period": {
        "start_date": null,
        "end_date": null
    }
}
```

---

### Summary with Filters

#### Request - Today's Summary for Specific Router
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions/summary?router_id=1&start_date=2025-10-20&end_date=2025-10-20
Headers: None
Body: None
```

#### Request - Monthly Summary
```
Method: GET
URL: http://localhost:8000/api/mpesa/transactions/summary?start_date=2025-10-01&end_date=2025-10-31
Headers: None
Body: None
```

#### Expected Response
```json
{
    "total_transactions": 45,
    "total_amount": 4500.0,
    "status_breakdown": {
        "completed": {
            "count": 40,
            "amount": 4000.0
        },
        "failed": {
            "count": 5,
            "amount": 500.0
        }
    },
    "router_breakdown": {
        "Guest Hotspot Router": {
            "count": 45,
            "amount": 4500.0,
            "router_id": 1
        }
    },
    "period": {
        "start_date": "2025-10-01",
        "end_date": "2025-10-31"
    }
}
```

---

## 📈 **Common Use Cases for Transaction Monitoring**

### Daily Revenue Report
```
GET /api/mpesa/transactions/summary?start_date=2025-10-20&end_date=2025-10-20
```
**Use:** Check today's earnings

### Weekly Performance
```
GET /api/mpesa/transactions/summary?start_date=2025-10-13&end_date=2025-10-20
```
**Use:** Analyze weekly trends

### Router-Specific Report
```
GET /api/mpesa/transactions?router_id=1&start_date=2025-10-01&end_date=2025-10-31
```
**Use:** Check performance of specific router

### Failed Payment Investigation
```
GET /api/mpesa/transactions?status=failed&start_date=2025-10-01&end_date=2025-10-31
```
**Use:** Investigate payment issues

### Hourly Sales (Today)
```
GET /api/mpesa/transactions?start_date=2025-10-20T00:00:00&end_date=2025-10-20T23:59:59&status=completed
```
**Use:** Track sales throughout the day

---

**Good luck testing your guest hotspot system! 🚀**

**Next Step:** Connect to your WiFi, get your device's MAC address, and test the complete flow!
