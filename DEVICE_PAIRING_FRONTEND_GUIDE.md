# Companion Device Pairing — Frontend Integration Guide

This document describes the backend APIs for pairing browserless devices (Smart TVs, gaming consoles, IoT devices) to the hotspot system. The customer uses their **phone as a companion** to authenticate the device's MAC address and pay for a plan.

All endpoints are **public** (no JWT required) — they are called from the captive portal frontend.

---

## Table of Contents

1. [Overview & User Flow](#1-overview--user-flow)
2. [Pair Device and Pay](#2-pair-device-and-pay)
3. [Pair Device with Voucher](#3-pair-device-with-voucher)
4. [Check Device Status](#4-check-device-status)
5. [List Paired Devices](#5-list-paired-devices)
6. [Unpair a Device](#6-unpair-a-device)
7. [Reconnect a Device](#7-reconnect-a-device)
8. [MAC Address Input UX](#8-mac-address-input-ux)
9. [Suggested UI Components](#9-suggested-ui-components)
10. [Error Handling](#10-error-handling)

---

## 1. Overview & User Flow

### The Problem

Smart TVs, gaming consoles, and IoT devices cannot complete the hotspot captive portal login because they lack a capable web browser. They connect to WiFi but get stuck at the redirect to the login page.

### The Solution

The customer uses their phone (which can browse the portal) to pair the TV by entering its MAC address and paying for a plan. The backend provisions the TV's MAC on MikroTik, and the TV gets internet access without ever opening a browser.

### Flow Diagram

```
Customer Phone                          Backend                         MikroTik Router
     |                                    |                                   |
     |  1. Opens portal "Add Device"      |                                   |
     |  2. Enters TV MAC + picks plan     |                                   |
     |----------------------------------->|                                   |
     |  POST /api/public/device/pair-and-pay                                  |
     |                                    |                                   |
     |  3. M-Pesa STK Push sent           |                                   |
     |<-----------------------------------|                                   |
     |                                    |                                   |
     |  4. Customer pays on phone         |                                   |
     |                                    |  5. Provision MAC on router        |
     |                                    |---------------------------------->|
     |                                    |  hotspot user + ip-binding bypass  |
     |                                    |                                   |
     |  6. Poll status: device online     |                                   |
     |<-----------------------------------|                                   |
     |                                    |                                   |
     Smart TV: Internet works!
```

### Entry Points

The "Add Device" flow should be accessible from:

- **Main portal page** — A prominent button: "Connect a TV / Other Device"
- **After login** — In a "My Devices" section where the user sees their phone + any paired devices
- **Direct URL** — `https://portal.example.com/pair-device?router={identity}` (can be linked from support instructions)

---

## 2. Pair Device and Pay

Pair a device and initiate payment. Supports M-Pesa (STK Push) and cash.

### `POST /api/public/device/pair-and-pay`

**Request Body:**

```json
{
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "owner_phone": "0712345678",
  "plan_id": 1,
  "router_id": 1,
  "device_name": "Living Room TV",
  "device_type": "tv",
  "payment_method": "mobile_money",
  "owner_name": "John Doe"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `device_mac` | string | Yes | MAC address of the TV/device (from its network settings) |
| `owner_phone` | string | Yes | Customer's phone number (for M-Pesa and lookup) |
| `plan_id` | int | Yes | The hotspot plan to purchase for the device |
| `router_id` | int | Yes | The router this device is connected to |
| `device_name` | string | No | Friendly name (e.g. "Living Room TV") |
| `device_type` | string | No | One of: `tv`, `console`, `laptop`, `iot`, `other`. Defaults to `tv` |
| `payment_method` | string | No | `mobile_money` (default) or `cash` |
| `payment_reference` | string | No | Reference for cash payments |
| `owner_name` | string | No | Customer name |

**Response (M-Pesa — 200):**

```json
{
  "success": true,
  "customer_id": 42,
  "pairing_id": 7,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "device_name": "Living Room TV",
  "device_type": "tv",
  "status": "pending",
  "message": "STK Push sent to phone. Device will be activated after payment."
}
```

**Response (Cash — 200):**

```json
{
  "success": true,
  "customer_id": 42,
  "pairing_id": 7,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "device_type": "tv",
  "attempt_id": 15,
  "expiry": "2026-04-13T12:00:00",
  "message": "Device paired and provisioning started."
}
```

**After M-Pesa payment:** Use the existing payment status polling endpoint:

```
GET /api/hotspot/payment-status/{customer_id}
```

This returns the same delivery status used for phone hotspot purchases. Once `status` is `"active"` and `delivery.delivery_status` is `"online"` or `"access_ready"`, the TV has internet.

---

## 3. Pair Device with Voucher

Pair a device by redeeming a voucher code instead of paying.

### `POST /api/public/device/pair-voucher`

**Request Body:**

```json
{
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "voucher_code": "1234-5678",
  "router_id": 1,
  "device_name": "Bedroom TV",
  "device_type": "tv"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `device_mac` | string | Yes | MAC address of the device |
| `voucher_code` | string | Yes | Valid voucher code (e.g. `1234-5678`) |
| `router_id` | int | Yes | Router ID |
| `device_name` | string | No | Friendly name |
| `device_type` | string | No | Device type (defaults to `tv`) |

**Response (200):**

```json
{
  "success": true,
  "customer_id": 43,
  "pairing_id": 8,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "device_type": "tv",
  "attempt_id": 16,
  "plan_name": "Daily 10Mbps",
  "expiry": "2026-04-13T12:00:00",
  "message": "Device paired with voucher. Provisioning started."
}
```

**Error Responses:**

| Status | Detail |
|---|---|
| 400 | Invalid MAC address format |
| 400 | Voucher has already been used / expired / disabled |
| 400 | This voucher is not valid for this hotspot |
| 404 | Voucher code not found |
| 404 | Router not found |

---

## 4. Check Device Status

Check whether a specific device is paired and its provisioning status.

### `GET /api/public/device/status/{router_id}/{mac}`

**Example:** `GET /api/public/device/status/1/AA:BB:CC:DD:EE:FF`

**Response (paired):**

```json
{
  "paired": true,
  "pairing": {
    "id": 7,
    "customer_id": 42,
    "device_mac": "AA:BB:CC:DD:EE:FF",
    "device_name": "Living Room TV",
    "device_type": "tv",
    "router_id": 1,
    "plan_id": 1,
    "is_active": true,
    "provisioned_at": "2026-04-12T10:30:00",
    "expires_at": "2026-04-13T10:30:00",
    "created_at": "2026-04-12T10:29:00"
  },
  "customer": {
    "id": 42,
    "name": "Living Room TV",
    "status": "active",
    "expiry": "2026-04-13T10:30:00",
    "plan_name": "Daily 10Mbps"
  },
  "delivery": {
    "attempt_id": 15,
    "delivery_status": "online",
    "provisioning_state": "router_updated",
    "online_state": "online",
    "attempt_count": 1,
    "last_error": null,
    "last_attempt_at": "2026-04-12T10:30:05",
    "last_online_at": "2026-04-12T10:30:10",
    "external_reference": "device-pair-7"
  }
}
```

**Response (not paired):**

```json
{
  "paired": false,
  "message": "Device is not paired on this router"
}
```

---

## 5. List Paired Devices

Get all active paired devices for a phone number on a router.

### `GET /api/public/device/paired/{router_id}/{phone}`

**Example:** `GET /api/public/device/paired/1/0712345678`

**Response:**

```json
{
  "phone": "0712345678",
  "router_id": 1,
  "devices": [
    {
      "id": 7,
      "customer_id": 42,
      "device_mac": "AA:BB:CC:DD:EE:FF",
      "device_name": "Living Room TV",
      "device_type": "tv",
      "router_id": 1,
      "plan_id": 1,
      "is_active": true,
      "provisioned_at": "2026-04-12T10:30:00",
      "expires_at": "2026-04-13T10:30:00",
      "created_at": "2026-04-12T10:29:00"
    },
    {
      "id": 9,
      "customer_id": 44,
      "device_mac": "11:22:33:44:55:66",
      "device_name": "PS5",
      "device_type": "console",
      "router_id": 1,
      "plan_id": 2,
      "is_active": true,
      "provisioned_at": "2026-04-12T14:00:00",
      "expires_at": "2026-04-19T14:00:00",
      "created_at": "2026-04-12T13:59:00"
    }
  ],
  "count": 2
}
```

---

## 6. Unpair a Device

Remove a paired device. This deactivates the pairing and removes the hotspot user + ip-binding from MikroTik.

### `DELETE /api/public/device/unpair/{pairing_id}`

**Example:** `DELETE /api/public/device/unpair/7`

**Response:**

```json
{
  "success": true,
  "pairing_id": 7,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "router_cleanup": "removed_from_router",
  "message": "Device unpaired successfully"
}
```

`router_cleanup` values:
- `"removed_from_router"` — Successfully removed from MikroTik
- `"router_unreachable"` — Pairing deactivated but router was offline
- `"removal_error: ..."` — Pairing deactivated but router removal had an error

---

## 7. Reconnect a Device

Re-provision a paired device that lost connectivity but still has an active subscription.

### `POST /api/public/device/reconnect`

**Request Body:**

```json
{
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "router_id": 1,
  "owner_phone": "0712345678"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `device_mac` | string | Yes | MAC address of the device |
| `router_id` | int | Yes | Router ID |
| `owner_phone` | string | Yes | Must match the phone on file (ownership check) |

**Response:**

```json
{
  "success": true,
  "customer_id": 42,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "device_name": "Living Room TV",
  "message": "Device reconnection started. It should come online shortly."
}
```

**Error Responses:**

| Status | Detail |
|---|---|
| 400 | Subscription is not active / expired |
| 403 | Phone number does not match the device owner |
| 404 | No active pairing found |

---

## 8. MAC Address Input UX

The MAC address is the critical input. Help customers find it easily.

### MAC Format

- Accept: `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, `AABBCCDDEEFF`
- The backend normalizes all formats to `AA:BB:CC:DD:EE:FF`
- Validate client-side with: `/^([0-9A-Fa-f]{2}[:-]?){5}[0-9A-Fa-f]{2}$/`

### Input Component Recommendations

- Auto-insert colons as user types (e.g. typing `AABB` shows `AA:BB`)
- Accept paste of any format
- Show character count / format hint: `XX:XX:XX:XX:XX:XX`
- Uppercase display

### Where to Find MAC Address — Per Brand

Include these text instructions (or a collapsible accordion) below the MAC input:

**Samsung Smart TV:**
Settings > General > Network > Network Status > IP Settings — look for "MAC Address"

**LG Smart TV (webOS):**
Settings > All Settings > General > About This TV — look for "Wi-Fi MAC Address"

**Sony Bravia / Android TV:**
Settings > Device Preferences > About > Status > Wi-Fi MAC Address

**Roku TV / Roku Stick:**
Settings > Network > About — look for "Wireless MAC address"

**Amazon Fire TV / Fire Stick:**
Settings > My Fire TV > About > Network — look for "Wi-Fi MAC Address"

**Apple TV:**
Settings > General > About — look for "Wi-Fi Address"

**Xbox:**
Settings > General > Network Settings > Advanced Settings — look for "Wireless MAC"

**PlayStation (PS4/PS5):**
Settings > Network > View Connection Status — look for "MAC Address (Wi-Fi)"

**Nintendo Switch:**
System Settings > Internet > look for "System MAC Address"

---

## 9. Suggested UI Components

### A. "Connect a Device" Button (Main Portal)

Place a prominent button on the portal landing page, next to the existing plan selection:

```
[ Connect Your Phone ]    [ Connect a TV / Device ]
```

Use a TV/monitor icon to make it visually distinct.

### B. Device Pairing Form (Step-by-Step)

**Step 1 — Enter MAC Address**
- Large input field with format helper
- Collapsible "Where do I find this?" accordion with per-brand instructions
- Device type selector: TV (default) | Console | Laptop | IoT | Other
- Optional: device name field

**Step 2 — Select Plan**
- Reuse existing plan cards/list component
- Show the same plans available for the hotspot

**Step 3 — Payment**
- Reuse existing M-Pesa / voucher / cash payment components
- For M-Pesa: phone number input (pre-filled if they came from the portal with `?mac=` params)
- For voucher: voucher code input

**Step 4 — Success**
- Show confirmation with device name, plan, and expiry
- "Your [device_name] should now have internet access"
- Show a "Check Status" button that polls the status endpoint

### C. "My Devices" Panel

A section showing all paired devices for the customer:

```
My Devices
┌─────────────────────────────────────────┐
│  📺 Living Room TV                      │
│  MAC: AA:BB:CC:DD:EE:FF                 │
│  Plan: Daily 10Mbps                     │
│  Expires: Apr 13, 2026                  │
│  Status: ● Online                       │
│  [ Reconnect ]  [ Remove ]              │
├─────────────────────────────────────────┤
│  🎮 PS5                                 │
│  MAC: 11:22:33:44:55:66                 │
│  Plan: Weekly 20Mbps                    │
│  Expires: Apr 19, 2026                  │
│  Status: ● Online                       │
│  [ Reconnect ]  [ Remove ]              │
└─────────────────────────────────────────┘
            [ + Add Another Device ]
```

To load this panel, call:
```
GET /api/public/device/paired/{router_id}/{phone}
```

### D. Device Type Icons

Map device types to icons:
- `tv` — Television / Monitor icon
- `console` — Game controller icon
- `laptop` — Laptop icon
- `iot` — Chip / Wifi icon
- `other` — Device icon

---

## 10. Error Handling

### Common Error Responses

All endpoints return errors in this format:

```json
{
  "detail": "Error message here"
}
```

### Error Handling Matrix

| Error | What to Show User |
|---|---|
| `Invalid MAC address format` | "Please check the MAC address. It should look like AA:BB:CC:DD:EE:FF" |
| `Invalid phone number format` | "Please enter a valid phone number" |
| `Router not found` | "This hotspot is not available. Please check your connection." |
| `Plan not found` | "This plan is no longer available." |
| `Plan does not belong to this router's owner` | "This plan is not available on this network." |
| `Selected plan is not a hotspot plan` | "Please select a WiFi plan." |
| `Service temporarily unavailable` (503) | "This hotspot is temporarily offline. Please try again later." |
| `Voucher has already been used` | "This voucher code has already been redeemed." |
| `Voucher has expired` | "This voucher code has expired." |
| `No active pairing found` | "This device is not registered. Please add it first." |
| `Subscription is not active` | "Your plan has ended. Please purchase a new one." |
| `Phone number does not match` | "This phone number doesn't match the one used to register this device." |

### Payment Status Polling

After M-Pesa payment initiation, poll every 3-5 seconds:

```
GET /api/hotspot/payment-status/{customer_id}
```

Stop polling when:
- `status` = `"active"` (payment completed, device provisioned)
- `status` = `"inactive"` and enough time has passed (payment likely failed)
- Max 120 seconds of polling

---

## Postman Collection

Import `device-pairing-endpoints.postman_collection.json` from the project root into Postman for testing:

**Postman > Import > Upload Files > select `device-pairing-endpoints.postman_collection.json`**
