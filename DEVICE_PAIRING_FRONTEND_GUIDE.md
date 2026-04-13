# Device Pairing (TV / Console) — Public Portal Frontend Guide

This document is the complete API reference for implementing companion device pairing on the **public captive portal**. It covers every endpoint, every request/response shape, every error code, polling logic, MAC address UX, and suggested UI layout.

All endpoints are **public** (no JWT required). Base URL is your backend API host.

---

## Table of Contents

1. [Overview & User Flow](#1-overview--user-flow)
2. [API Quick Reference](#2-api-quick-reference)
3. [Load Plans (existing)](#3-load-plans-existing)
4. [Pair Device and Pay](#4-pair-device-and-pay)
5. [Poll Payment Status (existing)](#5-poll-payment-status-existing)
6. [Pair Device with Voucher](#6-pair-device-with-voucher)
7. [Check Device Status](#7-check-device-status)
8. [List Paired Devices](#8-list-paired-devices)
9. [Unpair a Device](#9-unpair-a-device)
10. [Reconnect a Device](#10-reconnect-a-device)
11. [MAC Address Input UX](#11-mac-address-input-ux)
12. [Delivery Status Reference](#12-delivery-status-reference)
13. [Suggested UI Layout](#13-suggested-ui-layout)
14. [Complete Error Reference](#14-complete-error-reference)

---

## 1. Overview & User Flow

### The Problem

Smart TVs, gaming consoles, and IoT devices connect to the hotspot WiFi but cannot complete the captive portal login because they lack a capable web browser.

### The Solution

The customer opens the portal on their **phone**, taps "Connect a TV / Device", enters the device's MAC address, picks a plan, and pays. The backend provisions the device's MAC on the MikroTik router and the device gets internet without ever opening a browser.

### Flow Diagram

```
Customer Phone                          Backend                         MikroTik Router
     |                                    |                                   |
     |  1. Taps "Connect a TV / Device"   |                                   |
     |  2. Enters TV MAC + picks plan     |                                   |
     |----------------------------------->|                                   |
     |  POST /api/public/device/pair-and-pay                                  |
     |                                    |                                   |
     |  3. STK Push sent to phone         |                                   |
     |<-----------------------------------|                                   |
     |                                    |                                   |
     |  4. Customer enters M-Pesa PIN     |                                   |
     |                                    |                                   |
     |  5. Poll payment status            |  6. Provision MAC on router       |
     |<-----------------------------------|---------------------------------->|
     |                                    |  hotspot user + ip-binding bypass  |
     |                                    |                                   |
     |  7. Status: online                 |                                   |
     |<-----------------------------------|                                   |
     |                                    |                                   |
     TV: Internet works!
```

### Voucher Alternative Flow

```
Customer Phone                          Backend                         MikroTik Router
     |                                    |                                   |
     |  1. Enters TV MAC + voucher code   |                                   |
     |----------------------------------->|                                   |
     |  POST /api/public/device/pair-voucher                                  |
     |                                    |  2. Provision immediately          |
     |  3. Success + expiry returned      |---------------------------------->|
     |<-----------------------------------|                                   |
     |                                    |                                   |
     TV: Internet works!
```

---

## 2. API Quick Reference

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| `GET` | `/api/public/plans/{router_id}` | No | Load available plans (existing) |
| `POST` | `/api/public/device/pair-and-pay` | No | Pair device + M-Pesa or cash payment |
| `GET` | `/api/hotspot/payment-status/{customerId}` | No | Poll M-Pesa payment status (existing) |
| `POST` | `/api/public/device/pair-voucher` | No | Pair device with voucher code |
| `GET` | `/api/public/device/status/{router_id}/{mac}` | No | Check single device status |
| `GET` | `/api/public/device/paired/{router_id}/{phone}` | No | List all devices for a phone number |
| `DELETE` | `/api/public/device/unpair/{pairing_id}` | No | Remove a paired device |
| `POST` | `/api/public/device/reconnect` | No | Re-provision a device that lost connectivity |

---

## 3. Load Plans (existing)

You already use this endpoint. No changes needed — reuse your existing plan cards component.

### `GET /api/public/plans/{router_id}`

**Example:** `GET /api/public/plans/1`

**Response — 200:**

```json
[
  {
    "id": 1,
    "name": "Daily 10Mbps",
    "speed": "10M/10M",
    "price": 50,
    "duration_value": 1,
    "duration_unit": "DAYS",
    "connection_type": "hotspot",
    "plan_type": "regular",
    "is_hidden": false,
    "badge_text": null,
    "original_price": null
  },
  {
    "id": 2,
    "name": "Weekly 20Mbps",
    "speed": "20M/20M",
    "price": 300,
    "duration_value": 7,
    "duration_unit": "DAYS",
    "connection_type": "hotspot",
    "plan_type": "regular",
    "is_hidden": false,
    "badge_text": "Popular",
    "original_price": 350
  }
]
```

**Frontend note:** Filter to only show plans where `connection_type === "hotspot"`. Hide plans where `is_hidden === true`.

---

## 4. Pair Device and Pay

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
  "payment_reference": null,
  "owner_name": "John Doe"
}
```

**Field Reference:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_mac` | string | **Yes** | — | MAC address from the device's network settings. Accepts any format: `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, `AABB.CCDD.EEFF`, `AABBCCDDEEFF` |
| `owner_phone` | string | **Yes** | — | Customer phone number (min 10 chars). Used for M-Pesa STK push and device ownership lookup |
| `plan_id` | int | **Yes** | — | Plan ID from the plans list endpoint |
| `router_id` | int | **Yes** | — | Router ID from the portal context (`identity` param) |
| `device_name` | string | No | `"Device XX:XX"` | Friendly name. Suggest the user names it (e.g. "Living Room TV") |
| `device_type` | string | No | `"tv"` | One of: `tv`, `console`, `laptop`, `iot`, `other` |
| `payment_method` | string | No | `"mobile_money"` | `mobile_money` or `cash` |
| `payment_reference` | string | No | `null` | Only relevant for cash payments (receipt number, etc.) |
| `owner_name` | string | No | `null` | Customer display name |

### Response — M-Pesa Payment (200)

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

**What to do next:** Save `customer_id` and start polling `GET /api/hotspot/payment-status/42` every 3–5 seconds. See [Section 5](#5-poll-payment-status-existing).

### Response — Cash Payment (200)

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

**What to do next:** No polling needed. Show the success screen immediately with `expiry` as the plan end date. The device gets provisioned in the background within seconds.

### Response — Cash Payment on RADIUS Router (200)

```json
{
  "success": true,
  "customer_id": 42,
  "pairing_id": 7,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "device_type": "tv",
  "auth_method": "RADIUS",
  "radius_username": "AABBCCDDEEFF",
  "radius_password": "AABBCCDDEEFF",
  "expiry": "2026-04-13T12:00:00",
  "message": "Device paired and provisioned via RADIUS."
}
```

**Frontend note:** If `auth_method === "RADIUS"` is present, provisioning is complete. Show success screen.

### Error Responses

| Status | `detail` value | User-friendly message |
|--------|----------------|----------------------|
| 400 | `"Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF"` | "Please check the MAC address. It should look like AA:BB:CC:DD:EE:FF" |
| 400 | `"Invalid phone number format"` | "Please enter a valid phone number (at least 10 digits)" |
| 400 | `"Invalid payment method. Must be one of: mobile_money, cash"` | "Please select a valid payment method" |
| 400 | `"Plan does not belong to this router's owner"` | "This plan is not available on this network" |
| 400 | `"Selected plan is not a hotspot plan"` | "Please select a WiFi plan" |
| 404 | `"Router not found"` | "This hotspot is not available. Please check your connection." |
| 404 | `"Plan not found"` | "This plan is no longer available. Please select another." |
| 503 | `"This service is temporarily unavailable. Please contact your ISP."` | Show as-is |
| 500 | `"Device pairing failed: ..."` | "Something went wrong. Please try again." |

---

## 5. Poll Payment Status (existing)

You already use this endpoint for phone hotspot purchases. **Same logic applies for device payments.**

### `GET /api/hotspot/payment-status/{customerId}`

**Example:** `GET /api/hotspot/payment-status/42`

Use the `customer_id` returned from the `pair-and-pay` response.

### Polling Logic

```
Start polling immediately after pair-and-pay returns with status "pending"
Interval: every 3–5 seconds
Max duration: 120 seconds
```

### When to Stop Polling

| Condition | What happened | UI Action |
|-----------|--------------|-----------|
| `status === "active"` | Payment confirmed, device provisioned | Show success: "Your TV now has internet!" |
| `status === "active"` AND `delivery.delivery_status === "online"` | Device confirmed online | Show green "Online" badge |
| `status === "active"` AND `delivery.delivery_status === "access_ready"` | Provisioned, device hasn't connected yet | Show: "Provisioned! Connect your TV to WiFi now." |
| `status === "active"` AND `delivery.delivery_status === "failed"` | Payment OK but router provisioning failed | Show: "Payment received but setup failed. Tap Reconnect to retry." |
| `status === "inactive"` after 60+ seconds | Payment was cancelled or failed | Show: "Payment not received. Please try again." |
| 120 seconds elapsed | Timeout | Show: "Taking longer than expected. Check back in My Devices." |

### Pseudocode

```javascript
async function pollPaymentStatus(customerId) {
  const startTime = Date.now();
  const MAX_POLL_MS = 120_000;
  const INTERVAL_MS = 4_000;

  while (Date.now() - startTime < MAX_POLL_MS) {
    const res = await fetch(`/api/hotspot/payment-status/${customerId}`);
    const data = await res.json();

    if (data.status === "active") {
      // Payment confirmed — show success
      return { success: true, data };
    }

    if (data.status === "inactive" && Date.now() - startTime > 60_000) {
      // Likely cancelled / failed
      return { success: false, reason: "payment_failed" };
    }

    await new Promise(r => setTimeout(r, INTERVAL_MS));
  }

  return { success: false, reason: "timeout" };
}
```

---

## 6. Pair Device with Voucher

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

**Field Reference:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `device_mac` | string | **Yes** | — | MAC address (any format accepted) |
| `voucher_code` | string | **Yes** | — | Voucher code e.g. `1234-5678` |
| `router_id` | int | **Yes** | — | Router ID |
| `device_name` | string | No | `"Device XX:XX"` | Friendly name |
| `device_type` | string | No | `"tv"` | `tv`, `console`, `laptop`, `iot`, `other` |

### Response — Direct API Router (200)

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

### Response — RADIUS Router (200)

```json
{
  "success": true,
  "customer_id": 43,
  "pairing_id": 8,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "auth_method": "RADIUS",
  "radius_username": "AABBCCDDEEFF",
  "radius_password": "AABBCCDDEEFF",
  "message": "Device paired with voucher via RADIUS."
}
```

**Frontend note:** Voucher provisioning is immediate. No polling needed. Show the success screen right away with the plan name and expiry.

### Error Responses

| Status | `detail` value | User-friendly message |
|--------|----------------|----------------------|
| 400 | `"Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF"` | "Please check the MAC address" |
| 400 | `"Voucher has already been used"` | "This voucher code has already been redeemed" |
| 400 | `"Voucher has been disabled"` | "This voucher code is no longer valid" |
| 400 | `"Voucher has expired"` | "This voucher code has expired" |
| 400 | `"This voucher is not valid for this hotspot"` | "This voucher can't be used on this network" |
| 404 | `"Voucher code not found"` | "Voucher code not found. Please check and try again." |
| 404 | `"Router not found"` | "This hotspot is not available" |
| 500 | `"Device voucher pairing failed: ..."` | "Something went wrong. Please try again." |

---

## 7. Check Device Status

### `GET /api/public/device/status/{router_id}/{mac}`

Check the pairing, payment, and provisioning status of a single device.

The `mac` parameter in the URL accepts any format: `AA:BB:CC:DD:EE:FF`, `AABBCCDDEEFF`, etc.

**Example:** `GET /api/public/device/status/1/AA:BB:CC:DD:EE:FF`

### Response — Device is Paired (200)

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

### Response — Device Not Paired (200)

```json
{
  "paired": false,
  "message": "Device is not paired on this router"
}
```

### Key Fields to Display

| Field | Where | Display |
|-------|-------|---------|
| `pairing.device_name` | Card title | "Living Room TV" |
| `pairing.device_type` | Icon | See icon mapping in [Section 13](#13-suggested-ui-layout) |
| `customer.status` | Badge | `"active"` = green, `"pending"` = yellow, `"inactive"` = gray |
| `customer.expiry` | Subtitle | "Expires: Apr 13, 2026" |
| `customer.plan_name` | Subtitle | "Plan: Daily 10Mbps" |
| `delivery.delivery_status` | Status dot | See [Section 12](#12-delivery-status-reference) |
| `delivery.last_error` | Error text | Show if not null |

### Error Responses

| Status | `detail` value | User-friendly message |
|--------|----------------|----------------------|
| 400 | `"Invalid MAC address format"` | "Please check the MAC address" |
| 500 | `"Failed to get device status: ..."` | "Could not check device status. Please try again." |

---

## 8. List Paired Devices

### `GET /api/public/device/paired/{router_id}/{phone}`

Get all active paired devices for a customer identified by phone number.

**Example:** `GET /api/public/device/paired/1/0712345678`

### Response — Has Devices (200)

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

### Response — No Devices (200)

```json
{
  "phone": "0712345678",
  "router_id": 1,
  "devices": [],
  "count": 0
}
```

### Frontend Notes

- Use `count` to show/hide the "My Devices" section. If `count === 0`, show a message like "No devices paired yet" with an "Add Device" button.
- Each device in the `devices` array has an `id` field — this is the `pairing_id` needed for unpair and is used as the key for the list.
- `expires_at` can be `null` if provisioning hasn't completed yet.
- To check if a device is expired: `new Date(device.expires_at) < new Date()`.

### Error Responses

| Status | `detail` value | User-friendly message |
|--------|----------------|----------------------|
| 404 | `"Router not found"` | "This hotspot is not available" |
| 500 | `"Failed to list devices: ..."` | "Could not load your devices. Please try again." |

---

## 9. Unpair a Device

### `DELETE /api/public/device/unpair/{pairing_id}`

Remove a paired device. Deactivates the pairing in the database and removes the hotspot user + IP binding from the MikroTik router.

Use the `id` field from the device list as the `pairing_id`.

**Example:** `DELETE /api/public/device/unpair/7`

**Request Body:** None.

### Response — Success (200)

```json
{
  "success": true,
  "pairing_id": 7,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "router_cleanup": "removed_from_router",
  "message": "Device unpaired successfully"
}
```

### Response — Already Unpaired (200)

```json
{
  "success": true,
  "message": "Device is already unpaired"
}
```

### `router_cleanup` Values

| Value | Meaning | What to Show |
|-------|---------|-------------|
| `"removed_from_router"` | Fully cleaned up on router | "Device removed successfully" |
| `"router_unreachable"` | Pairing removed from DB but router was offline | "Device removed. Note: the router was offline — the device may stay connected until the router restarts." |
| `"removal_error: ..."` | Pairing removed from DB but router command failed | Same as above |

### Frontend Notes

- Show a confirmation dialog before unpairing: "Remove Living Room TV? This will disconnect the device from the internet."
- After successful unpair, remove the device from the list or refresh the list via `GET /api/public/device/paired/{router_id}/{phone}`.

### Error Responses

| Status | `detail` value | User-friendly message |
|--------|----------------|----------------------|
| 404 | `"Pairing not found"` | "Device not found. It may have already been removed." |
| 500 | `"Failed to unpair device: ..."` | "Could not remove device. Please try again." |

---

## 10. Reconnect a Device

### `POST /api/public/device/reconnect`

Re-provision a device that lost internet connectivity but still has an active, non-expired subscription. Useful when MikroTik was rebooted or the device's session expired.

**Request Body:**

```json
{
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "router_id": 1,
  "owner_phone": "0712345678"
}
```

**Field Reference:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `device_mac` | string | **Yes** | MAC address (any format) |
| `router_id` | int | **Yes** | Router ID |
| `owner_phone` | string | **Yes** | Must match the phone used when the device was paired (ownership check) |

### Response — Success (200)

```json
{
  "success": true,
  "customer_id": 42,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "device_name": "Living Room TV",
  "message": "Device reconnection started. It should come online shortly."
}
```

### Response — RADIUS Router (200)

```json
{
  "success": true,
  "customer_id": 42,
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "auth_method": "RADIUS",
  "radius_username": "AABBCCDDEEFF",
  "radius_password": "AABBCCDDEEFF",
  "message": "Device reconnected via RADIUS."
}
```

### Frontend Notes

- After a successful reconnect, show a brief "Reconnecting..." state, then optionally poll `GET /api/public/device/status/{router_id}/{mac}` once or twice to confirm `delivery.delivery_status` becomes `"online"`.
- The reconnect button should only be visible for devices where `expires_at` is in the future.
- If the plan has expired, guide the user to pair again with a new plan instead.

### Error Responses

| Status | `detail` value | User-friendly message |
|--------|----------------|----------------------|
| 400 | `"Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF"` | "Please check the MAC address" |
| 400 | `"Customer subscription is not active. Please purchase a new plan."` | "Your plan has ended. Please purchase a new plan for this device." |
| 400 | `"Subscription has expired. Please purchase a new plan."` | "Your plan expired on [date]. Please purchase a new plan." |
| 400 | `"No plan associated with this device"` | "No plan found for this device. Please add it again." |
| 403 | `"Phone number does not match the device owner"` | "This phone number doesn't match the one used to register this device." |
| 404 | `"No active pairing found for this device on this router"` | "This device is not registered on this hotspot. Please add it first." |
| 404 | `"Customer record not found"` | "Device record not found. Please add the device again." |
| 404 | `"Router not found"` | "This hotspot is not available" |
| 500 | `"Device reconnection failed: ..."` | "Could not reconnect. Please try again." |

---

## 11. MAC Address Input UX

The MAC address is the most critical input. Most customers have never seen a MAC address before. Make it as easy as possible.

### Accepted Formats

The backend normalizes all of these to `AA:BB:CC:DD:EE:FF`:

| Input | Valid |
|-------|-------|
| `AA:BB:CC:DD:EE:FF` | Yes (colon-separated) |
| `AA-BB-CC-DD-EE-FF` | Yes (dash-separated) |
| `AABB.CCDD.EEFF` | Yes (dot-separated) |
| `AABBCCDDEEFF` | Yes (bare hex) |
| `aa:bb:cc:dd:ee:ff` | Yes (lowercase) |
| `AA:BB:CC:DD:EE` | No (too short) |
| `GG:HH:II:JJ:KK:LL` | No (invalid hex) |

### Client-Side Validation Regex

```javascript
function isValidMac(mac) {
  const clean = mac.replace(/[:\-.\s]/g, '').toUpperCase();
  return /^[0-9A-F]{12}$/.test(clean);
}
```

### Auto-Format as User Types

```javascript
function formatMacInput(value) {
  const clean = value.replace(/[^0-9A-Fa-f]/g, '').toUpperCase().slice(0, 12);
  const pairs = clean.match(/.{1,2}/g) || [];
  return pairs.join(':');
}

// Usage: onChange={(e) => setMac(formatMacInput(e.target.value))}
// Typing "AABB" → displays "AA:BB"
// Typing "AABBCCDDEEFF" → displays "AA:BB:CC:DD:EE:FF"
// Pasting "AA-BB-CC-DD-EE-FF" → displays "AA:BB:CC:DD:EE:FF"
```

### Input Field Recommendations

- Placeholder text: `XX:XX:XX:XX:XX:XX`
- Use `inputMode="text"` and `autoCapitalize="characters"`
- Show a character counter: `6/12 characters` (count hex chars only)
- Show a green checkmark when 12 valid hex chars are entered
- Use monospace font for the input

### "Where do I find this?" — Per Brand Instructions

Display as a collapsible accordion below the MAC input:

| Brand | Instructions |
|-------|-------------|
| **Samsung Smart TV** | Settings > General > Network > Network Status > IP Settings — "MAC Address" |
| **LG Smart TV (webOS)** | Settings > All Settings > General > About This TV — "Wi-Fi MAC Address" |
| **Sony Bravia / Android TV** | Settings > Device Preferences > About > Status — "Wi-Fi MAC Address" |
| **Roku TV / Roku Stick** | Settings > Network > About — "Wireless MAC address" |
| **Amazon Fire TV / Fire Stick** | Settings > My Fire TV > About > Network — "Wi-Fi MAC Address" |
| **Apple TV** | Settings > General > About — "Wi-Fi Address" |
| **Xbox** | Settings > General > Network Settings > Advanced Settings — "Wireless MAC" |
| **PlayStation (PS4/PS5)** | Settings > Network > View Connection Status — "MAC Address (Wi-Fi)" |
| **Nintendo Switch** | System Settings > Internet — "System MAC Address" |
| **Generic / Other** | Look in your device's WiFi or Network settings for "MAC Address" or "Hardware Address" |

---

## 12. Delivery Status Reference

The `delivery.delivery_status` field in the device status response tells you the provisioning state. Map it to your UI:

| `delivery_status` | Meaning | UI |
|--------------------|---------|-----|
| `"online"` | Device is provisioned and confirmed online | Green dot + "Online" |
| `"access_ready"` | Provisioned on router, device hasn't connected to WiFi yet | Blue dot + "Ready — connect your device to WiFi" |
| `"scheduled"` | Provisioning is queued | Spinner + "Setting up..." |
| `"attempting"` | Actively being provisioned on the router | Spinner + "Connecting..." |
| `"failed"` | Provisioning failed (router unreachable, etc.) | Red dot + "Setup failed" + show Reconnect button |
| `"offline"` | Was online before but currently offline | Gray dot + "Offline" + show Reconnect button |
| `null` | No provisioning attempt exists yet (payment pending) | Yellow dot + "Waiting for payment" |

### `customer.status` Values

| `status` | Meaning | UI |
|----------|---------|-----|
| `"active"` | Paid and provisioned | Normal display |
| `"pending"` | Payment initiated, waiting for confirmation | Show "Payment pending..." |
| `"inactive"` | No active subscription | Show "Expired" or "Not active" |

---

## 13. Suggested UI Layout

### A. Entry Point — Main Portal Page

Add a prominent button next to the existing "Connect" flow:

```
┌───────────────────────────────────────────────┐
│                                               │
│          Welcome to [Hotspot Name]            │
│                                               │
│   ┌─────────────────┐  ┌──────────────────┐  │
│   │  Connect Your    │  │  Connect a TV /  │  │
│   │  Phone           │  │  Other Device    │  │
│   │  [Phone icon]    │  │  [TV icon]       │  │
│   └─────────────────┘  └──────────────────┘  │
│                                               │
│         "Connect Your Phone" uses the         │
│          existing flow. No changes.           │
│                                               │
│         "Connect a TV / Other Device"         │
│          opens the new device pairing form.   │
└───────────────────────────────────────────────┘
```

### B. Device Pairing Form — Step by Step

**Step 1: Device Info**
```
┌───────────────────────────────────────────────┐
│  Connect a Device                             │
│                                               │
│  MAC Address *                                │
│  ┌─────────────────────────────────────────┐  │
│  │  AA:BB:CC:DD:__:__                    ✓ │  │
│  └─────────────────────────────────────────┘  │
│  ▸ Where do I find this?                      │
│    (expands to show per-brand instructions)   │
│                                               │
│  Device Type                                  │
│  [📺 TV]  [🎮 Console]  [💻 Laptop]  [Other] │
│                                               │
│  Device Name (optional)                       │
│  ┌─────────────────────────────────────────┐  │
│  │  Living Room TV                         │  │
│  └─────────────────────────────────────────┘  │
│                                               │
│                            [ Next → ]         │
└───────────────────────────────────────────────┘
```

**Step 2: Select Plan**
```
┌───────────────────────────────────────────────┐
│  Select a Plan for Living Room TV             │
│                                               │
│  ┌────────────────┐  ┌────────────────┐       │
│  │ Daily 10Mbps   │  │ Weekly 20Mbps  │       │
│  │ KES 50 / 1 day │  │ KES 300 / 7 d  │       │
│  │   [ Select ]   │  │   [ Select ]   │       │
│  └────────────────┘  └────────────────┘       │
│                                               │
│  ┌────────────────┐                           │
│  │ Monthly 50Mbps │                           │
│  │ KES 1000 / 30d │                           │
│  │   [ Select ]   │                           │
│  └────────────────┘                           │
│                                               │
│  ─── Or use a voucher ───                     │
│  ┌─────────────────────────────────────────┐  │
│  │  Enter voucher code: ____-____          │  │
│  └─────────────────────────────────────────┘  │
│                           [ Apply Voucher ]   │
└───────────────────────────────────────────────┘
```

**Step 3: Payment (M-Pesa)**
```
┌───────────────────────────────────────────────┐
│  Pay for Living Room TV                       │
│                                               │
│  Plan: Daily 10Mbps                           │
│  Amount: KES 50                               │
│                                               │
│  Phone Number *                               │
│  ┌─────────────────────────────────────────┐  │
│  │  0712345678                             │  │
│  └─────────────────────────────────────────┘  │
│                                               │
│                    [ Pay KES 50 with M-Pesa ] │
│                                               │
│  ── After tapping Pay: ──                     │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │  ⏳ Waiting for M-Pesa payment...       │  │
│  │  Check your phone for the STK push.     │  │
│  │  Enter your M-Pesa PIN to confirm.      │  │
│  └─────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
```

**Step 4: Success**
```
┌───────────────────────────────────────────────┐
│                                               │
│              ✓ Device Connected!              │
│                                               │
│  📺 Living Room TV                            │
│  MAC: AA:BB:CC:DD:EE:FF                       │
│  Plan: Daily 10Mbps                           │
│  Expires: Apr 13, 2026 at 12:00 PM           │
│                                               │
│  Your TV should now have internet access.     │
│  If it doesn't connect automatically,         │
│  restart the TV's WiFi connection.            │
│                                               │
│  [ View My Devices ]   [ Done ]              │
└───────────────────────────────────────────────┘
```

### C. My Devices Panel

Accessible by entering a phone number. Call `GET /api/public/device/paired/{router_id}/{phone}`.

```
┌───────────────────────────────────────────────┐
│  My Devices                                   │
│  Phone: 0712345678                            │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │  📺 Living Room TV         ● Online     │  │
│  │  MAC: AA:BB:CC:DD:EE:FF                 │  │
│  │  Plan: Daily 10Mbps                     │  │
│  │  Expires: Apr 13, 2026                  │  │
│  │                                         │  │
│  │  [ Reconnect ]           [ Remove ]     │  │
│  └─────────────────────────────────────────┘  │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │  🎮 PS5                    ● Online     │  │
│  │  MAC: 11:22:33:44:55:66                 │  │
│  │  Plan: Weekly 20Mbps                    │  │
│  │  Expires: Apr 19, 2026                  │  │
│  │                                         │  │
│  │  [ Reconnect ]           [ Remove ]     │  │
│  └─────────────────────────────────────────┘  │
│                                               │
│              [ + Add Another Device ]         │
└───────────────────────────────────────────────┘
```

**Button actions:**

| Button | API Call | Notes |
|--------|----------|-------|
| Reconnect | `POST /api/public/device/reconnect` | Pass `device_mac`, `router_id`, `owner_phone` |
| Remove | `DELETE /api/public/device/unpair/{id}` | Show confirmation dialog first. Use `id` from the device object |
| + Add Another Device | Navigate to Step 1 | Pre-fill `router_id` and `owner_phone` |

### D. Device Type Icon Mapping

```javascript
const deviceIcons = {
  tv:      '📺',  // or a Monitor/TV SVG icon
  console: '🎮',  // or a Gamepad SVG icon
  laptop:  '💻',  // or a Laptop SVG icon
  iot:     '📡',  // or a Chip/WiFi SVG icon
  other:   '📱',  // or a generic Device SVG icon
};
```

---

## 14. Complete Error Reference

All error responses have this shape:

```json
{
  "detail": "Error message here"
}
```

Access it via `response.data.detail` (axios) or `(await response.json()).detail` (fetch).

### All Errors by Endpoint

#### `POST /api/public/device/pair-and-pay`

| Status | `detail` | Show to User |
|--------|----------|-------------|
| 400 | `Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF` | Please check the MAC address. It should look like AA:BB:CC:DD:EE:FF |
| 400 | `Invalid phone number format` | Please enter a valid phone number (at least 10 digits) |
| 400 | `Invalid payment method. Must be one of: mobile_money, cash` | Please select a valid payment method |
| 400 | `Plan does not belong to this router's owner` | This plan is not available on this network |
| 400 | `Selected plan is not a hotspot plan` | Please select a WiFi plan |
| 404 | `Router not found` | This hotspot is not available. Please check your connection. |
| 404 | `Plan not found` | This plan is no longer available. Please select another. |
| 503 | `This service is temporarily unavailable. Please contact your ISP.` | Show as-is |
| 500 | `Device pairing failed: ...` | Something went wrong. Please try again. |

#### `POST /api/public/device/pair-voucher`

| Status | `detail` | Show to User |
|--------|----------|-------------|
| 400 | `Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF` | Please check the MAC address |
| 400 | `Voucher has already been used` | This voucher code has already been redeemed |
| 400 | `Voucher has been disabled` | This voucher code is no longer valid |
| 400 | `Voucher has expired` | This voucher code has expired |
| 400 | `Voucher is not available` | This voucher is not available |
| 400 | `This voucher is not valid for this hotspot` | This voucher can't be used on this network |
| 404 | `Voucher code not found` | Voucher code not found. Please check and try again. |
| 404 | `Router not found` | This hotspot is not available |
| 500 | `Device voucher pairing failed: ...` | Something went wrong. Please try again. |

#### `GET /api/public/device/status/{router_id}/{mac}`

| Status | `detail` | Show to User |
|--------|----------|-------------|
| 400 | `Invalid MAC address format` | Please check the MAC address |
| 500 | `Failed to get device status: ...` | Could not check device status. Please try again. |

#### `GET /api/public/device/paired/{router_id}/{phone}`

| Status | `detail` | Show to User |
|--------|----------|-------------|
| 404 | `Router not found` | This hotspot is not available |
| 500 | `Failed to list devices: ...` | Could not load your devices. Please try again. |

#### `DELETE /api/public/device/unpair/{pairing_id}`

| Status | `detail` | Show to User |
|--------|----------|-------------|
| 404 | `Pairing not found` | Device not found. It may have already been removed. |
| 500 | `Failed to unpair device: ...` | Could not remove device. Please try again. |

#### `POST /api/public/device/reconnect`

| Status | `detail` | Show to User |
|--------|----------|-------------|
| 400 | `Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF` | Please check the MAC address |
| 400 | `Customer subscription is not active. Please purchase a new plan.` | Your plan has ended. Please purchase a new plan for this device. |
| 400 | `Subscription has expired. Please purchase a new plan.` | Your plan has expired. Please purchase a new plan. |
| 400 | `No plan associated with this device` | No plan found for this device. Please add it again. |
| 403 | `Phone number does not match the device owner` | This phone number doesn't match the one used to register this device. |
| 404 | `No active pairing found for this device on this router` | This device is not registered on this hotspot. Please add it first. |
| 404 | `Customer record not found` | Device record not found. Please add the device again. |
| 404 | `Router not found` | This hotspot is not available |
| 500 | `Device reconnection failed: ...` | Could not reconnect. Please try again. |

---

## Postman Collection

Import `device-pairing-endpoints.postman_collection.json` from the project root into Postman for testing all endpoints:

**Postman > Import > Upload Files > select `device-pairing-endpoints.postman_collection.json`**
