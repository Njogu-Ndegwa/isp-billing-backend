# RADIUS Authentication Failure - Diagnostic Report

**Date:** February 25, 2026
**System:** ISP Billing Platform with FreeRADIUS + MikroTik Hotspot
**Affected Router:** Router 3 — Identity "MikroTik", IP `10.0.0.3`, Profile `hsprof3`

---

## Symptom

Customers on the RADIUS-enabled router pay successfully via M-Pesa, but are **never granted internet access**. After payment the captive portal page reloads and they are asked to pay again. This is an infinite loop.

The FreeRADIUS server log shows:

```
Ready to process requests
```

…and **nothing else**. Zero authentication requests are ever received from the router.

---

## Investigation

### What works correctly

| Component | Status | Evidence |
|-----------|--------|----------|
| M-Pesa payment | OK | STK Push succeeds, callback received, `ResultCode: 0` |
| RADIUS user provisioning | OK | `radius_check` and `radius_reply` rows created (`E884A50506DB`) |
| Payment status API | OK | Returns `status: "active"` with `radius_username` and `radius_password` |
| FreeRADIUS container | OK | Running, connected to PostgreSQL, loaded `default` virtual server |
| FreeRADIUS SQL queries | OK | Queries point to `radius_check` / `radius_reply` with expiry filtering |
| MikroTik RADIUS config | OK | `/radius print` → `address=10.0.0.1, secret=testing12345, service=hotspot` |
| MikroTik RADIUS incoming | OK | `accept=yes, port=3799` |
| WireGuard connectivity | OK | `ping 10.0.0.1` from MikroTik → 0% loss, ~211 ms RTT |
| Hotspot server | OK | `hotspot3` active on `bridge`, using profile `hsprof3` |
| Hotspot profile RADIUS | OK | `hsprof3` has `use-radius=yes`, `radius-accounting=yes` |

### Root cause found

The **active hotspot profile `hsprof3`** has:

```
login-by=cookie,http-chap
```

The frontend auto-login redirects the customer's browser to:

```
http://192.168.88.1/login?username=E884A50506DB&password=<cleartext>
```

This is an **HTTP-PAP** (cleartext password) login request. However, `http-pap` is **not listed** in the profile's `login-by` methods — only `cookie` and `http-chap` are allowed.

**MikroTik rejects the login before it ever reaches RADIUS.** The router does not send an Access-Request to FreeRADIUS because the login method itself is disallowed at the hotspot level. This is why FreeRADIUS logs show zero authentication attempts.

### How HTTP-CHAP vs HTTP-PAP works

- **HTTP-CHAP:** The MikroTik login page serves a JavaScript challenge. The browser hashes the password with the challenge before submitting. The server verifies the hash. This requires loading the full login page and executing its JavaScript — a simple URL redirect cannot do this.

- **HTTP-PAP:** The password is sent in cleartext via HTTP. A URL like `/login?username=X&password=Y` works directly. MikroTik accepts it and forwards to RADIUS as a PAP Access-Request.

The auto-login flow (URL redirect after payment) **requires HTTP-PAP** because the browser is redirected directly to the login URL without loading MikroTik's login page JavaScript.

---

## Frontend issues (secondary)

During investigation, three additional problems were found in the captive portal frontend (`isp-landing-page/script.js`) that compound the login loop:

### 1. Missing `dst` parameter in login URL

The `buildRadiusLoginUrl()` function builds:

```
http://<gateway>/login?username=X&password=Y
```

But omits the `dst` (destination) parameter. MikroTik uses `dst` to redirect the user after successful login. Without it, even a successful login may redirect back to the captive portal.

**Fix applied:** Updated `buildRadiusLoginUrl()` to accept and include `dst`. Updated all 3 call sites.

### 2. No page-load recovery from redirect loop

After payment, the frontend saves RADIUS credentials to `localStorage`, then redirects to MikroTik. If the login fails, MikroTik redirects back to the captive portal. The page loads fresh and shows the payment screen again — the credentials in `localStorage` are never checked.

**Fix applied:** Added `checkSavedRadiusLogin()` function that runs on page load. If recent (< 5 min) saved credentials exist, it shows a success screen and re-attempts the MikroTik login redirect. Credentials are cleared before redirect to prevent infinite loops.

### 3. Already-active customer not handled

When a customer with an active subscription hits "Pay" again, the backend returns their RADIUS credentials immediately (without charging). But the frontend ignores these and enters the payment polling loop unnecessarily.

**Fix applied:** Added early detection in `handlePayment()` — if the response already contains credentials with `status=active`, skip polling and redirect to login directly.

---

## Fix required on MikroTik

Run this command on the MikroTik router to add `http-pap` to the allowed login methods:

```routeros
/ip hotspot profile set hsprof3 login-by=cookie,http-chap,http-pap
```

### Verification steps after applying the fix

1. **Check the profile was updated:**

   ```routeros
   /ip hotspot profile print detail where name=hsprof3
   ```

   Confirm `login-by` now shows `cookie,http-chap,http-pap`.

2. **Monitor RADIUS authentication in real-time:**

   ```routeros
   /log print follow where topics~"radius"
   ```

   Then have a customer pay and watch for RADIUS Access-Request / Access-Accept messages.

3. **Check FreeRADIUS logs on the server:**

   ```bash
   docker logs isp_billing_radius -f
   ```

   Should now show incoming auth requests after a customer pays.

4. **Verify from the server that UDP 1812 is reachable** (optional extra check):

   ```bash
   sudo ss -ulnp | grep 1812
   ```

   Should show the Docker proxy listening on `0.0.0.0:1812`.

---

## Optional: additional hardening

If after adding `http-pap` you still see no RADIUS requests, check whether a firewall on the AWS server is blocking UDP 1812/1813 from the WireGuard subnet:

```bash
# Check UFW rules
sudo ufw status verbose

# If 1812/1813 are not allowed, add them:
sudo ufw allow from 10.0.0.0/24 to any port 1812 proto udp comment "RADIUS Auth"
sudo ufw allow from 10.0.0.0/24 to any port 1813 proto udp comment "RADIUS Accounting"
```

Note: Docker typically bypasses UFW by manipulating iptables directly, so this may not be necessary. But it's worth checking if the primary fix alone doesn't resolve the issue.

---

## Summary

| # | Issue | Where | Status |
|---|-------|-------|--------|
| 1 | `hsprof3` missing `http-pap` in `login-by` — MikroTik blocks cleartext URL login before RADIUS | MikroTik router | **Pending — requires one command** |
| 2 | Login URL missing `dst` parameter | Frontend `script.js` | Fixed |
| 3 | No page-load recovery from failed login redirect | Frontend `script.js` | Fixed |
| 4 | Already-active customer loops through payment polling | Frontend `script.js` | Fixed |

**The single most impactful fix is issue #1** — one MikroTik command. Without it, RADIUS authentication will never be attempted regardless of how correctly the backend and frontend are implemented.
