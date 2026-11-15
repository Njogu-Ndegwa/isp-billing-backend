# Customer router (CPE) remote control

Bitwave reaches a customer router from its serving MikroTik, using the live PPPoE session address on each action. The address is never used as customer identity. No public port forwarding is required. The MikroTik management tunnel must be healthy.

## One-time Tenda setup

1. Configure the Tenda in router mode with the assigned customer's PPPoE credentials on its WAN/Internet port. Confirm an active session on the correct MikroTik.
2. From the Tenda's local administration page, enable Remote Web Management. Set the web port (the tested device uses 8080). Restrict the allowed management source to the MikroTik's PPPoE local/gateway address; the test line uses 192.168.89.1. Do not copy that address to other networks without checking their gateway.
3. On the customer page, save the Tenda admin password and the same web port. It is encrypted and never returned by the API. Select Tenda if the hardware model is unknown.
4. Check status before restarting. Restart interrupts the customer router; Disconnect line only removes its PPPoE session so it can redial. Neither reboots the MikroTik.

Remote management cannot be enabled through a WAN administration interface that is not yet reachable. That initial opt-in requires local access or an already-configured management channel.

## Verified and unverified support

| Protocol / device | Status | Restart | Limits |
|---|---|---|---|
| Tenda V12.01.01.59_multi, MikroTik ROS 7.19.6 | Deployed API/dashboard passed | Deployed API/dashboard passed; observed drop and redial in 29s | Verified November 15, 2026 on customer 53867/router 563. Hardware model not exposed by device status. |
| Existing Tenda legacy/F3/OAP adapters | Regression tests pass | Regression tests pass | Not live-qualified by this test. |
| Other Tenda firmware / other vendors | Not claimed | Not claimed | Add a firmware adapter and qualify against a real device before advertising support. |

V12 authentication is detected by its challenge response, independently of the saved model label. It uses a fresh challenge and server-issued cookie on each action. Unsupported responses are reported separately from rejected passwords. The V12 adapter does not expose unverified AP-mode or LAN configuration writes.

## Adding a firmware family

Keep authentication, status parsing, reboot payload and acknowledgement in a distinct adapter in `app/services/ap_adapters.py`. Reuse `RouterFetchHttpClient` for transport and cookie handling; never follow redirects with credentials. Capture sanitized request/response shapes in a fake that rejects incorrect commands. Test wrong passwords, missing sessions, unsupported status, rejected writes, and legacy regressions. Then prove status, session drop/redial, concurrent-action rejection, and dashboard behavior on one identified test device.

See [the dated test report](cpe-e2e-2026-11-15.md) for the exact live evidence and final release results.
