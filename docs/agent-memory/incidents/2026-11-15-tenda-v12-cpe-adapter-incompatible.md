# 2026-11-15 Tenda V12 CPE status adapter incompatible with real firmware

## Summary

The first live CPE test reached customer 53867's Tenda through MikroTik 563. Disconnect/redial passed; status failed with HTTP 502 because the adapter's assumed authentication and status protocol does not match firmware `V12.01.01.59_multi`. No CPE API reboot was attempted and no fix was deployed.

## Symptoms

- Panel GET 200 at 19:43:10 EAT.
- Disconnect POST 200 at 19:43:12; session returned by 19:43:14 with new ID and uptime 2s (4.1s from request start).
- Port 8080 responds through MikroTik; 80 and 8888 time out. Tenda remote management allows only source `192.168.89.1`.
- Credential saved at 19:44:41, with explicit user permission for agent entry of the test password.
- Status GET 502 at 19:44:52; credential `last_login_ok=false`, failed count 1, no status or login method persisted.
- Error and `last_error`: `The router (CPE) answered but no session opened: the saved admin password was rejected, or this model/firmware is not supported. Check the password and the selected model.`

## Cause and evidence

The password worked in the Tenda's own UI. Its served `js/login.js` calls `/goform/getstok`, reads `res.random`, then submits `MD5(Base64(password) + random)` to `/login/Auth`. The authenticated browser carries a cookie named `ecos_pw`. By contrast, `app/services/ap_adapters.py:49` / `:133` only tries raw MD5 or Base64 and a deterministic cookie named `password`; `app/services/ap_fetch.py:146` retains that guessed cookie rather than the observed firmware session cookie.

Both status candidates at `app/services/ap_adapters.py:218` / `:330` are absent on this device. Authenticated GETs return HTTP 200, content type text/html, with `Form getSysStatusInfo is not defined` or `Form GetRouterStatus is not defined`. The actual frontend uses `/goform/getStatus?modules=internetStatus,systemInfo,wifiRelay`, returning JSON with these nested objects. Relevant fields are `systemInfo.softVersion`, `statusWanIP`, `statusWanGaterway`, `wanConnectTime`, and `wifiRelay.wifiRelayType`. The mode value `disabled` means repeater/AP modes are disabled (normal router mode). A flat-key parsing extension alone will not suffice.

At 19:46:27 a diagnostic request through the MikroTik successfully fetched the challenge. Submitting the challenge-encoded login returned 302; a subsequent status read without the firmware session cookie returned 302 too. This does not prove authenticated transport succeeds; cookie handling remains required. The logged-in phone browser returned the correct status JSON from the LAN.

`app/services/ap_control.py:369` / `:380` treats failure to read any known status endpoint as failed authentication. `app/api/customer_cpe_routes.py:164` increments the credential failure counter for that result. Unsupported firmware therefore consumes the wrong-password allowance and can eventually lock a valid credential. Further test actions were stopped after this failure.

## Setup repairs applied with approval

The original Tenda was in AP mode and its saved account matched expired customer 2744 on router 207. Dennis selected active customer 53867 on router 563 instead. AP mode was disabled (configuration reboot at 19:40:05); existing customer 53867 credentials were configured. No customer expiry or MikroTik PPP secret was changed. Ether2 was changed from temporary plain mode to dedicated PPPoE directly at 19:42:17–30; ether3 was preserved and DB port fields synchronized. Remote management was enabled on 8080 and restricted to the PPPoE gateway source. This is authorized test-device setup, not evidence of a successful API reboot.

## Verification

At 19:46:26 the PPPoE session was active at `192.168.89.254`, uptime 3m13s, and caller identity matched the Tenda. The phone remained on Tenda LAN `192.168.0.100`. Firmware was read from the authenticated device; physical model was not independently confirmed. Passwords, cookie values, challenges and full MACs are intentionally absent.

Application access-log evidence and the seven-step table are in [the CPE test report](../../cpe-e2e-2026-11-15.md). Production backend revision for this test: `0319f48410617cd1020d7a61d94bac6d85d37727`.

## Follow-up

- Implement firmware-aware challenge authentication and session-cookie transport, then validate through MikroTik on this device. MikroTik documents `output=user-with-headers` in its [Fetch manual](https://help.mikrotik.com/docs/spaces/ROS/pages/8978514/Fetch); actual behavior with this firmware's 302 login response still needs verification before selecting that transport approach.
- Add the observed status endpoint and nested schema, with explicit unsupported-firmware errors rather than treating all unreadable status responses as wrong passwords.
- Capture sanitized response fixtures and test both challenge and legacy firmware, including cookie handling and unsupported-response classification.
- Re-run status before attempting the API reboot, concurrency and reseller UI checks. Do not mark the direct configuration reboot as the API reboot test.
- The separate slow-port-change fix is local commit `6d71f01`, 55 focused tests passed, not deployed. No CPE adapter fix is included in it.
