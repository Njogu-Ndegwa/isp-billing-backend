# 2026-11-15 Tenda V12 CPE status adapter incompatible with real firmware

## Summary

The first live CPE test reached customer 53867's Tenda through MikroTik 563. Disconnect/redial passed; status failed with HTTP 502 because the adapter's assumed authentication and status protocol does not match firmware `V12.01.01.59_multi`. The initial ordered test stopped at status. The firmware fix subsequently passed an isolated live status/reboot test; release verification is recorded below.

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

## Fix and isolated live verification

The firmware adapter now probes `getstok`, uses the challenge digest and captures the returned `ecos_pw` cookie from RouterOS `output=user-with-headers`. Redirect following is disabled. Status uses the observed nested modules; reboot uses `POST /goform/sysReboot` with `module1=sysOperate&action=reboot` and requires `errCode=100`. Unrecognised status is an unsupported-firmware error and does not increment the bad-password counter. Remote AP configuration remains unavailable for this firmware until its setters are verified.

At 19:59:42 EAT the candidate read firmware `V12.01.01.59_multi`, mode `router`, and the live session address/uptime through MikroTik 563 in 6.08 seconds. At 19:59:49 the reboot was accepted (7.42-second request). The observer saw no PPPoE session at 19:59:52 and a new session at 20:00:11 with uptime 0s, 29.1 seconds after request start. This was the CPE service candidate loaded only into an isolated Python process, not a deployment or production API pass.

The focused AP/CPE, transport, interactive mutation, port, and PPPoE redirect tests passed: 170 tests, including 23 wire-level V12 regression cases. Session-discipline guard passed. Physical model remains unknown because this status response does not expose it; no model is inferred from firmware.

## Production persistence failure and follow-up

PR 361 deployed as `3ffc498` at 20:39 EAT. At 20:40:41, the dashboard GET `/api/customers/53867/cpe/status` returned HTTP 500 `Internal server error`. The device login/status read completed, but `_persist_outcome` failed at `customer_cpe_routes.py:187`: `StringDataRightTruncationError: value too long for type character varying(16)`. The new login-method identifier `tenda_v12_challenge` had 19 characters; both credential tables limit it to 16. The transaction rolled back, leaving the earlier failed-login count and error unchanged. No production API reboot was attempted.

The identifier is shortened to `tenda_v12`, requiring no schema change. Regression coverage now checks the existing column bounds and runs successful status and reboot through the real HTTP route and outcome persistence. The bounds test reproduced the defect before the fix (19 > 16); CI runs the HTTP cases against Postgres. This closes the gap left by the isolated device/service test.

## Concurrent status authentication

The write routes already held a per-MikroTik CPE/AP action claim, but status reads used only the generic router connection guard. That guard allows two connections per router, so a status login could overlap another status or reboot and replace the Tenda's challenge/session cookie. PR 362 routes both CPE and AP status through the same claim as writes. Busy requests return HTTP 409 before contacting the device or persisting an outcome. The started worker retains ownership after caller timeout/cancellation, while abandoned queued requests cannot run later. HTTP overlap and worker-lifetime regressions passed in the 129-test focused run. Live deployed concurrency verification is recorded in the final report.

## Final deployed verification

Backend PR 362 merged as `629cecb` at 21:20:41 EAT; deployment succeeded and the new container started at 21:24:22. All 5,127 tests passed with no failures, errors or skips. At 21:25:10 the public API/dashboard status returned 200. A confirmed dashboard reboot returned 200 at 21:25:57; the observer saw the session drop and return at 21:26:18 with a new ID and zero uptime (29 seconds from request start). Follow-up status passed. Concurrent status requests produced 200/409 and the matching UI error toast. Disconnect returned 200 and redial completed in about five seconds. Final status passed at 21:28:00; at 21:28:20 the saved credential had zero failures, no error, successful login and a persisted reboot timestamp. Public health returned 200; the app was healthy with zero restarts.

The frontend generic-model correction shipped in PR 196. Hardware model remains unknown; firmware V12.01.01.59_multi and ROS 7.19.6 are the live-qualified combination. Other firmware and unverified AP/LAN setters require separate qualification. Full request/response/log evidence, timestamps and the seven-step table are in [the final report](../../cpe-e2e-2026-11-15.md).
