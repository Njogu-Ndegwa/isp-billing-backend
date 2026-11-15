# 2026-11-15 PPPoE expired portal disabled on test router 563

## Summary

During the Tenda CPE end-to-end test, Dennis clarified that the intended portal is the expired-customer PPPoE payment page, not the hotspot portal. MikroTik 563 had this feature disabled. It was enabled with approval and verified. PPPoE was subsequently added to the active ether2 bridge with approval, but no CPE session appeared. Both operations exposed excessive response times. A code fix is prepared locally; it has not been deployed.

## Symptoms

- At 19:03:11 EAT, `routers.pppoe_expired_redirect=false` and its configuration was null.
- The live MikroTik had no `bw-pppoe-expired` profile/pool, no expired-customer NAT/filter/address-list/proxy-access objects, and `/ip proxy enabled=false`.
- `GET /api/public/pppoe/expired/563` returned HTTP 404 with `{"detail":"Not available on this network"}` through both production API domains.
- The public `expired.html?r=563` page itself returned HTTP 200 and title `Renew your internet`.
- App access logs at 16:03:58 and 16:03:59 UTC (19:03 EAT) recorded the API 404s.
- No live PPPoE session existed. The only PPPoE server was enabled on `ether3`.
- Customer 53867 changed from INACTIVE to ACTIVE between observations, with expiry 2026-11-16 18:45:56 EAT; this agent did not activate it. Its enabled secret used the normal `pppoe_5M_5M` profile. It is not currently an expired test customer.

## Suspected Cause

The API 404 is deliberate: `app/api/pppoe_expired_routes.py:199-202` refuses routers whose per-router switch is off. The absence of router redirect infrastructure agrees with the disabled flag. All four routers owned by reseller 20 had the flag off during the read-only check.

Separately, the Tenda's PPPoE connection and mode remain unverified. The phone previously received both a Tenda LAN lease and a direct MikroTik DHCP lease while on the Tenda SSID, and Android rejects that saved network as `NETWORK_SELECTION_DISABLED_NO_INTERNET_PERMANENT`. Dennis confirmed the cable uses the Tenda WAN port. Do not treat this as proof of a specific Tenda mode or a working PPPoE path.

## Fix Applied

Dennis explicitly approved enabling expired PPPoE redirect on router 563. At 19:04:58 EAT, one `PUT /api/routers/563/pppoe-expired-redirect` request with `{"enabled":true}` was submitted through the running app as the owning reseller. The client raised `httpx.ReadTimeout` after 120 seconds, but the app continued and completed at 19:08:12 EAT, approximately 194 seconds after submission. There was no duplicate enable request.

App logs:

```text
2026-11-15T16:08:12.766096913Z INFO:pppoe_expired_redirect:expired redirect: router 563 repaired with 25 write(s)
2026-11-15T16:08:12.776188253Z INFO:pppoe_expired_routes:PPPoE expired redirect enabled on router 563 by user 20
```

No code was deployed, no customer was expired or activated by this agent, and no device was rebooted.

## Verification

Read-only production DB, live RouterOS prints, public HTML/API HTTP checks and app logs established the initial blocker. Source base: backend production/fetched `origin/main` `0319f48410617cd1020d7a61d94bac6d85d37727`.

At 19:08:52–19:08:57 EAT:

- Persisted enabled flag true; applied timestamp 16:08:12 UTC.
- Walled pool `10.254.252.0/22`, profile `bw-pppoe-expired`, gateway `10.254.252.1`, address list `BW_PPPOE_EXPIRED` present.
- Proxy enabled on port 3346; HTTP NAT redirects the expired address list to that port.
- Proxy access uses RouterOS 7 `action=redirect`, `action-data=https://isp-frontend-two.vercel.app/expired.html?r=563`, source `10.254.252.0/22`, local port 3346.
- DNS and portal allow rules plus the remaining-traffic rejects installed. Their forward-chain rules precede all existing static rules; only the untouched dynamic rules precede them. Proxy input allow precedes the proxy guard.
- Public `GET /api/public/pppoe/expired/563` now returns HTTP 200 with three plans. Response personal details were not printed.
- PPPoE active-session count remains zero. Physical check: ether1 and ether2 running, ether3/ether4/ether5 not running. Ether2 belongs to the regular bridge; the PPPoE server is enabled on ether3 only. Dennis confirmed the Tenda end is WAN; the MikroTik cable-end port is awaiting physical confirmation.

The long enable request is a confirmed usability/reliability defect. `app/api/pppoe_expired_routes.py:89` waits unbounded on `router_locks.acquire`, then awaits an unbounded worker; `app/services/mikrotik_background.py:134` shares three global slots with background jobs. Queue starvation is a plausible explanation, supported by fast direct RouterOS reads and no DB lock waiters during the stall, but no live stack/queue trace established which wait consumed the time. A related endpoint already bounds this wait in `app/api/load_balancing_routes.py:119`. Do not claim the entire 194 seconds was proven queue time.

## Follow-Up Work

- DONE: verify the approved enable request, persisted flag, live router objects and public API response.
- Establish the Tenda WAN mode and its live PPPoE session, then use an explicitly designated expired test account to verify HTTP redirect, portal access and payment-page loading. Customer 53867 is currently active; do not expire it without explicit authorization.
- Add bounded queue wait and explicit progress/retry behavior to the expired-redirect toggle. Preserve per-router serialization for the actual lifetime of the router worker, including caller timeouts. Prepare and test separately; no deployment is authorized by this incident note.
- Do not mark CPE status/reboot or expired-customer end-to-end behavior passed based only on infrastructure/API checks.

## Approved active-port PPPoE follow-up

Dennis subsequently authorized providing PPPoE on whichever LAN port is active. Ether2 was the only active LAN port. To retain its existing service, one supported API request was submitted at 19:13:02 EAT: `PUT /api/routers/563/dual-ports` with `{"ports":["ether2"],"repair_hotspot":false}`. This uses the existing shared-bridge PPPoE implementation, keeps the dedicated ether3 configuration, and skips hotspot-page repair. The API returned 202 at 19:14:17 with job `8bcc532ca7d14caeb8ce27f05c669c43`. The job finished at 19:19:28, elapsed 385.5 seconds, success true, warnings empty. At 19:21:09 the DB dual ports were `["ether2"]`, ether2 was still an active bridge member, and the enabled `pppoe-dual-bridge` server existed alongside the ether3 server. There were still zero PPP sessions.

At 19:25:58 another read confirmed customer 53867 ACTIVE, unexpired until November 16 at 18:45:56 EAT, on a one-day plan. Its PPP secret was enabled on the normal `pppoe_5M_5M` profile, but no session existed. Customer 41828 remained expired with no secret. Extending 53867's plan would not resolve its current lack of a session; the Tenda account match remains unverified.

## Delay fix prepared locally

Port-mode endpoints and the expired-redirect toggle now use `app/services/router_mutations.py`. It retains the shared per-router mutex, but uses two dedicated interactive worker threads and a separate bounded semaphore. Admission (router mutex plus worker capacity) has a five-second deadline and returns HTTP 429 without starting a delayed write when busy. Cancellation while queued removes the request; cancellation after submission leaves an owner task holding the mutex and capacity until the synchronous worker finishes. Queue and total duration are logged separately. Existing port-job 202/progress handling remains.

Focused validation: 55 tests passed across `test_router_mutations.py`, `test_port_config_jobs.py`, `test_pppoe_expired_redirect.py`, `test_pppoe_expired_redirect_flow.py`, and `test_pppoe_subnet_and_nat.py`. The new tests cover saturated background capacity/default executor, same-router serialization, admission timeout cleanup, queued and running cancellation (including cancellation as admission completes), worker failure cleanup, and both route adapters' 429 responses. This removes a demonstrated unbounded scheduling path; it does not establish which wait consumed all 385.5 seconds or prove a production latency improvement before deployment. Slow RouterOS operations themselves still take their actual execution time.

## Approved plain-port setup

Dennis requested starting with plain-port mode to configure the test Tenda. One API request, `PUT /api/routers/563/plain-ports` with `{"ports":["ether2"]}`, was sent at 19:29:35. It returned 202 at 19:30:50, job `8befd80e68de489588012875920ad8c1`, and remained applying after 150 seconds. Dennis explicitly requested applying it directly on MikroTik. The poll client was stopped; the server job remained pending with the same desired configuration.

At 19:32:41 the deployed `_apply_plain_ports_sync` helper was run directly against router 563 with ether2 as the only requested plain port and migration from its previous dual mode. It succeeded at 19:32:54 in 13.06 seconds with no warnings. The DB fields were synchronized to `plain_ports=["ether2"]`, `dual_ports=null`; dedicated PPPoE on ether3 was retained. Live verification at 19:32:55–56 confirmed ether2 on `bridge-plain`, DHCP `dhcp-plain` enabled using `plain-pool`, address `192.168.90.1/24`, and only the ether3 PPPoE server remaining. At 19:34:56 the earlier dashboard job was verified done: finished 19:34:44, elapsed 309.6 seconds, success true, no warnings, same desired plain/dual fields.

At 19:33:55 live DHCP showed the device matching the Tenda SSID MAC suffix bound at `192.168.90.254`; the phone joined its Wi-Fi and received `192.168.90.253`. At approximately 19:34 the phone browser reached `http://192.168.90.254/login.html`, displaying Login. Dennis was asked to enter the Tenda admin password himself on the phone; the agent did not enter it. The phone lock was released for this handoff. Home auto-connect was verified enabled before handoff. No WAN-mode claim is made until login succeeds.
