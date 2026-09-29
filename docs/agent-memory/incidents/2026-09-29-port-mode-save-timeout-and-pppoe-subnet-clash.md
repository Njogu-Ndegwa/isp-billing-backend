# 2026-09-29 Port-mode saves "failing", duplicate PPPoE NAT, PPPoE subnet clash on a cascaded router

## Summary

Reseller Powernet (user 88) could not get PPPoE + hotspot ("dual") ports or plain
ports to save on routers 537 (RB951) and 483 (hAP lite). The dual changes had
actually been applied, but the dashboard showed an error every time, so he kept
retrying. Router 483 is fed internet by a PPPoE session from router 537, which
also collided with the PPPoE subnet we configure on 483.

## Symptoms

- `Dual port sync for router 537 completed in 149.49s`, `... router 483 completed
  in 206.65s` (17:12 / 17:15 UTC). No access-log line for either PUT: the client
  had already disconnected.
- The API sits behind Cloudflare, which returns 524 after 100 s of origin silence.
- The dashboard saves dual → PPPoE → plain one after another; the 524 on dual
  threw before the plain PUT was ever sent ("even changing plain not working").
- 17 identical `NAT for PPPoE clients` masquerade rules on 537, 5 on 483.
- 483: WAN `pppoe-out1` = 192.168.89.244 (a PPPoE customer "Hotspot3" on 537),
  while its own `pppoe-pool` was 192.168.89.2-254 with local-address 192.168.89.1
  — the upstream gateway's address.

## Suspected Cause

1. Port-mode endpoints held the HTTP request open for the whole router session;
   first-time dual setup repairs the hotspot captive portal (`/tool fetch` on the
   router), which takes minutes on weak routers. Cloudflare cut it at 100 s.
2. PPPoE/dual setup called `/ip/firewall/nat/add` on every save and relied on a
   "duplicate" error that RouterOS never raises for NAT rules. Plain mode already
   checked for an existing rule; PPPoE and dual did not.
3. The PPPoE subnet was hardcoded to 192.168.89.0/24 with no check against the
   router's own addresses. A router chained behind another of our routers via
   PPPoE gets its WAN address from that same /24.
4. The PPPoE NAT rule is pinned to `out-interface=ether1`; when the WAN is a
   PPPoE client on ether1, traffic leaves via `pppoe-out1` and the rule never
   matches (483 only worked thanks to the defconf `out-interface-list=WAN` rule).

## Fix Applied

- `app/api/router_operations.py`: PPPoE/plain/dual port endpoints wait up to 75 s
  inline, then return 202 `{status: applying, job_id}` and finish in the
  background (DB persisted in a fresh session). `GET
  /api/routers/{id}/port-config-jobs/{job_id}` reports the result. A second save
  for the same router while one is applying gets 409 instead of stacking.
- `app/services/mikrotik_api.py`: `prepare_pppoe_subnet()` keeps the current
  PPPoE /24 unless it overlaps a router address, else moves pool, PPP profiles,
  PPPoE bridge address and stale FastTrack-bypass rules to the first free of
  192.168.89 / 192.168.189 / 192.168.199 / 172.16.89. `ensure_pppoe_nat()` keeps
  exactly one rule, updates its subnet and out-interface (PPPoE-client WAN aware)
  and removes duplicates — so the next save cleans up existing routers.
- `pppoe_provisioning.py`: customer profile gateway falls back to the pool's .1,
  not a hardcoded 192.168.89.1. `router_agent_commands.py`: same via
  `default-pppoe`. `mikrotik_lb.py`: new candidate subnets added to `LB_SRC`.
- Admin (`../isp-billing-admin`): `sendPortConfig` polls the job on 202, shows
  a "still applying" note, turns 502/504/524 into a clear message, and re-reads
  the router's saved modes after a partial failure.

## Verification

- `tests/test_pppoe_subnet_and_nat.py`, `tests/test_port_config_jobs.py`, plus the
  existing PPPoE/dual/agent tests.
- After deploy: a dual save on a slow router should log `still running; returning
  job` and the dashboard should finish without error.

## Follow-Up Work

- Fleet: other routers carry duplicate `NAT for PPPoE clients` rules; they are
  cleaned on the next PPPoE/dual save, or by a one-off sweep.
- Customer "Hotspot3" on 537 is router 483's uplink; if it expires (2026-10-27)
  483 and all its hotspot users go offline. Consider flagging PPPoE customers
  that are downstream routers so they are never auto-expired.
- First-time dual setup is slow mainly because of the captive-portal repair;
  consider skipping the `/tool fetch` when the login page on the router is
  already current.
