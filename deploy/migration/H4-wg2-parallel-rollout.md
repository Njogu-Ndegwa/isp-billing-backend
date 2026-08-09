# H4 — additive wg-hz rollout to Hetzner wg2 (2026-08-09)

Design correction from Dennis: do NOT re-point existing tunnels. Add a NEW tunnel
per router (like the AWS secondary shadowed the primary), verify it is up, and only
delete the AWS side after everything is green.

## New Hetzner identity (third tunnel plane)

| plane | server | key | port | subnet | router iface |
|---|---|---|---|---|---|
| primary | 54.91.202.229 wg0 | dYLjXkln… | 51820 | 10.0.0.0/16 | wireguard1 |
| AWS insurance | 35.170.199.141 wg1 | 5J3k7H/… | 51821 | 10.250.0.0/16 | wg-aws2 |
| **Hetzner insurance** | **91.98.238.12 wg2** | **9eh1o14IAxXXTAci2iSs4Jmho6QW6I2XsLCx/ZZnuQA=** | **51823** | **10.251.0.0/16** | **wg-hz** |

Hetzner wg1 (51821) is a byte-identical CLONE of AWS wg1 (same private key) from H2 —
it cannot run side-by-side with AWS on the same router. wg2 is the real parallel plane.
wg1 still serves post-H3 provisions; wg-egress (51822, router 110) untouched.

- wg2: `/etc/wireguard/wg2.conf`, `wg-quick@wg2` enabled. Key at `/etc/wireguard/wg2.key`.
- Second manager container `insurance_wg_manager_hz` (same image), host network,
  `WG_INTERFACE=wg2`, port **8730**, same secret as the :8729 manager.
- Prod `.env` pivoted (backup `.env.bak-pre-hz-20260809-0605`): MANAGER_URL :8730,
  SERVER_WG_PUBLIC_KEY 9eh1o14…, VPN_IP 10.251.0.1, WG_PORT 51823,
  ROUTER_INTERFACE wg-hz, WG_SUBNET 10.251.0.0/16. Only `web` recreated
  (`--no-deps --no-build --pull never`, image id unchanged 58379bdf03f0).

## Bug found and fixed (worktree)

`derive_insurance_ip()` defaulted to hardcoded 10.250.0.0/16 and NO call site passed
`settings.INSURANCE_WG_SUBNET` — the deployed batch tool would have addressed wg-hz
inside the AWS subnet, colliding with wg-aws2 on the router. Fixed in
`app/services/insurance_wireguard.py` to fall back to the configured subnet.
Deployed prod still has the old code: any driver script MUST pass the subnet
explicitly until this ships.

## Rollout result (2026-08-09, batches of 5, concurrency 1)

36 routers applied + verified — wg-hz up, handshake on wg2, ping+TCP 8728 from
10.251.0.1, AWS wg-aws2 untouched and still handshaking:

10 (canary Bitwave Wangige), 44, 68, 75, 131, 162, 163, 171, 184, 189, 211, 218,
221, 222, 226, 239, 240, 241, 253, 255, 258, 262, 263, 270, 277, 281, 292, 297,
302, 307, 309, 312, 319, 320, 325, 332.

Not done (7): 
- 4 RADIUS Test Router, 299 Jade Sea #1 — primary tunnel down (offline).
- 217 FAMILY ROOTED NET #1 — router rejects stored API credentials.
- 249 Ella net #3, 293 HOTSPOT @ 10 #3 — flaky primary, API session dies
  mid-configure; possibly partial (wg-hz may exist, peer not registered). Retry.
- 323 Browser, 331 FIBRE #6, 333 Acme #2 — primary down; insurance rides Hetzner
  wg1 clone (323/331 handshaking there). Could be configured over the wg1 rescue
  path if sanctioned.

Still pending for H5: ~11 L2TP (ROS6) routers on AWS 10.250.100.x; pull-svc
repoint (needs compose passthrough of PULL_SERVICE_URL — absent, code default
still 35.170.199.141:8443); then 7-day zero-activity gate, then STOP (not
terminate) the AWS box. AWS deletion of wg-aws2 interfaces per router is the
very last step after Dennis signs off.
