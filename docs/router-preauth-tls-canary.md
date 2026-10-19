# Native HotSpot HTTPS CPU canary

Status: retained on RouterOS 7 routers 597 (CJ Net) and 585 (APPOLO), following controlled tests on the owner's RB951 563. This is a targeted configuration fix. Native collector and paced-mutation experiments remain disabled by default.

## Mechanism and scope

Unauthenticated HTTPS attempts to unrelated destinations were being redirected to HotSpot's native HTTPS service on port 64875. The router paid for connection handling that could not provide useful captive-portal access. A `pre-hotspot` NAT accept rule skips that interception for unauthenticated, nonlocal TCP/443 outside the portal address list. An explicit first `hs-unauth` forward drop still denies those connections. NAT accept does not grant forwarding access.

The existing walled garden retains authorization decisions for portal destinations. RouterOS DNS FWD records attach the **actual answers given to clients** to an address list, preserving CDN rotation and allowed subdomains. Explicit FQDN entries prime concrete hosts; explicit walled-garden IPv4 networks remain excluded from optimization. Normal upstream DNS selection is preserved. Existing overlapping DNS records, regex policies and unbounded/unsupported garden patterns cause preflight refusal.

Authenticated traffic, native per-session queues and local router HTTPS do not match the optimization. No FastTrack or RADIUS is introduced. Existing rules, queues, billing users and scripts are preserved.

## Measurements

All CPU figures are total CPU, sampled once per second, including the observer. The spare has one 600 MHz core and RouterOS 7.19.6. Its virtual Ethernet transport uses VXLAN inside WireGuard and is not a physical WAN capacity test.

Five unpaid clients generated the same approximately 70 HTTPS attempts/second. With the four billing timers paused, repeated A/B/A/B windows measured:

| Window | Mean CPU | Peak CPU |
| --- | ---: | ---: |
| Original interception A1 | 44.171% | 51% |
| Narrow rejection B2 | 7.943% | 16% |
| Original interception A3 | 46.029% | 59% |
| Narrow rejection B4 | 8.271% | 19% |

The general DNS-protected policy then repeated approximately 8â€“9% mean / 16â€“17% peak against 43.043% mean / 51% peak with original interception. Unauthorized TLS did not complete. The unpaid portal returned HTTP 200. An authenticated control reached the internet and downloaded at 0.86â€“0.89 Mbps on a 1 Mbps native profile.

With the general guard and all four original billing scripts enabled for 140 samples, mean CPU was 9.621%, peak 60%, versus 8.425% / 13% with scripts paused for 40 samples. Run counters advanced 3/3/3/2 for usage/expiry/watchdog/check-in. This is one paid synthetic client, **not** a loaded fleet script budget or maximum-customer certification.

Live observations on 2026-10-19 UTC (2026-10-20 EAT):

| Router | Baseline mean / peak | Protected mean / peak | Sessions | WAN inbound baseline â†’ protected |
| --- | --- | --- | --- | --- |
| CJ 597, scripts paused | 27.667% / 48% (90 reads) | 24.010% / 50% (210 reads) | 14 â†’ 14 HS | 10.40 â†’ 9.55 Mbps |
| APPOLO 585, original scripts enabled | 94.289% / 100% (90 reads) | 40.257% / 100% (210 reads) | 14â†’15 HS + 8 PPP, then 15+8 | 43.29 â†’ 12.85 Mbps |

APPOLO's readings at or above 95% fell from 62/90 to 2/210. Its traffic also fell substantially: **the entire CPU decrease cannot be assigned to this change**. Native HTTPS redirect counters fell to zero on both; explicit reject counters increased. APPOLO's reject rate reached about 515 packets/second, suggesting immediate retries that require a separate drop-vs-reset experiment. Saturation is not fully resolved there.

A low-rate unpaid virtual client on CJ verified HTTP login and HTTPS frontend access. With browser headers, both backend domain variants returned HTTP 200 from the real public portal API. Python's default headers received an HTTP 403; that response was also observed on the original spare path and must not be called a firewall failure. Unrelated unpaid HTTPS was rejected. The live test client and its links were removed.

CJ's original four scripts were resumed after a final scoped legacy collection and native-host baseline handover. The 150-sample resumed window averaged 17.060%, peaked at 81%, retained all 13 sessions, and produced fresh push health and check-in receipts. A later independent check found a trusted native expiry clock, a fresh heartbeat and zero retry holdoff. Normal router expiry ownership was restored; the existing three-minute server safety net remains. Fresh host-counter rows persisted at 21:47:12 UTC and a pushed bandwidth snapshot at 21:43:13 UTC. The accounting handover has a small sampling gap and cannot reconstruct ended sessions losslessly.

## Tool and rollback

`scripts/hotspot_preauth_tls_canary.py` is explicit opt-in only. `PREAUTH_ROUTER_IDS` must name authorized routers; no fleet selector is inferred. Install measures a baseline, arms a 30-minute router-local rollback, validates/installs DNS and address protection, waits for concrete host resolution, enables denial before skipping interception, and measures the protected window. Failure attempts rollback; the local timer remains protection if the API cannot finish.

After reviewing CPU, traffic, session/queue continuity, portal/API access and billing receipts, `PREAUTH_MODE=keep` removes the rollback timer. `PREAUTH_MODE=rollback` executes it. Once retained, rollback is the generated `rollback_rsc` for the exact marker `bw-preauth-tls-<router_id>` and its `-portal` address list. Remove NAT interception bypass before the denial rule. DNS/address objects are exclusive to that marker.

Removing an FQDN deletes its dynamic children too. A single bulk address-list removal can stop on stale child IDs and leave later parents behind; rollback therefore removes static parents individually before remaining dynamic entries. Spare fixture cleanup exposed this, and final removal was independently verified.

Do not enroll RouterOS 6 using this tool. All available spares run RouterOS 7. This does not establish superiority of every operation over server polling, a universal customer capacity, or a strict instantaneous CPU ceiling. Changes to portal/walled-garden policy need a synchronized protection plan before the new destination is used.

References: [HotSpot customisation](https://help.mikrotik.com/docs/spaces/ROS/pages/87162881/Hotspot+customisation), [RouterOS DNS](https://manual.mikrotik.com/docs/network-management/dns/), [queues and FastTrack](https://help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues).

## Isolated original-script controls

On the empty spare, with one timer enabled per 125-sample window, usage reporting averaged 3.264% and peaked at 43%; quiet expiry averaged 2.344% and peaked at 10%; the healthy WireGuard watchdog also averaged 2.344% and peaked at 10%. Each ran twice. A separate 125-sample public HTTPS check-in control averaged 2.624% and peaked at 24%, with two executions. The settled paused control averaged 2.120%. These are quiet-operation measurements, excluding real expiry removals and tunnel recovery. A compact v3 reporting experiment reached production ingestion after empty-array and empty-string compatibility fixes, but its 40% peak did not improve on the original 37–43% range. It was not adopted or installed on serving routers. Optional resource-field completeness was also corrected in the prototype; no rollout relies on it.


## Retry feedback and the retained policy

The first guard used TCP resets. A later closed-loop experiment on the spare used five unpaid clients, three concurrent attempts per client, plus one paid control. All four original scripts were enabled. Reset windows averaged 12.74% and 11.37% CPU, with about 108–109 attempts/second; drop windows averaged 4.77% and 3.98%, with 7.58 attempts/second. Peaks were 58%, 57%, 65% and 33% respectively. Portal access and the paid control remained valid; its 1 Mbps profile delivered 0.838–0.891 Mbps. The first drop peak shows that reducing retry traffic does not remove every script peak.

Both retained live guards now use **drop**, applied at 22:30 UTC. CJ's low-load reset/drop windows averaged 10.80%/11.19% and peaked at 68%/75%; no improvement is claimed at that traffic level. APPOLO's matching-rule packet rate fell from 237.69/s to 3.90/s. Its mean CPU stayed near 47% while WAN traffic rose from 21.85 to 25.47 Mbps; three of 210 protected samples still reached 100%. That remaining saturation is unresolved. All original billing scripts remain enabled on both routers.

## Reporter experiments still under investigation

A compiled-script cache was not adopted. The empty-spare uncached control averaged 3.552% / peaked at 30%; the warmed cache averaged 3.400% / peaked at 38%. Initial compilation reached 62%. Original source and timer settings were restored after the test.

Temporarily omitting only the physical-port reporting block averaged 2.144% / peaked at 20%, with most readings at or below 9%. This isolates a recurring reporter cost but is not a deployable fix: port reporting must be preserved. The corrected bulk-read prototype executed its fast path for all six physical ports (11 metadata and 11 statistics rows), with fresh production ingestion, but still averaged 3.064% / peaked at 36%. No serving router has received that prototype.

Independent scheduled-script probes on spare 563 and APPOLO 585 confirmed that the existing gate serializes ordinary three-second jobs. Multiple script names in the job table therefore do not establish concurrent execution. The 20-second fail-open behavior remains a known limit; it was not triggered by this probe.
