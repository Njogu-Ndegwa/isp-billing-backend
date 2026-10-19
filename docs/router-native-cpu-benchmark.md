# RB951 script CPU work — 2026-10-19

Status: experimental. Native collection is disabled by default. Do not use these results as a fleet rollout approval or a 200-user traffic capacity claim.

The original **strict 1–2 percentage point peak increase** target, including RouterOS work triggered by our scripts, was not met. Current canary work targets avoiding sampled 100% CPU during realistic small payment and expiry cohorts; see [paced work canary](router-paced-work-canary.md). Neither result approves a fleet rollout.

## Changes

The check-in inventory previously searched the entire queue table for every CHECKIN binding. The compatible renderer now reads queue names once and uses exact associative keys. Snapshot row IDs are checked before cached properties are used; API-run scripts retain individual-get fallbacks.

The expiry reaper builds one bounded, anchored set of MAC/user/queue matches per removal batch. It disables users before disconnecting and checks live authorization tables before acknowledging removal. A failed removal retains EXP tags and remains retryable. Pending acknowledgements are sent 40 at a time, with the unsent suffix retained across successful replies. SCRIPT_VERSION stays 4 to avoid a forced automatic fleet upgrade.

The opt-in RouterOS 7 collector uses native table serialization. Check-in v3 carries six counted, selected one-column inventories; the server converts them to the established MAC validation and data-only command protocol. Usage v4 uploads bounded JSON parts, assembled atomically after token authentication. Missing, conflicting or invalid parts cannot clear customer presence or update usage. Arbitrary metadata uses JSON; DSV is restricted to controlled identifiers because the tested RouterOS DSV serializer did not safely escape arbitrary multiline text.

Assembly is process-local, capped by bytes, pending batches and TTL. The app currently runs one worker. Shared assembly or sticky routing is required before enabling it with multiple workers. An oversized part is deferred; this implementation does not claim support for arbitrarily large router tables.

## Hardware and method

Tests ran on an isolated RB951Ui-2HnD, single 600 MHz CPU, 128 MB RAM, RouterOS 7.19.6. The initial scale fixtures contain equal numbers of MAC-login users and bypass bindings, with one simple queue per account and no authenticated traffic clients or PPP sessions. A subsequent virtual-client experiment exercised actual simultaneous HotSpot sessions and traffic, described below. Configured records and simultaneous forwarding capacity are different measurements.

Temporary clones and fixture records are removed in finally blocks, with a timed router-local fallback installed before changing schedules. Original scripts and schedule settings are restored. The usage clone is installed through the canonical realtime_push_install entry point with this router's own rendered source; no live usage script is copied from another router.

RouterOS print-as-value and globals behave differently under API-run scripts. Native collectors are therefore run by their schedulers. RAM capture is used for validation, rather than writing large payloads into script comments. Pure script durations below use RouterOS :time. They exclude actual HTTP delivery and do not establish average CPU overhead.

Native collector durations with mocked transport:

| Configured accounts | Reporter | Check-in | Expiry initial scan |
| --- | ---: | ---: | ---: |
| 0 | 0.230 s | 0.068 s | 0.056 s |
| 20 | 0.313 s | 0.185 s | 0.143 s |
| 50 | 0.461 s | 0.331 s | 0.283 s |
| 100 | 0.736 s | 0.553 s | 0.529 s |
| 200 | 1.323 s | 1.053 s | 1.032 s |

The earlier 200-record implementation took about 8.1 seconds for reporting and 43.4 seconds for check-in in API-run measurements. These are diagnostic comparisons with different observer costs, not a matched CPU comparison. A recurring-scheduler measurement with real HTTP over the encrypted management tunnel is required for the CPU decision. Creating/deleting one-shot timers during sampling noticeably inflates CPU and must not be counted as ordinary scheduled operation.

## Real HTTP and recurring CPU result

The isolated receiver accepted all nine initial parts and the complete 200-account check-in over the encrypted management tunnel. Largest part: 27,100 bytes. There were no decoder errors. The first inventory report took 10.686 seconds wall time; check-in took 2.165 seconds. Four-part reports avoid inventory on subsequent ticks. Network wait and the shared script gate are included in these wall times.

With the same 200-record fixture, all four scripts on pre-created 60-second recurring timers averaged **7.935% total CPU over 185 one-second samples**, with a **91% peak**. The disabled-script baseline before that run averaged **1.967%**. No scheduler add/set/remove operations or payload reads occurred during the recurring measurement. The disabled-script baseline after the run was 2.033%; the average of the two controls was 2.000%, so the measured increment was 5.935 percentage points. CPU polling was present in both runs. The reporter, check-in, expiry and watchdog gates recognized the temporary clone names.

This **fails the 1–2 percentage point target**. The native mode remains experimental and must not be enabled fleet-wide. The earlier API-only bulk read benchmark also omitted delivery, expiry and watchdog work; it is not an apples-to-apples control-plane comparison. These tests do not establish that push is cheaper than native server-side bulk polling.

## Expiry fault tests

With 200 expired synthetic MAC users, the original first removal pass took 42.480 seconds for 39 accounts. The bounded batch took 3.158 seconds for the first 39. All 200 were removed and all 200 acknowledgements reached the real server parser across subsequent compressed test passes. The compressed passes do not represent production expiry latency.

An injected deletion failure retained 21 disabled users, kept their EXP tags, and acknowledged none. A later successful pass removed all 21. Mixed MAC-name/compact-name users, a bypass binding and its queue were removed while a future user and similarly prefixed queue were preserved. A seeded 200-acknowledgement outage backlog drained in five batches of 40 without duplicates or truncation.

## Payment/application burst result

With 180 existing configured accounts, the initial synthetic 20-user U batch took 4.509 seconds and an existing-user replay took 3.286 seconds. The final native applier reads existing user names once for frames of at least five operations and records successful additions in that lookup. This reduced the same 20-new-user batch to **2.734 seconds** and its existing-user replay to **1.451 seconds**. All 20 users were created successfully. Single-user delivery retained its direct lookup and took 1.284 seconds including inventory.

The final 20-user burst still reached **100% CPU** for three sampled seconds; its 30-second sample averaged 14.233% total CPU. The replay peaked at 100% for one sampled second and averaged 9.120% over 25 seconds. The action timers were installed before sampling; there were no API-driven configuration writes during the sampled operation. These tests use valid synthetic server frames, not M-Pesa payments, real client logins or live customer accounts.

The result rules out an instantaneous 1–2% guarantee for this implementation. It does not isolate RouterOS configuration processing from script interpreter CPU; both are part of the operational cost caused by our action. Meeting a strict sustained budget at high account counts needs fewer full inventories and a tested event/acknowledgement design. Merely lengthening intervals would trade payment/repair latency for lower average CPU and has not been applied.

## Enable and rollback

Keep ROUTER_NATIVE_CPU_IDENTITIES empty by default. Set only explicit, reviewed canary identities after the server-side parser is deployed; there is no wildcard enrolment. The usage and check-in installers refuse native mode below RouterOS 7.19.6 and leave existing scripts untouched. Prerelease versions are excluded. Native usage is first run by its scheduler, not by the API installer. hAP lite/mini and no-encrypted-tunnel exclusions remain in force.

To roll back native collection, clear the canary identity setting and reinstall the compatible renderers using the canonical installers. Preserve each router's disabled schedule choices and approved intervals. The existing usage installer also retains its previous-script rollback path.

No RouterOS 6 spare was available. Its native mode stays excluded. RouterOS 6 hardware validation, loaded forwarding tests, sustained fleet admission tests, real client payment flows and outage/recovery traffic measurements remain required before a broad rollout. An instantaneous 1–2% ceiling is not established by these tests.

Reference: [RouterOS scripting manual](https://manual.mikrotik.com/docs/developer-guides/scripting/). Hardware measurements above, rather than the manual, determine acceptance.

## Simultaneous authenticated clients

A temporary virtual Ethernet client generator reached 20, 50, 100, 150 and **200 distinct MAC-authenticated HotSpot clients**, with real UDP echo traffic and native per-client queues. With the tested Level 4 license, the 201st attempted client remained unauthenticated. The final 200-session comparison lasted over ten minutes without session-ID turnover or uptime resets. During the candidate and original-script windows respectively, 24,880 and 24,857 probes were sent and returned. These are actual authenticated sessions, not merely configured accounts.

The generator reached the router through VXLAN inside WireGuard. That adds encapsulation and encryption work; it does not measure 200 Wi-Fi associations or establish ordinary physical WAN capacity. An earlier ramp at 200 clients measured approximately 20%, 51%, 81% and 99% mean CPU at 1, 3, 5 and 10 Mbps of outgoing UDP payload respectively, with equal echo return traffic. The 5 and 10 Mbps stages reached 100% peaks. Initial ramp packet-loss counters were invalid because in-flight responses crossed counter resets; no packet-loss conclusion is drawn from them. The final comparison filtered those responses.

Under 200 active clients, the candidate averaged 64.768% CPU and the original scripts 48.336%, both peaking at 100%. Disabled-script controls drifted substantially: 61.067%/63.067% around the candidate and 58.400%/25.733% around the original. **This loaded comparison is inconclusive for relative script CPU cost.** It must not be used to claim the candidate is cheaper or more expensive. The controlled no-traffic result above remains a failure, and neither experiment establishes superiority over server polling.

Actual traffic exposed two correctness issues fixed in this patch. HotSpot host `print as-value` omitted byte counters even with a property list. The native collector now reads one complete property map per authorized/bypassed host and selects the exact host counters, preserving the existing accounting/reset domain. It does not substitute active-session counters. Queue reads filter the existing managed prefixes. RouterOS JSON also encoded durations as Unix-epoch date strings; the decoder normalizes those to durations while retaining actual link timestamps. The final receiver accepted all complete reports and check-ins with 200 host rows and no decoder errors.

The original scripts, schedule intervals and HotSpot pool setting were restored, and temporary clients, queues, interfaces, firewall rules and helper services were removed. RouterOS 6, physical forwarding capacity, real payment flows and controlled loaded CPU attribution remain unvalidated. The patch remains experimental and disabled by default.

Validation: 388 focused unit/integration tests passed on origin/main b9a9c70, including complete-only ingestion, tenant isolation, resource limits, exact queue matching, acknowledgement retention, duration normalization and firmware refusal. No application deployment or paying-router changes were made.
