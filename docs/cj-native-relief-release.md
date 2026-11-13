# CJ native accounting relief release

This release combines the reviewed changes from PRs 231–234 so deployment can
use one application rollout. Native accounting remains disabled by default.
The intended first enrollment is router 597 only, after its current temporary
collector releases ownership.

The release includes healthy same-plan renewal preservation, opt-in v3
encoding improvements, observation timestamps for buffered counters, the
native counter collector with a router-local RAM lease fallback, and gate v2.
It excludes the experimental expiry executor and the draft check-in tunnel
transport. Existing native accounting keys and customer speed enforcement
are preserved.

On 2026-10-20, CJ's finite native accounting canary accepted eight reports
with no rejected rows. It observed 391 CPU samples averaging 29.299%, peak
82%, with no saturated samples while receiving about 12.57 Mbps. Its earlier
90-sample script baseline averaged 22.011%, peak 100%, while receiving about
7.50 Mbps. Traffic differed, so this does not establish an average CPU saving.

A subsequent protected temporary collector accepted all ten reported
customers. A separate five-minute observer sampled once per second:
300 readings, mean 16.817%, peak 79%, zero saturated readings, and ten active
HotSpot customers at each minute check. Other billing timers stayed enabled.
These are measured windows, not an unlimited capacity or peak CPU guarantee.

The full payment-renewal path was also tested on home RB951 563, RouterOS
7.19.6, with 200 simultaneous synthetic MAC-login sessions carrying an
aggregate 200 UDP packets/second with 1024-byte payloads. Five healthy
same-plan renewals originally saturated the CPU in both runs despite
preserving sessions. Legacy cleanup requested every property of every
simple queue, and renewal checks transferred entire customer tables.
The release now filters customer metadata reads and requests only static
queue identity/ownership fields. A case-insensitive discovery fallback
preserves existing lowercase MAC usernames.

| Renewal path | Baseline mean / peak | Observation mean / peak | 100% samples | Five-renewal time |
| --- | --- | --- | --- | --- |
| Before, run 1 | 11.133 / 30 | 29.200 / 100 | 3 | 23.532 s |
| Before, run 2 | 12.200 / 47 | 25.911 / 100 | 1 | 23.905 s |
| Narrow reads, run 1 | 10.933 / 43 | 13.711 / 61 | 0 | 13.235 s |
| Narrow reads, run 2 | 11.267 / 57 | 15.578 / 73 | 0 | 13.266 s |

Each observation covers 45 roughly one-second CPU reads, including time
before and after the renewal operations. Both optimized runs retained all
200 session uptimes, successful traffic, and the five renewed users' native
1 Mbps queues. Only five user comments were written. The isolated fixture
was removed and all original billing timers restored. This validates a
specific improvement, not a 1–2 percentage-point peak contribution, initial
router setup cost, real Wi-Fi capacity, or 200 customers at full plan speed.

CJ's existing gate-only update preserves all four script bodies. Its reviewed
usage reporter SHA-256 is:

```
c49eaa030291697f283fdfdd88918959bac1d77cafe67c146b2b2edbd991dc7a
```

After approval, configure only `NATIVE_STREAM_ROUTER_IDS=597` and the matching
`NATIVE_STREAM_REPORTER_HASHES` entry. Deploy through normal CI. Verify one
collector owns the router, ingestion remains fresh, all expected customer
reports are accepted, and expiry/check-in/watchdog remain enabled. The router
must restore its original reporter when the native lease expires.

The temporary collector already holds a separate reviewed guard claim. The
permanent worker must respect that claim and wait for its release; never
force two accounting writers onto the router during handoff.
