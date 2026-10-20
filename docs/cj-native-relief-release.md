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
