# Opt-in native router counter streams

This collector replaces the work done by the periodic usage-report script on a
small, explicitly selected set of RB951s. RouterOS streams selected counters over
one persistent API connection; the backend formats the existing v3 report. It
does not replace authentication, customer speed limits, check-in, expiry, or the
management watchdog. RADIUS is not involved.

Enrollment is off by default. Set `NATIVE_STREAM_ROUTER_IDS` and a matching
`NATIVE_STREAM_REPORTER_HASHES` list of `id:sha256` entries only after reviewing
each router's current reporter. The initial limit is eight routers. The collector
requires an RB951Ui-2HnD on RouterOS 7.19.6 or later; RouterOS 6 remains excluded
pending fallback certification. Shadow and scheduler-standby instances never
start it. Observation-time support from PR #232 is required.

Counter subscriptions use direct native IDs in chunks of 32. Host statistics are
requested only for authorized or bypassed entries, and interface statistics only
for physical ports and the WAN. Membership discovery runs every 30 seconds;
inventory discovery runs every five minutes. Stable chunks stay subscribed when
other clients join. A feed that ends is rebuilt from current IDs. Host counters
retain the existing MAC plus original-IP key; queue order and limits are retained.
Per-row observation times protect the billing baseline from delayed delivery.

Before pausing the usage timer, the collector verifies its exact source hash,
identity and token, creates its own fallback timer, and seeds a RAM-only lease.
The previous reporter job is allowed to drain. Other timers and script sources
are preserved. A unique guard and owner marker prevent overlapping collectors;
fresh claims cannot be mistaken for stale guards during startup.

The lease is refreshed by adding a new timed address-list entry before removing
the previous entry. This reserved list is not referenced by a forwarding rule.
Heartbeats therefore do not rewrite a scheduler deadline or source to flash.
After three minutes without a heartbeat, the guard restores the old reporter on
its next 30-second check. A router reboot also loses the RAM lease and restores
the reporter. A reporter already enabled by an operator keeps its current
interval. Normal shutdown restores reporting and removes only the collector's
own guard and lease entries. Removing enrollment restores the original path at
the next normal deployment; no router reset is needed.

The client bounds reply sizes, table sizes and cached data. It does not log
RouterOS error bodies, HTTP bodies, tokens, script sources or customer identifiers.
Database reads commit and close before router or HTTP I/O.

## Hardware evidence and limits

On spare 563, 200 authenticated virtual clients at 200 aggregate UDP packets per
second retained their sessions and traffic during native counter streaming. The
direct-ID run peaked at 85% during startup and 65% afterward, against a 67% control
peak. An unpaid client was blocked and a paid 1 Mbps profile delivered about
0.97 Mbps when offered more traffic. This certifies that workload, not the maximum
capacity for 200 people streaming video or using Wi-Fi.

Controlled replacement of a host entry and cancellation of a subscription both
recovered on the spare. Nineteen untouched sessions kept their uptimes, and all
twenty clients kept echo access. The test peaked at 19%.

Nine-minute live canaries on CJ 597 and APPOLO 585 recovered real table changes,
updated billing and health, and restored their original timers. Both peaked at
54%. APPOLO's original control peaked at 70%; WAN receive traffic increased from
1.33 to 1.93 Mbps. CJ's mean increased from 5.45% to 6.26% while WAN traffic rose
from 0.086 to 0.518 Mbps, so no mean-CPU reduction is claimed for that comparison.
Those windows were below peak customer traffic.

The production session's guard and RAM lease were also exercised on the empty
spare: a second owner was refused, loss of the test heartbeat restored reporting,
an operator's changed interval was preserved, and cleanup succeeded. That test
peaked at 14% total CPU. The permanent background worker still requires a normal
deployment and supervised canary acceptance before retaining enrollment.

Expiry remains a separate optimization. The scan-only candidate still saturated
at 200 clients and is not part of this change. No universal CPU ceiling is claimed
when forwarding traffic itself exhausts the board.
