# hAP lite watchdog bursts and independent CPU peaks

Router541 was verified against its owner and identity on20 October2026. It is a32MiB hAP lite on RouterOS6.48.7, not an RB951. Its only recurring script was the1-minute SSTP watchdog. Usage, check-in and expiry-push scripts were absent by the small-board policy. Seven native HotSpot logins were active initially; historical billing rows are not simultaneous customers.

## What the observations establish

An initial120-second CPU-only observation had119samples,mean15.95%,p9537%,peak100% once. A separate later bounded profile associated a watchdog run with certificate40.5 and SPI22 percentage points of a70.5 total. These are RouterOS profiler subsystem labels, not proof of a damaged certificate or flash device. The SSTP tunnel remained continuously connected; a later resource read reported free storage and zero bad blocks.

A controlled enabled/paused/enabled comparison kept profiling active in all phases. CPU means were10.763/9.330/9.939%; peaks94/31/45%. These small drifting means are not a causal saving estimate. More specifically, certificate work appeared during enabled watchdog jobs, was absent during the paused phase, and returned in the final enabled phase. Script body matched the current canonical SSTP template; only its gate was older(v1). Updating the gate was not established as a CPU fix.

## Native monitor experiment was rejected and rolled back

Native Netwatch was tested as an alternative to executing the full watchdog every healthy minute. An up callback paused the legacy watchdog while the SSTP client was running; a down callback enabled the unchanged recovery script. Existing missed-check/backoff/reset logic was retained. Callbacks used the current gate renderer. No real tunnel disconnect was induced.

A dummy-resource up/down/up test passed on the home RouterOS7 spare and cleaned up. A bounded RouterOS6 canary then passed the same monitor-destination handoff on541 with a router-local automatic rollback timer. The actual SSTP tunnel remained connected. This was not a cold-boot or real redial test.

The five-minute canary nevertheless sampled100% three times(mean11.937% across287samples excluding the first10seconds). A separate state read at19:57:25UTC showed the legacy watchdog run-count unchanged at1291 and the native monitor continuously up since19:52:24UTC. Thus the watchdog is not required for every saturation event. The no-saturation acceptance criterion failed. The experiment restored the original enabled watchdog and removed the native entry and its owned recovery timer at19:57:30UTC. **No native-monitor canary should be treated as installed or approved for fleet rollout.** The harness cleanup field reported a stale boolean for the timer ID; verify actual router objects rather than interpreting that field as proof of a leftover. Raw canary samples were not emitted on this failed path; preserve the progress/independent state receipts and do not invent per-sample timestamps.

Use a bounded CPU/profile observation plus a passive management-command trace while the watchdog is inactive to identify the independent peaks. Distinguish new API logins/reads, work in existing interval feeds, HotSpot services and traffic changes. Profiling and diagnostic reads can add CPU. Do not solve this by disabling security, queues or certificate checks, changing management encryption, restarting the tunnel or upgrading/rebooting this live board without an appropriate maintenance plan.

## Accounting relief is separate

Its latest bandwidth snapshot and credited usage were16:19:54UTC despite fresh reachability and live customers. The broad collector repeatedly selected8routers but attempted only1before a soft time-budget exit, advancing past unvisited routers. PR244 fixes that rotation starvation. It does not create a hard per-router deadline or a freshness SLA.

A single owner-scoped execution of the existing accounting path at19:50:40UTC updated this router's actual snapshot and usage. It selected only541, blocked CPE mutation commands, skipped unrelated retention, and verified no plan caps or pending FUP reversals before running. No artificial usage or historical backfill was inserted. Missing counters lost before a reboot were not reconstructed. See the PR244 incident note once merged for the collector fix.

Private evidence remains in the authorized investigation workspace under `work/`: the `glenn-router-*`, `netcom541-accounting-check-*`, `netcom541-followup-*`, `netcom541-watchdog-aba-*`, `home-native-netwatch-check-*`, `netcom541-native-watchdog-canary-*`, `netcom541-native-current-*`, and `netcom541-scoped-accounting-refresh-*` receipts. No customer emails, credentials or live script/token bodies belong in reusable notes.
