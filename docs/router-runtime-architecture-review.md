# Router runtime review: local HotSpot, without RADIUS

The paced experiment is not a fleet-ready fix. An actual serving RB951 reached 100% CPU in four of 185 observations, with 53.049% mean total CPU. The paced check-in and expiry sources were restored to their preceding versions. These observations do not isolate script CPU or prove the canary caused saturation. They do reject the proposed acceptance claim.

A subsequent 65-sample observation after restoration also reached 100% once (58.923% mean total CPU). Restoration did not resolve the underlying saturation. Customer traffic was not controlled between the two live windows; their means must not be used to rank the script versions.

Scope: local HotSpot authentication remains authoritative on the router. RADIUS is excluded from this design. This review follows the implementation at origin/main b9a9c70 and the disabled-by-default experimental changes on this branch. It does not authorize a backend deployment or fleet migration.

## What the measurements establish

The roughly 75% result for five expiries was total CPU under an existing traffic workload, not a 75 percentage point increase from five removals. Final paced lab runs with 20 active sessions reached 76% for five removals and 75% for a backlog of 20 with five processed. They had approximately 46–48% mean total CPU. The workload was 200 aggregate UDP packets/second with 1024-byte payloads and equal echo traffic, carried through VXLAN inside WireGuard. Those means are not matched disabled-script controls and cannot be subtracted to calculate precise script overhead.

A previous controlled test with 200 configured accounts and no client traffic did isolate substantial recurring overhead: 7.935% mean total CPU versus a 2.000% control, with a 91% peak. Neither experiment demonstrates that moving reporting to the router costs less than bulk server polling.

On the serving router, an eight-second profile showed roughly 0.5–1.5% console CPU while total CPU was approximately 74–88%. DNS, HotSpot's internal web proxy, forwarding, ethernet, firewall and queues accounted for much of the rest. This profile is a short observation, not an attribution of every earlier peak. The profiler itself also costs CPU.

## Existing mechanisms worth keeping

- `hotspot_mac_login.py` uses local MAC-login users and shared rate profiles. RouterOS creates a dynamic queue for the active session; the queue follows its current IP. This already avoids the legacy bypass/static-queue repair problem on converted routers.
- `expiry_reaper_script.py` already caches the next deadline and entry count. It scans when a deadline is due, counts change, acknowledgements are pending, or its five-minute rescan deadline arrives. Replacing an alleged full expiry scan every minute would solve a problem this implementation already partly avoids.
- `realtime_state.py` and `mikrotik_background.py` suppress normal usage polling while host reports remain fresh. There are additional repair paths, but it is inaccurate to claim all ordinary polling continues alongside every push.
- `router_agent_commands.py` and `RouterCommand` already provide a durable outbox, idempotency keys, delivery leases, expiry-generation checks and acknowledgements. Reuse these semantics rather than add another command queue.
- Preserve exact usage counter domains, disabled-before-disconnect expiry ordering, renewal protection and retryable acknowledgements. A lower CPU reading is not sufficient if paid access, enforcement or metering becomes incorrect.

## Problems in the current mechanism

### Expiry-only renewals can reset a healthy session

`hotspot_mac_login.provision_customer` rewrites an existing user, scans for legacy bypass artifacts, then unconditionally calls `_kick`, which removes that MAC's active sessions and hosts. Check-in deliberately hands existing-user renewals to the API path. An expiry-only change can therefore trigger disconnect/re-authentication and dynamic-queue turnover even though the plan and device did not change.

This is a code-level explanation for an avoidable disconnect mechanism, not proof that it caused the reported customer's particular disconnection. The reconciler already has a healthy-user path that can tag a comment without kicking; the payment path needs equally careful handling.

The first implementation should preserve an already healthy native session when only its deadline changes. It must prove that the user is enabled, the MAC and rate profile match, no bypass still grants access, and no block/plan/device change requires re-authentication. Preserve a later deadline and reject stale generations. Missing users, failed reads and ambiguous access state must retain the repair path. Verify active session IDs, queue limits and cumulative usage through renewal, replay, concurrent expiry and outage recovery.

### Coordination does not cover all router work

`router_script_gate.py` waits at most 20 seconds, then proceeds; errors also fail open. It is not a strict mutual-exclusion guarantee. It covers named script jobs, not direct server API writers. Background jobs have server-process locks, but these do not lock an independently executing RouterOS script.

A sampled CPU threshold is also not a quota. It can stop the next command but cannot interrupt the current native command or stop forwarding load from increasing. Adding pauses can reduce collisions while increasing completion latency; it does not establish a sound ownership model.

### Payment delivery has competing normal paths

The default `both` mode races payment-time API delivery against check-in reconciliation, with guards and grace windows. These guards are useful, but successful delivery still depends on several independent observations and retries. A single logical operation should have one delivery owner, with a fallback that takes over the same durable operation after lease expiry. It must not become a second independent provisioning attempt.

Do not simply enable the existing command agent. Its current implementation downloads/imports scripts through public HTTPS, writes a temporary file, and contains bare `:return` paths that are incompatible with the branch's tested RouterOS 7.19 execution constraints. Reuse the outbox, not the current agent unchanged.

### Expiry removal mixes enforcement with housekeeping

The reaper accommodates both bypass-era and native MAC-login artifacts and verifies users, bindings, sessions, hosts and queues. Some state changes revoke access; others remove historical artifacts. They should have separate priorities and acknowledgements. First verify that the applicable authorization is disabled/absent and the session/host cannot retain access. Defer non-authorizing remnants to bounded cleanup. Do not omit a table merely because it looks redundant: the spare must prove which state can still authorize a device, including reconnect attempts after each failed deletion.

### Reporting remains proportional to router state

Usage serialization and check-in census still enumerate tables. Repeated full inventory is expensive even when no configuration changed. Native serialization reduces interpreter work, but real transport and RouterOS configuration costs remain. The active serving router had no logout hooks attached, so a presumed per-disconnect upload storm is not an explanation for its observed CPU.

## Target mechanism

Keep local MAC authentication and native dynamic queues. Use the existing durable outbox for versioned, data-only operations. One coordinated router runtime owns mutation work, due expiry work and outbound exchange; independently necessary tunnel recovery can remain isolated but must defer expensive work safely. Optional telemetry and inventory yield to customer access operations.

An ordinary idle exchange contains a health summary, last acknowledged sequence and an inventory revision/count, rather than every MAC. The server returns bounded changed entitlements. A count alone cannot prove equality: use revisions, periodic digests and infrequent full repair snapshots. Preserve the public fallback needed when the management tunnel fails, with backoff and a measured CPU cost.

Retain the reaper's existing next-deadline cache. Extend it with generation-aware due work updated by successful entitlement changes. Rebuild from durable user/binding metadata after reboot or uncertain state. While disconnected, preserve the established trusted-clock and last-confirmed-deadline rules; a payment never delivered to an isolated router remains an explicit limitation. Do not write a flash file for every timer tick or keep one permanent script/scheduler per customer.

Retain cumulative usage collection until a replacement proves final-session accounting and reset handling. Batching reports must not silently discard customers who connected and left between samples. Bound any event buffer and specify reboot/overflow behavior. Merely moving all work into one large script would not remove its cost.

## Validation before replacing the current runtime

1. Compare scripts disabled, current scripts and the candidate at the same client count and traffic rate; bracket and repeat runs to detect baseline drift. Measure total CPU, latency/loss, session-ID turnover and completed operations.
2. Test 1/2/5 simultaneous expiries and renewals, not only account creation. Separate configured records from active sessions and aggregate packet rate from per-client rate.
3. Inject a renewal after an expiry decision, duplicate/out-of-order delivery, lost acknowledgement, deletion failure, command timeout, reboot, bad clock, tunnel outage and backend outage. Confirm no paid session is removed by a stale operation and unpaid clients cannot re-authenticate.
4. Demonstrate backlog age and expiry delay under load. A five-per-pass cap is not a pass if it leaves a large expiry backlog indefinitely.
5. Measure normal work and recovery together. A design cannot claim a peak improvement by hiding catch-up in an unmeasured window.

The current hardware result is a rejection, not a guarantee that the next mechanism will pass. A router already saturated by packet processing has no CPU headroom for a controller. Admission limits must include packet rate, traffic mix, queue count and required latency, rather than a single maximum-customer number.

MikroTik documents that simple queues are traversed in order and that FastTrack bypasses simple queues and parts of HotSpot processing. Enabling FastTrack to make a benchmark look cheaper could break billing speed enforcement. Keep this invariant while investigating packet-path cost: [Queues](https://help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues), [Packet flow](https://help.mikrotik.com/docs/spaces/ROS/pages/328227/Packet+Flow+in+RouterOS).
