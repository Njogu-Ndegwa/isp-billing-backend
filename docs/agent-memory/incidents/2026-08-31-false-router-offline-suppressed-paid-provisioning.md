# False router offline status suppressed paid provisioning

## Summary

Router availability was stored as one shared `last_status` value per router. Advisory cleanup jobs and other independent probes could overwrite that value with `offline`, even when paid-customer provisioning could still reach RouterOS. Hotspot and PPPoE provisioning trusted the stored value and sometimes returned before attempting delivery, leaving a successful payment without a corresponding router user.

## Symptoms

- Resellers reported routers as offline while subscribers still had internet access.
- Some successful payments were not followed by a router-user add and customers were prompted to pay again.
- Router histories contained frequent `expired_cleanup` offline samples that conflicted with successful checks close to the same time.
- The behavior varied by router because frequent successful writers, such as usage-push jobs, could quickly overwrite false offline samples.

## Suspected Cause

- Approximately 40 availability-reporting call sites wrote to a single router summary using last-writer-wins behavior.
- `expired_cleanup` emitted negative observations but no corresponding successful observation, so it was not a reliable authority for the router's overall state.
- Paid hotspot and PPPoE provisioning treated the cached offline summary as a hard gate instead of attempting a fresh, bounded RouterOS connection.
- An accepted reboot command incorrectly recorded the router as online even though it was expected to disconnect.

## Fix Applied

- Preserve every availability observation in history while applying source-aware rules to the shared summary.
- Treat `expired_cleanup` failures as advisory history only.
- Require two recent, consecutive non-advisory failures to mark a router offline; a successful observation resets the confirmation sequence.
- Prevent stale observations from overwriting a newer summary.
- Always make a bounded direct RouterOS attempt for paid hotspot and PPPoE provisioning, even when cached status says offline.
- Record an accepted reboot as deliberately offline until a later successful probe confirms recovery.

## Verification

- Added regressions for advisory cleanup samples, two-failure offline confirmation, success reset, stale observations, hotspot paid delivery, PPPoE paid delivery, and reboot state.
- Focused regression suite: 85 tests passed.
- Full local test suite: passed at 100% in 283 seconds.
- Session-discipline check passed.
- Python compilation check passed.
- Production deployment and live verification remain pending explicit approval.

## Follow-Up

- Produce a read-only reconciliation preview for failed, active, unexpired paid attempts and compare each candidate against the current router user list.
- After approval, requeue or repair only confirmed missing users; do not charge customers again.
- Continue the existing work toward a durable router-command outbox so genuine long outages can recover after the current retry window.

## Post-Deployment Retry Observation

The first hour of the production watch found a second reliability gap after the
status fix itself was deployed. A completed hotspot payment on router 293 reached
the direct API five times between 19:03:59 and 19:12:19 UTC. The management path
accepted a diagnostic connection but stalled during reads, and the fifth failed
attempt became terminal. Five attempts had therefore exhausted in about eight
minutes even though the configured retry window was four hours.

The follow-up candidate on `fix/paid-retry-resilience`:

- shares one retry policy between hotspot and PPPoE;
- raises the bounded ceiling to 14 attempts while retaining the four-hour limit;
- spaces attempts at 1, 2, 3, 5, 8, 13, 21, then 30-minute capped delays;
- resumes legacy terminal attempts below the new ceiling only when their error is
  transport-shaped (`connect`, `timeout`, or `unreachable`), leaving deterministic
  RouterOS configuration failures terminal;
- keeps the existing batch limits, per-router serialization/concurrency caps, and
  60% DB-pool shedding threshold unchanged.

Verification before deployment approval: focused provisioning/status regressions
passed (56 tests), the session-discipline gate passed, and the full local suite
passed (1,037 tests). Production deployment and automatic legacy-attempt recovery
remain pending explicit approval.
