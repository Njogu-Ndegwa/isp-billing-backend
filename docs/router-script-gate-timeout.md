# Defer a billing job when an earlier job outlasts the gate

The gate waited for an older Bitwave job for up to 20 seconds, then ran its
body even if that job was still active. A slow expiry scan or stalled fetch
could therefore overlap the next billing job. Gate v2 ends that invocation
with a static deferral error when a known earlier job remains. The periodic
scheduler can try again on its next normal run.

The oldest job still runs immediately. Unreadable job IDs retain the existing
compatibility behavior. This change does not terminate the earlier job, change
timers, add a persistent lock, or make an exactly-once execution guarantee.

On the home RB951Ui-2HnD running RouterOS 7.19.6, two temporary scheduled jobs
demonstrated the timeout behavior:

| Earlier job | Gate | Later body executed | Overlap |
| --- | --- | --- | --- |
| 25 seconds | previous behavior | yes | yes |
| 25 seconds | v2 | no | no |
| 3 seconds | v2 | yes | no |

The probe used temporary jobs and verified the four installed billing sources
were unchanged. It removed its temporary scripts, timers, and rollback timer.
The gate and expiry renderer suites passed locally: 94 tests using the SQLite
harness. These tests do not establish a router CPU ceiling or RouterOS 6
compatibility; neither is claimed here.

Existing routers require a gate-only upgrade around their current sources.
Keep backups and verify that stripping the old and new gate yields identical
bodies. Do not regenerate per-router sources merely to upgrade the gate.
