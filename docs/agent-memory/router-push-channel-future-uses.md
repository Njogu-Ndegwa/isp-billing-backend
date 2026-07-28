# Router Push Channel — What Else Could Ride On It

Status as of 2026-07-28: the usage-push channel is built and tested but not yet
proved on a live router. This note records the *other* work that becomes possible
once a router reports to us instead of us polling it, so the option is not lost.

Nothing here is scheduled. Do not build any of it before the usage channel is
proved on Router-0721.

## Why the channel is worth more than usage alone

Everything we currently know about a router, we learn by phoning it. That cost is
paid per router per fact, and it degrades as the fleet grows: the bandwidth job
walks 8 routers per 157s tick, so a router is revisited every ~49 minutes at 187
routers, and every new router makes that worse for everyone.

A router reporting to us inverts that. The cost per router is zero polling, the
router picks a moment when its uplink is actually working, and — because it
initiates — the report gets through NAT and flaky/Starlink links that we cannot
reach inbound. That last property is why `pull_provisioning` exists at all.

So any fact we currently poll for is a candidate to ride along in a report the
router is already sending.

## Candidates, roughly by value

### 1. Router liveness (replaces availability polling)

- **Today:** we poll every router to see if it is up. Routers that have never
  answered are polled forever — router 49 has **20,336 checks and 0 successes**,
  router 62 19,336 with 0, router 72 16,621 with 4. That is pure waste, and it
  slows the rotation for every router that *is* reachable.
- **With push:** a report *is* a heartbeat. Silence past a threshold means down.
  We would also finally distinguish "no usage" from "haven't heard from this
  router in 20 minutes" — today those look identical on the dashboard, which is
  part of why SkyNet's problem went unnoticed for weeks.
- **Care:** absence of a report is not proof of a dead router (it may be shedding
  or rate-limited). Treat it as a signal, not a verdict.

### 2. Expired-binding / config drift detection

- **Today:** the 2026-07-15 free-internet incident happened partly because
  cleanup could not reach the router during a 21h Starlink outage, so expired
  `type=bypassed` ip-bindings lingered. We only find that by polling — which is
  exactly what fails in that scenario.
- **With push:** the router reports which bindings and hotspot users it currently
  holds. We diff against what we believe and flag drift. Orphan bindings (a MAC
  with no customer row) and expired-but-still-bypassed customers surface without
  ever reaching the router.
- Would also catch the second-hand-router leftovers documented in AGENTS.md
  (`html-directory-override`, foreign tunnels, wrong bridge) via a config hash.

### 3. Provisioning acknowledgement

- **Today:** the pull channel delivers commands one way. We learn a command failed
  by polling, or not at all — konza energy's second activation retried 5× with
  `secret with the same name already exists` and nothing surfaced it.
- **With push:** the router reports applied/failed per command. Closes the loop on
  the existing pull channel with no new transport.

### 4. Payments taken while the tunnel is down

- The original reason the pull channel was built: during the Starlink outages a
  customer pays and there is no path to tell the server. A router-side queue that
  reports on reconnect would make payment delivery survive the outage in the
  direction that currently fails.
- **Care:** money is not usage. Usage reports are cumulative and therefore safe to
  drop and safe to replay; a payment is a one-shot event and needs an idempotency
  key and an explicit acknowledgement before the router may discard it. Do not
  reuse the usage semantics for this.

### 5. Router health telemetry

- CPU, free memory, disk, uptime, RouterOS version. Cheap to include in a report
  the router is already sending.
- Would let us see a router struggling before it fails, and would tell us which
  devices are near their limit on simple-queue count — the real ceiling on how
  many users a small hAP can serve.

### 6. Uplink quality

- Latency/loss/throughput as the router measures it, which is the only place it
  can be measured honestly. Directly useful for the Starlink congestion work
  (`project-simseas-starlink-egress`) instead of inferring from our side.

## Design rules that should carry over

These fell out of building the usage channel and are what make it safe. Anything
added later should keep them.

1. **Cumulative, not incremental.** Usage reports carry totals, so a dropped or
   replayed report costs nothing and the server may shed load freely. Any new
   payload should be cumulative-or-idempotent, or it loses that property — see
   the payments caveat above.
2. **The router is not a trustworthy narrator.** It keeps queues for deleted
   customers, reboots and resets counters, retries, and delivers out of order.
   Validate lifecycle (status *and* expiry), bound magnitudes, and scope every
   report to the reporting router's own tenants.
3. **No schema for operational state.** Whether a router pushes is observable from
   whether it pushed; a rate limiter is a throttle, not a fact. Adding a column
   costs an idempotent migration in `main.py` plus a refreshed
   `tests/schema_snapshot.json`.
4. **Server sets the cadence.** The response carries `next_push_seconds`, so the
   fleet can be retuned centrally without touching a thousand devices.
5. **Jitter everything.** Routers that reboot together after a power cut come back
   together.
