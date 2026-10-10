# 2026-10-10 Bitwave router scripts stacking on one second (RB951 CPU)

## Summary

KWETU WIFI (router 585 "APPOLO", RB951Ui-2HnD, 600 MHz single core, ROS 7.24.5)
asked why his CPU was high with ~30 users. Most of the load was his own
traffic: ~20 Mbps through hotspot + 7 PPPoE + 18 simple queues on a 2013-era
board (hotspot rules out fasttrack). On top of that, our scripts held the CPU
at 100% for ~4 s every minute, because they all fired in the same second.

## Symptoms

- `/system resource` 81% CPU, 51% irq; `/tool profile` spread evenly over
  kernel/ethernet/queuing/firewall/networking (forwarding, not one process).
- Per-second profile across the :06 tick: `console` (= scripts) 20–40%, total
  63 → 100 → 74 (off-peak) and 95 → 100 → 100 → 100 (peak, 75–85% baseline).
- All of `bw-mgmt-watchdog-wg`, `bitwave-expiry-reaper` and
  `bitwave-usage-push` showed the same `last-started` second.

## Cause

Every installer adds its scheduler with `start-time=startup`, so all of them
are phased from boot: the 1 m and 2 m ones always coincide, and the check-in
(server-set 54 s / 10 s) and command agent drift through them. Offsetting start
times cannot hold, because the check-in and push retune their own intervals.

## Fix Applied

- `app/services/router_script_gate.py`: each Bitwave script waits (1 s steps,
  max 20 s) while a Bitwave script job with a smaller job id is running. Job ids
  only grow, so the oldest never waits; ids that do not parse skip the wait.
- Renderers for watchdog (SSTP/WG), check-in, reaper, real-time push and command
  agent emit it; `scripts/router_script_gate_rollout.py` prepends it in place on
  routers that already had the scripts.
- Primitives verified by `/execute` probe on ROS 7.24.5, 6.49.18, 6.48.6:
  `[:tonum "0x1A3"]` = 419, `[:tonum "0xZZ"]` is nil, job ids increase, the
  scheduler-run job carries its script name.

## Verification

- Pilot 585 + 166: scripts run back to back (push report ~8 s after the tick);
  585's stacked 100% went from 4 s/min to 1 s/min. Push reports kept arriving.
- `tests/test_router_script_gate.py` + existing router-script tests.

## Lessons

- Measure our own cost per second, not per minute: `/tool profile` sections are
  one per second; a 60 s average (2–3%) hid a 4 s saturation.
- Any new router scheduler must be gated (`GATED_SCRIPTS`), not just staggered.
- `router_health` keeps only the latest sample per router; there is no CPU
  history to look back on. Live sampling was needed to see the spike.

## Follow-Up Work

- One script alone still costs ~30% console for a second on an RB951 at peak;
  the heaviest (reaper vs push) has not been isolated.
- Same day, unrelated: customer 39099 on 585 has a 111,111-day custom duration
  (expiry 2330), an 11-digit epoch the check-in whitelist (`^\d{10}$`) rejects
  every check-in. Durations are not capped at entry.
