# Accounting rotation skipped routers after budget exits

Investigated against main `77843f7` on 20 October 2026. A small RouterOS6 board used server polling by design: its four newer router scripts were absent, customers were online, reachability checks were fresh, but the latest bandwidth snapshot and credited usage were more than three hours old.

The accounting collector selected eight eligible routers and advanced its cursor past all eight before attempting the first. When time or pool pressure stopped the loop early, unattempted routers lost their turn. Production logs repeatedly showed eight selected but only one attempted, followed by another eight-position advance. The nominal90-second budget was sometimes exceeded inside a router attempt or while waiting for shared locks; this change does not make that budget a hard deadline.

Advance the cursor immediately before each actual attempt, after the time and pool checks. This keeps unattempted routers next while retaining progress on failed or cancelled attempts. Stable ID ordering, eligibility filters, batch size, cadence, customer matching, counter/reset handling, retention and enforcement remain unchanged.

Regression tests run the real collector with eight database-backed routers and a slow/failing mocked read. The old code repeatedly revisits only the first router. Tests also cover pool-pressure exits, zero budget, wrapping/full batches and cancellation. Existing MAC-login usage and duplicate-counter tests remain relevant.

Do not describe this as a CPU-spike fix, an accounting freshness SLA, or proof that every historical gap on the reported router had this cause. Changing eligibility still affects index-based rotation. Per-router deadlines and fresher scheduling for poll-only boards remain follow-up work. Do not cancel a worker thread and release its router lock while it may still be doing RouterOS I/O.

Small32MiB hAP lite/mini boards intentionally remain off the push runtime. See [realtime rollout](../realtime-push-rollout.md). A newer RB951 native-accounting pilot is not automatic authorization or compatibility evidence to install it on RouterOS6/smips.
