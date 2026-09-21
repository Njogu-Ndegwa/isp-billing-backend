# 2026-09-21 Expiry cleanup queue blocked by long-offline routers

## Summary

Expired customers on routers that had been offline for weeks kept returning to the direct RouterOS cleanup batch. New five-minute hotspot expiries then waited behind old records and could remain active for several minutes.

## Symptoms

- The production database had 752 expired customers still marked `ACTIVE` during the final 2026-09-21 audit.
- 626 of those customers belonged to routers with no successful online signal for at least three days.
- The cleanup job accepts 60 customers per run and 15 per router.
- Runs took longer than the 67-second schedule, so APScheduler skipped overlapping runs.
- Two customers on Router-0964 remained active after five-minute plans expired. The worker had deferred at least one of them because its batch was full.

## Suspected Cause

The cleanup worker backs off an unreachable router for 30 minutes. Once that backoff expires, every customer on the dead router is eligible again. Large offline groups repeatedly filled the bounded batch, timed out, stayed `ACTIVE`, and returned after the next backoff window.

## Fix Applied

- `app/services/mikrotik_background.py` now quarantines direct-router cleanup work when `last_status` is offline and the last successful online signal is at least three days old.
- A router that has never reported online uses its creation time as the start of the three-day window.
- Quarantined customer rows remain `ACTIVE`; the job does not claim that RouterOS access was removed.
- A recovered router automatically re-enters cleanup after its next successful status update.
- The worker logs the number and first 50 customer IDs quarantined in each run.

## Verification

- `python -m pytest tests/test_expired_hotspot_cleanup.py -q` (`8 passed`)
- `python -m pytest tests/test_expired_pppoe_cleanup.py tests/test_customer_expiry_notifications.py -q` (`23 passed`)
- A read-only production query showed the rule would quarantine 626 of 752 expired-ACTIVE rows and leave 126 router-backed rows in the normal cleanup path.

## Follow-Up Work

- Add a cleanup health endpoint with hot-queue and quarantined counts.
- Add an operator action to retry one quarantined router without waiting for the shared status monitor.
