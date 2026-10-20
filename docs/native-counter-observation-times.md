# Buffered router counter observations

Native RouterOS API subscriptions can reduce the work done by RouterOS scripts.
Their counter observations may precede the HTTP batch that carries them. Stamping
every observation with its HTTP arrival time would allow an older, lower counter
to overwrite a newer baseline and appear to be a fresh reset.

Queue and host reports therefore accept an optional `sampled_at` UTC timestamp.
Ingest forwards it to the existing stale-sample check in
`record_queue_usage_sample`. Supplied timestamps must be no more than 360 seconds
old and must not be in the future. Offset timestamps are normalized to UTC.
Reports without this field keep their existing behavior.

This field does not change counter keys: HotSpot entries remain keyed by MAC and
original host IP, and PPPoE entries retain their queue keys. A fresh observation
of lower counters still follows the existing reset rule. A stale observation
cannot regress the baseline or credit a second copy of its bytes.

This change does not install a native collector or pause any router timer. The
collector remains a separate, opt-in change requiring hardware acceptance,
exclusive report ownership, bounded subscriptions, and automatic fallback.
