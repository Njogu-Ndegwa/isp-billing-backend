# Hotspot reconnect could not revoke a MAC login user

On 2026-10-18, a paid customer on router 620 repeatedly received HTTP 503 from
`/api/public/reconnect`: “We could not safely move your active session.” The
router cleanup removed the old MAC's active session and host entry, but the
verification immediately found both again. The endpoint correctly kept the
customer's database MAC unchanged rather than grant access to two devices.

The router's hotspot profile had `login-by=mac` and its user was named with a
colon-formatted MAC (`XX:XX:XX:XX:XX:XX`). Cleanup searched only for the compact
username (`XXXXXXXXXXXX`), so it left that user enabled. The connected old
device authenticated again as soon as the session was removed.

The fix matches both MAC username formats when removing and verifying the user,
and removes that authorization before the active session. Regression tests
simulate immediate MAC reauthentication and a rejected user removal. Keep the
post-cleanup verification: a failed or incomplete router operation must still
block the device move.

The target MAC later belonged to a separate active paid customer on the same
router. The reconnect endpoint's `mac_conflict_active` check should continue to
reject a move onto a device owned by another active account.
