# Account admins

A reseller can have additional account admins, each with their own email and
password, backed by `reseller_staff.is_account_admin`. The primary `users` row
remains the tenant and billing owner. An account admin authenticates with the
reseller role and owner user ID, plus the staff ID and session version. It never
becomes a platform admin. Existing staff default to false.

`POST /api/staff` and `PUT /api/staff/{id}` accept `is_account_admin` from the
owner or another account admin. Regular staff cannot grant it. Account admins
can manage staff and all reseller operations. Individual permission checkboxes
apply only to ordinary staff; demoting an admin restores those saved permissions.
All role changes revoke existing sessions. Deactivation/removal also ends access.

Login and `/api/staff/me` return `staff: null` for account admins so existing
clients expose the full account navigation. Their separate identity is returned
as `account_admin`; JWTs and audit logs retain the actor staff ID. Profile reads,
email changes and password changes operate on the signed-in identity; business
fields remain shared. The primary login remains the durable tenant anchor.

Forgot-password works for each active login. Recovery tokens identify the staff
row, its session version and the receiving email, in addition to the tenant.
A link cannot restore a removed, disabled, renamed or demoted identity, and it
cannot reset the primary login. Hashing releases the DB connection; token use
is checked again under a row lock. Requesting one admin's reset does not revoke
another admin's reset link or login.

Startup adds the admin flag and recovery columns idempotently, before serving
authentication. Existing rows keep their permissions. Staff reset tokens use a
separate hash domain, so older releases cannot find or consume them as primary
login reset tokens if this release is rolled back.

Tests: `tests/test_account_admins.py`, `tests/test_staff.py`,
`tests/test_password_reset.py`, and `tests/test_schema_migrations.py`. CI exercises
PostgreSQL migration reruns and concurrent reset consumption as well as the
normal SQLite local suite.
