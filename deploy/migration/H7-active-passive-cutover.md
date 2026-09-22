# H7 — Hetzner primary / AWS recoverable standby cutover

This is a **single-writer** design. At any moment only one application stack
may accept writes or run schedulers. PostgreSQL streams AWS → Hetzner before
the first cutover; after promotion, AWS must be re-seeded from Hetzner before it
can be called a standby again.

## Tunnel rule carried into the migration

- RouterOS 7 WireGuard tunnels may stay up to both hosts.
- RouterOS 6 L2TP/IPsec is single-active. `l2tp-aws2` is provisioned disabled.
- Before any ROS6 failover, fix Hetzner strongSwan with
  `configure-l2tp-rekey-safety.sh --apply`, verify zero duplicate connmark
  tuples, then switch each router in a controlled window. Never leave both
  L2TP clients enabled.

## One-time standby build

1. Deploy this branch to Hetzner with `SHADOW_MODE=true`, both scheduler flags
   false, dispatch flags false, and FreeRADIUS stopped.
2. Create a dedicated SSH key on Hetzner. Authorize only its public key for the
   AWS deploy user. Do not copy an operator private key.
3. On AWS, set `REPLICATION_PASSWORD` in the shell and run
   `configure-postgres-primary.sh --apply`.
4. On Hetzner, install the dedicated key and run
   `install-replication-tunnel.sh --apply`.
5. On Hetzner, export the same replication password and run
   `clone-hetzner-replica.sh --apply`. This destroys only the stale Hetzner DB
   volume, replaces it with a physical standby, and leaves RADIUS stopped.
6. Verify `pg_is_in_recovery() = true`, replay lag remains near zero, `/health`
   reports `shadow`, and attempts to POST receive `shadow_mode_blocked`.

## Planned promotion

1. Announce a short maintenance window and stop insurance-tunnel batch work.
2. On AWS, run `fence-aws-primary.sh --apply`. This stops app and RADIUS writers
   while leaving PostgreSQL and the tunnel manager alive.
3. On Hetzner, run `promote-hetzner.sh --apply`. It refuses promotion unless AWS
   app and RADIUS are stopped and WAL replay has caught up to the fenced LSN.
4. Smoke-test login, dashboard reads, one sandbox/non-customer payment callback,
   router reachability over `wg2`, and `/health` = `active`.
5. With a scoped Cloudflare DNS token, run
   `switch_backend_origin.sh hetzner`. Watch payment success, callback errors,
   DB pool pressure, scheduler logs, and router reachability.
6. Enable SMS dispatch and automated payouts separately after the observation
   window; do not bundle money movement into the database promotion command.

## Disaster promotion

If AWS is genuinely unreachable, inspect replay lag first. Promotion requires
`ALLOW_DATA_LOSS=yes promote-hetzner.sh --disaster`; the explicit flag records
that the operator accepted the displayed recovery-point gap. Do not attempt to
start the old AWS app later: it is a stale former primary.

## Rebuilding AWS as standby / failback

After Hetzner accepts its first write, failback is **not** a DNS reversal.
Provision the reverse replication tunnel, wipe/re-seed the AWS database from
Hetzner, confirm it is in recovery and caught up, then perform the same fence →
catch-up → promote sequence in the opposite direction. Starting both old and
new databases as writable primaries is split brain and is never an acceptable
rollback.
