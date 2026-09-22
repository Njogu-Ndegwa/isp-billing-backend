from pathlib import Path


MIGRATION_DIR = Path("deploy/migration")


def test_postgres_replica_flow_has_single_writer_guards():
    clone = (MIGRATION_DIR / "clone-hetzner-replica.sh").read_text(encoding="utf-8")
    promote = (MIGRATION_DIR / "promote-hetzner.sh").read_text(encoding="utf-8")
    fence = (MIGRATION_DIR / "fence-aws-primary.sh").read_text(encoding="utf-8")

    assert 'test "$runtime_mode" = "shadow"' in clone
    assert "pg_basebackup" in clone
    assert "standby.signal" in clone
    assert 'docker stop "$APP_CONTAINER" "$RADIUS_CONTAINER"' in fence
    assert 'test "$aws_app" = "false" -a "$aws_radius" = "false"' in promote
    assert "pg_wal_lsn_diff" in promote
    assert "pg_ctl -D /var/lib/postgresql/data promote -w" in promote
    assert "set_env SHADOW_MODE false" in promote


def test_l2tp_safety_artifacts_default_to_audit():
    safety = (MIGRATION_DIR / "configure-l2tp-rekey-safety.sh").read_text(encoding="utf-8")
    cleanup = Path("scripts/cleanup_ipsec_connmarks.py").read_text(encoding="utf-8")

    assert 'MODE="${1:-audit}"' in safety
    assert "delete_rekeyed = yes" in safety
    assert 'parser.add_argument("--apply", action="store_true")' in cleanup
