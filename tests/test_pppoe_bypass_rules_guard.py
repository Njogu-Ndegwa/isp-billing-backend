"""Guard: PPPoE FastTrack bypass rules are written in one place, as 2 rules.

Every forwarded packet walks the forward chain until a rule matches, so each
extra rule ahead of FastTrack costs CPU on every router. Until Nov 2026 the
usual ``.2-.254`` pool was written as 13 CIDR blocks, 26 rules, on 38 routers
(isp-billing-backend #439; firewall CPU per packet fell 9-18% on the A/B
routers). These tests fail if a new provisioning path writes its own bypass
rules, or if the pool layout provisioning uses stops compacting to one pair.
Router drift is caught separately, by the fleet detector in
``scripts/pppoe_fasttrack_bypass_compact.py`` (dry run).
"""

import ast
import pathlib

from app.services.mikrotik_api import PPPOE_FASTTRACK_BYPASS_COMMENT_PREFIX, MikroTikAPI

ROOT = pathlib.Path(__file__).resolve().parents[1]
WRITER = "ensure_pppoe_fasttrack_bypass"
# Code allowed to mention bypass rules without writing them (removal on renumber, repair script).
READERS = {"scripts/pppoe_fasttrack_bypass_compact.py"}


def _python_files():
    for base in ("app", "scripts"):
        for path in (ROOT / base).rglob("*.py"):
            yield path, path.relative_to(ROOT).as_posix()


def test_only_the_one_writer_builds_bypass_rule_comments():
    """A bypass comment is ``f"{PREFIX} (src|dst) <matcher>"``. Building one
    anywhere but ``ensure_pppoe_fasttrack_bypass`` means a second writer."""
    offenders = []
    for path, rel in _python_files():
        source = path.read_text(encoding="utf-8")
        if PPPOE_FASTTRACK_BYPASS_COMMENT_PREFIX in source and rel != "app/services/mikrotik_api.py":
            offenders.append(f"{rel}: literal bypass comment (import the constant and call {WRITER})")
        if "PPPOE_FASTTRACK_BYPASS_COMMENT_PREFIX" not in source or rel in READERS:
            continue
        tree = ast.parse(source)
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) or func.name == WRITER:
                continue
            for node in ast.walk(func):
                if isinstance(node, ast.JoinedStr) and any(
                    isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name)
                    and v.value.id == "PPPOE_FASTTRACK_BYPASS_COMMENT_PREFIX"
                    for v in node.values
                ):
                    offenders.append(f"{rel}:{node.lineno} in {func.name}()")
    assert offenders == [], "PPPoE bypass rules must be written only by " + WRITER + ": " + "; ".join(offenders)


def test_every_pppoe_provisioning_path_uses_the_one_writer():
    for rel in ("app/services/pppoe_provisioning.py", "app/services/pppoe_router_transfer.py"):
        assert f".{WRITER}(" in (ROOT / rel).read_text(encoding="utf-8"), rel


def test_the_pool_provisioning_creates_is_one_rule_pair():
    api = MikroTikAPI.__new__(MikroTikAPI)
    for prefix in ("192.168.89", "10.10.7", "172.16.0"):
        pool = MikroTikAPI.pppoe_subnet_layout(prefix)["pool_range"]
        assert api._pool_ranges_to_matchers(pool) == [pool], pool          # one matcher = 2 rules
