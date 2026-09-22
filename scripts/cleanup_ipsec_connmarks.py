#!/usr/bin/env python3
"""Audit or remove superseded strongSwan connmark rules.

The connmark plugin inserts the newest CHILD_SA rule first.  For an exact
NAT-T tuple, keep the first rule and remove only later duplicates.  Audit is
the default; pass ``--apply`` to mutate iptables after writing a full backup.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import pathlib
import re
import shlex
import subprocess
from dataclasses import dataclass


RULE_RE = re.compile(
    r"^-A PREROUTING -s (?P<src>\S+) -d (?P<dst>\S+) -p udp .*?"
    r"--sport (?P<sport>\d+) --dport (?P<dport>\d+) .*?"
    r"--set-xmark 0x[0-9a-fA-F]+/0xffffffff$"
)


@dataclass(frozen=True)
class ConnmarkRule:
    line: str
    key: tuple[str, str, str, str]


def parse_rules(text: str) -> list[ConnmarkRule]:
    parsed: list[ConnmarkRule] = []
    for raw in text.splitlines():
        line = raw.strip()
        match = RULE_RE.match(line)
        if not match:
            continue
        values = match.groupdict()
        parsed.append(
            ConnmarkRule(
                line=line,
                key=(values["src"], values["dst"], values["sport"], values["dport"]),
            )
        )
    return parsed


def superseded_rules(rules: list[ConnmarkRule]) -> list[ConnmarkRule]:
    seen: set[tuple[str, str, str, str]] = set()
    stale: list[ConnmarkRule] = []
    for rule in rules:
        if rule.key in seen:
            stale.append(rule)
        else:
            seen.add(rule.key)
    return stale


def run(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=True,
        text=True,
        capture_output=capture,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup-dir", default="/var/backups")
    args = parser.parse_args()

    saved = run("iptables-legacy-save", "-t", "mangle", capture=True).stdout
    rules = parse_rules(saved)
    stale = superseded_rules(rules)
    counts = collections.Counter(rule.key for rule in rules)
    duplicate_groups = {key: count for key, count in counts.items() if count > 1}

    print(f"inspected_rules={len(rules)}")
    print(f"duplicate_tuple_count={len(duplicate_groups)}")
    print(f"superseded_rule_count={len(stale)}")
    for key, count in sorted(duplicate_groups.items()):
        print(f"duplicate tuple={'|'.join(key)} rules={count}")

    if not args.apply or not stale:
        print("mode=audit" if not args.apply else "mode=apply nothing_to_remove=true")
        return 0

    backup_dir = pathlib.Path(args.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"iptables-before-ipsec-mark-cleanup-{stamp}.rules"
    backup_path.write_text(run("iptables-legacy-save", capture=True).stdout)
    backup_path.chmod(0o600)

    for rule in stale:
        tokens = shlex.split(rule.line)
        if tokens[:2] != ["-A", "PREROUTING"]:
            raise RuntimeError(f"refusing unexpected rule: {rule.line}")
        run("iptables-legacy", "-t", "mangle", "-D", "PREROUTING", *tokens[2:])

    after = run("iptables-legacy-save", "-t", "mangle", capture=True).stdout
    remaining = superseded_rules(parse_rules(after))
    print(f"mode=apply backup={backup_path}")
    print(f"remaining_superseded_rule_count={len(remaining)}")
    return 1 if remaining else 0


if __name__ == "__main__":
    raise SystemExit(main())
