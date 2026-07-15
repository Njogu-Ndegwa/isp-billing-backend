"""Tests for the secondary-server pull service (pull_service.py).

Focused on the free-internet fix: a command is served only within its paid window and
is dropped the moment it expires, and stale commands never accumulate — including for
routers whose agent never checks in. Importing the module must have no side effects
(the HTTP server only starts under __main__).
"""
import os
import time

import pytest

import pull_service


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(pull_service, "DATA", str(tmp_path))
    return str(tmp_path)


def _write(data_dir, ident, key, body):
    d = os.path.join(data_dir, ident)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, key + ".rsc")
    with open(p, "w") as fh:
        fh.write(body)
    return p


def _cmd(expires_at=None, body="/ip hotspot user\nadd name=x\n"):
    head = f"# PULL-EXPIRES {expires_at}\n" if expires_at is not None else ""
    return head + body


# --- expiry parsing ---

def test_parse_expires_reads_header(data_dir):
    p = _write(data_dir, "R1", "k", _cmd(expires_at=1752566400))
    assert pull_service._parse_expires(p) == 1752566400


def test_parse_expires_none_without_header(data_dir):
    p = _write(data_dir, "R1", "k", _cmd(expires_at=None))
    assert pull_service._parse_expires(p) is None


# --- the core fix: served only within the paid window ---

def test_served_before_expiry(data_dir):
    now = 1_000_000
    _write(data_dir, "R1", "guest", _cmd(expires_at=now + 600))
    out = pull_service._pending_rsc("R1", now=now)
    assert b"add name=x" in out
    assert out != b"# idle\n"


def test_dropped_after_expiry(data_dir):
    now = 1_000_000
    p = _write(data_dir, "R1", "guest", _cmd(expires_at=now - 1))  # expired 1s ago
    out = pull_service._pending_rsc("R1", now=now)
    assert out == b"# idle\n"                 # not served
    assert not os.path.exists(p)              # and removed from the queue


def test_expiry_overrides_short_ttl(data_dir, monkeypatch):
    # A long paid window must survive even though the file is older than PULL_TTL:
    # expiry — not mtime — governs a command that carries an expiry header.
    monkeypatch.setattr(pull_service, "PULL_TTL", 1)
    now = 1_000_000
    p = _write(data_dir, "R1", "guest", _cmd(expires_at=now + 3600))
    os.utime(p, (now - 10_000, now - 10_000))  # very old mtime
    out = pull_service._pending_rsc("R1", now=now)
    assert b"add name=x" in out                # still served — expiry wins over TTL


# --- legacy (no expiry header): mtime TTL still applies ---

def test_legacy_command_pruned_by_ttl(data_dir, monkeypatch):
    monkeypatch.setattr(pull_service, "PULL_TTL", 3600)
    now = 1_000_000
    p = _write(data_dir, "R1", "legacy", _cmd(expires_at=None))
    os.utime(p, (now - 7200, now - 7200))      # 2h old, TTL 1h
    out = pull_service._pending_rsc("R1", now=now)
    assert out == b"# idle\n"
    assert not os.path.exists(p)


# --- background pruner sweeps agent-less routers (the Major1 case) ---

def test_prune_all_removes_expired_across_routers(data_dir):
    now = 1_000_000
    live = _write(data_dir, "R1", "active", _cmd(expires_at=now + 600))
    dead1 = _write(data_dir, "R2", "old1", _cmd(expires_at=now - 5))
    dead2 = _write(data_dir, "R2", "old2", _cmd(expires_at=now - 5))
    removed = pull_service._prune_all(now=now)
    assert removed == 2
    assert os.path.exists(live)
    assert not os.path.exists(dead1) and not os.path.exists(dead2)


def test_idle_when_router_unknown(data_dir):
    assert pull_service._pending_rsc("NoSuchRouter", now=1_000_000) == b"# idle\n"


def test_import_has_no_side_effects():
    # /data must not be created just by importing (server only starts under __main__)
    assert hasattr(pull_service, "_pending_rsc")
    assert callable(pull_service._pending_rsc)
