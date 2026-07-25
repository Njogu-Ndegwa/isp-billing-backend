#!/usr/bin/env python3
"""Shared read-only production DB helper for the WhatsApp copilot lookup tools.

Runs FROM the local workstation and reaches production exactly the way the
`accessing-production-server` skill prescribes: key-based, non-interactive SSH
to dennis@54.91.202.229, then `docker exec` into the postgres container. The
SQL is piped over stdin (`psql -f -`) so no quotes are hand-nested through
ssh -> sh -> docker (the skill's documented pattern).

READ-ONLY BY CONSTRUCTION — three independent layers:
  1. Callers can only go through run_sql(), which rejects anything that is not
     a single SELECT/WITH statement (no semicolons, no write keywords).
  2. Every session starts with `SET default_transaction_read_only = on;` so
     even a slipped write would be refused by Postgres itself.
  3. `SET statement_timeout = '5s';` — the prod box has ~1 GB RAM; anything
     slower than 5s is aborted server-side rather than hammered.

Output convention for the CLI tools: compact JSON on stdout, diagnostics on
stderr, exit 0 on success / 1 on failure.

CONNECTION BUDGET — IMPORTANT: prod port 22 is UFW rate-limited (server
hardening 2026-07-21: 6+ new connections in ~30s from one IP = temporary
block, observed live while building these tools). Every tool therefore batches
ALL of its statements into ONE ssh connection via run_batch(). Never call
run_sql() in a loop; if you get "Connection timed out" right after successful
calls, you are rate-limited — wait 60s, do not retry in a loop.
"""

import hashlib
import json
import re
import subprocess
import sys
import time

SSH_HOST = "dennis@54.91.202.229"
# -q suppresses SET echoes, -A -t gives bare output, ON_ERROR_STOP makes psql
# exit non-zero on SQL errors, -f - reads the SQL from stdin.
REMOTE_PSQL = (
    "docker exec -i isp_billing_postgres "
    "psql -U isp_user -d isp_billing_db -v ON_ERROR_STOP=1 -qAt -f -"
)
SSH_CMD = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", SSH_HOST, REMOTE_PSQL]

# Any of these appearing as a standalone word fails validation. Belt and
# braces on top of the SELECT/WITH prefix check and the read-only session.
_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|"
    r"vacuum|call|do|merge|reindex|cluster|lock|listen|notify|refresh|"
    r"prepare|execute|deallocate|set|reset|discard|security)\b",
    re.IGNORECASE,
)


class ProdQueryError(RuntimeError):
    pass


def assert_select_only(sql: str) -> None:
    """Reject anything that is not a single read-only SELECT/WITH statement."""
    if ";" in sql:
        raise ProdQueryError("semicolons are not allowed in tool SQL (single statement only)")
    if "\x00" in sql:
        raise ProdQueryError("NUL byte in SQL")
    # Strip leading whitespace and -- comments to find the first keyword.
    head = re.sub(r"(?:\s|--[^\n]*\n?)+", " ", sql, count=0).strip().lower()
    if not (head.startswith("select") or head.startswith("with")):
        raise ProdQueryError("only SELECT/WITH statements are allowed")
    m = _FORBIDDEN.search(sql)
    if m:
        raise ProdQueryError(f"forbidden keyword in SQL: {m.group(0)!r}")


def _wrap(sql: str) -> str:
    """Wrap a SELECT so its whole result is one line of JSON on stdout."""
    return ("SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (\n"
            + sql + "\n) t;\n")


def run_batch(queries, timeout: int = 60):
    """Run several read-only SELECTs in ONE ssh connection / psql session.

    queries: list of (tag, sql). Returns {tag: rows}. One JSON output line per
    statement, in order. This is the only sanctioned way to run more than one
    statement — prod's port 22 is rate-limited (see module docstring).
    """
    queries = list(queries)
    if not queries:
        return {}
    for _tag, sql in queries:
        assert_select_only(sql)
    payload = (
        "SET default_transaction_read_only = on;\n"  # hard read-only enforcement
        "SET statement_timeout = '5s';\n"            # never hammer the 1GB box
        + "".join(_wrap(sql) for _tag, sql in queries)
    )
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            SSH_CMD, input=payload, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise ProdQueryError("ssh executable not found on PATH")
    except subprocess.TimeoutExpired:
        raise ProdQueryError(f"batch: ssh call exceeded {timeout}s (prod unreachable or overloaded)")
    elapsed = time.monotonic() - t0
    tags = ",".join(t for t, _ in queries)
    print(f"[prodquery] batch({tags}): {elapsed:.1f}s over one ssh connection", file=sys.stderr)
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()[:500]
        if "Connection timed out" in err or "Connection refused" in err:
            err += " | likely the UFW port-22 rate limit -- wait 60s, do not retry in a loop"
        raise ProdQueryError(f"batch({tags}): remote query failed (rc={proc.returncode}): {err}")
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if len(lines) != len(queries):
        raise ProdQueryError(
            f"batch({tags}): expected {len(queries)} result lines, got {len(lines)}: "
            f"{proc.stdout[:200]!r}")
    out = {}
    for (tag, _sql), line in zip(queries, lines):
        try:
            out[tag] = json.loads(line)
        except json.JSONDecodeError as e:
            raise ProdQueryError(f"{tag}: unparseable psql output: {line[:200]} ({e})")
    return out


def run_sql(sql: str, tag: str = "query", timeout: int = 60):
    """Run ONE read-only SELECT (single ssh connection). Prefer run_batch when
    a tool needs more than one statement."""
    return run_batch([(tag, sql)], timeout=timeout)[tag]


# ---------------------------------------------------------------------------
# SQL literal helpers (psql -f has no parameter binding; quote by construction)
# ---------------------------------------------------------------------------

def lit(value: str) -> str:
    """Quote a string as a safe SQL literal (single-statement, no escapes)."""
    s = str(value).replace("\x00", "")
    return "'" + s.replace("'", "''") + "'"


def like_frag(value: str) -> str:
    """Escape LIKE/ILIKE wildcards inside user input, return bare fragment."""
    s = str(value).replace("\x00", "")
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def ilike_contains(value: str) -> str:
    """SQL literal for ILIKE '%<value>%' with wildcards escaped."""
    return lit("%" + like_frag(value) + "%")


# ---------------------------------------------------------------------------
# Phone helpers (Kenyan MSISDN forms: 07XXXXXXXX / 2547XXXXXXXX / +254...)
# ---------------------------------------------------------------------------

def phone_digits(raw: str) -> str:
    return re.sub(r"\D", "", raw or "")


def phone_last9(raw: str) -> str:
    d = phone_digits(raw)
    return d[-9:] if len(d) >= 9 else d


def phone_254(raw: str) -> str:
    d = phone_digits(raw)
    return ("254" + d[-9:]) if len(d) >= 9 else d


def phone_sha256_254(raw: str) -> str:
    """Safaricom C2B MSISDN hash = plain sha256 of the 254-form number."""
    return hashlib.sha256(phone_254(raw).encode()).hexdigest()


def phone_match_cond(column: str, raw: str) -> str:
    """NULL-safe SQL condition matching a phone column against any stored form."""
    last9 = phone_last9(raw)
    if len(last9) >= 9:
        return (f"RIGHT(regexp_replace(COALESCE({column}, ''), '[^0-9]', '', 'g'), 9) "
                f"= {lit(last9)}")
    # Short fragment — substring match on the digits.
    return (f"regexp_replace(COALESCE({column}, ''), '[^0-9]', '', 'g') "
            f"LIKE {lit('%' + last9 + '%')}")


def mask_msisdn(value):
    """Mask the middle digits of an MSISDN; label sha256-hashed ones."""
    if value is None:
        return None
    s = str(value)
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return s[:8] + "...(sha256)"
    d = re.sub(r"\D", "", s)
    if len(d) >= 7:
        return d[:4] + "*" * (len(d) - 6) + d[-2:]
    return "*" * len(s) if s else s


# ---------------------------------------------------------------------------
# CLI output helpers
# ---------------------------------------------------------------------------

def emit(obj) -> None:
    """Compact JSON to stdout."""
    json.dump(obj, sys.stdout, separators=(",", ":"), default=str)
    sys.stdout.write("\n")


def fail(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def reseller_ident_sql(ident: str):
    """Turn --reseller (numeric users.id or email) into SQL, WITHOUT a round trip.

    Returns (id_expr, resolve_sql):
      id_expr    — scalar SQL usable as `col = {id_expr}` in dependent queries
                   (either the literal id or a scalar subquery on email);
      resolve_sql — SELECT echoing the matched user row, to run in the same
                   batch so the tool can report who it matched (empty result
                   means the ident resolved to nobody and the dependent
                   queries returned nothing).
    Keeping resolution inline lets every tool stay at ONE ssh connection
    (port-22 rate limit — see module docstring).
    """
    ident = (ident or "").strip()
    if not ident:
        raise ProdQueryError("empty --reseller ident")
    if ident.isdigit():
        cond = f"u.id = {int(ident)}"
        id_expr = str(int(ident))
    else:
        cond = f"lower(u.email) = lower({lit(ident)})"
        id_expr = f"(SELECT u.id FROM users u WHERE {cond} LIMIT 1)"
    resolve_sql = (
        "SELECT u.id, u.email, u.role::text AS role, u.organization_name,\n"
        "       u.business_name, u.subscription_status::text AS subscription_status,\n"
        "       u.subscription_expires_at\n"
        f"FROM users u WHERE {cond} LIMIT 2"
    )
    return id_expr, resolve_sql


def check_resolved(rows, ident: str):
    """Validate the resolve_sql result; return the single matched user row."""
    if not rows:
        fail(f"no user found for --reseller {ident!r}")
    if len(rows) > 1:
        print("[prodquery] WARNING: reseller ident matched multiple users; using first",
              file=sys.stderr)
    row = rows[0]
    if row.get("role") != "RESELLER":
        print(f"[prodquery] note: user {row.get('id')} role is {row.get('role')}, not RESELLER",
              file=sys.stderr)
    return row
