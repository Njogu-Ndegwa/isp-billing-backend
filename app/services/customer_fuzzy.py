"""Close matches for a customer search that found nothing ("amnia" -> Amina).

The customer list's search is a plain "contains" match, so one wrong letter in a name
or one wrong digit in a phone number finds no one. When that happens the list offers
these instead, as a separate `did_you_mean` list: exact results never change.

Bounded on purpose: only the reseller's own customers are read, only four short
columns, at most MAX_POOL of them, and each candidate passes difflib's cheap upper
bounds before the real ratio is worked out. Pure CPU on rows already read; no I/O.
"""
from __future__ import annotations

from difflib import SequenceMatcher
import re
from typing import Iterable, Optional

MAX_POOL = 10000        # customers read at most (the largest accounts have a few thousand; ~0.2 s at the cap)
MAX_SUGGESTIONS = 5
NAME_MIN_RATIO = 0.75
ACCOUNT_MIN_RATIO = 0.8
MIN_QUERY = 3

_WORD = re.compile(r"[^\w]+", re.UNICODE)


def _norm(text: Optional[str]) -> str:
    return " ".join(_WORD.sub(" ", (text or "").lower()).split())


def _digits(text: Optional[str]) -> str:
    return "".join(ch for ch in (text or "") if ch.isdigit())


def _name_parts(name: str) -> list[str]:
    """The whole name, each word, and each pair of words side by side ("mary jane")."""
    words = name.split()
    parts = [name] if name else []
    parts += words
    parts += [f"{a} {b}" for a, b in zip(words, words[1:])]
    return parts


def _best_ratio(matcher: SequenceMatcher, parts: Iterable[str], floor: float) -> float:
    best = 0.0
    for part in parts:
        matcher.set_seq1(part)
        if matcher.real_quick_ratio() < floor or matcher.quick_ratio() < floor:
            continue
        r = matcher.ratio()
        if r > best:
            best = r
    return best


def _phone_close(q9: str, phone: Optional[str]) -> bool:
    """Same last nine digits but one: one digit wrong, or two side by side swapped."""
    p9 = _digits(phone)[-9:]
    if len(p9) != len(q9) or p9 == q9:
        return False
    diff = [i for i, (a, b) in enumerate(zip(q9, p9)) if a != b]
    if len(diff) == 1:
        return True
    return len(diff) == 2 and diff[1] == diff[0] + 1 and q9[diff[0]] == p9[diff[1]] and q9[diff[1]] == p9[diff[0]]


def close_matches(query: str, rows: Iterable, limit: int = MAX_SUGGESTIONS) -> list[dict]:
    """Ranked close matches for `query` among `rows` (objects or tuples with id, name,
    phone, account_number). Returns [{id, matched_on, score}], best first."""
    q = _norm(query)
    if len(q.replace(" ", "")) < MIN_QUERY:
        return []
    q_digits = _digits(query)
    q9 = q_digits[-9:] if len(q_digits) >= 7 and len(q_digits) >= len(q.replace(" ", "")) - 1 else ""
    has_letters = any(ch.isalpha() for ch in q)
    name_matcher = SequenceMatcher(None, "", q, autojunk=False)
    acct_q = q.replace(" ", "")
    acct_matcher = SequenceMatcher(None, "", acct_q, autojunk=False)

    found: list[tuple[float, int, str]] = []
    for row in rows:
        cid, name, phone, account = _fields(row)
        score, on = 0.0, ""
        if q9 and _phone_close(q9, phone):
            score, on = 0.9, "phone"
        if has_letters and name:
            r = _best_ratio(name_matcher, _name_parts(_norm(name)), NAME_MIN_RATIO)
            if r >= NAME_MIN_RATIO and r > score:
                score, on = r, "name"
        if account and len(acct_q) >= 4:
            r = _best_ratio(acct_matcher, [_norm(account).replace(" ", "")], ACCOUNT_MIN_RATIO)
            if r >= ACCOUNT_MIN_RATIO and r > score:
                score, on = r, "account_number"
        if on:
            found.append((score, cid, on))
    found.sort(key=lambda t: (-t[0], t[1]))
    return [{"id": cid, "matched_on": on, "score": round(score, 2)} for score, cid, on in found[:limit]]


def _fields(row) -> tuple:
    if isinstance(row, (tuple, list)):
        return tuple(row[:4])
    return row.id, row.name, row.phone, row.account_number
