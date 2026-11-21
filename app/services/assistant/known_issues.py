"""What Bitwave support has learnt about why internet, routers, payments and SMS fail.

known_issues.json is distilled from the incident registry, the WhatsApp support
knowledge and the router triage runbooks, written for resellers: each entry is a
symptom in their words, what is really happening, what to check first, what they
do, and when Bitwave has to act. It holds no reseller's, customer's or router's
identity and nothing about our servers, so any signed-in person may read it.

The assistant reads it through the known_issues tool when someone reports that
something does not work, then checks live data to see which cause applies.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

_FILE = Path(__file__).with_name("known_issues.json")
_WORD = re.compile(r"[a-z0-9]+")
# words that say nothing about which fault it is
_STOP = frozenset("""
the and but for not are was were has have had his her its our you your they them this that with
from what when why how who can cant can't does doesnt don dont did any all some one get got
just still also only into out about after before then than there here very much many more
iko kwa na ya wa ni sana hii hiyo lakini bado pia tu
""".split())


@lru_cache(maxsize=1)
def _issues() -> tuple[dict, ...]:
    data = json.loads(_FILE.read_text(encoding="utf-8"))
    return tuple(i for i in data.get("issues", []) if isinstance(i, dict) and i.get("id"))


def index() -> list[dict]:
    return [{"id": i["id"], "title": i.get("title", "")} for i in _issues()]


def index_text() -> str:
    """One line per entry for the system prompt: id, title and how people put it."""
    lines = []
    for i in _issues():
        said = " / ".join(f'"{s}"' for s in (i.get("symptoms") or [])[:2])
        lines.append(f"- {i['id']}: {i.get('title', '')}" + (f" ({said})" if said else ""))
    return "\n".join(lines)


def _words(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if len(w) > 2 and w not in _STOP}


def _score(issue: dict, query: str, words: set[str]) -> int:
    score = 0
    for keyword in issue.get("keywords") or []:
        k = str(keyword).lower().strip()
        if k and (k in query if " " in k else k in words):
            score += 3 if " " in k else 2
    for symptom in issue.get("symptoms") or []:
        score += len(words & _words(str(symptom)))
    score += 2 * len(words & _words(str(issue.get("title") or "")))
    return score


def _public(issue: dict) -> dict:
    return {k: v for k, v in issue.items() if k != "keywords" and v not in (None, "", [])}


def search(symptom: str = "", issue_id: Optional[str] = None, limit: int = 3) -> dict:
    """The entries that best match what the person described (or the one asked for by id),
    with the general order to check things in, and the list of every entry's title."""
    issues = _issues()
    index_ = index()
    triage = next((i for i in issues if i["id"] == "triage-order"), None)
    if issue_id:
        hit = next((i for i in issues if i["id"] == issue_id), None)
        if hit is None:
            return {"error": f"No entry '{issue_id}'.", "all_entries": index_}
        return {"matches": [_public(hit)]}
    query = " ".join(str(symptom or "").lower().split())
    words = _words(query)
    ranked = sorted(((_score(i, query, words), n, i) for n, i in enumerate(issues) if i["id"] != "triage-order"),
                    key=lambda t: (-t[0], t[1]))
    matches = [_public(i) for score, _, i in ranked[:limit] if score > 0]
    out: dict = {"matches": matches}
    if triage is not None:
        out["check_in_this_order"] = _public(triage)
    if not matches:
        out["note"] = "Nothing in the known issues matches these words; check live data, or look one up by id."
        out["all_entries"] = index_
    return out
