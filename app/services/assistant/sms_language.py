"""The language of an SMS the assistant drafts.

A draft follows the language the person writes to the assistant in. It is in
Swahili only when they write Swahili, ask for it, or their account's
preferred_language is Swahili. Resellers who wrote English were handed Swahili
drafts (and one went out before the English one was ready), so a Swahili draft
for someone who writes English is sent back to the model once per turn to be
written again in English.

A word-list check, not a language model: it only acts when the draft is
clearly Swahili and the person clearly writes English.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

_WORD = re.compile(r"[a-zA-Z']+")
_STAMPS = re.compile(r"^(\s*\[[^\]]*\])+\s*")

_SWAHILI = frozenset("""
habari hujambo mpendwa ndugu karibu asante tafadhali samahani pole
muda wako yako yetu wetu wenu yenu chako changu kifurushi vifurushi kimekwisha kinaisha
unaisha umekwisha imekwisha inaisha itaisha malizika unamalizika haujamalizika
lipa lipia lipwa malipo nunua kununua tena leo kesho jana sasa bado kabla baada
ili kwa na ya wa za la cha vya kwenye kupitia kupata kuwa uendelee kuendelea endelea
mteja wateja intaneti mtandao simu ombi hakikisha haraka ndani siku saa wiki mwezi
hivi karibuni sana ni si hapana ndiyo kama lakini pia tu kila hapa huduma akaunti namba
ujumbe tuma tumia ukishaona subiri ingiza fungua
""".split())

_ENGLISH = frozenset("""
the a an to of for and or is are was be your you my me i we our their them they it this that
send sent reminder customers customer who whose what when how please can will would should
today tomorrow time ends ended expire expires expired buy again all with in on at from have has
message sms write english change body
""".split())


def _words(text: str) -> list[str]:
    return [w.lower() for w in _WORD.findall(text or "")]


def looks_swahili(text: str) -> bool:
    words = _words(text)
    hits = sum(1 for w in words if w in _SWAHILI)
    return hits >= 3 and hits >= 0.25 * len(words)


def _looks_english(text: str) -> bool:
    words = _words(text)
    hits = sum(1 for w in words if w in _ENGLISH)
    return hits >= 2 and hits > sum(1 for w in words if w in _SWAHILI)


def person_texts(messages: Iterable[dict]) -> list[str]:
    """What the person typed in this chat, without the [time] / [Account now] stamps, the
    confirmation results or Bitwave support notes."""
    out = []
    for m in messages:
        if m.get("role") != "user" or not isinstance(m.get("content"), list):
            continue
        for b in m["content"]:
            text = b.get("text") if isinstance(b, dict) and b.get("type") == "text" else None
            if not text or text.startswith(("[Confirmation results]", "[Bitwave support note")):
                continue
            out.append(_STAMPS.sub("", text))
    return out


def draft_problem(drafts: list[str], said: list[str]) -> Optional[str]:
    """Why a draft is in the wrong language for what the person writes, or None when it is fine.
    The account's preferred_language is checked by the caller (it allows Swahili too)."""
    if not any(looks_swahili(d) for d in drafts):
        return None
    if any(looks_swahili(t) or re.search(r"swahili", t, re.I) for t in said):
        return None
    if not said or not _looks_english(said[-1]):
        return None
    return ("Not proposed: the SMS text is in Swahili, but the person writes to you in English and "
            "did not ask for Swahili. Write the message in English and send this call again.")
