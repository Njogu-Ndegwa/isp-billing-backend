"""SMS segment counting (GSM-7 vs UCS-2), independent of any provider."""

import math

# GSM 03.38 basic alphabet
_GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
# Characters that require an escape (count as 2 septets) but keep us in GSM-7
_GSM7_EXTENSION = "^{}\\[~]|€"

_GSM7_SET = set(_GSM7_BASIC) | set(_GSM7_EXTENSION)


def _is_gsm7(body: str) -> bool:
    return all(ch in _GSM7_SET for ch in body)


def _gsm7_weight(body: str) -> int:
    return sum(2 if ch in _GSM7_EXTENSION else 1 for ch in body)


def encoding(body: str) -> str:
    """"GSM-7" when every character is in the GSM alphabet, else "UCS-2"."""
    return "GSM-7" if _is_gsm7(body or "") else "UCS-2"


def non_gsm_characters(body: str, limit: int = 10) -> list[str]:
    """The characters that push a message into UCS-2 (smart quotes, emoji...), each once."""
    out: list[str] = []
    for ch in body or "":
        if ch not in _GSM7_SET and ch not in out:
            out.append(ch)
            if len(out) >= limit:
                break
    return out


def count_segments(body: str) -> int:
    """Number of SMS segments (>=1) this body consumes per recipient.

    GSM-7: 160 single / 153 per part. UCS-2: 70 single / 67 per part.
    Extension chars (^{}[]~|\\€) weigh 2 septets but stay GSM-7.
    UCS-2 counts UTF-16 code units, as the network does: an emoji outside
    the basic plane takes two of the 70.
    """
    if body is None:
        body = ""
    if _is_gsm7(body):
        length = _gsm7_weight(body)
        single, multi = 160, 153
    else:
        length = len(body.encode("utf-16-le")) // 2
        single, multi = 70, 67
    if length <= single:
        return 1
    return math.ceil(length / multi)
