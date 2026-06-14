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


def count_segments(body: str) -> int:
    """Number of SMS segments (>=1) this body consumes per recipient.

    GSM-7: 160 single / 153 per part. UCS-2: 70 single / 67 per part.
    Extension chars (^{}[]~|\\€) weigh 2 septets but stay GSM-7.
    """
    if body is None:
        body = ""
    if _is_gsm7(body):
        length = _gsm7_weight(body)
        single, multi = 160, 153
    else:
        length = len(body)
        single, multi = 70, 67
    if length <= single:
        return 1
    return math.ceil(length / multi)
