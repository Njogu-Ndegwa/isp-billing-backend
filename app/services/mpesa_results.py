"""M-Pesa STK results in words a reseller can act on.

Safaricom's callback says why a payment prompt did not end in a payment
(ResultCode + ResultDesc). Kept on the order so "why did it fail" is answerable
later, and shown on the payment card in the chat.
"""
from typing import Optional

PLAIN = {
    1: "not enough money on that M-Pesa account",
    1001: "the phone was busy with another M-Pesa request; try again in a minute",
    1019: "the request expired before it was answered",
    1025: "M-Pesa could not send the prompt; try again",
    1032: "the prompt was cancelled on the phone",
    1037: "the phone did not answer (off, out of network, or no SIM toolkit); check the number and try again",
    2001: "the M-Pesa PIN was wrong",
    9999: "M-Pesa could not send the prompt; try again",
}


def failure_reason(result_code, result_desc: Optional[str]) -> str:
    """'<plain words> (M-Pesa <code>: <desc>)', at most 255 characters."""
    try:
        code = int(result_code)
    except (TypeError, ValueError):
        code = None
    words = PLAIN.get(code) if code is not None else None
    raw = f"M-Pesa {code if code is not None else '?'}: {(result_desc or '').strip()}".strip()
    return (f"{words} ({raw})" if words else raw)[:255]
