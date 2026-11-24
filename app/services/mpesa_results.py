"""M-Pesa STK results in words a reseller can act on.

Safaricom's callback says why a payment prompt did not end in a payment
(ResultCode + ResultDesc). Kept on the order so "why did it fail" is answerable
later, and shown on the payment card in the chat.

This module is the one place that says what an STK result means: who is at
fault, what happened in plain words, and what the reseller should do. The
failed-payment lists and the dashboard assistant read it through `explain`, so
the same M-Pesa reply is always explained the same way.

Sources (checked 2026-11-23): Safaricom Daraja "M-Pesa Express" result codes
(2001 = the customer entered a wrong M-Pesa PIN; 1037 = phone could not be
reached; 1032 = cancelled; 1 = insufficient balance; 1019 = expired; 1025 =
push request failed; 2028 = wrong till/paybill type; 8006 = PIN locked; 17 =
same amount within 2 minutes). Daraja's B2C docs use 2001 for invalid
initiator credentials, but an STK prompt sends no initiator credential, so on
a payment prompt "The initiator information is invalid" is a wrong PIN.
"""
from typing import Optional

# who is at fault
CUSTOMER = "customer"        # the payer's phone, PIN, balance or choice
MPESA = "mpesa"              # Safaricom's side, or no answer came back from it
MERCHANT_SETUP = "merchant_setup"  # the reseller's till / paybill setup
BITWAVE = "bitwave"          # our own system
NONE = "none"                # it was paid
UNKNOWN = "unknown"          # not in this table: say so, do not guess

# code -> (fault, short words for the order card, explanation, what to do)
_CODES: dict[str, tuple[str, str, str, str]] = {
    "0": (NONE, "paid", "The payment went through.", "Nothing to do."),
    "1": (CUSTOMER, "not enough money on that M-Pesa account",
          "The customer's M-Pesa balance was too low for this amount.",
          "Ask them to top up M-Pesa and pay again."),
    "17": (MPESA, "the same amount was just sent; wait 2 minutes",
           "M-Pesa blocked a repeat of the same amount within 2 minutes.",
           "Wait 2 minutes, then pay again."),
    "1001": (CUSTOMER, "the phone was busy with another M-Pesa request; try again in a minute",
             "The phone was busy with another M-Pesa request at that moment.",
             "Wait a minute, then pay again."),
    "1019": (CUSTOMER, "the request expired before it was answered",
             "The prompt expired before the customer finished it.",
             "Ask them to pay again and enter the PIN straight away."),
    "1025": (MPESA, "M-Pesa could not send the prompt; try again",
             "M-Pesa could not send the prompt to the phone.",
             "Try again; if every prompt fails, tell Bitwave support."),
    "9999": (MPESA, "M-Pesa could not send the prompt; try again",
             "M-Pesa could not send the prompt to the phone.",
             "Try again; if every prompt fails, tell Bitwave support."),
    "1032": (CUSTOMER, "the prompt was cancelled on the phone",
             "The customer cancelled the M-Pesa prompt on their phone.",
             "Nothing is wrong; they can pay again when ready."),
    "1037": (CUSTOMER, "the phone did not answer (off, out of network, or no SIM toolkit); check the number and try again",
             "M-Pesa could not reach the phone (off, no network, busy, or an old SIM).",
             "Check the number, have the phone on and unlocked, then pay again."),
    "1038": (CUSTOMER, "the PIN prompt was not answered",
             "The prompt reached the phone but the customer did not enter the PIN.",
             "Ask them to pay again and enter the PIN when the prompt shows."),
    "2001": (CUSTOMER, "the M-Pesa PIN was wrong",
             "The customer entered a wrong M-Pesa PIN. Your payment setup is not the cause.",
             "Ask them to pay again with the correct PIN."),
    "2028": (MERCHANT_SETUP, "the till or paybill type does not match this payment",
             "M-Pesa refused the till/paybill details on this payment method.",
             "Check the payment method selected for the router; tell Bitwave support the error."),
    "8006": (CUSTOMER, "the customer's M-Pesa PIN is locked",
             "The customer's M-Pesa PIN is locked after wrong tries.",
             "They must call Safaricom on 100 or 200 to unlock it, then pay."),
    # our own codes (app/services/mpesa_transactions.py, app/api/payment_routes.py)
    "TIMEOUT": (MPESA, "no answer came back from M-Pesa in time",
                "No result came back from M-Pesa in time; usually the customer did not finish. Not a fault in your setup.",
                "If they were charged, send Bitwave support the M-Pesa code; if not, pay again."),
    "STK_PUSH_FAILED": (MPESA, "M-Pesa refused to start the prompt",
                        "M-Pesa refused to start the prompt.",
                        "Try again; if every prompt fails, tell Bitwave support the time."),
    "SERVER_ERROR": (BITWAVE, "our system failed while handling M-Pesa's reply",
                     "Bitwave's system failed while handling M-Pesa's reply.",
                     "Tell Bitwave support the time and amount; if charged, Bitwave delivers it."),
}

# M-Pesa's own words, for rows that carry a text but no code we know
_TEXTS: tuple[tuple[str, str], ...] = (
    ("initiator information is invalid", "2001"),
    ("wrong pin", "2001"),
    ("incorrect pin", "2001"),
    ("insufficient", "1"),
    ("cancelled by user", "1032"),
    ("canceled by user", "1032"),
    ("ds timeout", "1037"),
    ("cannot be reached", "1037"),
    ("no response from user", "1038"),
    ("unable to lock subscriber", "1001"),
    ("transaction is already in process", "1001"),
)

# kept for callers that import it: plain words per numeric code
PLAIN = {int(code): short for code, (_, short, _, _) in _CODES.items() if code.isdigit() and code != "0"}


def _code_text(result_code) -> Optional[str]:
    if result_code is None:
        return None
    text = str(result_code).strip()
    if not text:
        return None
    try:
        return str(int(text))
    except ValueError:
        return text.upper()


def explain(result_code, result_desc: Optional[str] = None) -> dict:
    """Who is at fault, what happened and what to do, for one STK result.

    Looks up the code first, then M-Pesa's words. Anything not in the table
    comes back as fault "unknown" with M-Pesa's own words, never a guess.
    """
    code = _code_text(result_code)
    desc = " ".join(str(result_desc or "").split())
    key = code if code in _CODES else None
    if key is None:
        low = desc.lower()
        key = next((c for words, c in _TEXTS if words in low), None)
    if key is None:
        said = f"M-Pesa code {code or 'none'}" + (f' ("{desc[:120]}")' if desc else "")
        return {
            "fault": UNKNOWN,
            "explanation": f"{said} is not one we know, so the cause is unknown.",
            "next_step": "Quote M-Pesa's words; if it repeats, tell Bitwave support the code and time.",
            "known": False,
        }
    fault, _, explanation, next_step = _CODES[key]
    return {"fault": fault, "explanation": explanation, "next_step": next_step, "known": True}


def failure_explained(result_code, result_desc: Optional[str] = None) -> str:
    """One plain line: 'Fault: <who>. <what happened> Next: <what to do>'."""
    e = explain(result_code, result_desc)
    return f"Fault: {e['fault']}. {e['explanation']} Next: {e['next_step']}"


def failure_reason(result_code, result_desc: Optional[str]) -> str:
    """'<plain words> (M-Pesa <code>: <desc>)', at most 255 characters."""
    try:
        code = int(result_code)
    except (TypeError, ValueError):
        code = None
    words = PLAIN.get(code) if code is not None else None
    raw = f"M-Pesa {code if code is not None else '?'}: {(result_desc or '').strip()}".strip()
    return (f"{words} ({raw})" if words else raw)[:255]
