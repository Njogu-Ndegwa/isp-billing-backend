"""Turn raw SMS gateway errors into reasons a reseller can act on.

`sms_messages.error` holds whatever the gateway said ("Invalid credentials",
"You have exceeded your sending limit.", "fwrite(): ... No space left on
device") or one of our own status codes ("missing_api_key", "no_response").
None of that tells a reseller what to do, and the wording differs per vendor.

`classify()` maps any of them onto a small, fixed set of reasons, each with a
title, an explanation and the action that fixes it. Matching is on lowercase
substrings so a vendor rewording its message usually still lands in the right
bucket; anything unrecognised falls through to "unknown" with the raw text
kept alongside, so nothing is hidden.

`severity` drives the health state:
  * blocking   — every message will fail until someone changes something
  * per_message — only this recipient is affected (bad phone number)
  * temporary  — the gateway or network hiccuped; a retry may succeed
"""

from dataclasses import asdict, dataclass
from typing import Optional

BLOCKING = "blocking"
PER_MESSAGE = "per_message"
TEMPORARY = "temporary"


@dataclass(frozen=True)
class FailureReason:
    code: str
    title: str
    explanation: str
    action: str
    severity: str

    def as_dict(self, provider_label: Optional[str] = None) -> dict:
        out = asdict(self)
        for key in ("title", "explanation", "action"):
            text = out[key]
            if provider_label:
                text = text.replace("your SMS provider", provider_label)
            out[key] = text[:1].upper() + text[1:]
        return out


INVALID_CREDENTIALS = FailureReason(
    code="invalid_credentials",
    title="Gateway rejected your login",
    explanation=(
        "your SMS provider refused the API key or account ID saved here. "
        "This usually means the key was regenerated, or the account was "
        "suspended."
    ),
    action=(
        "Copy the current API key and partner/account ID from your SMS "
        "provider dashboard and save them again under Messaging → Gateway."
    ),
    severity=BLOCKING,
)
LOW_BALANCE = FailureReason(
    code="low_balance",
    title="Gateway balance too low",
    explanation="your SMS provider says the account has run out of SMS credit.",
    action="Top up your account with your SMS provider.",
    severity=BLOCKING,
)
SENDING_LIMIT = FailureReason(
    code="sending_limit",
    title="Gateway sending limit reached",
    explanation="your SMS provider has capped how many messages this account may send.",
    action="Ask your SMS provider to raise the limit, or wait for it to reset.",
    severity=BLOCKING,
)
ACCOUNT_SETUP = FailureReason(
    code="account_setup",
    title="Gateway account not fully set up",
    explanation=(
        "your SMS provider accepted the login but the account is missing "
        "setup on their side (pricing, routes or account details)."
    ),
    action="Contact your SMS provider and ask them to finish setting up the account.",
    severity=BLOCKING,
)
CONFIG_INCOMPLETE = FailureReason(
    code="config_incomplete",
    title="Gateway settings incomplete",
    explanation="A required gateway setting (API key, partner ID or URL) is empty.",
    action="Fill in every required field under Messaging → Gateway and save.",
    severity=BLOCKING,
)
SENDER_ID = FailureReason(
    code="sender_id",
    title="Sender ID not accepted",
    explanation=(
        "your SMS provider rejected the sender ID. It may be missing, "
        "misspelt, or not yet approved on your account."
    ),
    action=(
        "Check the sender ID under Messaging → Gateway matches one approved "
        "on your SMS provider account exactly."
    ),
    severity=BLOCKING,
)
NO_GATEWAY = FailureReason(
    code="no_gateway",
    title="No working gateway",
    explanation="No SMS gateway could be loaded to send this message.",
    action="Open Messaging → Gateway and save your gateway settings again, or contact support.",
    severity=BLOCKING,
)
INVALID_RECIPIENT = FailureReason(
    code="invalid_recipient",
    title="Invalid phone number",
    explanation="The customer's phone number is not a valid mobile number.",
    action="Correct the customer's phone number (e.g. 0712345678).",
    severity=PER_MESSAGE,
)
PROVIDER_ERROR = FailureReason(
    code="provider_error",
    title="Gateway had an internal error",
    explanation="your SMS provider failed on their side while handling the message.",
    action="Usually clears on its own. If it keeps happening, contact your SMS provider.",
    severity=TEMPORARY,
)
NETWORK = FailureReason(
    code="network",
    title="Could not reach the gateway",
    explanation="The connection to your SMS provider failed or timed out.",
    action="Usually clears on its own. If it keeps happening, contact support.",
    severity=TEMPORARY,
)
NO_RESPONSE = FailureReason(
    code="no_response",
    title="Gateway gave no answer",
    explanation="your SMS provider did not report a result for this message.",
    action="Usually clears on its own. If it keeps happening, contact support.",
    severity=TEMPORARY,
)
UNKNOWN = FailureReason(
    code="unknown",
    title="Message not sent",
    explanation="The gateway returned an error we don't recognise.",
    action="Check the error text below. Contact support if it keeps happening.",
    severity=TEMPORARY,
)

ALL_REASONS = {
    r.code: r for r in (
        INVALID_CREDENTIALS, LOW_BALANCE, SENDING_LIMIT, ACCOUNT_SETUP,
        CONFIG_INCOMPLETE, SENDER_ID, NO_GATEWAY, INVALID_RECIPIENT,
        PROVIDER_ERROR, NETWORK, NO_RESPONSE, UNKNOWN,
    )
}

# Ordered: the first matching rule wins, so the more specific patterns come
# first ("invalid_sender_id" must not be caught by a generic "invalid").
_RULES: list[tuple[FailureReason, tuple[str, ...]]] = [
    (INVALID_CREDENTIALS, (
        "invalid credentials", "invalid_credentials", "unauthenticated",
        "unauthorized", "unauthorised", "authentication", "invalid api key",
        "invalid apikey", "invalid token", "http_401", "http_403",
    )),
    (CONFIG_INCOMPLETE, (
        "missing_api_key", "missing_api_token", "missing_partner_id",
        "missing_base_url", "no api key", "no partner id",
    )),
    (SENDER_ID, (
        "sender id", "sender_id", "senderid", "shortcode", "invalid_sender",
    )),
    (LOW_BALANCE, (
        "low credit", "low_credits", "insufficient", "not enough credit",
        "no credit", "insufficient balance", "low balance",
    )),
    (SENDING_LIMIT, ("sending limit", "rate limit", "too many requests", "http_429")),
    (ACCOUNT_SETUP, (
        "pricing configuration", "account_not_found", "details not found",
        "account not found", "not activated", "inactive account",
    )),
    (NO_GATEWAY, ("no_provider_configured", "could not be decrypted", "unsupported sms provider")),
    (INVALID_RECIPIENT, (
        "invalid phone", "invalid_recipient", "invalid mobile", "invalid number",
        "is a invalid", "is an invalid", "invalid msisdn",
    )),
    (NETWORK, ("network_error", "timed out", "timeout", "connecterror", "connection")),
    (NO_RESPONSE, ("no_response", "no_result", "bad_response", "no result")),
    (PROVIDER_ERROR, (
        "no space left", "service unavailable", "unexpected error", "system_error",
        "internal_error", "internal error", "http_5", "fwrite", "server error",
    )),
]


def classify(error: Optional[str]) -> FailureReason:
    text = (error or "").strip().lower()
    if not text:
        return NO_RESPONSE
    for reason, needles in _RULES:
        if any(n in text for n in needles):
            return reason
    return UNKNOWN


def describe(
    error: Optional[str],
    *,
    own_gateway: bool,
    provider_label: Optional[str] = None,
) -> dict:
    """classify() rendered for one reseller, ready for the API.

    On their own gateway the reseller is the one who can fix a gateway-side
    problem, so the action names their provider. On the platform gateway any
    gateway-side failure is ours to fix; telling the reseller to rotate an API
    key they never had would only confuse them.
    """
    reason = classify(error)
    if own_gateway or reason.code == INVALID_RECIPIENT.code:
        out = reason.as_dict(provider_label)
    else:
        out = reason.as_dict("The platform SMS gateway")
        # The vendor-facing titles ("Gateway rejected your login") describe
        # our account, not theirs; say so plainly instead.
        out["title"] = "Platform SMS gateway problem"
        out["explanation"] = (
            "The platform SMS gateway could not send this message. Nothing on "
            "your account caused it."
        )
        out["action"] = (
            "This is on our side, not your account. Contact support if it "
            "keeps happening."
        )
    out["raw_error"] = (error or None)
    return out
