"""Dashboard assistant: a chat that can do everything the dashboard does.

How it works, in one paragraph: the person types in the chat; the model
(Anthropic, ``settings.ASSISTANT_MODEL``) reads a compact index of this app's
own API -- built from ``app.openapi()`` and filtered to what the caller may
use -- and calls it through two tools. Reads run at once; anything that
changes data is stored as a pending action and runs only when the person taps
Confirm on a card that shows the exact request. Every call goes through the
app itself (in-process ASGI) with the caller's own bearer token, so roles,
staff permissions, the View-as read-only guard and the staff activity log all
apply exactly as they do to the dashboard. Secrets never travel through the
chat: secret-looking fields are masked in results and refused in requests.

Modules:
    caller     who is asking (from the request's token)
    catalog    the API index the model sees, and request matching
    shaping    masking secrets and cutting results to size
    executor   the in-process API call
    store      conversations and pending actions (short DB sessions only)
    agent      the model loop and its two tools
"""
