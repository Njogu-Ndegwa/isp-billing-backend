"""Render the RouterOS side of the usage-push channel.

Two pieces get installed on a router:

1. **A periodic reporter** — a scheduler script that walks ``/queue simple``,
   builds one JSON batch and POSTs it. Reading the queues is free: the router
   already holds those counters in memory, so the only real cost is the outbound
   HTTPS call, and that cost is per *push*, not per customer. A router with 5
   users and one with 50 cost the same.

2. **An on-logout hook** — set on the hotspot user profile. RouterOS runs it when
   a session ends and hands it that session's exact totals, so a 15-minute
   customer who came and went entirely between two polls is still counted. This
   is the piece polling structurally cannot replicate.

Both post to the same endpoint; the hook sets ``final`` so the server knows the
number is a finished session total rather than a mid-flight sample.

SECURITY: everything interpolated here is either a value we generated (the push
token), a strictly validated identity, or a URL from our own settings. The
rendered text is executed by the router, so nothing derived from customer input
is ever embedded — same discipline as ``pull_provisioning.render_hotspot_provision_rsc``.
"""

from __future__ import annotations

import re

from app.services.usage_push_auth import derive_router_token

# Identities we generate look like ``Router-0721``; refuse anything else rather
# than risk breaking out of the RouterOS string it lands in.
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._:/-]{3,200}$")

# Scheduler name is stable so re-running the installer replaces rather than
# duplicates, and so an operator can find and remove it by name.
SCHEDULER_NAME = "bitwave-usage-push"
SCRIPT_NAME = "bitwave-usage-push"
LOGOUT_SCRIPT_NAME = "bitwave-usage-final"

# Bumped whenever the meaning of a reported metric changes, so the server can
# tell a re-scripted router from one still running the previous version.
#   1 — hotspot_active = :len [/ip hotspot active]  (portal logins only)
#   2 — hotspot_active = host-table entries that are authorized or bypassed
METRICS_VERSION = 2


def _require(value: str, rx: re.Pattern, name: str) -> str:
    v = str(value or "").strip()
    if not rx.match(v):
        raise ValueError(f"usage-push script: unsafe {name}={value!r}")
    return v


def render_usage_push_script(
    *,
    identity: str,
    endpoint_url: str,
    interval_seconds: int = 120,
    include_router_metrics: bool = False,
) -> str:
    """Render the installable RouterOS script.

    ``interval_seconds`` is the starting cadence only — the server returns
    ``next_push_seconds`` on every accepted push, so the fleet can be retuned
    centrally without reinstalling anything.

    ``include_router_metrics`` appends a ``router`` block to each batch:
    interface byte counters plus hotspot/PPPoE active counts. Every added
    command is a READ — ``/interface get``, ``:len [... find]`` — nothing on the
    router is changed by them. Rolled out separately from the usage reports so a
    metrics problem can be reverted without touching usage collection.
    """
    identity = _require(identity, _IDENTITY_RE, "identity")
    endpoint_url = _require(endpoint_url, _URL_RE, "endpoint_url")
    if not (30 <= int(interval_seconds) <= 3600):
        raise ValueError("usage-push script: interval must be 30..3600 seconds")

    token = derive_router_token(identity)

    # Read-only lookups, guarded so a router missing the hotspot/ppp package or
    # an ether1 by that name skips metrics instead of losing the whole push.
    # ``:set first false`` marks the batch as worth sending even with no queues.
    #
    # ``hotspot_active`` counts HOST-TABLE entries that are authorized or
    # bypassed, NOT ``/ip hotspot active``. A device only holds a host entry
    # while it is actually present on the hotspot network, so this is "who is
    # in the router right now" — and the authorized/bypassed filter drops the
    # devices that are connected but have not paid (they sit in the host table
    # unauthorized, seeing only the portal). ``/ip hotspot active`` lists portal
    # LOGINS only, so it reads 0 forever on the MAC-bypass model most of our
    # resellers run — that zero is what surfaced every hotspot customer as a
    # phantom PPPoE user on 2026-08-06.
    #
    # A host can in principle carry both flags, so this counts each host once
    # rather than adding two ``find`` lengths.
    metrics_block = ""
    if include_router_metrics:
        metrics_block = (
            '    :do {\n'
            '        :local rxb [/interface get [find name="ether1"] rx-byte]\n'
            '        :local txb [/interface get [find name="ether1"] tx-byte]\n'
            '        :local hs 0\n'
            '        :foreach h in=[/ip hotspot host find] do={\n'
            '            :local ha [/ip hotspot host get $h authorized]\n'
            '            :local hb [/ip hotspot host get $h bypassed]\n'
            '            :if ($ha || $hb) do={ :set hs ($hs + 1) }\n'
            '        }\n'
            '        :local pp [:len [/ppp active find]]\n'
            '        :set body ($body . ",\\"router\\":{\\"iface_rx_bytes\\":" . $rxb'
            ' . ",\\"iface_tx_bytes\\":" . $txb . ",\\"hotspot_active\\":" . $hs'
            ' . ",\\"pppoe_active\\":" . $pp . ",\\"queue_count\\":" . $qcount'
            ' . ",\\"metrics_version\\":' + str(METRICS_VERSION) + '}")\n'
            '        :set first false\n'
            '    } on-error={ :log info "usage-push: metrics skipped" }\n'
        )

    # A random start delay spreads the fleet out. Without it, routers that
    # rebooted together — after a power cut, which is common — would come back
    # aligned and hit the server as one wave. This is the difference between
    # 1,000 routers arriving smoothly and arriving simultaneously.
    return f"""# Bitwave usage push — installs the periodic reporter and the logout hook.
# Safe to re-run: both scripts and the scheduler are removed first.

/system script remove [find name="{SCRIPT_NAME}"]
/system script remove [find name="{LOGOUT_SCRIPT_NAME}"]
/system scheduler remove [find name="{SCHEDULER_NAME}"]

# --- periodic reporter -------------------------------------------------------
/system script add name="{SCRIPT_NAME}" policy=read,write,test,policy source={{
    :local url "{endpoint_url}"
    :local tok "{token}"
    :local ident "{identity}"
    :local body "{{\\"identity\\":\\"$ident\\",\\"reports\\":["
    :local first true
    :local qcount 0
    :foreach q in=[/queue simple find] do={{
        :local qn [/queue simple get $q name]
        :local qb [/queue simple get $q bytes]
        :local qt [/queue simple get $q target]
        # Our hotspot queues are named plan_<MAC>; PPPoE dynamic queues are
        # <pppoe-USERNAME>. Anything else on the router is not ours — skip it
        # rather than report a key the server will only reject.
        :local key ""
        :if ([:pick $qn 0 5] = "plan_") do={{ :set key [:pick $qn 5 [:len $qn]] }}
        :if ([:pick $qn 0 7] = "<pppoe-") do={{
            :set key ("pppoe:" . [:pick $qn 7 ([:len $qn] - 1)])
        }}
        :if ($key != "") do={{
            :local up [:pick $qb 0 [:find $qb "/"]]
            :local dn [:pick $qb ([:find $qb "/"] + 1) [:len $qb]]
            :if (!$first) do={{ :set body ($body . ",") }}
            :set body ($body . "{{\\"queue_key\\":\\"" . $key . \\
                "\\",\\"upload_bytes\\":" . $up . ",\\"download_bytes\\":" . $dn . "}}")
            :set first false
            :set qcount ($qcount + 1)
        }}
    }}
    :set body ($body . "]")
{metrics_block}    :set body ($body . "}}")
    # Nothing to say is not worth a connection.
    :if (!$first) do={{
        :do {{
            /tool fetch url=$url http-method=post http-header-field=\\
                ("Content-Type: application/json,Authorization: Bearer " . $tok) \\
                http-data=$body output=none
        }} on-error={{
            # Server unreachable or shedding load. Nothing to retry: the counters
            # are cumulative, so the next run carries these totals plus whatever
            # happened since.
            :log info "usage-push: deferred"
        }}
    }}
}}

# --- on-logout hook ----------------------------------------------------------
# RouterOS runs this when a hotspot session ends and provides $user, $bytes-in
# and $bytes-out — the session's exact totals. ``final`` tells the server this
# is a finished session, not a mid-flight sample.
/system script add name="{LOGOUT_SCRIPT_NAME}" policy=read,write,test,policy source={{
    :local url "{endpoint_url}"
    :local tok "{token}"
    :local ident "{identity}"
    :local mac $"mac-address"
    :if ([:len $mac] > 0) do={{
        :local body ("{{\\"identity\\":\\"" . $ident . "\\",\\"reports\\":[{{\\"queue_key\\":\\"" . \\
            $mac . "\\",\\"upload_bytes\\":" . $"bytes-in" . ",\\"download_bytes\\":" . \\
            $"bytes-out" . ",\\"final\\":true}}]}}")
        :do {{
            /tool fetch url=$url http-method=post http-header-field=\\
                ("Content-Type: application/json,Authorization: Bearer " . $tok) \\
                http-data=$body output=none
        }} on-error={{ :log info "usage-push: final deferred" }}
    }}
}}

# --- scheduler ---------------------------------------------------------------
# start-time=startup plus a random offset so a fleet that reboots together does
# not come back as one synchronised wave.
/system scheduler add name="{SCHEDULER_NAME}" interval={int(interval_seconds)}s \\
    start-time=startup on-event=("/system script run {SCRIPT_NAME}") \\
    policy=read,write,test,policy comment="Bitwave usage reporting"

:delay [:rndnum from=1 to=30]
:log info "usage-push: installed for {identity}"
"""


def render_logout_hook_attach(profile_name: str) -> str:
    """Attach the logout hook to a hotspot user profile.

    Kept separate because it is the only part that touches live hotspot config:
    it should be applied per profile, and reviewed, rather than bundled into the
    installer above.
    """
    profile = _require(profile_name, re.compile(r"^[A-Za-z0-9._/-]{1,72}$"), "profile_name")
    return (
        f'/ip hotspot user profile set [find name="{profile}"] '
        f'on-logout="/system script run {LOGOUT_SCRIPT_NAME}"'
    )
