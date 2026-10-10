"""One Bitwave router script at a time.

Every Bitwave scheduler is added with ``start-time=startup``, so the 1-minute
and 2-minute ones (watchdog, expiry reaper, usage push) fire in the same
second, and the check-in and command agent, whose intervals the server sets,
drift into them. On a single-core RB951 that stacked run held the CPU at
100% for ~4 s every minute (router 585, 2026-10-10). Offsetting start times
cannot fix it: two of the intervals change at run time.

So each script starts with this gate. ``/system script job`` ids grow with
every job, so "a Bitwave job with a smaller id than mine is still running"
means "one started before me": wait for it, 1 s at a time, at most
``MAX_WAIT_SECONDS``. The oldest job never waits, so there is no deadlock,
and the cap bounds how long a hung fetch can hold the others back.

It fails open: if this router's ids cannot be read or parsed, the script runs
as it did before the gate. Only ``:local`` variables (the check-in applier
must not use ``:global``) and no ``:return`` (RouterOS 7.19+ rejects it).
"""

from __future__ import annotations

GATE_VERSION = 1
MAX_WAIT_SECONDS = 20

GATED_SCRIPTS = (
    "bw-mgmt-watchdog",
    "bw-mgmt-watchdog-wg",
    "bitwave-checkin",
    "bitwave-usage-push",
    "bitwave-expiry-reaper",
    "bitwave-command-agent",
)

GATE_BEGIN = "# bw-gate v"
GATE_END = "# bw-gate end"

_GATE_TEMPLATE = r'''# bw-gate v__VERSION__: run one Bitwave script at a time. Waits (max __MAX__ s) while
# a Bitwave job that started before this one is still running; on error, runs.
:local bwgMe 0
:local bwgWait 0
:local bwgBusy true
:do {
    :foreach j in=[/system script job find where script="__SELF__"] do={
        :local n [:tonum ("0x" . [:pick [:tostr $j] 1 16])]
        :if ([:typeof $n] = "num") do={ :if ($n > $bwgMe) do={ :set bwgMe $n } }
    }
} on-error={ :set bwgMe 0 }
:if ($bwgMe = 0) do={ :set bwgBusy false }
:while ($bwgBusy && ($bwgWait < __MAX__)) do={
    :set bwgBusy false
    :do {
        :foreach j in=[/system script job find where (__WHERE__)] do={
            :local n [:tonum ("0x" . [:pick [:tostr $j] 1 16])]
            :if ([:typeof $n] = "num") do={ :if ($n < $bwgMe) do={ :set bwgBusy true } }
        }
    } on-error={ :set bwgBusy false }
    :if ($bwgBusy) do={
        :delay 1s
        :set bwgWait ($bwgWait + 1)
    }
}
# bw-gate end
'''


def render_gate(self_name: str) -> str:
    """The gate for the script called ``self_name`` (one of ``GATED_SCRIPTS``)."""
    if self_name not in GATED_SCRIPTS:
        raise ValueError(f"bw-gate: unknown script {self_name!r}")
    where = " or ".join(f'script="{name}"' for name in GATED_SCRIPTS)
    return (
        _GATE_TEMPLATE
        .replace("__VERSION__", str(GATE_VERSION))
        .replace("__MAX__", str(MAX_WAIT_SECONDS))
        .replace("__SELF__", self_name)
        .replace("__WHERE__", where)
    )


def strip_gate(source: str) -> str:
    """``source`` without a leading gate of any version."""
    body = source.lstrip("\n")
    if not body.lstrip().startswith(GATE_BEGIN):
        return source
    end = body.find(GATE_END)
    if end < 0:
        return source
    return body[end + len(GATE_END):].lstrip("\n")


def with_gate(self_name: str, source: str) -> str:
    """``source`` with exactly one current gate in front. Idempotent."""
    return render_gate(self_name) + strip_gate(source)


def has_current_gate(self_name: str, source: str) -> bool:
    return source.startswith(render_gate(self_name))


def gate_rsc_body(self_name: str, rsc: str) -> str:
    """Put the gate at the top of the ``source={`` block of an installable .rsc."""
    marker = "source={\n"
    at = rsc.index(marker) + len(marker)
    return rsc[:at] + render_gate(self_name) + rsc[at:]
