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
    # Hotspot users are counted from ``/ip hotspot host`` (authorized + bypassed),
    # the same figure the background poller persists. Paid customers get in via
    # a ``bypassed`` ip-binding and never appear in ``/ip hotspot active``, so
    # counting that table reported 0 on a router with live paying customers
    # (router 10, 2026-09-23: 0 active, 4 bypassed hosts online).
    metrics_block = ""
    health_prelude = ""
    if include_router_metrics:
        # Health is read FIRST, before the queue walk below, so the script's own
        # work does not inflate the CPU figure it reports. Every read is a local
        # /system resource value (RouterOS 6 and 7 alike), no network, no login.
        health_prelude = (
            '    :local hcpu [/system resource get cpu-load]\n'
            '    :local hfm [/system resource get free-memory]\n'
            '    :local htm [/system resource get total-memory]\n'
            '    :local hfh [/system resource get free-hdd-space]\n'
            '    :local hth [/system resource get total-hdd-space]\n'
            '    :local hup [/system resource get uptime]\n'
            '    :local hver [/system resource get version]\n'
            '    :local hbrd [/system resource get board-name]\n'
        )
        metrics_block = (
            '    :do {\n'
            '        :local rxb [/interface get [find name="ether1"] rx-byte]\n'
            '        :local txb [/interface get [find name="ether1"] tx-byte]\n'
            '        :local lnd [/interface get [find name="ether1"] link-downs]\n'
            '        :local hs ([:len [/ip hotspot host find where authorized]]'
            ' + [:len [/ip hotspot host find where bypassed]])\n'
            '        :local pp [:len [/ppp active find]]\n'
            '        :set body ($body . ",\\"router\\":{\\"iface_rx_bytes\\":" . $rxb'
            ' . ",\\"iface_tx_bytes\\":" . $txb . ",\\"hotspot_active\\":" . $hs'
            ' . ",\\"pppoe_active\\":" . $pp . ",\\"queue_count\\":" . $qcount'
            ' . ",\\"cpu_load\\":" . $hcpu . ",\\"free_memory\\":" . $hfm'
            ' . ",\\"total_memory\\":" . $htm . ",\\"free_hdd\\":" . $hfh'
            ' . ",\\"total_hdd\\":" . $hth . ",\\"wan_link_downs\\":" . $lnd'
            ' . ",\\"uptime\\":\\"" . $hup . "\\",\\"version\\":\\"" . $hver'
            ' . "\\",\\"board\\":\\"" . $hbrd . "\\"}")\n'
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
{health_prelude}    :local body "{{\\"identity\\":\\"$ident\\",\\"reports\\":["
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


# ---------------------------------------------------------------------------
# v2 reporter — real-time pilot
# ---------------------------------------------------------------------------
#
# Same channel, more facts per report, and a cadence the server can actually
# change. The v1 reporter posts with ``output=none``, so it never saw the
# ``next_push_seconds`` the server returns and every router stayed on the
# interval it was installed with. v2 reads the reply and retunes its own
# scheduler.
#
# Per report:
#   reports[] — every plan_/pppoe queue in ROUTER ORDER (order decides which
#               queue a packet hits) with its target, max-limit and disabled.
#   hosts[]   — every bypassed or authorized /ip hotspot host: the device's own
#               byte counters, which are what the pilot meters usage from.
#   router{}  — WAN counters, CPU, memory, uptime, version, board, counts.
#
# Only reads, plus one write: the scheduler's own interval. Parsing uses
# :find/:pick, not :deserialize, so it runs on RouterOS 6 as well as 7.

_REALTIME_TEMPLATE = r'''# Bitwave usage push v2 (real-time) - safe to re-run.
/system script remove [find name="__SCRIPT__"]
/system script remove [find name="__LOGOUT__"]
/system scheduler remove [find name="__SCHED__"]

/system script add name="__SCRIPT__" policy=read,write,test,policy source={
    :local url "__URL__"
    :local tok "__TOKEN__"
    :local ident "__IDENT__"
    # Health first, so this script's own work does not inflate the CPU figure.
    :local cpu [/system resource get cpu-load]
    :local fm [/system resource get free-memory]
    :local tm [/system resource get total-memory]
    :local fh [/system resource get free-hdd-space]
    :local th [/system resource get total-hdd-space]
    :local upt [/system resource get uptime]
    :local ver [/system resource get version]
    :local brd [/system resource get board-name]
    :local body "{\"identity\":\"$ident\",\"v\":3,\"reports\":["
    :local first true
    :local qcount 0
    # An entry can vanish between find and get (customer logs out, queue
    # removed). ROS 7 then returns EMPTY values instead of an error, which
    # wrote "upload_bytes":, and got the whole report rejected (2026-09-26,
    # busy routers 118/221/256). Every loop skips an entry that came back empty.
    :foreach q in=[/queue simple find] do={
      :do {
        :local qn [/queue simple get $q name]
        :local key ""
        :if ([:pick $qn 0 5] = "plan_") do={ :set key [:pick $qn 5 [:len $qn]] }
        :if ([:pick $qn 0 7] = "<pppoe-") do={ :set key ("pppoe:" . [:pick $qn 7 ([:len $qn] - 1)]) }
        :if ($key != "") do={
            :local qb [/queue simple get $q bytes]
            :local qt [:tostr [/queue simple get $q target]]
            :local ql [/queue simple get $q max-limit]
            :local qd [/queue simple get $q disabled]
            :local slash [:find $qb "/"]
            :if (([:typeof $slash] = "num") && ([:typeof $qd] = "bool")) do={
                :local up [:pick $qb 0 $slash]
                :local dn [:pick $qb ($slash + 1) [:len $qb]]
                :if (!$first) do={ :set body ($body . ",") }
                :set body ($body . "{\"queue_key\":\"" . $key . "\",\"upload_bytes\":" . $up . ",\"download_bytes\":" . $dn . ",\"target_ip\":\"" . $qt . "\",\"max_limit\":\"" . $ql . "\",\"disabled\":" . $qd . "}")
                :set first false
                :set qcount ($qcount + 1)
            }
        }
      } on-error={}
    }
    :set body ($body . "],\"hosts\":[")
    :local hfirst true
    :local hids ([/ip hotspot host find where bypassed] , [/ip hotspot host find where authorized])
    :foreach h in=$hids do={
        :do {
            :local hm [/ip hotspot host get $h mac-address]
            :local ha [/ip hotspot host get $h address]
            :local hbi [/ip hotspot host get $h bytes-in]
            :local hbo [/ip hotspot host get $h bytes-out]
            :local hby [/ip hotspot host get $h bypassed]
            :local hau [/ip hotspot host get $h authorized]
            :local hit [/ip hotspot host get $h idle-time]
            :local hup [/ip hotspot host get $h uptime]
            :if (([:len $hm] > 0) && ([:typeof $hbi] = "num") && ([:typeof $hbo] = "num") && ([:typeof $hby] = "bool") && ([:typeof $hau] = "bool")) do={
            :if (!$hfirst) do={ :set body ($body . ",") }
            :set body ($body . "{\"mac\":\"" . $hm . "\",\"ip\":\"" . $ha . "\",\"bytes_in\":" . $hbi . ",\"bytes_out\":" . $hbo . ",\"bypassed\":" . $hby . ",\"authorized\":" . $hau . ",\"idle_time\":\"" . $hit . "\",\"uptime\":\"" . $hup . "\"}")
            :set hfirst false
            }
        } on-error={}
    }
    :set body ($body . "],\"ppp\":[")
    :local pfirst true
    :do {
        :foreach a in=[/ppp active find] do={
            :local an [/ppp active get $a name]
            :local aa [/ppp active get $a address]
            :local au [/ppp active get $a uptime]
            :local ac [/ppp active get $a caller-id]
            :if ([:len $an] > 0) do={
            :if (!$pfirst) do={ :set body ($body . ",") }
            :set body ($body . "{\"name\":\"" . $an . "\",\"address\":\"" . $aa . "\",\"uptime\":\"" . $au . "\",\"caller_id\":\"" . $ac . "\"}")
            :set pfirst false
            }
        }
    } on-error={}
    :set body ($body . "]")
    # v3: physical ports every report (a handful of rows).
    :set body ($body . ",\"ports\":[")
    :local ifirst true
    :foreach i in=[/interface find where (type="ether" or type="wlan" or type="wifi")] do={
        :do {
            :local inm [/interface get $i name]
            :local iru [/interface get $i running]
            :local idi [/interface get $i disabled]
            :local irx [/interface get $i rx-byte]
            :local itx [/interface get $i tx-byte]
            :local ild [/interface get $i link-downs]
            :local irp [/interface get $i rx-packet]
            :local itp [/interface get $i tx-packet]
            :local ire [/interface get $i rx-error]
            :local ite [/interface get $i tx-error]
            :local ilu [:tostr [/interface get $i last-link-up-time]]
            # Some drivers (RB4011 ethernet/SFP on ROS 7) return no value for
            # a counter; an empty value made the JSON invalid ("rx_errors":,)
            # and every report from those routers was rejected (2026-09-26).
            :if ([:typeof $irx] != "num") do={ :set irx 0 }
            :if ([:typeof $itx] != "num") do={ :set itx 0 }
            :if ([:typeof $ild] != "num") do={ :set ild 0 }
            :if ([:typeof $irp] != "num") do={ :set irp 0 }
            :if ([:typeof $itp] != "num") do={ :set itp 0 }
            :if ([:typeof $ire] != "num") do={ :set ire 0 }
            :if ([:typeof $ite] != "num") do={ :set ite 0 }
            :if (!$ifirst) do={ :set body ($body . ",") }
            :set body ($body . "{\"name\":\"" . $inm . "\",\"running\":" . $iru . ",\"disabled\":" . $idi . ",\"rx_bytes\":" . $irx . ",\"tx_bytes\":" . $itx . ",\"link_downs\":" . $ild . ",\"rx_packets\":" . $irp . ",\"tx_packets\":" . $itp . ",\"rx_errors\":" . $ire . ",\"tx_errors\":" . $ite . ",\"last_link_up\":\"" . $ilu . "\"}")
            :set ifirst false
        } on-error={}
    }
    :set body ($body . "]")
    # v3: long lists every 5th report (~5 min): which device is behind which
    # port, and the access bindings. They change slowly and can be hundreds of
    # rows on a big router.
    :global bwPushN
    :if ([:typeof $bwPushN] != "num") do={ :set bwPushN 0 }
    :set bwPushN ($bwPushN + 1)
    :if (($bwPushN % __LISTS_EVERY__) = 1) do={
        :set body ($body . ",\"bridge_hosts\":[")
        :local bfirst true
        :do {
            :foreach b in=[/interface bridge host find where !local] do={
                :local bm [/interface bridge host get $b mac-address]
                :local bo [/interface bridge host get $b on-interface]
                :if (!$bfirst) do={ :set body ($body . ",") }
                :set body ($body . "{\"mac\":\"" . $bm . "\",\"port\":\"" . $bo . "\"}")
                :set bfirst false
            }
        } on-error={}
        :set body ($body . "],\"bindings\":[")
        :local gfirst true
        :do {
            :foreach g in=[/ip hotspot ip-binding find] do={
                :local gm [/ip hotspot ip-binding get $g mac-address]
                :local gt [/ip hotspot ip-binding get $g type]
                :local gd [/ip hotspot ip-binding get $g disabled]
                :if ([:typeof $gd] = "bool") do={
                :if (!$gfirst) do={ :set body ($body . ",") }
                :set body ($body . "{\"mac\":\"" . $gm . "\",\"type\":\"" . $gt . "\",\"disabled\":" . $gd . "}")
                :set gfirst false
                }
            }
        } on-error={}
        # DHCP leases give devices their names on the ports card. A host-name
        # carrying a quote or backslash would break the JSON, so it is dropped.
        :set body ($body . "],\"leases\":[")
        :local lfirst true
        :do {
            :foreach l in=[/ip dhcp-server lease find] do={
                :local lm [/ip dhcp-server lease get $l mac-address]
                :local la [/ip dhcp-server lease get $l address]
                :local lh [:tostr [/ip dhcp-server lease get $l host-name]]
                :local ls [:tostr [/ip dhcp-server lease get $l status]]
                :local lc [:tostr [/ip dhcp-server lease get $l comment]]
                :if (([:typeof [:find $lh "\""]] = "num") || ([:typeof [:find $lh "\\"]] = "num")) do={ :set lh "" }
                :if (([:typeof [:find $lc "\""]] = "num") || ([:typeof [:find $lc "\\"]] = "num")) do={ :set lc "" }
                :if (!$lfirst) do={ :set body ($body . ",") }
                :set body ($body . "{\"mac\":\"" . $lm . "\",\"ip\":\"" . $la . "\",\"host\":\"" . $lh . "\",\"status\":\"" . $ls . "\",\"comment\":\"" . $lc . "\"}")
                :set lfirst false
            }
        } on-error={}
        # Neighbour discovery (MNDP/CDP/LLDP): how the ports card recognises
        # equipment (APs, switches, other MikroTiks) behind a port.
        :set body ($body . "],\"neighbors\":[")
        :local nfirst true
        :do {
            :foreach n in=[/ip neighbor find] do={
                :local nm [:tostr [/ip neighbor get $n mac-address]]
                :local ni [:tostr [/ip neighbor get $n identity]]
                :local nb [:tostr [/ip neighbor get $n board]]
                :local np [:tostr [/ip neighbor get $n platform]]
                :local nv [:tostr [/ip neighbor get $n version]]
                :local nf [:tostr [/ip neighbor get $n interface]]
                :local na [:tostr [/ip neighbor get $n address]]
                :if (([:typeof [:find $ni "\""]] = "num") || ([:typeof [:find $ni "\\"]] = "num")) do={ :set ni "" }
                :if (([:typeof [:find $nb "\""]] = "num") || ([:typeof [:find $nb "\\"]] = "num")) do={ :set nb "" }
                :if (([:typeof [:find $nv "\""]] = "num") || ([:typeof [:find $nv "\\"]] = "num")) do={ :set nv "" }
                :if (!$nfirst) do={ :set body ($body . ",") }
                :set body ($body . "{\"mac\":\"" . $nm . "\",\"identity\":\"" . $ni . "\",\"board\":\"" . $nb . "\",\"platform\":\"" . $np . "\",\"version\":\"" . $nv . "\",\"interface\":\"" . $nf . "\",\"address\":\"" . $na . "\"}")
                :set nfirst false
            }
        } on-error={}
        :set body ($body . "],\"bridge_ports\":[")
        :local pfirst2 true
        :do {
            :foreach p in=[/interface bridge port find] do={
                :local pi [/interface bridge port get $p interface]
                :local pb [/interface bridge port get $p bridge]
                :if (!$pfirst2) do={ :set body ($body . ",") }
                :set body ($body . "{\"interface\":\"" . $pi . "\",\"bridge\":\"" . $pb . "\"}")
                :set pfirst2 false
            }
        } on-error={}
        :set body ($body . "]")
    }
    :do {
        :local rxb [/interface get [find name="__WAN__"] rx-byte]
        :local txb [/interface get [find name="__WAN__"] tx-byte]
        :local hs ([:len [/ip hotspot host find where authorized]] + [:len [/ip hotspot host find where bypassed]])
        :local pp [:len [/ppp active find]]
        :set body ($body . ",\"router\":{\"iface_rx_bytes\":" . $rxb . ",\"iface_tx_bytes\":" . $txb . ",\"hotspot_active\":" . $hs . ",\"pppoe_active\":" . $pp . ",\"queue_count\":" . $qcount . ",\"cpu_load\":" . $cpu . ",\"free_memory\":" . $fm . ",\"total_memory\":" . $tm . ",\"free_hdd\":" . $fh . ",\"total_hdd\":" . $th . ",\"uptime\":\"" . $upt . "\",\"version\":\"" . $ver . "\",\"board\":\"" . $brd . "\"}")
    } on-error={ :log info "usage-push: metrics skipped" }
    :set body ($body . "}")
    :do {
        :local res [/tool fetch url=$url http-method=post http-header-field=("Content-Type: application/json,Authorization: Bearer " . $tok) http-data=$body output=user as-value]
        :local d ($res->"data")
        :local p [:find $d "\"next_push_seconds\":"]
        :if ([:typeof $p] = "num") do={
            :local s ($p + 20)
            :local e [:find $d "}" $s]
            :local n [:tonum [:pick $d $s $e]]
            :if (([:typeof $n] = "num") && ($n >= 5) && ($n <= 3600)) do={
                :local want [:totime ($n . "s")]
                :if ([/system scheduler get [find name="__SCHED__"] interval] != $want) do={
                    /system scheduler set [find name="__SCHED__"] interval=$want
                    :log info ("usage-push: interval now " . $n . "s")
                }
            }
        }
    } on-error={ :log info "usage-push: deferred" }
}

/system scheduler add name="__SCHED__" interval=__INTERVAL__s start-time=startup on-event="/system script run __SCRIPT__" policy=read,write,test,policy comment="Bitwave usage reporting v2 (real-time)"
:log info "usage-push v2: installed for __IDENT__"
'''

_WAN_RE = re.compile(r"^[A-Za-z0-9._\[\]-]{1,32}$")  # "Ether1[WAN]" exists in the fleet


def render_realtime_push_script(
    *,
    identity: str,
    endpoint_url: str,
    interval_seconds: int = 10,
    wan_interface: str = "ether1",
    lists_every: int = 5,
) -> str:
    """Render the v2 (real-time pilot) reporter. See the block comment above.

    ``lists_every``: the slow-changing lists (device-per-port, bindings,
    leases, neighbours, bridge ports) ride every Nth report. Smallest boards
    use a larger N; keep N x interval under the 15-minute list freshness.
    """
    identity = _require(identity, _IDENTITY_RE, "identity")
    endpoint_url = _require(endpoint_url, _URL_RE, "endpoint_url")
    wan = _require(wan_interface, _WAN_RE, "wan_interface")
    if not (5 <= int(interval_seconds) <= 3600):
        raise ValueError("usage-push script: interval must be 5..3600 seconds")
    if not (2 <= int(lists_every) <= 15):
        raise ValueError("usage-push script: lists_every must be 2..15")
    return (
        _REALTIME_TEMPLATE
        .replace("__SCRIPT__", SCRIPT_NAME)
        .replace("__LOGOUT__", LOGOUT_SCRIPT_NAME)
        .replace("__SCHED__", SCHEDULER_NAME)
        .replace("__URL__", endpoint_url)
        .replace("__TOKEN__", derive_router_token(identity))
        .replace("__IDENT__", identity)
        .replace("__WAN__", wan)
        .replace("__INTERVAL__", str(int(interval_seconds)))
        .replace("__LISTS_EVERY__", str(int(lists_every)))
    )
