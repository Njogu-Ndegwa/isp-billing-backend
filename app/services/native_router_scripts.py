"""Opt-in RouterOS 7 collectors with native serialization and exact counters."""
from __future__ import annotations

import re


def native_cpu_enabled(identity: str) -> bool:
    from app.config import settings
    selected = {x.strip() for x in settings.ROUTER_NATIVE_CPU_IDENTITIES.split(",") if x.strip()}
    return identity in selected


def native_cpu_supported(version: str) -> bool:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:\s|$)", str(version))
    return bool(match and tuple(int(x or 0) for x in match.groups()) >= (7, 19, 6))


NATIVE_CENSUS_COLLECT = r'''    :local readOk true
    :local post ""
    :do {
        :local census [:toarray ""]
        :local table [/ip hotspot user print as-value proplist=name where comment~"^MACLOGIN" and name~"^[0-9A-Fa-f:]+\$"]
        :local data ""
        :if ([:len $table] > 0) do={ :set data [:serialize to=dsv options=dsv.remap delimiter="," order={"name"} value=$table] }
        :set ($census->"users") {"count"=[:len $table];"data"=$data}
        :set table [/ip hotspot user print as-value proplist=name where comment~"^MACLOGIN" and comment~"CHECKIN" and name~"^[0-9A-Fa-f:]+\$"]
        :set data ""
        :if ([:len $table] > 0) do={ :set data [:serialize to=dsv options=dsv.remap delimiter="," order={"name"} value=$table] }
        :set ($census->"checkin_users") {"count"=[:len $table];"data"=$data}
        :set table [/ip hotspot ip-binding print as-value proplist=mac-address where comment~"USER:"]
        :set data ""
        :if ([:len $table] > 0) do={ :set data [:serialize to=dsv options=dsv.remap delimiter="," order={"mac-address"} value=$table] }
        :set ($census->"bindings") {"count"=[:len $table];"data"=$data}
        :set table [/ip hotspot ip-binding print as-value proplist=mac-address where comment~"USER:" and comment~"CHECKIN"]
        :set data ""
        :if ([:len $table] > 0) do={ :set data [:serialize to=dsv options=dsv.remap delimiter="," order={"mac-address"} value=$table] }
        :set ($census->"checkin_bindings") {"count"=[:len $table];"data"=$data}
        :set table [/queue simple print as-value proplist=name where name~"^plan_[0-9A-Fa-f]+\$"]
        :set data ""
        :if ([:len $table] > 0) do={ :set data [:serialize to=dsv options=dsv.remap delimiter="," order={"name"} value=$table] }
        :set ($census->"queues") {"count"=[:len $table];"data"=$data}
        :set table [/ip hotspot ip-binding print as-value proplist=mac-address where type!="blocked" and disabled=no and !(comment~"USER:")]
        :set data ""
        :if ([:len $table] > 0) do={ :set data [:serialize to=dsv options=dsv.remap delimiter="," order={"mac-address"} value=$table] }
        :set ($census->"others") {"count"=[:len $table];"data"=$data}
        :set post [:serialize to=json options=json.no-string-conversion value={"v"=3;"id"=$ident;"census"=$census}]
        :if ([:len $post] > 32768) do={ :set readOk false }
    } on-error={ :set readOk false }
'''


NATIVE_PUSH_BODY = r'''# bw-native-snapshot v1: RouterOS 7.19.6+; send native tables as bounded parts.
    :local url "__URL__"
    :local tok "__TOKEN__"
    :local ident "__IDENT__"
    :local health [/system resource print as-value]
    :global bwPushN
    :if ([:typeof $bwPushN] != "num") do={ :set bwPushN 0 }
    :set bwPushN ($bwPushN + 1)
    :local parts {"queues";"queue_stats";"hosts";"summary"}
    :if (($bwPushN % __LISTS_EVERY__) = 1) do={
        :set parts ($parts, {"bridge_hosts";"bindings";"leases";"neighbors";"bridge_ports"})
    }
    :local batch [:rndstr from="0123456789abcdef" length=16]
    :local failed false
    :local reply ""
    :foreach part in=$parts do={
        :if (!$failed) do={
            :do {
                :local data [:toarray ""]
                :if ($part = "queues") do={ :set data [/queue simple print as-value proplist=name,target,max-limit,disabled where name~"^(plan_|<pppoe-)"] }
                :if ($part = "queue_stats") do={ :set data [/queue simple print stats as-value proplist=name,bytes where name~"^(plan_|<pppoe-)"] }
                :if ($part = "hosts") do={
                    # Host print omits byte counters even with proplist/detail.
                    # One get returns exact counters and metadata together.
                    :local hostRows [:toarray ""]
                    :local authorized [:toarray ""]
                    :local bypassed [:toarray ""]
                    :foreach h in=[/ip hotspot host find where authorized or bypassed] do={
                        :do {
                            :local row [/ip hotspot host get $h]
                            :if (($row->"authorized") || ($row->"bypassed")) do={
                                :local selected {".id"=$h;"mac-address"=($row->"mac-address");"address"=($row->"address");"bytes-in"=($row->"bytes-in");"bytes-out"=($row->"bytes-out");"idle-time"=($row->"idle-time");"uptime"=($row->"uptime")}
                                :set hostRows ($hostRows, {$selected})
                                :if ($row->"authorized") do={ :set authorized ($authorized, {$h}) }
                                :if ($row->"bypassed") do={ :set bypassed ($bypassed, {$h}) }
                            }
                        } on-error={}
                    }
                    :set data {"rows"=$hostRows;"authorized"=$authorized;"bypassed"=$bypassed}
                }
                :if ($part = "summary") do={
                    :set data {"resource"=$health;"wan"="__WAN__";"queue_disabled"=[/queue simple find where disabled];"ppp"=[/ppp active print as-value proplist=name,address,uptime,caller-id];"interfaces"=[/interface print as-value proplist=name,type,last-link-up-time];"interface_stats"=[/interface print stats as-value proplist=name,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,link-downs];"interface_running"=[/interface find where running];"interface_disabled"=[/interface find where disabled]}
                }
                :if ($part = "bridge_hosts") do={ :set data [/interface bridge host print as-value proplist=mac-address,on-interface where !local] }
                :if ($part = "bindings") do={ :set data {"rows"=[/ip hotspot ip-binding print as-value proplist=mac-address,type];"disabled"=[/ip hotspot ip-binding find where disabled]} }
                :if ($part = "leases") do={ :set data [/ip dhcp-server lease print as-value proplist=mac-address,address,host-name,status,comment] }
                :if ($part = "neighbors") do={ :set data [/ip neighbor print as-value proplist=mac-address,identity,board,platform,version,interface,address] }
                :if ($part = "bridge_ports") do={ :set data [/interface bridge port print as-value proplist=interface,bridge] }
                :local body [:serialize to=json options=json.no-string-conversion value={"identity"=$ident;"v"=4;"native"={"batch"=$batch;"parts"=$parts;"part"=$part;"data"=$data}}]
                :if ([:len $body] <= 60000) do={
                    :local res [/tool fetch url=$url http-method=post http-header-field=("Content-Type: application/json,Authorization: Bearer " . $tok) http-data=$body output=user as-value]
                    :set reply [:tostr ($res->"data")]
                } else={ :set failed true }
            } on-error={ :set failed true }
        }
    }
    :if ($failed) do={ :log info "usage-push: native snapshot deferred" } else={
        :local p [:find $reply "\"next_push_seconds\":"]
        :if ([:typeof $p] = "num") do={
            :local s ($p + 20)
            :local e [:find $reply "}" $s]
            :local n [:tonum [:pick $reply $s $e]]
            :if (([:typeof $n] = "num") && ($n >= 5) && ($n <= 3600)) do={
                :local want [:totime ($n . "s")]
                :if ([/system scheduler get [find name="__SCHED__"] interval] != $want) do={
                    /system scheduler set [find name="__SCHED__"] interval=$want
                }
            }
        }
    }
'''
