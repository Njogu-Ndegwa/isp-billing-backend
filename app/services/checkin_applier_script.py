"""Render the RouterOS applier for the check-in delivery pilot.

This is the router half of ``app/services/checkin_delivery.py``. It is FIXED
code: the server only ever sends data lines, and this script owns every
command it runs. That is the lesson of the old router agent
(``router_agent_script.py``), which ``/import``-ed server-generated script and
used a bare top-level ``:return`` — both broke on RouterOS 7.19+.

Portability rules this template keeps (RouterOS 6.48 - 7.21):

* no ``:return``, ``/import``, ``:parse``, ``:execute``, ``:global``;
* no v7-only syntax (``:deserialize``, ``:onerror``, ``:timestamp``,
  ``:toarray delimiter=``, ``/file/read``);
* error handling only with ``:do {} on-error={}``;
* server values reach commands only as variables, never spliced into a
  command string;
* ``:find`` is never called with a start offset (its start semantics are not
  documented); lines are split by re-slicing the remaining text instead, and
  ``A`` line fields are taken at fixed offsets (MAC 2..19, ref = last 12,
  epoch = the 10 chars before the ref's comma); ``Q`` lines likewise (MAC
  2..19, ref = last 12, rate = between);
* nothing is remembered between runs — every run reads its own bindings.

Per run:

1. Skip if another copy is still running (a slow fetch at a 5 s interval).
2. Collect the MACs of ip-bindings whose comment contains ``USER:``, and the
   ``CHECKIN``-tagged subset with no ``plan_<MAC without colons>`` simple
   queue. Only check-in bindings are queue-checked (a string match on the
   comment first), so a router with hundreds of push bindings does not run a
   queue lookup per binding every minute; the server only acts on Q lines
   for check-in bindings anyway.
   The same comment read yields ``c=``: the CHECKIN-tagged MACs, i.e. the
   bindings this applier added itself (so the server credits the check-in
   only for those). One more find collects ``o=``: MACs of every other
   enabled, non-blocked binding (no ``USER:`` in the comment), capped at
   ``MAX_OTHER_MACS``, so the server never offers an add for a MAC that
   already has a legacy/agent/reseller binding.
3. POST ``v=1&id=<identity>&n=<count>&macs=<csv>&q=<csv>&c=<csv>&o=<csv>``
   with the check-in token. Sending ``q=``/``c=``/``o=`` (even empty) tells
   the server this applier supports them; each is left out if its own read
   failed (a partial list would be read as a complete one).
4. Validate the WHOLE frame first: ``BWE1,`` header, every line a well-formed
   ``A`` or ``Q`` line, an ``END`` line, and the header count equal to the
   number of lines. Anything else (Cloudflare page, captive portal,
   truncation) applies nothing and drops the interval back to at least 60 s.
5. For each ``A`` line whose MAC has NO ip-binding at all: add the bypassed
   binding with the push's comment format, kick that MAC's hotspot active +
   host entries (only on this new add), and replace its ``plan_<ref>`` simple
   queue exactly like ``MikroTikAPI.add_customer_bypass_mode``. A MAC that
   already has any binding (ours or a reseller's block) is left alone.
   For each ``Q`` line: only if the MAC has a ``CHECKIN``-tagged binding and
   still no ``plan_<ref>`` queue, and its IP is now known (hotspot host, arp,
   dhcp lease), create the queue exactly as the ``A`` path does. No IP yet
   means nothing happens; the server offers it again on a later check-in.
6. Set its own scheduler interval to the header's ``next_s`` (5..3600).

Version 2 (``v=2``, 2026-09-29) adds MAC login (``hotspot_mac_login``): the
MACs of hotspot users tagged ``MACLOGIN`` are reported with the bindings (and
in ``c=`` when tagged ``CHECKIN``), and ``U,<mac>,<rate>,<exp>,<t>`` lines make
such a user (profile ``plan_<rate>`` with that rate-limit, ``T:``/``EXP:`` tags)
when the MAC has no user yet, drop its tagged bypass binding and kick it so it
logs in by MAC. The server only sends U lines to MAC-login routers, and never
sends them (or A lines) to a MAC-login router whose applier is still v1.

Version 3 (``v=3``, 2026-11-14, ``render_checkin_applier_source(actions=True)``)
adds the router actions of ``app/services/router_checkin_actions.py``: the
report also carries ``u=`` (uptime) and ``h=`` (1 if ``bitwave-heal-tunnel``
is installed), and four more line kinds are applied by fixed code here:
``R,<id>`` restart (refused when up for under 5 min, run last of all, after
the acks are sent), ``H,<id>`` run ``bitwave-heal-tunnel``, ``C,...`` add or
update one access-credential hotspot user, ``D,...`` remove one (only a user
or binding whose comment carries that credential's ``ACCESS_CRED|cred:<id>|``
tag). Each one's outcome is posted back at once in a second, small POST
(``ack=1&k=<done>&f=<failed>``), so nothing has to be remembered between
runs. Server values still reach commands only as variables. v3 needs the
``reboot`` policy on the script and its scheduler (``POLICY_ACTIONS``).
The server only sends these lines to a router that reported ``v=3``.
"""

from __future__ import annotations

import re

from app.services.router_script_gate import with_gate
from app.services.checkin_tunnel_transport import prefer_tunnel_transport
from app.services.usage_push_auth import derive_checkin_token

SCRIPT_NAME = "bitwave-checkin"
SCHEDULER_NAME = "bitwave-checkin"
POLICY = "read,write,test,policy"
# v3 (router actions) may restart the router: /system reboot needs "reboot".
POLICY_ACTIONS = "read,write,test,policy,reboot"
HEAL_SCRIPT_NAME = "bitwave-heal-tunnel"
HEAL_POLICY = "read,write,test"
VERSION_BASE = 2
VERSION_ACTIONS = 3
SCHEDULER_COMMENT = "Bitwave check-in delivery (pilot)"
INITIAL_INTERVAL_SECONDS = 60

CHECK_CERTIFICATE_VALUES = ("no", "yes", "yes-without-crl")

# Cap on o= (other bindings). The POST body is a script string variable;
# RouterOS strings built in a script are not bound by the 4 KB file-read
# limit, but a small body keeps the fetch cheap on a hAP lite and well under
# the server's MAX_BODY_BYTES. 150 MACs = ~2.7 KB. Beyond the cap an
# untagged binding for a paid MAC is simply offered (and backed off) as
# before this field existed.
MAX_OTHER_MACS = 150

_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._:/-]{3,200}$")

_TEMPLATE = r''':local url "__URL__"
:local tok "__TOKEN__"
:local ident "__IDENT__"
:local running 0
:do { :set running [:len [/system script job find where script="__SCRIPT__"]] } on-error={}
:if ($running < 2) do={
    :local macs ""
    :local n 0
    :local readOk true
    :local qmacs ""
    :local nq 0
    :local qOk true
    :local cmacs ""
    :local nc 0
    :local cOk true
    :local omacs ""
    :local nOth 0
    :local oOk true
    :do {
        :foreach b in=[/ip hotspot ip-binding find where comment~"USER:"] do={
            :local bm [:tostr [/ip hotspot ip-binding get $b mac-address]]
            :if ([:len $bm] = 17) do={
                :if ($n > 0) do={ :set macs ($macs . ",") }
                :set macs ($macs . $bm)
                :set n ($n + 1)
                :local bc ""
                :do {
                    :set bc [:tostr [/ip hotspot ip-binding get $b comment]]
                } on-error={
                    :set cOk false
                    :set qOk false
                }
                :if ([:typeof [:find $bc "CHECKIN"]] = "num") do={
                    :if ($nc > 0) do={ :set cmacs ($cmacs . ",") }
                    :set cmacs ($cmacs . $bm)
                    :set nc ($nc + 1)
                    :do {
                        :local rf ([:pick $bm 0 2] . [:pick $bm 3 5] . [:pick $bm 6 8] . [:pick $bm 9 11] . [:pick $bm 12 14] . [:pick $bm 15 17])
                        :if ([:len [/queue simple find where name=("plan_" . $rf)]] = 0) do={
                            :if ($nq > 0) do={ :set qmacs ($qmacs . ",") }
                            :set qmacs ($qmacs . $bm)
                            :set nq ($nq + 1)
                        }
                    } on-error={ :set qOk false }
                }
            }
        }
    } on-error={ :set readOk false }
    # v2: MAC-login users (hotspot users tagged MACLOGIN, named after the MAC)
    # are this app's access on MAC-login routers; report them like bindings so
    # the server sees them as delivered. "^MACLOGIN": "|" is regex alternation.
    :do {
        :foreach u in=[/ip hotspot user find where comment~"^MACLOGIN"] do={
            :local um [:tostr [/ip hotspot user get $u name]]
            :if ([:len $um] = 17) do={
                :if ($n > 0) do={ :set macs ($macs . ",") }
                :set macs ($macs . $um)
                :set n ($n + 1)
                :local uc ""
                :do { :set uc [:tostr [/ip hotspot user get $u comment]] } on-error={ :set cOk false }
                :if ([:typeof [:find $uc "CHECKIN"]] = "num") do={
                    :if ($nc > 0) do={ :set cmacs ($cmacs . ",") }
                    :set cmacs ($cmacs . $um)
                    :set nc ($nc + 1)
                }
            }
        }
    } on-error={ :set readOk false }
    # Other usable bindings (no USER: tag: legacy, agent or reseller ones), so
    # the server never offers an add the applier would refuse. One find, and
    # no per-binding read once the cap is reached.
    :do {
        :foreach b in=[/ip hotspot ip-binding find where type!="blocked" && disabled=no && !(comment~"USER:")] do={
            :if ($nOth < __OCAP__) do={
                :local om [:tostr [/ip hotspot ip-binding get $b mac-address]]
                :if ([:len $om] = 17) do={
                    :if ($nOth > 0) do={ :set omacs ($omacs . ",") }
                    :set omacs ($omacs . $om)
                    :set nOth ($nOth + 1)
                }
            }
        }
    } on-error={ :set oOk false }
    :local post ("v=__VER__&id=" . $ident . "&n=" . $n . "&macs=" . $macs)
__REPORT_EXTRA__
    :if ($qOk) do={ :set post ($post . "&q=" . $qmacs) }
    :if ($cOk) do={ :set post ($post . "&c=" . $cmacs) }
    :if ($oOk) do={ :set post ($post . "&o=" . $omacs) }
    :local d ""
    :if ($readOk) do={
        :do {
            :local res [/tool fetch url=$url http-method=post http-header-field=("Content-Type: text/plain,Authorization: Bearer " . $tok) http-data=$post check-certificate=__CHECKCERT__ output=user as-value]
            :if (($res->"status") = "finished") do={ :set d [:tostr ($res->"data")] }
        } on-error={ :log info "checkin: deferred" }
    }
    :local frameOk false
    :local hdrOk false
    :local want 0
    :local nexts 0
    :local body ""
    :local hdrEnd [:find $d "\n"]
    :if (([:pick $d 0 5] = "BWE1,") && ([:typeof $hdrEnd] = "num")) do={
        :local hdr [:pick $d 5 $hdrEnd]
        :set body [:pick $d ($hdrEnd + 1) [:len $d]]
        :local c1 [:find $hdr ","]
        :if ([:typeof $c1] = "num") do={
            :local hrest [:pick $hdr ($c1 + 1) [:len $hdr]]
            :local c2 [:find $hrest ","]
            :if ([:typeof $c2] = "num") do={
                :local wr [:tonum [:pick $hrest 0 $c2]]
                :local nr [:tonum [:pick $hrest ($c2 + 1) [:len $hrest]]]
                :if (([:typeof $wr] = "num") && ([:typeof $nr] = "num")) do={
                    :set want $wr
                    :set nexts $nr
                    :set hdrOk true
                }
            }
        }
    }
    # Pass 1: validate every line. Nothing is applied unless all of it is good.
    :if ($hdrOk) do={
        :local cnt 0
        :local bad false
        :local done false
        :local guard 0
        :local rest $body
        :while ((!$done) && (!$bad) && ($guard < 40)) do={
            :set guard ($guard + 1)
            :local ln ""
            :local e [:find $rest "\n"]
            :if ([:typeof $e] = "num") do={
                :set ln [:pick $rest 0 $e]
                :set rest [:pick $rest ($e + 1) [:len $rest]]
            } else={
                :set ln $rest
                :set rest ""
            }
            :if ($ln = "END") do={
                :set done true
            } else={
                :local ok false
                :local ll [:len $ln]
                :if (($ll >= 47) && ($ll <= 80)) do={
                    :if (([:pick $ln 0 2] = "A,") && ([:pick $ln 19 20] = ",") && ([:pick $ln ($ll - 24) ($ll - 23)] = ",") && ([:pick $ln ($ll - 13) ($ll - 12)] = ",")) do={
                        :local vm [:pick $ln 2 19]
                        :local vr [:pick $ln 20 ($ll - 24)]
                        :local ve [:tonum [:pick $ln ($ll - 23) ($ll - 13)]]
                        :if (([:pick $vm 2 3] = ":") && ([:pick $vm 5 6] = ":") && ([:pick $vm 8 9] = ":") && ([:pick $vm 11 12] = ":") && ([:pick $vm 14 15] = ":")) do={
                            :if (([:typeof [:find $vr "/"]] = "num") && ([:typeof [:find $vr ","]] != "num") && ([:typeof $ve] = "num")) do={
                                :set ok true
                            }
                        }
                    }
                }
                :if (($ll >= 36) && ($ll <= 70)) do={
                    :if (([:pick $ln 0 2] = "Q,") && ([:pick $ln 19 20] = ",") && ([:pick $ln ($ll - 13) ($ll - 12)] = ",")) do={
                        :local vm [:pick $ln 2 19]
                        :local vr [:pick $ln 20 ($ll - 13)]
                        :if (([:pick $vm 2 3] = ":") && ([:pick $vm 5 6] = ":") && ([:pick $vm 8 9] = ":") && ([:pick $vm 11 12] = ":") && ([:pick $vm 14 15] = ":")) do={
                            :if (([:typeof [:find $vr "/"]] = "num") && ([:typeof [:find $vr ","]] != "num")) do={
                                :set ok true
                            }
                        }
                    }
                }
                :if (($ll >= 45) && ($ll <= 80)) do={
                    :if (([:pick $ln 0 2] = "U,") && ([:pick $ln 19 20] = ",") && ([:pick $ln ($ll - 22) ($ll - 21)] = ",") && ([:pick $ln ($ll - 11) ($ll - 10)] = ",")) do={
                        :local vm [:pick $ln 2 19]
                        :local vr [:pick $ln 20 ($ll - 22)]
                        :local ve [:tonum [:pick $ln ($ll - 21) ($ll - 11)]]
                        :local vt [:tonum [:pick $ln ($ll - 10) $ll]]
                        :if (([:pick $vm 2 3] = ":") && ([:pick $vm 5 6] = ":") && ([:pick $vm 8 9] = ":") && ([:pick $vm 11 12] = ":") && ([:pick $vm 14 15] = ":")) do={
                            :if (([:typeof [:find $vr "/"]] = "num") && ([:typeof [:find $vr ","]] != "num") && ([:typeof $ve] = "num") && ([:typeof $vt] = "num")) do={
                                :set ok true
                            }
                        }
                    }
                }
__VALIDATE_EXTRA__                :if ($ok) do={ :set cnt ($cnt + 1) } else={ :set bad true }
            }
        }
        :if ((!$bad) && $done && ($cnt = $want)) do={
            :set frameOk true
        } else={
            :log warning "checkin: reply rejected, nothing applied"
        }
    }
__DECLARE_EXTRA__    # Pass 2: apply. Same splitting; only reached when pass 1 accepted it all.
    :if ($frameOk && ($want > 0)) do={
        :local rest $body
        :local done false
        :local guard 0
        :while ((!$done) && ($guard < 40)) do={
            :set guard ($guard + 1)
            :local ln ""
            :local e [:find $rest "\n"]
            :if ([:typeof $e] = "num") do={
                :set ln [:pick $rest 0 $e]
                :set rest [:pick $rest ($e + 1) [:len $rest]]
            } else={
                :set ln $rest
                :set rest ""
            }
            :if (($ln = "END") || ($ln = "")) do={
                :set done true
            } else={
                :local ll [:len $ln]
                :local kind [:pick $ln 0 1]
__APPLY_EXTRA__                :local mac [:pick $ln 2 19]
__REF_LINE__
                :local rate ""
                :local exp ""
                :local need false
                :if ($kind = "A") do={
                    :set rate [:pick $ln 20 ($ll - 24)]
                    :set exp [:pick $ln ($ll - 23) ($ll - 13)]
                    :if ([:len [/ip hotspot ip-binding find where mac-address=$mac]] = 0) do={
                        :set need true
                    } else={
                        :log info ("checkin: " . $mac . " already has a binding, left alone")
                    }
                }
                :if ($kind = "U") do={
                    # MAC login: a hotspot user named after the MAC on the
                    # plan's rate-limited profile; RouterOS makes the queue.
                    :local urate [:pick $ln 20 ($ll - 22)]
                    :local uexp [:pick $ln ($ll - 21) ($ll - 11)]
                    :local uts [:pick $ln ($ll - 10) $ll]
                    :if ([:len [/ip hotspot user find where name=$mac]] = 0) do={
                        :local sl [:find $urate "/"]
                        :local pn ("plan_" . [:pick $urate 0 $sl] . "_" . [:pick $urate ($sl + 1) [:len $urate]])
                        :local uadded false
                        :do {
                            :if ([:len [/ip hotspot user profile find where name=$pn]] = 0) do={
                                /ip hotspot user profile add name=$pn rate-limit=$urate
                            }
                            /ip hotspot user add name=$mac password="" mac-address=$mac profile=$pn comment=("MACLOGIN|MAC:" . $mac . "|T:" . $uts . "|EXP:" . $uexp . "|CHECKIN")
                            :set uadded true
                        } on-error={ :log warning ("checkin: mac-login add failed " . $mac) }
                        :if ($uadded) do={
                            :do {
                                :foreach b in=[/ip hotspot ip-binding find where mac-address=$mac type=bypassed comment~"USER:"] do={ /ip hotspot ip-binding remove $b }
                            } on-error={}
                            :do { /ip hotspot active remove [find where mac-address=$mac] } on-error={}
                            :do { /ip hotspot host remove [find where mac-address=$mac] } on-error={}
                            :log info ("checkin: mac-login " . $mac)
                        }
                    } else={
                        :log info ("checkin: " . $mac . " already has a user, left alone")
                    }
                }
                :if ($kind = "Q") do={
                    :set rate [:pick $ln 20 ($ll - 13)]
                    :do {
                        :if ([:len [/ip hotspot ip-binding find where mac-address=$mac comment~"CHECKIN"]] > 0) do={
                            :if ([:len [/queue simple find where name=("plan_" . $ref)]] = 0) do={ :set need true }
                        }
                    } on-error={}
                }
                :if ($need) do={
                    :local ip ""
                    :do {
                        :foreach h in=[/ip hotspot host find where mac-address=$mac] do={
                            :if ($ip = "") do={ :set ip [:tostr [/ip hotspot host get $h address]] }
                        }
                    } on-error={}
                    :if ($ip = "") do={
                        :do {
                            :foreach a in=[/ip arp find where mac-address=$mac] do={
                                :if ($ip = "") do={ :set ip [:tostr [/ip arp get $a address]] }
                            }
                        } on-error={}
                    }
                    :if ($ip = "") do={
                        :do {
                            :foreach l in=[/ip dhcp-server lease find where mac-address=$mac] do={
                                :if ($ip = "") do={ :set ip [:tostr [/ip dhcp-server lease get $l address]] }
                            }
                        } on-error={}
                    }
                    :local added false
                    :if ($kind = "A") do={
                        :do {
                            /ip hotspot ip-binding add mac-address=$mac type=bypassed comment=("USER:" . $ref . "|EXPIRES:DB_MANAGED|CHECKIN|EXP:" . $exp)
                            :set added true
                        } on-error={ :log warning ("checkin: bypass add failed " . $mac) }
                    }
                    :if ($added) do={
                        :do { /ip hotspot active remove [find where mac-address=$mac] } on-error={}
                        :do { /ip hotspot host remove [find where mac-address=$mac] } on-error={}
                    }
                    :if ($added || ($kind = "Q")) do={
                        :if ($ip != "") do={
                            :local qn ("plan_" . $ref)
                            :do {
                                :foreach q in=[/queue simple find where name=$qn] do={ /queue simple remove $q }
                                :foreach q in=[/queue simple find where comment~("MAC:" . $mac)] do={ /queue simple remove $q }
                                /queue simple add name=$qn target=($ip . "/32") max-limit=$rate comment=("MAC:" . $mac . "|Plan rate limit")
                            } on-error={ :log warning ("checkin: queue failed " . $mac) }
                            :do {
                                :if ([:len [/ip firewall filter find where action=fasttrack-connection disabled=no]] > 0) do={
                                    :if ([:len [/ip firewall address-list find where list="isp_queue_limited_clients" address=$ip]] = 0) do={
                                        /ip firewall address-list add list="isp_queue_limited_clients" address=$ip comment="Managed by ISP Billing queue sync"
                                    }
                                }
                            } on-error={}
                            :if ($kind = "Q") do={ :log info ("checkin: queued " . $mac) }
                        } else={
                            :if ($added) do={ :log info ("checkin: no IP yet for " . $mac . ", queue left to sync") }
                        }
                        :if ($added) do={ :log info ("checkin: bypassed " . $mac) }
                    }
                }
            }
        }
    }
    # Cadence: the server's next_s on a good frame; at least 60 s otherwise.
    :do {
        :local cur [/system scheduler get [find name="__SCHED__"] interval]
        :if ($frameOk) do={
            :if (($nexts >= 5) && ($nexts <= 3600)) do={
                :local wantI [:totime ($nexts . "s")]
                :if ($cur != $wantI) do={ /system scheduler set [find name="__SCHED__"] interval=$wantI }
            }
        } else={
            :local minI [:totime "60s"]
            :if ($cur < $minI) do={ /system scheduler set [find name="__SCHED__"] interval=$minI }
        }
    } on-error={}
__TAIL_EXTRA__}
'''

_REPORT_EXTRA = r'''    :do { :set post ($post . "&u=" . [:tostr [/system resource get uptime]]) } on-error={}
    :set post ($post . "&h=" . [:len [/system script find where name="__HEAL__"]])
'''

_VALIDATE_EXTRA = r'''                # v3 actions: R/H = letter + 12-digit id; C/D = fixed comma counts,
                # every field before the last one non-empty.
                :if (($ll = 14) && (([:pick $ln 0 2] = "R,") || ([:pick $ln 0 2] = "H,"))) do={ :set ok true }
                :local nfw 0
                :if (([:pick $ln 0 2] = "C,") && ($ll >= 14) && ($ll <= 240)) do={ :set nfw 4 }
                :if (([:pick $ln 0 2] = "D,") && ($ll >= 9) && ($ll <= 120)) do={ :set nfw 2 }
                :if ($nfw > 0) do={
                    :local fr [:pick $ln 2 $ll]
                    :local nf 0
                    :local fgo true
                    :while ($fgo && ($nf < $nfw)) do={
                        :local fp [:find $fr ","]
                        :set fgo false
                        :if ([:typeof $fp] = "num") do={
                            :if ($fp > 0) do={
                                :set fr [:pick $fr ($fp + 1) [:len $fr]]
                                :set nf ($nf + 1)
                                :set fgo true
                            }
                        }
                    }
                    :if (($nf = $nfw) && ([:len $fr] > 0)) do={ :set ok true }
                }
'''

_DECLARE_EXTRA = r'''    :local acks ""
    :local fails ""
    :local rebootId ""
'''

_APPLY_EXTRA = r'''                :if (($kind = "R") || ($kind = "H") || ($kind = "C") || ($kind = "D")) do={
                    :local aid ""
                    :local aok false
                    :if ($kind = "R") do={
                        :set aid [:pick $ln 2 14]
                        :if ([/system resource get uptime] > 5m) do={
                            :set rebootId $aid
                            :set aok true
                        } else={ :log warning "checkin: restart refused, router up for under 5 min" }
                    }
                    :if ($kind = "H") do={
                        :set aid [:pick $ln 2 14]
                        :do {
                            :if ([:len [/system script find where name="__HEAL__"]] > 0) do={
                                /system script run __HEAL__
                                :set aok true
                            }
                        } on-error={ :log warning "checkin: tunnel repair failed" }
                    }
                    :if (($kind = "C") || ($kind = "D")) do={
                        :local fr [:pick $ln 2 $ll]
                        :local fp [:find $fr ","]
                        :set aid [:pick $fr 0 $fp]
                        :set fr [:pick $fr ($fp + 1) [:len $fr]]
                        :local tag ("ACCESS_CRED|cred:" . $aid . "|")
                        :if ($kind = "C") do={
                            :set fp [:find $fr ","]
                            :local cuid [:pick $fr 0 $fp]
                            :set fr [:pick $fr ($fp + 1) [:len $fr]]
                            :set fp [:find $fr ","]
                            :local crate [:pick $fr 0 $fp]
                            :set fr [:pick $fr ($fp + 1) [:len $fr]]
                            :set fp [:find $fr ","]
                            :local cuser [:pick $fr 0 $fp]
                            :local cpass [:pick $fr ($fp + 1) [:len $fr]]
                            :local pn "cred-unlimited"
                            :if ($crate != "-") do={
                                :local sl [:find $crate "/"]
                                :set pn ("cred-" . [:pick $crate 0 $sl] . "_" . [:pick $crate ($sl + 1) [:len $crate]])
                            }
                            :local cm ("ACCESS_CRED|cred:" . $aid . "|user:" . $cuid)
                            :do {
                                :if ([:len [/ip hotspot user profile find where name=$pn]] = 0) do={
                                    /ip hotspot user profile add name=$pn shared-users=1
                                }
                                :local pf [/ip hotspot user profile find where name=$pn]
                                :if ($crate = "-") do={
                                    /ip hotspot user profile set $pf shared-users=1 rate-limit=""
                                } else={
                                    /ip hotspot user profile set $pf shared-users=1 rate-limit=$crate
                                }
                                :local uf [/ip hotspot user find where name=$cuser]
                                :if ([:len $uf] = 0) do={
                                    /ip hotspot user add name=$cuser password=$cpass profile=$pn disabled=no comment=$cm
                                    :set aok true
                                } else={
                                    :local oc [:tostr [/ip hotspot user get [:pick $uf 0] comment]]
                                    :if ([:pick $oc 0 11] = "ACCESS_CRED") do={
                                        /ip hotspot user set $uf password=$cpass profile=$pn disabled=no comment=$cm
                                        :set aok true
                                    } else={ :log warning ("checkin: hotspot user " . $cuser . " is not ours, left alone") }
                                }
                            } on-error={ :log warning ("checkin: credential add failed " . $cuser) }
                        }
                        :if ($kind = "D") do={
                            :set fp [:find $fr ","]
                            :local dmac [:pick $fr 0 $fp]
                            :local duser [:pick $fr ($fp + 1) [:len $fr]]
                            :do {
                                :local keep false
                                :foreach u in=[/ip hotspot user find where name=$duser] do={
                                    :if ([:typeof [:find [:tostr [/ip hotspot user get $u comment]] $tag]] = "num") do={
                                        /ip hotspot user remove $u
                                    } else={ :set keep true }
                                }
                                :if (!$keep) do={
                                    :foreach a in=[/ip hotspot active find where user=$duser] do={ /ip hotspot active remove $a }
                                }
                                :foreach q in=[/queue simple find where name=("cred_" . $aid)] do={ /queue simple remove $q }
                                :if ($dmac != "-") do={
                                    :foreach b in=[/ip hotspot ip-binding find where mac-address=$dmac] do={
                                        :if ([:typeof [:find [:tostr [/ip hotspot ip-binding get $b comment]] $tag]] = "num") do={
                                            /ip hotspot ip-binding remove $b
                                        }
                                    }
                                }
                                :set aok true
                            } on-error={ :log warning ("checkin: credential remove failed " . $duser) }
                        }
                    }
                    :if ($aok) do={
                        :if ([:len $acks] > 0) do={ :set acks ($acks . ",") }
                        :set acks ($acks . $kind . $aid)
                    } else={
                        :if ([:len $fails] > 0) do={ :set fails ($fails . ",") }
                        :set fails ($fails . $kind . $aid)
                    }
                    :set kind "-"
                }
'''

# Short action lines (D can be 9 chars) must not reach a negative :pick.
_REF_LINE_ACTIONS = r'''                :local ref ""
                :if ($ll >= 14) do={ :set ref [:pick $ln ($ll - 12) $ll] }'''
_REF_LINE_BASE = r'''                :local ref [:pick $ln ($ll - 12) $ll]'''

_TAIL_EXTRA = r'''    # v3: report what ran in one small POST (the reply is ignored), then restart if asked.
    :if (([:len $acks] > 0) || ([:len $fails] > 0)) do={
        :do {
            /tool fetch url=$url http-method=post http-header-field=("Content-Type: text/plain,Authorization: Bearer " . $tok) http-data=("v=__VER__&id=" . $ident . "&ack=1&k=" . $acks . "&f=" . $fails) check-certificate=__CHECKCERT__ output=none
        } on-error={ :log info "checkin: action ack deferred" }
    }
    :if ([:len $rebootId] > 0) do={
        :log warning "checkin: restarting the router (requested by Bitwave)"
        :delay 2s
        /system reboot
    }
'''


def _require(value: str, rx: re.Pattern, name: str) -> str:
    v = str(value or "").strip()
    if not rx.match(v):
        raise ValueError(f"checkin applier: unsafe {name}={value!r}")
    return v


def _template(actions: bool) -> str:
    parts = {
        "__REPORT_EXTRA__\n": _REPORT_EXTRA if actions else "",
        "__VALIDATE_EXTRA__": _VALIDATE_EXTRA if actions else "",
        "__DECLARE_EXTRA__": _DECLARE_EXTRA if actions else "",
        "__APPLY_EXTRA__": _APPLY_EXTRA if actions else "",
        "__REF_LINE__": _REF_LINE_ACTIONS if actions else _REF_LINE_BASE,
        "__TAIL_EXTRA__": _TAIL_EXTRA if actions else "",
    }
    out = _TEMPLATE
    for key, value in parts.items():
        assert out.count(key) == 1, key
        out = out.replace(key, value)
    return out.replace("__VER__", str(VERSION_ACTIONS if actions else VERSION_BASE))


def render_checkin_applier_source(
    *,
    identity: str,
    endpoint_url: str,
    check_certificate: str = "no",
    tunnel_endpoint_url: str | None = None,
    actions: bool = False,
) -> str:
    """Return the ``source`` of the ``bitwave-checkin`` system script.

    Only three values are interpolated, all validated: the identity (strict
    charset), our own endpoint URL, and the derived hex token.
    ``check_certificate`` defaults to ``no`` for the pilot: RouterOS < 7.19
    has no CA store, so verification needs roots imported per router (bench).
    """
    identity = _require(identity, _IDENTITY_RE, "identity")
    endpoint_url = _require(endpoint_url, _URL_RE, "endpoint_url")
    if check_certificate not in CHECK_CERTIFICATE_VALUES:
        raise ValueError(f"checkin applier: check_certificate must be one of {CHECK_CERTIFICATE_VALUES}")
    token = derive_checkin_token(identity)
    source = with_gate(SCRIPT_NAME, (
        _template(actions)
        .replace("__HEAL__", HEAL_SCRIPT_NAME)
        .replace("__URL__", endpoint_url)
        .replace("__TOKEN__", token)
        .replace("__IDENT__", identity)
        .replace("__SCRIPT__", SCRIPT_NAME)
        .replace("__SCHED__", SCHEDULER_NAME)
        .replace("__CHECKCERT__", check_certificate)
        .replace("__OCAP__", str(int(MAX_OTHER_MACS)))
    ))
    return prefer_tunnel_transport(source, tunnel_endpoint_url) if tunnel_endpoint_url else source


def scheduler_on_event() -> str:
    return f"/system script run {SCRIPT_NAME}"


# ---------------------------------------------------------------------------
# Install / uninstall on a connected router (RouterOS I/O only)
# ---------------------------------------------------------------------------
#
# Same steps as scripts/checkin_pilot_install.py, as reusable helpers for the
# automatic installer (app/services/standard_runtime_enrol.py). Callers must
# not hold a DB session while calling them. The script is never run over the
# API: its scheduler runs it, the first check-in within one interval.

def _rows(api, path: str) -> list:
    return (api.send_command(f"{path}/print") or {}).get("data") or []


def _named(api, path: str, name: str) -> list:
    return [r for r in _rows(api, path) if r.get("name") == name]


def same_policy(a, b) -> bool:
    """RouterOS prints policies in its own order: compare as sets."""
    def norm(v):
        return frozenset(p.strip() for p in str(v or "").split(",") if p.strip())
    return norm(a) == norm(b)


def install_checkin_applier(
    api,
    *,
    identity: str,
    endpoint_url: str,
    check_certificate: str = "no",
    tunnel_endpoint_url: str | None = None,
    actions: bool = False,
) -> dict:
    """Install or update the applier script + scheduler. Idempotent.

    Returns ``{"status": ..., "error": ...}`` where status is one of
    installed / updated / unchanged / scheduler_disabled / script_failed /
    scheduler_failed. An identical script is not rewritten (no flash write).
    The scheduler's interval is never touched (the applier owns it). A
    DISABLED scheduler means someone paused the check-in on this router on
    purpose (e.g. the 2026-09-26 hAP lite CPU A/B): reported, not re-enabled.
    """
    source = render_checkin_applier_source(
        identity=identity, endpoint_url=endpoint_url, check_certificate=check_certificate,
        tunnel_endpoint_url=tunnel_endpoint_url, actions=actions,
    )
    policy = POLICY_ACTIONS if actions else POLICY
    changed = False
    res: dict = {}
    scripts = _named(api, "/system/script", SCRIPT_NAME)
    if not scripts:
        res = api.send_command("/system/script/add", {"name": SCRIPT_NAME, "policy": policy, "source": source})
        changed = True
    elif scripts[0].get("source") != source or not same_policy(scripts[0].get("policy"), policy):
        res = api.send_command("/system/script/set", {".id": scripts[0][".id"], "source": source, "policy": policy})
        changed = True
    if (res or {}).get("error"):
        return {"status": "script_failed", "error": str(res["error"])[:200]}

    scheds = _named(api, "/system/scheduler", SCHEDULER_NAME)
    if not scheds:
        res = api.send_command("/system/scheduler/add", {
            "name": SCHEDULER_NAME, "interval": f"{INITIAL_INTERVAL_SECONDS}s", "start-time": "startup",
            "on-event": scheduler_on_event(), "policy": policy, "comment": SCHEDULER_COMMENT,
        })
        if (res or {}).get("error"):
            return {"status": "scheduler_failed", "error": str(res["error"])[:200]}
        return {"status": "installed", "error": ""}
    sched = scheds[0]
    if sched.get("disabled") == "true":
        return {"status": "scheduler_disabled", "error": ""}
    if sched.get("on-event") != scheduler_on_event() or not same_policy(sched.get("policy"), policy):
        res = api.send_command("/system/scheduler/set", {
            ".id": sched[".id"], "on-event": scheduler_on_event(), "policy": policy,
        })
        if (res or {}).get("error"):
            return {"status": "scheduler_failed", "error": str(res["error"])[:200]}
        changed = True
    return {"status": "updated" if changed else "unchanged", "error": ""}


def uninstall_checkin_applier(api) -> None:
    """Remove the scheduler, then the script. Bindings and queues the applier
    created stay: they are in the push's own format, so the normal expiry
    cleanup removes them like any other."""
    for s in _named(api, "/system/scheduler", SCHEDULER_NAME):
        api.send_command("/system/scheduler/remove", {".id": s[".id"]})
    for s in _named(api, "/system/script", SCRIPT_NAME):
        api.send_command("/system/script/remove", {".id": s[".id"]})


# ---------------------------------------------------------------------------
# bitwave-heal-tunnel: what an ``H`` line runs (applier v3)
# ---------------------------------------------------------------------------
#
# A separate script, one fixed source per tunnel kind, because RouterOS 6 has
# no /interface wireguard menu and would refuse a whole applier that names it.
# It is NOT gated (router_script_gate): it only ever runs from inside the
# applier's own, already gated run, and a gate would make it wait for that
# run to finish. No scheduler: it runs only when the server asked.

_HEAL_WG = r'''# bitwave-heal-tunnel (wg): asked for by Bitwave over check-in. Never reboots.
# Re-enables wg-hz if someone switched it off, re-resolves the endpoints and
# resets the management peers (wg-aws only when its interface is enabled).
:do { /ip dns cache flush } on-error={}
:do {
    :foreach i in=[/interface wireguard find where name="wg-hz" disabled=yes] do={ /interface wireguard enable $i }
} on-error={}
:foreach ifn in={"wg-hz";"wg-aws"} do={
    :if ([:len [/interface wireguard find where name=$ifn disabled=no]] > 0) do={
        :foreach p in=[/interface wireguard peers find where interface=$ifn] do={
            :do {
                :local ep [/interface wireguard peers get $p endpoint-address]
                :local epp [/interface wireguard peers get $p endpoint-port]
                :foreach cx in=[/ip firewall connection find where protocol="udp" dst-address=($ep . ":" . $epp)] do={
                    :do { /ip firewall connection remove $cx } on-error={}
                }
            } on-error={}
            :do { /interface wireguard peers disable $p } on-error={}
            :delay 2s
            :do { /interface wireguard peers enable $p } on-error={}
        }
    }
}
:log warning "bitwave-heal-tunnel: WireGuard management tunnel reset"
'''

_HEAL_SSTP = r'''# bitwave-heal-tunnel (sstp): asked for by Bitwave over check-in. Never reboots.
# Enables sstp-hetzner if someone switched it off and redials it (which also
# re-resolves its server address).
:do { /ip dns cache flush } on-error={}
:local id [/interface sstp-client find where name="sstp-hetzner"]
:if ([:len $id] > 0) do={
    :do { /interface sstp-client disable $id } on-error={}
    :delay 3s
    :do { /interface sstp-client enable $id } on-error={}
    :log warning "bitwave-heal-tunnel: SSTP management tunnel redialled"
}
'''

HEAL_SOURCES = {"wg": _HEAL_WG, "sstp": _HEAL_SSTP}


def render_heal_tunnel_source(kind: str) -> str:
    """Fixed source for ``kind`` (``mgmt_watchdog_script.KIND_WG``/``KIND_SSTP``)."""
    if kind not in HEAL_SOURCES:
        raise ValueError(f"heal-tunnel: unknown tunnel kind {kind!r}")
    return HEAL_SOURCES[kind]


def install_heal_tunnel(api, kind: str) -> dict:
    """Install or update ``bitwave-heal-tunnel`` for ``kind``. Idempotent."""
    source = render_heal_tunnel_source(kind)
    scripts = _named(api, "/system/script", HEAL_SCRIPT_NAME)
    if not scripts:
        res = api.send_command("/system/script/add", {
            "name": HEAL_SCRIPT_NAME, "policy": HEAL_POLICY, "source": source,
            "comment": "Bitwave: run by the check-in when asked to repair the tunnel",
        })
        status = "installed"
    elif scripts[0].get("source") != source or not same_policy(scripts[0].get("policy"), HEAL_POLICY):
        res = api.send_command("/system/script/set", {
            ".id": scripts[0][".id"], "source": source, "policy": HEAL_POLICY,
        })
        status = "updated"
    else:
        return {"status": "unchanged", "error": ""}
    if (res or {}).get("error"):
        return {"status": "script_failed", "error": str(res["error"])[:200]}
    return {"status": status, "error": ""}


def uninstall_heal_tunnel(api) -> None:
    for s in _named(api, "/system/script", HEAL_SCRIPT_NAME):
        api.send_command("/system/script/remove", {".id": s[".id"]})
