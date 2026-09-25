"""Render the RouterOS expiry reaper (router side of ``router_expiry.py``).

One script plus a 1-minute scheduler. Written for RouterOS 6.4x and 7.x alike:

* The clock is parsed from both date shapes (``sep/25/2026`` before 7.10,
  ``2026-09-25`` after) and ``gmt-offset`` as ``+03:00`` or as seconds, then
  turned into a unix minute with integer maths only (no ``:totime``/
  ``:timestamp``, which 6.x lacks). Leading zeros are stripped before
  ``:tonum`` so nothing is read as octal.
* No bare ``:return`` anywhere: RouterOS 7.19+ rejects the whole script for it
  (it is what killed the router agent). Control flow is nested ``:if`` only.
* Lists are walked with ``:find``/``:pick`` (never ``:toarray``, which would
  type-guess MAC addresses).

Cost, by design (a hAP lite spent 5-7 s at 100% CPU per HTTPS request):
* A quiet minute reads the clock and counts the bindings, and stops there.
  The binding list is only walked when a deadline has passed, a binding was
  added or removed, or a removal is waiting to be reported, and at most every
  5 minutes otherwise.
* It calls the server only when a customer is due, a removal needs reporting,
  or every 60 minutes as a heartbeat (the first run after a boot calls at
  once, which is how the router gets its clock confirmed). It tries plain HTTP inside the
  management tunnel first and public HTTPS only if that fails, and after a
  failed call it waits 5 minutes before calling again.
"""

from __future__ import annotations

import re

from app.services.usage_push_auth import derive_router_token

SCRIPT_NAME = "bitwave-expiry-reaper"
SCHEDULER_NAME = "bitwave-expiry-reaper"
POLICY = "read,write,test,policy"
COMMENT = "Bitwave expiry reaper: removes expired hotspot customers"

_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._:/-]{3,200}$")

_TEMPLATE = r'''# Bitwave expiry reaper - safe to re-run.
/system script remove [find name="__SCRIPT__"]
/system scheduler remove [find name="__SCHED__"]

/system script add name="__SCRIPT__" policy=__POLICY__ source={
    :global bwExpNext
    :global bwExpCount
    :global bwExpDone
    :global bwExpClockOk
    :global bwExpBeat
    :global bwExpRetryAt
    :if ([:typeof $bwExpNext] != "num") do={ :set bwExpNext 0 }
    :if ([:typeof $bwExpCount] != "num") do={ :set bwExpCount -1 }
    :if ([:typeof $bwExpDone] != "str") do={ :set bwExpDone "" }
    :if ([:typeof $bwExpClockOk] != "bool") do={ :set bwExpClockOk false }
    :if ([:typeof $bwExpBeat] != "num") do={ :set bwExpBeat 0 }
    :if ([:typeof $bwExpRetryAt] != "num") do={ :set bwExpRetryAt 0 }
    :local turl "__TURL__"
    :local purl "__PURL__"
    :local tok "__TOKEN__"
    :local ident "__IDENT__"

    # --- now, as a unix minute (UTC) ---------------------------------------
    :local d [:tostr [/system clock get date]]
    :local t [:tostr [/system clock get time]]
    :local y 0
    :local mo 0
    :local dd 0
    :if ([:pick $d 4 5] = "-") do={
        :set y [:tonum [:pick $d 0 4]]
        :local s1 [:pick $d 5 7]
        :if ([:pick $s1 0 1] = "0") do={ :set s1 [:pick $s1 1 2] }
        :set mo [:tonum $s1]
        :local s2 [:pick $d 8 10]
        :if ([:pick $s2 0 1] = "0") do={ :set s2 [:pick $s2 1 2] }
        :set dd [:tonum $s2]
    } else={
        :local names "janfebmaraprmayjunjulaugsepoctnovdec"
        :local mpos [:find $names [:pick $d 0 3]]
        :if ([:typeof $mpos] = "num") do={ :set mo (($mpos / 3) + 1) }
        :local s3 [:pick $d 4 6]
        :if ([:pick $s3 0 1] = "0") do={ :set s3 [:pick $s3 1 2] }
        :set dd [:tonum $s3]
        :set y [:tonum [:pick $d 7 11]]
    }
    :local hs [:pick $t 0 2]
    :if ([:pick $hs 0 1] = "0") do={ :set hs [:pick $hs 1 2] }
    :local ms [:pick $t 3 5]
    :if ([:pick $ms 0 1] = "0") do={ :set ms [:pick $ms 1 2] }
    :local h [:tonum $hs]
    :local mi [:tonum $ms]
    :local g [:tostr [/system clock get gmt-offset]]
    :local sign 1
    :if ([:pick $g 0 1] = "-") do={
        :set sign -1
        :set g [:pick $g 1 [:len $g]]
    }
    :if ([:pick $g 0 1] = "+") do={ :set g [:pick $g 1 [:len $g]] }
    :local offm 0
    :local gc [:find $g ":"]
    :if ([:typeof $gc] = "num") do={
        :local gh [:pick $g 0 $gc]
        :if ([:pick $gh 0 1] = "0") do={ :set gh [:pick $gh 1 [:len $gh]] }
        :if ($gh = "") do={ :set gh "0" }
        :local gm [:pick $g ($gc + 1) ($gc + 3)]
        :if ([:pick $gm 0 1] = "0") do={ :set gm [:pick $gm 1 2] }
        :if ($gm = "") do={ :set gm "0" }
        :set offm ((([:tonum $gh] * 60) + [:tonum $gm]) * $sign)
    } else={
        :local gsec [:tonum $g]
        :if ([:typeof $gsec] = "num") do={ :set offm (($gsec / 60) * $sign) }
    }
    :local sane false
    :if (([:typeof $y] = "num") && ([:typeof $mo] = "num") && ([:typeof $dd] = "num") && ([:typeof $h] = "num") && ([:typeof $mi] = "num")) do={
        :if (($y >= 2025) && ($y <= 2045) && ($mo >= 1) && ($mo <= 12)) do={ :set sane true }
    }
    :local nowm 0
    :if ($sane) do={
        :local yy $y
        :if ($mo <= 2) do={ :set yy ($yy - 1) }
        :local era ($yy / 400)
        :local yoe ($yy - ($era * 400))
        :local mp ($mo + 9)
        :if ($mo > 2) do={ :set mp ($mo - 3) }
        :local doy ((((153 * $mp) + 2) / 5) + ($dd - 1))
        :local doe ((($yoe * 365) + ($yoe / 4)) - (($yoe / 100) - $doy))
        :local days ((($era * 146097) + $doe) - 719468)
        :set nowm (((($days * 1440) + ($h * 60)) + $mi) - $offm)
    }

    # A clock that is not plausible (a no-RTC board just rebooted into 1970)
    # does nothing at all until NTP fixes it; the platform is the backstop.
    :if ($sane) do={
        # --- which deadlines have passed ------------------------------------
        :local cnt [:len [/ip hotspot ip-binding find]]
        :local due ""
        :if (($nowm >= $bwExpNext) || ($cnt != $bwExpCount) || ([:len $bwExpDone] > 0)) do={
            :local nxt ($nowm + 5)
            :foreach b in=[/ip hotspot ip-binding find where comment~"EXP:"] do={
                :local cm [/ip hotspot ip-binding get $b comment]
                :local p [:find $cm "EXP:"]
                :local v [:pick $cm ($p + 4) [:len $cm]]
                :local e [:find $v "|"]
                :if ([:typeof $e] = "num") do={ :set v [:pick $v 0 $e] }
                :local x [:tonum $v]
                :if ([:typeof $x] = "num") do={
                    :if ($x <= $nowm) do={
                        :local bm [:tostr [/ip hotspot ip-binding get $b mac-address]]
                        :if (([:len $bm] = 17) && ([:len $due] < 700)) do={ :set due ($due . $bm . ",") }
                        :set nxt $nowm
                    } else={
                        :if ($x < $nxt) do={ :set nxt $x }
                    }
                }
            }
            :set bwExpNext $nxt
            :set bwExpCount $cnt
        }

        # --- ask / report ---------------------------------------------------
        :local todo ""
        :local docall false
        :if (($due != "") || ([:len $bwExpDone] > 0) || (($nowm - $bwExpBeat) >= 60)) do={ :set docall true }
        :if ($nowm < $bwExpRetryAt) do={ :set docall false }
        :if ($docall) do={
            :local body ("ident=" . $ident . "&now=" . $nowm . "&due=" . $due . "&done=" . $bwExpDone)
            :local hdr ("Content-Type: text/plain,Authorization: Bearer " . $tok)
            :local rd ""
            :local ok false
            :do {
                :local res [/tool fetch url=$turl http-method=post http-header-field=$hdr http-data=$body output=user as-value]
                :set rd [:tostr ($res->"data")]
                :set ok true
            } on-error={}
            :if (!$ok) do={
                :do {
                    :local res2 [/tool fetch url=$purl http-method=post http-header-field=$hdr http-data=$body output=user as-value]
                    :set rd [:tostr ($res2->"data")]
                    :set ok true
                } on-error={}
            }
            :if ($ok && ([:pick $rd 0 3] = "BW1")) do={
                :set bwExpBeat $nowm
                :set bwExpRetryAt 0
                :set bwExpDone ""
                :set bwExpClockOk ([:typeof [:find $rd ";C=1;"]] = "num")
                # R: remove
                :local rp [:find $rd ";R="]
                :if ([:typeof $rp] = "num") do={ :set todo [:pick $rd ($rp + 3) [:find $rd ";" ($rp + 1)]] }
                # K: renewed, new deadline
                :local kp [:find $rd ";K="]
                :if ([:typeof $kp] = "num") do={
                    :local ks [:pick $rd ($kp + 3) [:find $rd ";" ($kp + 1)]]
                    :while ([:len $ks] > 0) do={
                        :local ki [:find $ks ","]
                        :local item $ks
                        :if ([:typeof $ki] = "num") do={
                            :set item [:pick $ks 0 $ki]
                            :set ks [:pick $ks ($ki + 1) [:len $ks]]
                        } else={ :set ks "" }
                        :local at [:find $item "@"]
                        :if ([:typeof $at] = "num") do={
                            :local km [:pick $item 0 $at]
                            :local kv [:pick $item ($at + 1) [:len $item]]
                            :foreach kb in=[/ip hotspot ip-binding find where mac-address=$km] do={
                                :local kc [/ip hotspot ip-binding get $kb comment]
                                :local kx [:find $kc "EXP:"]
                                :if ([:typeof $kx] = "num") do={
                                    :local ktail [:pick $kc ($kx + 4) [:len $kc]]
                                    :local ke [:find $ktail "|"]
                                    :local krest ""
                                    :if ([:typeof $ke] = "num") do={ :set krest [:pick $ktail $ke [:len $ktail]] }
                                    /ip hotspot ip-binding set $kb comment=([:pick $kc 0 ($kx + 4)] . $kv . $krest)
                                }
                            }
                        }
                    }
                }
                # X: not ours, stop asking
                :local xp [:find $rd ";X="]
                :if ([:typeof $xp] = "num") do={
                    :local xs [:pick $rd ($xp + 3) [:find $rd ";" ($xp + 1)]]
                    :while ([:len $xs] > 0) do={
                        :local xi [:find $xs ","]
                        :local xm $xs
                        :if ([:typeof $xi] = "num") do={
                            :set xm [:pick $xs 0 $xi]
                            :set xs [:pick $xs ($xi + 1) [:len $xs]]
                        } else={ :set xs "" }
                        :foreach xb in=[/ip hotspot ip-binding find where mac-address=$xm] do={
                            :local xc [/ip hotspot ip-binding get $xb comment]
                            :local xx [:find $xc "EXP:"]
                            :if ([:typeof $xx] = "num") do={
                                /ip hotspot ip-binding set $xb comment=([:pick $xc 0 $xx] . "EXX:" . [:pick $xc ($xx + 4) [:len $xc]])
                            }
                        }
                    }
                }
                :set bwExpNext 0
            } else={
                # Server unreachable. Try again in 5 minutes; meanwhile enforce
                # our own deadlines, but only with a clock the server confirmed
                # since this router booted.
                :set bwExpRetryAt ($nowm + 5)
                :if ($bwExpClockOk) do={ :set todo $due }
            }
        } else={
            :if (($due != "") && ($nowm < $bwExpRetryAt) && $bwExpClockOk) do={ :set todo $due }
        }

        # --- remove ---------------------------------------------------------
        :while ([:len $todo] > 0) do={
            :local ti [:find $todo ","]
            :local m $todo
            :if ([:typeof $ti] = "num") do={
                :set m [:pick $todo 0 $ti]
                :set todo [:pick $todo ($ti + 1) [:len $todo]]
            } else={ :set todo "" }
            :if ([:len $m] = 17) do={
                :local u ([:pick $m 0 2] . [:pick $m 3 5] . [:pick $m 6 8] . [:pick $m 9 11] . [:pick $m 12 14] . [:pick $m 15 17])
                :do { /ip hotspot ip-binding remove [find where mac-address=$m] } on-error={}
                :do { /ip hotspot active remove [find where mac-address=$m] } on-error={}
                :do { /ip hotspot host remove [find where mac-address=$m] } on-error={}
                :do { /ip hotspot user remove [find where name=$u] } on-error={}
                :do { /queue simple remove [find where name=("plan_" . $u)] } on-error={}
                :if ([:len $bwExpDone] < 700) do={ :set bwExpDone ($bwExpDone . $m . "@" . $nowm . ",") }
                :log info ("expiry-reaper: removed " . $m)
            }
        }
    }
}

/system scheduler add name="__SCHED__" interval=1m start-time=startup on-event="/system script run __SCRIPT__" policy=__POLICY__ comment="__COMMENT__"
:log info "expiry-reaper: installed for __IDENT__"
'''


def _require(value: str, rx: re.Pattern, name: str) -> str:
    v = str(value or "").strip()
    if not rx.match(v):
        raise ValueError(f"expiry-reaper script: unsafe {name}={value!r}")
    return v


def render_expiry_reaper_script(*, identity: str, tunnel_url: str, public_url: str) -> str:
    """The installable RouterOS script (the ``source={...}`` body is also what
    the API installer puts into ``/system script``)."""
    identity = _require(identity, _IDENTITY_RE, "identity")
    tunnel_url = _require(tunnel_url, _URL_RE, "tunnel_url")
    public_url = _require(public_url, _URL_RE, "public_url")
    return (
        _TEMPLATE
        .replace("__SCRIPT__", SCRIPT_NAME)
        .replace("__SCHED__", SCHEDULER_NAME)
        .replace("__POLICY__", POLICY)
        .replace("__COMMENT__", COMMENT)
        .replace("__TURL__", tunnel_url)
        .replace("__PURL__", public_url)
        .replace("__TOKEN__", derive_router_token(identity))
        .replace("__IDENT__", identity)
    )


def script_source(rendered: str) -> str:
    """Just the body between ``source={`` and its closing brace."""
    start = rendered.index("source={\n") + len("source={\n")
    end = rendered.index("\n}\n\n/system scheduler add")
    return rendered[start:end]
