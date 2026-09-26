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
3. POST ``v=1&id=<identity>&n=<count>&macs=<csv>&q=<csv>`` with the check-in
   token. Sending ``q=`` (even empty) tells the server this applier
   understands ``Q`` lines; it is left out if the queue check itself failed.
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
"""

from __future__ import annotations

import re

from app.services.usage_push_auth import derive_checkin_token

SCRIPT_NAME = "bitwave-checkin"
SCHEDULER_NAME = "bitwave-checkin"
POLICY = "read,write,test,policy"
SCHEDULER_COMMENT = "Bitwave check-in delivery (pilot)"
INITIAL_INTERVAL_SECONDS = 60

CHECK_CERTIFICATE_VALUES = ("no", "yes", "yes-without-crl")

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
    :do {
        :foreach b in=[/ip hotspot ip-binding find where comment~"USER:"] do={
            :local bm [:tostr [/ip hotspot ip-binding get $b mac-address]]
            :if ([:len $bm] = 17) do={
                :if ($n > 0) do={ :set macs ($macs . ",") }
                :set macs ($macs . $bm)
                :set n ($n + 1)
                :do {
                    :local bc [:tostr [/ip hotspot ip-binding get $b comment]]
                    :if ([:typeof [:find $bc "CHECKIN"]] = "num") do={
                        :local rf ([:pick $bm 0 2] . [:pick $bm 3 5] . [:pick $bm 6 8] . [:pick $bm 9 11] . [:pick $bm 12 14] . [:pick $bm 15 17])
                        :if ([:len [/queue simple find where name=("plan_" . $rf)]] = 0) do={
                            :if ($nq > 0) do={ :set qmacs ($qmacs . ",") }
                            :set qmacs ($qmacs . $bm)
                            :set nq ($nq + 1)
                        }
                    }
                } on-error={ :set qOk false }
            }
        }
    } on-error={ :set readOk false }
    :local post ("v=1&id=" . $ident . "&n=" . $n . "&macs=" . $macs)
    :if ($qOk) do={ :set post ($post . "&q=" . $qmacs) }
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
                :if ($ok) do={ :set cnt ($cnt + 1) } else={ :set bad true }
            }
        }
        :if ((!$bad) && $done && ($cnt = $want)) do={
            :set frameOk true
        } else={
            :log warning "checkin: reply rejected, nothing applied"
        }
    }
    # Pass 2: apply. Same splitting; only reached when pass 1 accepted it all.
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
                :local mac [:pick $ln 2 19]
                :local ref [:pick $ln ($ll - 12) $ll]
                :local rate ""
                :local need false
                :if ($kind = "A") do={
                    :set rate [:pick $ln 20 ($ll - 24)]
                    :if ([:len [/ip hotspot ip-binding find where mac-address=$mac]] = 0) do={
                        :set need true
                    } else={
                        :log info ("checkin: " . $mac . " already has a binding, left alone")
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
                            /ip hotspot ip-binding add mac-address=$mac type=bypassed comment=("USER:" . $ref . "|EXPIRES:DB_MANAGED|CHECKIN")
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
}
'''


def _require(value: str, rx: re.Pattern, name: str) -> str:
    v = str(value or "").strip()
    if not rx.match(v):
        raise ValueError(f"checkin applier: unsafe {name}={value!r}")
    return v


def render_checkin_applier_source(
    *,
    identity: str,
    endpoint_url: str,
    check_certificate: str = "no",
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
    return (
        _TEMPLATE
        .replace("__URL__", endpoint_url)
        .replace("__TOKEN__", token)
        .replace("__IDENT__", identity)
        .replace("__SCRIPT__", SCRIPT_NAME)
        .replace("__SCHED__", SCHEDULER_NAME)
        .replace("__CHECKCERT__", check_certificate)
    )


def scheduler_on_event() -> str:
    return f"/system script run {SCRIPT_NAME}"
