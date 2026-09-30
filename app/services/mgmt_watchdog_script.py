"""Router-side management-tunnel watchdog (SSTP and WireGuard variants).

Ported from the host tool ``/root/bw_watchdog.py`` (v4, 2026-09-27) so the app
can install it on every router it enrols (``standard_runtime_enrol``). The two
RouterOS sources below are the field-tested v4 sources, unchanged apart from
the per-router splay.

What the scripts do (patient, never reboot):

* SSTP (``bw-mgmt-watchdog``, client ``sstp-hetzner``): healthy = the client
  is running and 10.251.0.1 answers a ping. A failure only counts when the
  router's own internet works (1.1.1.1 / 8.8.8.8 answer). After 3 counted
  failures the client is disabled/enabled once, then held off 10 min, doubling
  to 60 min while it stays broken.
* WireGuard (``bw-mgmt-watchdog-wg``, RouterOS 7): watches the peers of
  ``wg-hz`` / ``wg-aws`` whose INTERFACE is enabled. A peer whose handshake is
  older than 5 min is reset (conntrack for its endpoint flow removed, peer
  disabled/enabled), with the same hold-off and backoff.
  v5: when a reset did not bring the peer back (the backoff entry from the
  previous reset is still there) and the router's internet works, the
  interface's ``listen-port`` is also moved to a random port. A reset alone
  keeps the same source port, so a broken NAT entry on the ISP modem/CGNAT
  that our 25 s keepalives never let expire keeps eating the replies (router
  393, 2026-09-30: 5 h dark, fixed at once by a new port). The servers learn
  the new endpoint from the next handshake; replies are accepted as
  established traffic, so no new input rule is needed.
* State lives in RAM-only dynamic address-list entries (``bw-wd-*``, with
  timeouts): script ``:global`` variables do NOT persist between scheduler runs
  of an API-created script (verified on RouterOS 6.48.6).
* ``__SPLAY__`` = last octet of the management IP mod 40 s (SSTP) / 20 s (WG),
  so routers behind one outage do not all redial in the same second.

The scheduler runs the script every minute. Nothing here calls
``/system/script/run`` over the API: a long script run that way can die with
the API session.

The install/uninstall helpers take a connected ``MikroTikAPI`` (or anything
with ``send_command``) and do RouterOS I/O only; callers must not hold a DB
session while calling them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

KIND_SSTP = "sstp"
KIND_WG = "wg"

SCRIPT_NAME_SSTP = "bw-mgmt-watchdog"
SCRIPT_NAME_WG = "bw-mgmt-watchdog-wg"
SCRIPT_NAMES = {KIND_SSTP: SCRIPT_NAME_SSTP, KIND_WG: SCRIPT_NAME_WG}
POLICY = "read,write,test"
COMMENT = "Bitwave mgmt-tunnel watchdog"
INTERVAL = "1m"
SSTP_CLIENT = "sstp-hetzner"
WG_INTERFACES = ("wg-hz", "wg-aws")
SPLAY_MOD = {KIND_SSTP: 40, KIND_WG: 20}
STATE_LIST_PREFIX = "bw-wd"
# Bump when a template changes: routers whose recorded install reason lacks
# "<kind> <version>" are picked up again by standard_runtime_enrol and updated.
VERSIONS = {KIND_SSTP: "v3", KIND_WG: "v5"}
# Range the WG watchdog picks a new listen-port from (above the 51820-51834
# ports provisioning uses, below the ephemeral range).
ROTATE_PORT_MIN = 40000
ROTATE_PORT_MAX = 48999

_SSTP_TEMPLATE = r'''# bw-mgmt-watchdog v3 (Bitwave): restart the SSTP management tunnel if it stays dead. Never reboots.
# v3: healthy fast path (tunnel running + 1 ping answered) exits before any address-list scan.
:local iface "sstp-hetzner"
:local srv "10.251.0.1"
:local fid [/interface sstp-client find where name=$iface]
:local healthy false
:if ([:len $fid] > 0) do={ :if ([/interface sstp-client get $fid running] = true) do={ :if ([/ping $srv count=1] > 0) do={ :set healthy true } } }
:if ($healthy = false) do={
:local t [/ip firewall address-list find where list="bw-wd-test"]
:if ([:len $t] > 0) do={ :set srv [/ip firewall address-list get [:pick $t 0] address] }
:local id [/interface sstp-client find where name=$iface]
:if ([:len $id] > 0) do={
  :if ([:len [/ip firewall address-list find where list="bw-wd-busy"]] > 0) do={
    /interface sstp-client enable $id
    /ip firewall address-list remove [find where list="bw-wd-busy"]
  }
  :local ok false
  :if ([/interface sstp-client get $id running] = true) do={
    :if ([/ping $srv count=3 interval=1s] > 0) do={ :set ok true }
  }
  :if ($ok) do={
    /ip firewall address-list remove [find where list="bw-wd-fail"]
    /ip firewall address-list remove [find where list="bw-wd-backoff"]
  } else={
    :if (([/ping 1.1.1.1 count=2] + [/ping 8.8.8.8 count=2]) > 0) do={
      :local n ([:len [/ip firewall address-list find where list="bw-wd-fail"]] + 1)
      /ip firewall address-list add list=bw-wd-fail address=("0.0.0." . $n) timeout=10m
    }
    :local fails [:len [/ip firewall address-list find where list="bw-wd-fail"]]
    :local held [:len [/ip firewall address-list find where list="bw-wd-hold"]]
    :if ($fails >= 3 && $held = 0) do={
      :local hold 10
      :local b [/ip firewall address-list find where list="bw-wd-backoff"]
      :if ([:len $b] > 0) do={
        :local a [:tostr [/ip firewall address-list get [:pick $b 0] address]]
        :set hold [:tonum [:pick $a 6 [:len $a]]]
      }
      :log warning ("bw-watchdog: " . $iface . " dead for " . $fails . " checks, restarting it; hold " . $hold . " min")
      :delay __SPLAY__
      /ip firewall address-list add list=bw-wd-busy address=0.0.0.1 timeout=5m
      /interface sstp-client disable $id
      :delay 5s
      /interface sstp-client enable $id
      /ip firewall address-list remove [find where list="bw-wd-busy"]
      /ip firewall address-list remove [find where list="bw-wd-fail"]
      /ip firewall address-list add list=bw-wd-hold address=0.0.0.1 timeout=[:totime ($hold . "m")]
      :local next ($hold * 2)
      :if ($next > 60) do={ :set next 60 }
      /ip firewall address-list remove [find where list="bw-wd-backoff"]
      /ip firewall address-list add list=bw-wd-backoff address=("0.0.0." . $next) timeout=3h
    }
  }
}
}
'''

_WG_TEMPLATE = r'''# bw-mgmt-watchdog-wg v5 (Bitwave, RouterOS 7): reset a WireGuard management peer whose handshake is stale.
# Never reboots. State in RAM-only address-list entries (bw-wd-*). Test hook: list bw-wd-test-stale => treat all as stale.
# v3: healthy fast path (every watched peer enabled with a fresh handshake) exits before pings/address-list scans.
# v4: only tunnels whose INTERFACE is enabled are watched, so a Hetzner-only router with wg-aws switched off is not
# treated as stale every minute (and the AWS peer is never touched).
# v5: a reset that did not help (backoff entry still present) + working internet => also move the interface to a
# random listen-port, so the ISP NAT has to build a fresh entry (a stuck one outlives every same-port reset).
:local hzOn ([:len [/interface wireguard find where name="wg-hz" disabled=no]] > 0)
:local awsOn ([:len [/interface wireguard find where name="wg-aws" disabled=no]] > 0)
:local fresh true
:foreach q in=[/interface wireguard peers find where (interface="wg-hz" or interface="wg-aws")] do={
  :local qi [/interface wireguard peers get $q interface]
  :if (($qi = "wg-hz" && $hzOn) || ($qi = "wg-aws" && $awsOn)) do={
    :if ([/interface wireguard peers get $q disabled] = true) do={ :set fresh false } else={
      :local qh [/interface wireguard peers get $q last-handshake]
      :if ([:typeof $qh] != "time") do={ :set fresh false } else={ :if ($qh >= 4m) do={ :set fresh false } }
    }
  }
}
:if ($fresh = false) do={
:local staleAfter 5m
:if ([:len [/ip firewall address-list find where list="bw-wd-test-stale"]] > 0) do={ :set staleAfter 0s }
:foreach ifn in={"wg-hz";"wg-aws"} do={
  :if ([:len [/ip firewall address-list find where list=("bw-wd-busy-" . $ifn)]] > 0) do={
    /interface wireguard peers enable [find where interface=$ifn]
    /ip firewall address-list remove [find where list=("bw-wd-busy-" . $ifn)]
  }
}
:local up false
:if (([/ping 1.1.1.1 count=1] + [/ping 8.8.8.8 count=1]) > 0) do={ :set up true }
:foreach p in=[/interface wireguard peers find where disabled=no] do={
  :local ifn [/interface wireguard peers get $p interface]
  :if (($ifn = "wg-hz" && $hzOn) || ($ifn = "wg-aws" && $awsOn)) do={
    :local hs [/interface wireguard peers get $p last-handshake]
    :if ([:typeof $hs] = "time") do={ :if ($hs < 3m) do={ :set up true } }
  }
}
:foreach p in=[/interface wireguard peers find where disabled=no] do={
  :local ifn [/interface wireguard peers get $p interface]
  :if (($ifn = "wg-hz" && $hzOn) || ($ifn = "wg-aws" && $awsOn)) do={
    :local hs [/interface wireguard peers get $p last-handshake]
    :local stale true
    :if ([:typeof $hs] = "time") do={ :if ($hs < $staleAfter) do={ :set stale false } }
    :local hl ("bw-wd-hold-" . $ifn)
    :local bl ("bw-wd-backoff-" . $ifn)
    :if ($stale = false) do={
      /ip firewall address-list remove [find where list=$bl]
    } else={
      :if ([:len [/ip firewall address-list find where list=$hl]] = 0) do={
        :local hold 10
        :local b [/ip firewall address-list find where list=$bl]
        :local rotate false
        :if ([:len $b] > 0) do={
          :local a [:tostr [/ip firewall address-list get [:pick $b 0] address]]
          :set hold [:tonum [:pick $a 6 [:len $a]]]
          :if ($up) do={ :set rotate true }
        }
        :if ($up = false) do={ :set hold 60 }
        :local ep [/interface wireguard peers get $p endpoint-address]
        :local epp [/interface wireguard peers get $p endpoint-port]
        :log warning ("bw-watchdog: " . $ifn . " handshake stale (" . [:tostr $hs] . "), resetting peer; hold " . $hold . " min")
        # Record the hold-off and next backoff FIRST, so a failure later in this run can never
        # cause a reset again on the next minute (seen 2026-09-26: "no such item" from the
        # conntrack cleanup aborted the run before the hold was written).
        :do { /ip firewall address-list add list=$hl address=0.0.0.1 timeout=[:totime ($hold . "m")] } on-error={}
        :local next ($hold * 2)
        :if ($next > 60) do={ :set next 60 }
        :do { /ip firewall address-list remove [find where list=$bl] } on-error={}
        :do { /ip firewall address-list add list=$bl address=("0.0.0." . $next) timeout=3h } on-error={}
        :delay __SPLAY__
        :foreach cx in=[/ip firewall connection find where protocol="udp" dst-address=($ep . ":" . $epp)] do={
          :do { /ip firewall connection remove $cx } on-error={}
        }
        :do { /ip firewall address-list add list=("bw-wd-busy-" . $ifn) address=0.0.0.1 timeout=5m } on-error={}
        :do { /interface wireguard peers disable $p } on-error={}
        :if ($rotate) do={
          :do {
            :local wi [/interface wireguard find where name=$ifn]
            :local op [/interface wireguard get $wi listen-port]
            :local np [:rndnum from=__PORT_MIN__ to=__PORT_MAX__]
            :if ($np = $op) do={ :set np ($np + 1) }
            /interface wireguard set $wi listen-port=$np
            :log warning ("bw-watchdog: " . $ifn . " still stale after a reset, listen-port " . $op . " -> " . $np)
          } on-error={ :log warning ("bw-watchdog: " . $ifn . " listen-port change failed") }
        }
        :delay 2s
        :do { /interface wireguard peers enable $p } on-error={}
        :do { /ip firewall address-list remove [find where list=("bw-wd-busy-" . $ifn)] } on-error={}
      }
    }
  }
}
}
'''

_TEMPLATES = {KIND_SSTP: _SSTP_TEMPLATE, KIND_WG: _WG_TEMPLATE}


def script_name(kind: str) -> str:
    if kind not in SCRIPT_NAMES:
        raise ValueError(f"watchdog: unknown kind {kind!r}")
    return SCRIPT_NAMES[kind]


def splay_seconds(kind: str, mgmt_ip: Optional[str]) -> int:
    """Last octet of the management IP mod 40 (SSTP) / 20 (WG); 0 if unparsable."""
    mod = SPLAY_MOD.get(kind, SPLAY_MOD[KIND_SSTP])
    try:
        return int(str(mgmt_ip or "").strip().split(".")[-1]) % mod
    except ValueError:
        return 0


def render_watchdog_source(kind: str, mgmt_ip: Optional[str]) -> str:
    """The ``source`` of the watchdog script for this router."""
    script_name(kind)  # validates kind
    return (
        _TEMPLATES[kind]
        .replace("__SPLAY__", f"{splay_seconds(kind, mgmt_ip)}s")
        .replace("__PORT_MIN__", str(ROTATE_PORT_MIN))
        .replace("__PORT_MAX__", str(ROTATE_PORT_MAX))
    )


def version_tag(kind: str) -> str:
    """``"wg v5"``: recorded in the install reason so outdated installs can be found."""
    script_name(kind)  # validates kind
    return f"{kind} {VERSIONS[kind]}"


def is_current(kind: Optional[str], reason: Optional[str]) -> bool:
    """Whether a router's recorded install (kind + reason) has the current template."""
    return kind in VERSIONS and version_tag(kind) in str(reason or "")


def _data(res) -> list:
    return (res or {}).get("data") or []


def _find(api, path: str, name: str) -> Optional[dict]:
    return next((r for r in _data(api.send_command(f"{path}/print")) if r.get("name") == name), None)


def detect_kind(api, version: str) -> tuple[Optional[str], str]:
    """Which watchdog fits this router, from what it actually has.

    * an ENABLED ``sstp-hetzner`` client -> SSTP (a staged or reverted,
      disabled one is not the management tunnel);
    * else RouterOS 7 with a peer on an ENABLED ``wg-hz`` / ``wg-aws``
      interface -> WireGuard;
    * else nothing to watch (e.g. L2TP-only routers: no L2TP variant yet).
    """
    sstp = _find(api, "/interface/sstp-client", SSTP_CLIENT)
    if sstp and sstp.get("disabled") != "true":
        return KIND_SSTP, f"{SSTP_CLIENT} client"
    if not str(version or "").startswith("7"):
        return None, f"no enabled {SSTP_CLIENT} client on RouterOS {version or '?'}"
    enabled = {
        w.get("name") for w in _data(api.send_command("/interface/wireguard/print"))
        if w.get("name") in WG_INTERFACES and w.get("disabled") != "true"
    }
    peers = [p for p in _data(api.send_command("/interface/wireguard/peers/print"))
             if p.get("interface") in enabled]
    if peers:
        return KIND_WG, "peers on " + "/".join(sorted({p.get("interface") for p in peers}))
    return None, f"no enabled {SSTP_CLIENT} client and no peer on an enabled wg-hz/wg-aws"


@dataclass
class InstallResult:
    # installed / updated / unchanged / scheduler_disabled / script_failed / scheduler_failed
    status: str
    kind: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("installed", "updated", "unchanged")


def _remove_named(api, name: str) -> None:
    # Scheduler first, so it can never fire a script that is already gone.
    for path in ("/system/scheduler", "/system/script"):
        for item in _data(api.send_command(f"{path}/print")):
            if item.get("name") == name:
                api.send_command(f"{path}/remove", {".id": item[".id"]})


def install_watchdog(api, kind: str, mgmt_ip: Optional[str]) -> InstallResult:
    """Install or update the ``kind`` watchdog. Idempotent.

    * The other kind's script and scheduler are removed (the router moved
      between SSTP and WireGuard).
    * An identical script is not rewritten (no flash write); a different one
      is updated in place.
    * An existing scheduler is left as it is. A DISABLED one means someone
      paused the watchdog on purpose: reported as ``scheduler_disabled`` and
      not re-enabled.
    """
    name = script_name(kind)
    source = render_watchdog_source(kind, mgmt_ip)
    for other_kind, other in SCRIPT_NAMES.items():
        if other_kind != kind:
            _remove_named(api, other)

    changed = False
    res: dict = {}
    script = _find(api, "/system/script", name)
    if script is None:
        res = api.send_command("/system/script/add",
                               {"name": name, "source": source, "policy": POLICY, "comment": COMMENT})
        changed = True
    elif script.get("source") != source or script.get("policy") != POLICY:
        res = api.send_command("/system/script/set",
                               {".id": script[".id"], "source": source, "policy": POLICY})
        changed = True
    if (res or {}).get("error"):
        return InstallResult("script_failed", kind, str(res["error"])[:200])

    sched = _find(api, "/system/scheduler", name)
    if sched is None:
        res = api.send_command("/system/scheduler/add", {
            "name": name, "interval": INTERVAL, "start-time": "startup",
            "on-event": f"/system script run {name}", "policy": POLICY, "comment": COMMENT,
        })
        if (res or {}).get("error"):
            return InstallResult("scheduler_failed", kind, str(res["error"])[:200])
        return InstallResult("installed", kind)
    if sched.get("disabled") == "true":
        return InstallResult("scheduler_disabled", kind)
    return InstallResult("updated" if changed else "unchanged", kind)


def uninstall_watchdog(api) -> None:
    """Remove both watchdog variants and their RAM state entries."""
    for name in SCRIPT_NAMES.values():
        _remove_named(api, name)
    for entry in _data(api.send_command("/ip/firewall/address-list/print")):
        if str(entry.get("list", "")).startswith(STATE_LIST_PREFIX):
            api.send_command("/ip/firewall/address-list/remove", {".id": entry[".id"]})
